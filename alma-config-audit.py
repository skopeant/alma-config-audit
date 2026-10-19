#!/usr/bin/env python3

import argparse
import configparser
import copy
import fcntl
import hashlib
import json
from itertools import combinations
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests


CONFIG_FILE = "/etc/alma-config-audit.conf"


def log(msg=""):
    print(msg, flush=True)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_csv(value):
    return [
        item.strip()
        for item in (value or "").split(",")
        if item.strip()
    ]


def load_config():
    cfg = configparser.ConfigParser()

    if not cfg.read(CONFIG_FILE):
        raise RuntimeError(
            f"Nelze načíst konfiguraci {CONFIG_FILE}"
        )

    api_base = cfg.get(
        "alma",
        "api_base",
    ).rstrip("/")

    api_key = cfg.get(
        "alma",
        "api_key",
    ).strip()

    if not api_key or api_key == "SEM_API_KLIC":
        raise RuntimeError(
            "Není nastaven Alma API key."
        )

    primo_enabled = cfg.getboolean(
        "primo",
        "enabled",
        fallback=False,
    )

    primo_api_base = cfg.get(
        "primo",
        "api_base",
        fallback=(
            api_base.replace(
                "/almaws/v1",
                "/primo/v1",
            )
        ),
    ).rstrip("/")

    primo_views = parse_csv(
        cfg.get(
            "primo",
            "views",
            fallback="",
        )
    )

    return {
        "api_base": api_base,
        "api_key": api_key,

        "primo_enabled": primo_enabled,
        "primo_api_base": primo_api_base,
        "primo_views": primo_views,

        "database": cfg.get(
            "audit",
            "database",
            fallback="/var/lib/alma-config-audit/audit.sqlite3",
        ),

        "lock_file": cfg.get(
            "audit",
            "lock_file",
            fallback="/var/lib/alma-config-audit/audit.lock",
        ),

        "lock_wait_seconds": cfg.getint(
            "audit",
            "lock_wait_seconds",
            fallback=300,
        ),

        "include_code": cfg.getboolean(
            "audit",
            "include_code_tables",
            fallback=True,
        ),

        "include_mapping": cfg.getboolean(
            "audit",
            "include_mapping_tables",
            fallback=True,
        ),

        "include_extended": cfg.getboolean(
            "audit",
            "include_extended_configuration",
            fallback=True,
        ),

        "extra_code_tables": parse_csv(
            cfg.get(
                "audit",
                "extra_code_tables",
                fallback="",
            )
        ),

        # Optional multilingual Code Table audit. When empty, the script
        # keeps the historical behavior and retrieves only the institution
        # default language. Example: cs,en
        "code_table_languages": [
            language.lower()
            for language in parse_csv(
                cfg.get(
                    "audit",
                    "code_table_languages",
                    fallback="",
                )
            )
        ],

        "extra_mapping_tables": parse_csv(
            cfg.get(
                "audit",
                "extra_mapping_tables",
                fallback="",
            )
        ),

        "discovery_candidates_file": cfg.get(
            "audit",
            "discovery_candidates_file",
            fallback="/etc/alma-config-audit-discover.txt",
        ),

        "timeout": cfg.getint(
            "audit",
            "timeout",
            fallback=60,
        ),

        "request_delay": cfg.getfloat(
            "audit",
            "request_delay",
            fallback=0.10,
        ),

        "redact_patterns": [
            x.strip().lower()
            for x in cfg.get(
                "audit",
                "redact_patterns",
                fallback=(
                    "password,passwd,secret,token,"
                    "apikey,api_key,consumer_key,"
                    "licence_key,license_key,"
                    "jwt_signature"
                ),
            ).split(",")
            if x.strip()
        ],
    }


def connect_db(path):
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    conn = sqlite3.connect(
        path,
        timeout=30,
    )
    conn.row_factory = sqlite3.Row

    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=30000;

        CREATE TABLE IF NOT EXISTS current_object (
            object_type TEXT NOT NULL,
            object_name TEXT NOT NULL,
            object_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            PRIMARY KEY (
                object_type,
                object_name
            )
        );

        CREATE TABLE IF NOT EXISTS change_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            detected_at TEXT NOT NULL,

            object_type TEXT NOT NULL,
            object_name TEXT NOT NULL,

            change_type TEXT NOT NULL,
            row_key TEXT,

            before_json TEXT,
            after_json TEXT,

            analytics_event_id TEXT,
            analytics_event_at TEXT,
            analytics_user TEXT,
            analytics_description TEXT,

            enriched INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS discovered_object (
            object_type TEXT NOT NULL,
            object_name TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            source TEXT,
            PRIMARY KEY (
                object_type,
                object_name
            )
        );

        CREATE TABLE IF NOT EXISTS audit_scope (
            object_type TEXT PRIMARY KEY,
            initialized_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS object_label (
            object_type TEXT NOT NULL,
            object_name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (
                object_type,
                object_name
            )
        );

        CREATE INDEX IF NOT EXISTS
            idx_change_log_detected
        ON change_log (
            detected_at
        );

        CREATE INDEX IF NOT EXISTS
            idx_change_log_object
        ON change_log (
            object_type,
            object_name
        );

        CREATE INDEX IF NOT EXISTS
            idx_change_log_enriched
        ON change_log (
            enriched
        );
        """
    )

    return conn


def acquire_audit_lock(
    lock_file,
    wait_seconds=300,
):
    """
    Zabrání souběžnému zápisu více auditních skriptů do stejné SQLite DB.
    Lock je společný pro API i Analytics audit a funguje i při ručním spuštění.
    """
    lock_dir = os.path.dirname(lock_file)

    if lock_dir:
        os.makedirs(
            lock_dir,
            exist_ok=True,
        )

    handle = open(
        lock_file,
        "a+",
        encoding="utf-8",
    )

    deadline = time.monotonic() + max(
        0,
        wait_seconds,
    )

    while True:
        try:
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_EX
                | fcntl.LOCK_NB,
            )
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                handle.close()
                raise RuntimeError(
                    "Nepodařilo se získat auditní lock "
                    f"{lock_file} do {wait_seconds} s."
                )

            time.sleep(1)

    handle.seek(0)
    handle.truncate()
    handle.write(
        f"pid={os.getpid()} started={utc_now()}\n"
    )
    handle.flush()

    return handle


def release_audit_lock(handle):
    if handle is None:
        return

    try:
        fcntl.flock(
            handle.fileno(),
            fcntl.LOCK_UN,
        )
    finally:
        handle.close()


class AlmaAPI:
    def __init__(self, cfg):
        self.base = cfg["api_base"]
        self.key = cfg["api_key"]
        self.timeout = cfg["timeout"]
        self.delay = cfg["request_delay"]

        self.session = requests.Session()

        self.calls = 0
        self.remaining = None

    def request(
        self,
        path,
        params=None,
        allow_not_found=False,
    ):
        query = {
            "apikey": self.key,
            "format": "json",
        }

        if params:
            query.update(params)

        response = self.session.get(
            self.base + path,
            params=query,
            timeout=self.timeout,
        )

        self.calls += 1

        remaining = response.headers.get(
            "X-Exl-Api-Remaining"
        )

        if remaining:
            self.remaining = remaining

        if self.delay:
            time.sleep(self.delay)

        if (
            allow_not_found
            and response.status_code in (
                400,
                404,
            )
        ):
            return None

        if not response.ok:
            raise RuntimeError(
                f"GET {path}: "
                f"HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )

        return response.json()

    def get(
        self,
        path,
        params=None,
    ):
        return self.request(
            path,
            params=params,
            allow_not_found=False,
        )

    def try_get(
        self,
        path,
        params=None,
    ):
        return self.request(
            path,
            params=params,
            allow_not_found=True,
        )

    def list_code_tables(self):
        data = self.get(
            "/conf/code-tables"
        )

        return data.get(
            "code_table",
            [],
        )

    def list_mapping_tables(self):
        data = self.get(
            "/conf/mapping-tables"
        )

        return data.get(
            "mapping_table",
            [],
        )

    def get_code_table(self, name, lang=None):
        params = None

        if lang:
            params = {
                "lang": lang,
            }

        return self.get(
            "/conf/code-tables/"
            + quote(name, safe=""),
            params=params,
        )

    def get_mapping_table(self, code):
        return self.get(
            "/conf/mapping-tables/"
            + quote(code, safe="")
        )

    def try_code_table(self, name):
        return self.try_get(
            "/conf/code-tables/"
            + quote(name, safe="")
        )

    def try_mapping_table(self, name):
        return self.try_get(
            "/conf/mapping-tables/"
            + quote(name, safe="")
        )


def should_redact(
    name,
    patterns,
):
    value = str(
        name or ""
    ).lower()

    return any(
        pattern in value
        for pattern in patterns
    )


def redact_mapping_table(
    data,
    patterns,
):
    result = copy.deepcopy(data)

    for row in result.get(
        "row",
        [],
    ):
        key = str(
            row.get(
                "column0",
                "",
            )
        )

        if should_redact(
            key,
            patterns,
        ):
            for column in list(
                row.keys()
            ):
                if (
                    column.startswith("column")
                    and column != "column0"
                ):
                    row[column] = (
                        "***REDACTED***"
                    )

    return result


def redact_code_table(
    data,
    patterns,
):
    result = copy.deepcopy(data)

    for row in result.get(
        "row",
        [],
    ):
        code = str(
            row.get(
                "code",
                "",
            )
        )

        if should_redact(
            code,
            patterns,
        ):
            for key in list(
                row.keys()
            ):
                if key != "code":
                    row[key] = (
                        "***REDACTED***"
                    )

    return result


def sanitize_generic(
    value,
    patterns,
    sensitive_context=False,
):
    if isinstance(value, list):
        return [
            sanitize_generic(
                item,
                patterns,
                sensitive_context,
            )
            for item in value
        ]

    if not isinstance(value, dict):
        if sensitive_context:
            return "***REDACTED***"

        return value

    identifiers = []

    for key in (
        "name",
        "code",
        "key",
        "parameter_name",
    ):
        candidate = value.get(key)

        if isinstance(
            candidate,
            (
                str,
                int,
                float,
            ),
        ):
            identifiers.append(
                str(candidate)
            )

    local_sensitive = (
        sensitive_context
        or should_redact(
            " ".join(identifiers),
            patterns,
        )
    )

    result = {}

    for key, item in value.items():
        lower_key = str(
            key
        ).lower()

        if lower_key == "link":
            continue

        key_sensitive = should_redact(
            lower_key,
            patterns,
        )

        if key_sensitive:
            result[key] = (
                "***REDACTED***"
            )
            continue

        if (
            local_sensitive
            and lower_key in (
                "value",
                "content",
            )
        ):
            result[key] = (
                "***REDACTED***"
            )
            continue

        result[key] = sanitize_generic(
            item,
            patterns,
            False,
        )

    return result



def remove_global_runtime_noise(
    value,
):
    """Odstraní provozní hodnoty, které nechceme auditovat nikde.

    lastProcessDirectory je technický stav posledního běhu integračního
    procesu. Mění se automaticky bez změny konfigurace, proto je
    odstraněn z libovolného seznamu parameter podle name.value.
    """
    if isinstance(
        value,
        list,
    ):
        cleaned = []

        for item in value:
            if isinstance(
                item,
                dict,
            ):
                name = item.get(
                    "name"
                )

                if isinstance(
                    name,
                    dict,
                ):
                    name_value = str(
                        name.get(
                            "value",
                            "",
                        )
                    ).strip()

                    if (
                        name_value
                        == "lastProcessDirectory"
                    ):
                        continue

            cleaned.append(
                remove_global_runtime_noise(
                    item
                )
            )

        return cleaned

    if isinstance(
        value,
        dict,
    ):
        return {
            key: remove_global_runtime_noise(
                item
            )
            for key, item in value.items()
        }

    return value


def normalize_payload(
    object_type,
    data,
    redact_patterns,
):
    result = copy.deepcopy(data)

    result.pop(
        "link",
        None,
    )

    if object_type in (
        "code",
        "mapping",
    ):
        result.pop(
            "updated_by",
            None,
        )

        result.pop(
            "update_date",
            None,
        )

    if object_type == "scheduled_job":
        # Scheduled Jobs se musí porovnávat podle vlastní konfigurace,
        # ne podle technických/metadatových údajů Almy.
        #
        # next_run je provozní údaj, který se automaticky posouvá.
        # id se při deaktivaci/aktivaci nebo přegenerování sady jobů
        # může změnit, i když jde obsahově o stejný job.
        # creator se při takovém přegenerování může změnit na uživatele,
        # který operaci provedl, a proto také nesmí měnit hash konfigurace.
        for key in (
            "next_run",
            "id",
            "creator",
        ):
            result.pop(
                key,
                None,
            )

        # schedule.desc je pouze textový popis plánovacího slotu.
        # Alma jej může hromadně přepočítat (např. 08:00 -> 07:00),
        # aniž by se změnila kanonická hodnota schedule.value.
        # Pro audit proto používáme value, nikoli automaticky
        # generovaný desc.
        schedule = result.get(
            "schedule"
        )

        if isinstance(
            schedule,
            dict,
        ):
            schedule.pop(
                "desc",
                None,
            )

    if object_type == "mapping":
        return redact_mapping_table(
            result,
            redact_patterns,
        )

    if object_type == "code":
        return redact_code_table(
            result,
            redact_patterns,
        )

    result = sanitize_generic(
        result,
        redact_patterns,
    )

    # Provozní parametry, které se automaticky mění bez zásahu
    # do konfigurace, odstraňujeme napříč všemi typy objektů.
    result = remove_global_runtime_noise(
        result
    )

    if object_type == "library":
        result.pop(
            "number_of_locations",
            None,
        )

        result.pop(
            "number_of_circ_desks",
            None,
        )

    if object_type == "library_department":
        # Alma nemusí garantovat stabilní pořadí operátorů ani knihoven.
        # Řadíme je podle stabilních identifikátorů, aby pouhá změna pořadí
        # nevytvářela falešný konfigurační diff.
        operators = result.get(
            "operator",
            [],
        )

        if isinstance(operators, list):
            result["operator"] = sorted(
                operators,
                key=lambda item: (
                    str(
                        item.get(
                            "primary_id",
                            "",
                        )
                    )
                    if isinstance(item, dict)
                    else str(item)
                ),
            )

        libraries = result.get(
            "library",
            [],
        )

        if isinstance(libraries, list):
            result["library"] = sorted(
                libraries,
                key=lambda item: (
                    str(
                        item.get(
                            "value",
                            "",
                        )
                    )
                    if isinstance(item, dict)
                    else str(item)
                ),
            )


    if object_type == "primo_view":
        # Primo Configuration API vrací v každém View také některé
        # sdílené mapping tables. Typicky "View Properties" obsahuje
        # řádky pro více různých Views. Změna v TEST View by tak bez
        # filtrace změnila hash i produkčního a záložního View.
        #
        # Pro audit konkrétního View proto v "View Properties"
        # ponecháme pouze řádky patřící aktuálnímu VID.
        # Současně je stabilně seřadíme, aby pouhá změna pořadí
        # v odpovědi API nevytvářela falešný diff.
        vid = str(
            result.get(
                "_audit_key",
                "",
            )
        )

        configuration = result.get(
            "configuration",
            {},
        )

        if isinstance(
            configuration,
            dict,
        ):
            mapping_tables = configuration.get(
                "mapping-tables",
                {},
            )

            if isinstance(
                mapping_tables,
                dict,
            ):
                view_properties = mapping_tables.get(
                    "View Properties",
                )

                if isinstance(
                    view_properties,
                    list,
                ):
                    filtered = []

                    for item in view_properties:
                        if not isinstance(
                            item,
                            dict,
                        ):
                            continue

                        if str(
                            item.get(
                                "source1",
                                "",
                            )
                        ) == vid:
                            filtered.append(
                                item
                            )

                    mapping_tables[
                        "View Properties"
                    ] = sorted(
                        filtered,
                        key=lambda item: (
                            str(
                                item.get(
                                    "source2",
                                    "",
                                )
                            ),
                            str(
                                item.get(
                                    "source3",
                                    "",
                                )
                            ),
                            str(
                                item.get(
                                    "source4",
                                    "",
                                )
                            ),
                            str(
                                item.get(
                                    "source5",
                                    "",
                                )
                            ),
                            str(
                                item.get(
                                    "source6",
                                    "",
                                )
                            ),
                            str(
                                item.get(
                                    "target",
                                    "",
                                )
                            ),
                            canonical_json(
                                item
                            ),
                        ),
                    )


                # Primo Configuration API vrací tabulku
                # "Rapido Self Registration Optional Parameters"
                # v nestabilním pořadí. Obsah řádků je přitom stejný,
                # ale jiné pořadí mění hash celého Primo View a vytváří
                # falešné OBJECT_UPDATED. Pro tuto konkrétní tabulku
                # proto pořadí stabilizujeme podle celého obsahu řádku.
                # Skutečná změna kterékoliv hodnoty zůstává zachycena.
                rapido_self_registration = mapping_tables.get(
                    "Rapido Self Registration Optional Parameters",
                )

                if isinstance(
                    rapido_self_registration,
                    list,
                ):
                    mapping_tables[
                        "Rapido Self Registration Optional Parameters"
                    ] = sorted(
                        rapido_self_registration,
                        key=canonical_json,
                    )

    if object_type == "integration_profile":
        # Alma může vracet parametry integračního profilu v jiném pořadí.
        # Pořadí samo o sobě není změna konfigurace, proto seznam
        # stabilně řadíme podle názvu, akce a nakonec celého obsahu.
        parameters = result.get(
            "parameter",
            [],
        )

        if isinstance(parameters, list):
            def integration_parameter_sort_key(item):
                if not isinstance(item, dict):
                    return (
                        "",
                        "",
                        canonical_json(item),
                    )

                name = item.get(
                    "name",
                    {},
                )
                action = item.get(
                    "action",
                    {},
                )

                if isinstance(name, dict):
                    name_value = str(
                        name.get(
                            "value",
                            name.get(
                                "desc",
                                "",
                            ),
                        )
                    )
                else:
                    name_value = str(name)

                if isinstance(action, dict):
                    action_value = str(
                        action.get(
                            "value",
                            action.get(
                                "desc",
                                "",
                            ),
                        )
                    )
                else:
                    action_value = str(action)

                return (
                    name_value,
                    action_value,
                    canonical_json(item),
                )

            result["parameter"] = sorted(
                parameters,
                key=integration_parameter_sort_key,
            )

    return result


def canonical_json(data):
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def hash_payload(data):
    return hashlib.sha256(
        canonical_json(
            data
        ).encode(
            "utf-8"
        )
    ).hexdigest()


def json_for_db(value):
    if value is None:
        return None

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
    )


def record_change(
    conn,
    detected_at,
    object_type,
    object_name,
    change_type,
    row_key=None,
    before=None,
    after=None,
):
    conn.execute(
        """
        INSERT INTO change_log (
            detected_at,
            object_type,
            object_name,
            change_type,
            row_key,
            before_json,
            after_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detected_at,
            object_type,
            object_name,
            change_type,
            row_key,
            json_for_db(before),
            json_for_db(after),
        ),
    )


def row_key_code(
    row,
    index,
):
    if "code" in row:
        return str(
            row["code"]
        )

    return f"#{index}"


def row_without_audit_metadata(row):
    """Vrátí řádek bez auditních metadat Almy.

    updated_by/update_date jsou užitečné pro zobrazení autora skutečné změny,
    ale jejich samotné doplnění nesmí vytvořit konfigurační změnu.
    """
    if not isinstance(row, dict):
        return row

    result = copy.deepcopy(row)
    result.pop("updated_by", None)
    result.pop("update_date", None)
    return result


def mapping_column_names(rows):
    columns = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        for key in row:
            if str(key).startswith("column"):
                suffix = str(key)[6:]
                if suffix.isdigit():
                    columns.add(str(key))

    return sorted(
        columns,
        key=lambda key: int(key[6:]),
    )


def mapping_key_value(row, columns):
    values = tuple(
        str(row.get(column, ""))
        for column in columns
    )

    if len(columns) == 1 and columns[0] == "column0":
        return values[0]

    return " | ".join(
        f"{column}={value}"
        for column, value in zip(columns, values)
    )


def mapping_key_columns(before_rows, after_rows):
    """Najde společnou stabilní kombinaci sloupců pro Mapping Table.

    Alma negarantuje pořadí řádků. Pokud column0 není unikátní, hledáme
    nejmenší kombinaci columnN, která je unikátní zvlášť v BEFORE i AFTER.
    Tím se vyhneme klíčům #index a falešným změnám při pouhém přeřazení.
    """
    all_rows = list(before_rows) + list(after_rows)
    columns = mapping_column_names(all_rows)

    if not columns:
        return None

    def usable(candidate, rows):
        keys = []

        for row in rows:
            if not isinstance(row, dict):
                return False

            values = tuple(
                str(row.get(column, ""))
                for column in candidate
            )

            if not any(values):
                return False

            keys.append(values)

        return len(keys) == len(set(keys))

    # Nejdřív zachováme dosavadní nejhezčí variantu: samotný column0.
    if (
        "column0" in columns
        and usable(("column0",), before_rows)
        and usable(("column0",), after_rows)
    ):
        return ("column0",)

    # Pak preferujeme kombinace obsahující column0 a co nejméně dalších
    # sloupců. Typický příklad: WorkOrderTypeStatuses = column0 + column1.
    for size in range(2, len(columns) + 1):
        candidates = list(combinations(columns, size))
        candidates.sort(
            key=lambda combo: (
                0 if "column0" in combo else 1,
                tuple(int(column[6:]) for column in combo),
            )
        )

        for candidate in candidates:
            if (
                usable(candidate, before_rows)
                and usable(candidate, after_rows)
            ):
                return candidate

    return None


def mapping_rows_to_dict_pair(before_rows, after_rows):
    key_columns = mapping_key_columns(
        before_rows,
        after_rows,
    )

    if key_columns is not None:
        old = {
            mapping_key_value(row, key_columns): row
            for row in before_rows
        }
        new = {
            mapping_key_value(row, key_columns): row
            for row in after_rows
        }
        return old, new

    # Krajní fallback: stabilní obsahový hash bez updated_by/update_date.
    # Přeřazení řádků pak nevytvoří změnu. Skutečná změna řádku se může
    # zobrazit jako odstranění+přidání, což je bezpečnější než falešný diff.
    def hashed(rows):
        result = {}
        counters = {}

        for row in rows:
            comparable = row_without_audit_metadata(row)
            digest = hashlib.sha256(
                canonical_json(comparable).encode("utf-8")
            ).hexdigest()[:16]
            count = counters.get(digest, 0) + 1
            counters[digest] = count
            key = f"hash:{digest}#{count}"
            result[key] = row

        return result

    return hashed(before_rows), hashed(after_rows)


def rows_to_dict(
    object_type,
    payload,
):
    rows = (
        payload.get(
            "row",
            [],
        )
        or []
    )

    if object_type == "code":
        return {
            row_key_code(
                row,
                index,
            ): row
            for index, row
            in enumerate(rows)
        }

    # Pro mapping se dvojice BEFORE/AFTER zpracovává společně v
    # diff_table_payload(), aby se použila stejná strategie klíčování.
    return {
        f"#{index}": row
        for index, row in enumerate(rows)
    }


def strip_rows(payload):
    result = copy.deepcopy(
        payload
    )

    result.pop(
        "row",
        None,
    )

    return result


def diff_table_payload(
    conn,
    detected_at,
    object_type,
    object_name,
    before,
    after,
):
    changes = 0

    before_meta = strip_rows(
        before
    )

    after_meta = strip_rows(
        after
    )

    if before_meta != after_meta:
        record_change(
            conn,
            detected_at,
            object_type,
            object_name,
            "TABLE_UPDATE",
            before=before_meta,
            after=after_meta,
        )

        changes += 1

    if object_type == "mapping":
        old_rows, new_rows = mapping_rows_to_dict_pair(
            before.get("row", []) or [],
            after.get("row", []) or [],
        )
    else:
        old_rows = rows_to_dict(
            object_type,
            before,
        )

        new_rows = rows_to_dict(
            object_type,
            after,
        )

    for key in sorted(
        set(old_rows)
        | set(new_rows)
    ):
        old = old_rows.get(key)
        new = new_rows.get(key)

        if old is None:
            record_change(
                conn,
                detected_at,
                object_type,
                object_name,
                "ROW_ADDED",
                row_key=key,
                after=new,
            )

            changes += 1

        elif new is None:
            record_change(
                conn,
                detected_at,
                object_type,
                object_name,
                "ROW_DELETED",
                row_key=key,
                before=old,
            )

            changes += 1

        elif (
            row_without_audit_metadata(old)
            != row_without_audit_metadata(new)
        ):
            record_change(
                conn,
                detected_at,
                object_type,
                object_name,
                "ROW_UPDATED",
                row_key=key,
                before=old,
                after=new,
            )

            changes += 1

    return changes


def process_table_object(
    conn,
    detected_at,
    object_type,
    object_name,
    payload,
    redact_patterns,
):
    normalized = normalize_payload(
        object_type,
        payload,
        redact_patterns,
    )

    payload_json = canonical_json(
        normalized
    )

    payload_hash = hash_payload(
        normalized
    )

    row = conn.execute(
        """
        SELECT
            object_hash,
            payload_json
        FROM current_object
        WHERE object_type = ?
          AND object_name = ?
        """,
        (
            object_type,
            object_name,
        ),
    ).fetchone()

    if row is None:
        conn.execute(
            """
            INSERT INTO current_object (
                object_type,
                object_name,
                object_hash,
                payload_json,
                captured_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                object_type,
                object_name,
                payload_hash,
                payload_json,
                detected_at,
            ),
        )

        return "BASELINE", 0

    if row["object_hash"] == payload_hash:
        conn.execute(
            """
            UPDATE current_object
            SET captured_at = ?
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                detected_at,
                object_type,
                object_name,
            ),
        )

        return "UNCHANGED", 0

    before = json.loads(
        row["payload_json"]
    )

    changes = diff_table_payload(
        conn,
        detected_at,
        object_type,
        object_name,
        before,
        normalized,
    )

    conn.execute(
        """
        UPDATE current_object
        SET
            object_hash = ?,
            payload_json = ?,
            captured_at = ?
        WHERE object_type = ?
          AND object_name = ?
        """,
        (
            payload_hash,
            payload_json,
            detected_at,
            object_type,
            object_name,
        ),
    )

    return "CHANGED", changes


def scope_initialized(
    conn,
    object_type,
):
    row = conn.execute(
        """
        SELECT 1
        FROM audit_scope
        WHERE object_type = ?
        """,
        (
            object_type,
        ),
    ).fetchone()

    return row is not None


def mark_scope_initialized(
    conn,
    object_type,
):
    conn.execute(
        """
        INSERT INTO audit_scope (
            object_type,
            initialized_at
        )
        VALUES (?, ?)
        ON CONFLICT (object_type)
        DO NOTHING
        """,
        (
            object_type,
            utc_now(),
        ),
    )


def process_config_object(
    conn,
    detected_at,
    object_type,
    object_name,
    payload,
    redact_patterns,
    initialized,
):
    normalized = normalize_payload(
        object_type,
        payload,
        redact_patterns,
    )

    payload_json = canonical_json(
        normalized
    )

    payload_hash = hash_payload(
        normalized
    )

    row = conn.execute(
        """
        SELECT
            object_hash,
            payload_json
        FROM current_object
        WHERE object_type = ?
          AND object_name = ?
        """,
        (
            object_type,
            object_name,
        ),
    ).fetchone()

    if row is None:
        conn.execute(
            """
            INSERT INTO current_object (
                object_type,
                object_name,
                object_hash,
                payload_json,
                captured_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                object_type,
                object_name,
                payload_hash,
                payload_json,
                detected_at,
            ),
        )

        if initialized:
            record_change(
                conn,
                detected_at,
                object_type,
                object_name,
                "OBJECT_ADDED",
                after=normalized,
            )

            return "ADDED"

        return "BASELINE"

    if row["object_hash"] == payload_hash:
        conn.execute(
            """
            UPDATE current_object
            SET captured_at = ?
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                detected_at,
                object_type,
                object_name,
            ),
        )

        return "UNCHANGED"

    before = json.loads(
        row["payload_json"]
    )

    # Při změně normalizačních pravidel nechceme vytvořit jednorázový
    # falešný OBJECT_UPDATED jen proto, že starý snapshot ještě obsahuje
    # nově ignorované provozní hodnoty.
    #
    # Starý uložený payload proto vždy převedeme aktuální normalizací.
    # Pokud se po ní rovná novému stavu, pouze tiše aktualizujeme baseline.
    normalized_before = normalize_payload(
        object_type,
        before,
        redact_patterns,
    )

    if hash_payload(
        normalized_before
    ) == payload_hash:
        conn.execute(
            """
            UPDATE current_object
            SET
                object_hash = ?,
                payload_json = ?,
                captured_at = ?
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                payload_hash,
                payload_json,
                detected_at,
                object_type,
                object_name,
            ),
        )

        return "UNCHANGED"

    record_change(
        conn,
        detected_at,
        object_type,
        object_name,
        "OBJECT_UPDATED",
        before=before,
        after=normalized,
    )

    conn.execute(
        """
        UPDATE current_object
        SET
            object_hash = ?,
            payload_json = ?,
            captured_at = ?
        WHERE object_type = ?
          AND object_name = ?
        """,
        (
            payload_hash,
            payload_json,
            detected_at,
            object_type,
            object_name,
        ),
    )

    return "UPDATED"


def finish_object_scope(
    conn,
    detected_at,
    object_type,
    seen,
    initialized,
):
    if not initialized:
        mark_scope_initialized(
            conn,
            object_type,
        )

        return 0

    rows = conn.execute(
        """
        SELECT
            object_name,
            payload_json
        FROM current_object
        WHERE object_type = ?
        """,
        (
            object_type,
        ),
    ).fetchall()

    deleted = 0

    for row in rows:
        name = row["object_name"]

        if name in seen:
            continue

        before = json.loads(
            row["payload_json"]
        )

        record_change(
            conn,
            detected_at,
            object_type,
            name,
            "OBJECT_DELETED",
            before=before,
        )

        conn.execute(
            """
            DELETE FROM current_object
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                object_type,
                name,
            ),
        )

        deleted += 1

    return deleted


def extract_list(
    data,
    key,
):
    if not isinstance(
        data,
        dict,
    ):
        return []

    value = data.get(
        key,
        [],
    )

    return (
        value
        if isinstance(value, list)
        else []
    )


def stable_name(
    item,
    fields,
):
    if not isinstance(
        item,
        dict,
    ):
        return None

    for field in fields:
        value = item.get(field)

        if value not in (
            None,
            "",
        ):
            return str(value)

    return None



def scheduled_job_identity(
    job,
):
    """Vrátí stabilní auditní klíč Scheduled Job.

    Alma může mít více fyzických Scheduled Jobs se stejným názvem.
    Diagnostika ukázala, že jednotlivé plánovací sloty rozlišuje
    schedule.value (např. DAILY, DAILY2, DAILY3, DAILY4, WEEKLY,
    2WEEKLY atd.). Samotný name proto není jednoznačný a technické
    Alma id se může změnit.

    Stabilní logická identita:
      category.value | type.value | name | schedule.value
    """
    if not isinstance(job, dict):
        return ""

    name = str(job.get("name", "")).strip()

    category = job.get("category", {})
    job_type = job.get("type", {})
    schedule = job.get("schedule", {})

    category_value = (
        str(category.get("value", "")).strip()
        if isinstance(category, dict)
        else str(category or "").strip()
    )

    type_value = (
        str(job_type.get("value", "")).strip()
        if isinstance(job_type, dict)
        else str(job_type or "").strip()
    )

    schedule_value = (
        str(schedule.get("value", "")).strip()
        if isinstance(schedule, dict)
        else str(schedule or "").strip()
    )

    if (
        category_value
        and type_value
        and name
        and schedule_value
    ):
        return "|".join(
            (
                category_value,
                type_value,
                name,
                schedule_value,
            )
        )

    job_id = str(job.get("id", "")).strip()

    if job_id:
        return "ID|" + job_id

    if name:
        return "NAME|" + name

    return ""


def scheduled_job_has_legacy_baseline(
    conn,
):
    """Zjistí, zda current_object ještě používá staré Scheduled Job klíče."""
    rows = conn.execute(
        """
        SELECT object_name
        FROM current_object
        WHERE object_type = 'scheduled_job'
        """
    ).fetchall()

    for row in rows:
        name = str(row["object_name"] or "")

        # Nový složený klíč má minimálně tři oddělovače.
        # Staré Alma S... id i staré name klíče je nemají.
        if name.count("|") < 3:
            return True

    return False


def rebaseline_scheduled_jobs(
    conn,
    details,
    detected_at,
    redact_patterns,
):
    """Jednorázově vytvoří čistý Scheduled Job baseline bez change_log.

    Přechod z klíče id/name na nový složený klíč nelze bezpečně převést
    kus po kuse, protože starý name klíč sloučil více fyzických jobů.
    Proto při zjištění legacy baseline Scheduled Jobs pouze tuto jednu
    oblast tiše znovu založíme z aktuálního API stavu.
    """
    prepared = []
    seen = set()

    for detail in details:
        identity = scheduled_job_identity(detail)

        if not identity:
            continue

        if identity in seen:
            raise RuntimeError(
                "Duplicitní nový Scheduled Job klíč: "
                + identity
            )

        seen.add(identity)

        normalized = normalize_payload(
            "scheduled_job",
            detail,
            redact_patterns,
        )

        prepared.append(
            (
                identity,
                hash_payload(normalized),
                canonical_json(normalized),
            )
        )

    conn.execute(
        """
        DELETE FROM current_object
        WHERE object_type = 'scheduled_job'
        """
    )

    for identity, payload_hash, payload_json in prepared:
        conn.execute(
            """
            INSERT INTO current_object (
                object_type,
                object_name,
                object_hash,
                payload_json,
                captured_at
            )
            VALUES (
                'scheduled_job',
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                identity,
                payload_hash,
                payload_json,
                detected_at,
            ),
        )

    mark_scope_initialized(
        conn,
        "scheduled_job",
    )

    conn.commit()

    return len(prepared)



def audit_collection(
    conn,
    detected_at,
    object_type,
    objects,
    key_fields,
    redact_patterns,
    prefix="",
):
    initialized = scope_initialized(
        conn,
        object_type,
    )

    seen = set()

    stats = {
        "baseline": 0,
        "unchanged": 0,
        "added": 0,
        "updated": 0,
        "deleted": 0,
    }

    for item in objects:
        key = stable_name(
            item,
            key_fields,
        )

        if not key:
            continue

        name = (
            f"{prefix}{key}"
            if prefix
            else key
        )

        seen.add(name)

        status = process_config_object(
            conn,
            detected_at,
            object_type,
            name,
            item,
            redact_patterns,
            initialized,
        )

        status_key = status.lower()

        if status_key in stats:
            stats[status_key] += 1

    stats["deleted"] += finish_object_scope(
        conn,
        detected_at,
        object_type,
        seen,
        initialized,
    )

    conn.commit()

    return stats


def load_discovered_objects(
    conn,
    object_type,
):
    rows = conn.execute(
        """
        SELECT object_name
        FROM discovered_object
        WHERE object_type = ?
        ORDER BY object_name
        """,
        (
            object_type,
        ),
    ).fetchall()

    return [
        row["object_name"]
        for row in rows
    ]


def build_code_table_list(
    api,
    conn,
    extra_tables,
):
    """Return Code Tables with both technical API name and UI description.

    GET /conf/code-tables returns a Code Table object which includes the
    technical ``name`` used by the API and a human-readable ``description``.
    We keep the technical name as the stable audit/database key and persist
    the description separately for display in the PHP web.
    """
    result = []
    seen = set()

    for item in api.list_code_tables():
        name = str(
            item.get(
                "name",
                "",
            )
        ).strip()

        if not name or name in seen:
            continue

        description = str(
            item.get(
                "description",
                "",
            )
        ).strip()

        seen.add(name)
        result.append(
            {
                "name": name,
                "display_name": description or name,
                "source": "list_endpoint",
            }
        )

    for name in extra_tables:
        name = str(name).strip()

        if not name or name in seen:
            continue

        seen.add(name)
        result.append(
            {
                "name": name,
                "display_name": name,
                "source": "extra",
            }
        )

    for name in load_discovered_objects(
        conn,
        "code",
    ):
        name = str(name).strip()

        if not name or name in seen:
            continue

        seen.add(name)
        result.append(
            {
                "name": name,
                "display_name": name,
                "source": "discovery",
            }
        )

    return result


def save_object_label(
    conn,
    object_type,
    object_name,
    display_name,
    updated_at,
):
    display_name = str(
        display_name
        or object_name
    ).strip()

    if not display_name:
        display_name = str(object_name)

    conn.execute(
        """
        INSERT INTO object_label (
            object_type,
            object_name,
            display_name,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (
            object_type,
            object_name
        )
        DO UPDATE SET
            display_name = excluded.display_name,
            updated_at = excluded.updated_at
        """,
        (
            object_type,
            object_name,
            display_name,
            updated_at,
        ),
    )


def build_mapping_table_list(
    api,
    conn,
    extra_tables,
):
    result = []
    seen = set()

    for item in api.list_mapping_tables():
        code = item.get("code")

        if not code or code in seen:
            continue

        seen.add(code)
        result.append(code)

    for code in extra_tables:
        if code in seen:
            continue

        seen.add(code)
        result.append(code)

    for code in load_discovered_objects(
        conn,
        "mapping",
    ):
        if code in seen:
            continue

        seen.add(code)
        result.append(code)

    return result


def register_table_status(
    stats,
    status,
    changes,
):
    if status == "BASELINE":
        stats["baseline"] += 1

    elif status == "UNCHANGED":
        stats["unchanged"] += 1

    elif status == "CHANGED":
        stats["changed_tables"] += 1
        stats["changes"] += changes


def load_discovery_candidates(path):
    if not os.path.exists(path):
        return []

    result = []

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as handle:
        for raw_line in handle:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            result.append(line)

    return sorted(
        set(result)
    )


def save_discovered_object(
    conn,
    object_type,
    object_name,
    source,
):
    conn.execute(
        """
        INSERT INTO discovered_object (
            object_type,
            object_name,
            discovered_at,
            source
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (
            object_type,
            object_name
        )
        DO UPDATE SET
            discovered_at = excluded.discovered_at,
            source = excluded.source
        """,
        (
            object_type,
            object_name,
            utc_now(),
            source,
        ),
    )


def run_discovery(
    cfg,
    api,
    conn,
):
    candidates = load_discovery_candidates(
        cfg["discovery_candidates_file"]
    )

    if not candidates:
        log(
            "Discovery: žádní kandidáti."
        )

        log(
            "Soubor: "
            + cfg[
                "discovery_candidates_file"
            ]
        )

        return 0

    standard_code = {
        item.get("name")
        for item in api.list_code_tables()
        if item.get("name")
    }

    standard_mapping = {
        item.get("code")
        for item in api.list_mapping_tables()
        if item.get("code")
    }

    known_code = set(
        cfg["extra_code_tables"]
    )

    known_mapping = set(
        cfg["extra_mapping_tables"]
    )

    known_code.update(
        load_discovered_objects(
            conn,
            "code",
        )
    )

    known_mapping.update(
        load_discovered_objects(
            conn,
            "mapping",
        )
    )

    stats = {
        "candidates": 0,
        "already_known": 0,
        "found_code": 0,
        "found_mapping": 0,
        "not_found": 0,
        "errors": 0,
    }

    log(
        f"Discovery kandidátů: "
        f"{len(candidates)}"
    )

    log("")

    for name in candidates:
        stats["candidates"] += 1

        if name in standard_code:
            log(
                f"STANDARD CODE     {name}"
            )

            stats[
                "already_known"
            ] += 1

            continue

        if name in standard_mapping:
            log(
                f"STANDARD MAPPING  {name}"
            )

            stats[
                "already_known"
            ] += 1

            continue

        if name in known_code:
            log(
                f"KNOWN CODE        {name}"
            )

            stats[
                "already_known"
            ] += 1

            continue

        if name in known_mapping:
            log(
                f"KNOWN MAPPING     {name}"
            )

            stats[
                "already_known"
            ] += 1

            continue

        try:
            data = api.try_code_table(
                name
            )

            if data is not None:
                save_discovered_object(
                    conn,
                    "code",
                    name,
                    "discover",
                )

                conn.commit()

                known_code.add(name)

                log(
                    f"FOUND CODE        {name}"
                )

                stats[
                    "found_code"
                ] += 1

                continue

        except Exception as exc:
            log(
                f"ERROR CODE TEST   "
                f"{name}: {exc}"
            )

            stats["errors"] += 1
            continue

        try:
            data = api.try_mapping_table(
                name
            )

            if data is not None:
                save_discovered_object(
                    conn,
                    "mapping",
                    name,
                    "discover",
                )

                conn.commit()

                known_mapping.add(name)

                log(
                    f"FOUND MAPPING     {name}"
                )

                stats[
                    "found_mapping"
                ] += 1

                continue

        except Exception as exc:
            log(
                f"ERROR MAP TEST    "
                f"{name}: {exc}"
            )

            stats["errors"] += 1
            continue

        log(
            f"NOT FOUND         {name}"
        )

        stats["not_found"] += 1

    log("")
    log("=" * 70)
    log("DISCOVERY SOUHRN")
    log("=" * 70)

    log(
        f"Kandidátů:              "
        f"{stats['candidates']}"
    )

    log(
        f"Již známých:             "
        f"{stats['already_known']}"
    )

    log(
        f"Nalezeno Code Tables:    "
        f"{stats['found_code']}"
    )

    log(
        f"Nalezeno Mapping Tables: "
        f"{stats['found_mapping']}"
    )

    log(
        f"Nenalezeno:              "
        f"{stats['not_found']}"
    )

    log(
        f"Chyb:                    "
        f"{stats['errors']}"
    )

    log(
        f"API volání:              "
        f"{api.calls}"
    )

    return (
        1
        if stats["errors"]
        else 0
    )


def get_all_scheduled_jobs(api):
    result = []

    limit = 100
    offset = 0

    while True:
        data = api.get(
            "/conf/jobs",
            params={
                "type": "SCHEDULED",
                "limit": limit,
                "offset": offset,
            },
        )

        jobs = extract_list(
            data,
            "job",
        )

        result.extend(
            jobs
        )

        total = data.get(
            "total_record_count",
            len(result),
        )

        try:
            total = int(total)
        except Exception:
            total = len(result)

        if not jobs:
            break

        if len(result) >= total:
            break

        offset += limit

    return result


def get_all_libraries(api):
    result = []

    limit = 100
    offset = 0

    while True:
        data = api.get(
            "/conf/libraries",
            params={
                "limit": limit,
                "offset": offset,
            },
        )

        items = extract_list(
            data,
            "library",
        )

        result.extend(
            items
        )

        total = data.get(
            "total_record_count",
            len(result),
        )

        try:
            total = int(total)
        except Exception:
            total = len(result)

        if not items:
            break

        if len(result) >= total:
            break

        offset += limit

    return result


def get_all_printers(api):
    result = []

    limit = 100
    offset = 0

    while True:
        data = api.get(
            "/conf/printers",
            params={
                "limit": limit,
                "offset": offset,
            },
        )

        items = extract_list(
            data,
            "printer",
        )

        result.extend(
            items
        )

        total = data.get(
            "total_record_count",
            len(result),
        )

        try:
            total = int(total)
        except Exception:
            total = len(result)

        if not items:
            break

        if len(result) >= total:
            break

        offset += limit

    return result


def audit_extended(
    cfg,
    api,
    conn,
    detected_at,
):
    totals = {
        "objects": 0,
        "baseline": 0,
        "unchanged": 0,
        "added": 0,
        "updated": 0,
        "deleted": 0,
        "errors": 0,
    }

    def add_stats(stats):
        for key in (
            "baseline",
            "unchanged",
            "added",
            "updated",
            "deleted",
        ):
            totals[key] += stats.get(
                key,
                0,
            )

        totals["objects"] += sum(
            stats.get(
                key,
                0,
            )
            for key in (
                "baseline",
                "unchanged",
                "added",
                "updated",
            )
        )

    def safe_collection(
        label,
        object_type,
        objects,
        key_fields,
        prefix="",
    ):
        try:
            stats = audit_collection(
                conn,
                detected_at,
                object_type,
                objects,
                key_fields,
                cfg[
                    "redact_patterns"
                ],
                prefix=prefix,
            )

            add_stats(stats)

            changed = (
                stats["added"]
                + stats["updated"]
                + stats["deleted"]
            )

            if changed:
                log(
                    f"CHANGED "
                    f"{label:<24} "
                    f"{changed} změn"
                )

        except Exception as exc:
            conn.rollback()

            totals["errors"] += 1

            log(
                f"ERROR {label}: "
                f"{exc}"
            )

    log("")
    log(
        "Načítám rozšířenou konfiguraci ..."
    )

    # -------------------------------------------------
    # LIBRARIES
    # -------------------------------------------------

    try:
        libraries = get_all_libraries(
            api
        )

        safe_collection(
            "Libraries",
            "library",
            libraries,
            (
                "code",
                "id",
            ),
        )

    except Exception as exc:
        libraries = []

        totals["errors"] += 1

        log(
            f"ERROR Libraries: {exc}"
        )

    # -------------------------------------------------
    # LIBRARY DETAIL
    # -------------------------------------------------

    library_details = []
    library_details_ok = True

    for library in libraries:
        library_code = stable_name(
            library,
            (
                "code",
                "id",
            ),
        )

        if not library_code:
            continue

        try:
            detail = api.get(
                "/conf/libraries/"
                + quote(
                    library_code,
                    safe="",
                )
            )

            wrapped = copy.deepcopy(
                detail
            )

            wrapped[
                "_library_code"
            ] = library_code

            wrapped[
                "_audit_key"
            ] = library_code

            library_details.append(
                wrapped
            )

        except Exception as exc:
            library_details_ok = False
            totals["errors"] += 1

            log(
                f"ERROR Library Detail "
                f"{library_code}: {exc}"
            )

    if library_details_ok:
        safe_collection(
            "Library Details",
            "library_detail",
            library_details,
            (
                "_audit_key",
            ),
        )

    # -------------------------------------------------
    # LOCATIONS + CIRC DESKS
    # -------------------------------------------------

    all_locations = []
    all_circ_desks = []
    all_circ_desk_details = []

    locations_ok = True
    circ_ok = True
    circ_detail_ok = True

    for library in libraries:
        library_code = stable_name(
            library,
            (
                "code",
                "id",
            ),
        )

        if not library_code:
            continue

        safe_library = quote(
            library_code,
            safe="",
        )

        try:
            data = api.get(
                f"/conf/libraries/"
                f"{safe_library}/locations"
            )

            for item in extract_list(
                data,
                "location",
            ):
                wrapped = copy.deepcopy(
                    item
                )

                wrapped[
                    "_library_code"
                ] = library_code

                wrapped[
                    "_audit_key"
                ] = (
                    f"{library_code}/"
                    f"{stable_name(item, ('code', 'id'))}"
                )

                all_locations.append(
                    wrapped
                )

        except Exception as exc:
            locations_ok = False
            totals["errors"] += 1

            log(
                f"ERROR Locations "
                f"{library_code}: {exc}"
            )

        try:
            data = api.get(
                f"/conf/libraries/"
                f"{safe_library}/circ-desks"
            )

            circ_desks = extract_list(
                data,
                "circ_desk",
            )

            for item in circ_desks:
                circ_code = stable_name(
                    item,
                    (
                        "code",
                        "name",
                    ),
                )

                wrapped = copy.deepcopy(
                    item
                )

                wrapped[
                    "_library_code"
                ] = library_code

                wrapped[
                    "_audit_key"
                ] = (
                    f"{library_code}/"
                    f"{circ_code}"
                )

                all_circ_desks.append(
                    wrapped
                )

                if not circ_code:
                    continue

                try:
                    detail = api.get(
                        f"/conf/libraries/"
                        f"{safe_library}/circ-desks/"
                        + quote(
                            circ_code,
                            safe="",
                        )
                    )

                    detail_wrapped = copy.deepcopy(
                        detail
                    )

                    detail_wrapped[
                        "_library_code"
                    ] = library_code

                    detail_wrapped[
                        "_audit_key"
                    ] = (
                        f"{library_code}/"
                        f"{circ_code}"
                    )

                    all_circ_desk_details.append(
                        detail_wrapped
                    )

                except Exception as exc:
                    circ_detail_ok = False
                    totals["errors"] += 1

                    log(
                        f"ERROR Circ Desk Detail "
                        f"{library_code}/{circ_code}: "
                        f"{exc}"
                    )

        except Exception as exc:
            circ_ok = False
            circ_detail_ok = False
            totals["errors"] += 1

            log(
                f"ERROR Circ Desks "
                f"{library_code}: {exc}"
            )

    if locations_ok:
        safe_collection(
            "Locations",
            "location",
            all_locations,
            (
                "_audit_key",
            ),
        )

    if circ_ok:
        safe_collection(
            "Circulation Desks",
            "circ_desk",
            all_circ_desks,
            (
                "_audit_key",
            ),
        )

    if circ_detail_ok:
        safe_collection(
            "Circulation Desk Details",
            "circ_desk_detail",
            all_circ_desk_details,
            (
                "_audit_key",
            ),
        )

    # -------------------------------------------------
    # GENERAL
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/general"
        )

        safe_collection(
            "General",
            "general",
            [
                {
                    "_audit_key": "institution",
                    **data,
                }
            ],
            (
                "_audit_key",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR General: {exc}"
        )

    # -------------------------------------------------
    # DEPARTMENTS
    # -------------------------------------------------

    # Institucionální Departments zachováváme jako samostatný scope.
    try:
        data = api.get(
            "/conf/departments",
            params={
                "view": "full",
                "limit": 100,
                "offset": 0,
            },
        )

        safe_collection(
            "Departments",
            "department",
            extract_list(
                data,
                "department",
            ),
            (
                "code",
                "id",
                "name",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Departments: {exc}"
        )

    # Departments jednotlivých dílčích knihoven jsou v Alma API
    # dostupné pouze s parametrem library=<CODE>. Auditujeme full view,
    # aby se zachytily např. type, owner, work_days, operator atd.
    library_departments = []
    library_departments_ok = True

    for library in libraries:
        library_code = stable_name(
            library,
            (
                "code",
                "id",
            ),
        )

        if not library_code:
            continue

        try:
            data = api.get(
                "/conf/departments",
                params={
                    "library": library_code,
                    "view": "full",
                    "limit": 100,
                    "offset": 0,
                },
            )

            for item in extract_list(
                data,
                "department",
            ):
                department_code = stable_name(
                    item,
                    (
                        "code",
                        "id",
                        "name",
                    ),
                )

                if not department_code:
                    continue

                wrapped = copy.deepcopy(
                    item
                )

                wrapped[
                    "_library_code"
                ] = library_code

                wrapped[
                    "_audit_key"
                ] = (
                    f"{library_code}/"
                    f"{department_code}"
                )

                library_departments.append(
                    wrapped
                )

        except Exception as exc:
            library_departments_ok = False
            totals["errors"] += 1

            log(
                f"ERROR Departments "
                f"{library_code}: {exc}"
            )

    if library_departments_ok:
        safe_collection(
            "Library Departments",
            "library_department",
            library_departments,
            (
                "_audit_key",
            ),
        )

    # -------------------------------------------------
    # LIBRARY OPEN HOURS
    # -------------------------------------------------
    # Záměrně NEAUDITUJEME. Endpoint /open-hours vrací klouzavý kalendář
    # konkrétních dat. I bez změny konfigurace se tedy každý den posune
    # časové okno a vytvářelo by falešné OBJECT_UPDATED u všech knihoven.
    # Pokud bude někdy potřeba auditovat kalendáře, musí se zpracovat
    # samostatně jako pravidla/výjimky, ne jako surový denní výstup API.

    # -------------------------------------------------
    # INTEGRATION PROFILES
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/integration-profiles",
            params={
                "limit": 100,
                "offset": 0,
            },
        )

        safe_collection(
            "Integration Profiles",
            "integration_profile",
            extract_list(
                data,
                "integration_profile",
            ),
            (
                "id",
                "code",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            "ERROR Integration Profiles: "
            f"{exc}"
        )

    # -------------------------------------------------
    # IMPORT PROFILES - FULL DETAIL
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/md-import-profiles"
        )

        summaries = extract_list(
            data,
            "import_profile",
        )

        details = []

        for item in summaries:
            profile_id = stable_name(
                item,
                (
                    "id",
                ),
            )

            if not profile_id:
                details.append(item)
                continue

            try:
                detail = api.get(
                    "/conf/md-import-profiles/"
                    + quote(
                        profile_id,
                        safe="",
                    )
                )

                details.append(detail)

            except Exception as exc:
                totals["errors"] += 1

                log(
                    "ERROR Import Profile "
                    f"{profile_id}: {exc}"
                )

                details.append(item)

        safe_collection(
            "Import Profiles",
            "import_profile",
            details,
            (
                "id",
                "name",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Import Profiles: "
            f"{exc}"
        )

    # -------------------------------------------------
    # PRINTERS - FULL DETAIL
    # -------------------------------------------------

    try:
        summaries = get_all_printers(
            api
        )

        details = []

        for item in summaries:
            printer_id = stable_name(
                item,
                (
                    "id",
                ),
            )

            if not printer_id:
                details.append(item)
                continue

            try:
                detail = api.get(
                    "/conf/printers/"
                    + quote(
                        printer_id,
                        safe="",
                    )
                )

                details.append(detail)

            except Exception as exc:
                totals["errors"] += 1

                log(
                    "ERROR Printer "
                    f"{printer_id}: {exc}"
                )

                details.append(item)

        safe_collection(
            "Printers",
            "printer",
            details,
            (
                "id",
                "code",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Printers: {exc}"
        )

    # -------------------------------------------------
    # LETTERS
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/letters"
        )

        summaries = extract_list(
            data,
            "letter",
        )

        details = []

        for item in summaries:
            code = stable_name(
                item,
                (
                    "code",
                ),
            )

            if not code:
                details.append(item)
                continue

            detail = api.try_get(
                "/conf/letters/"
                + quote(
                    code,
                    safe="",
                )
            )

            if detail is None:
                log(
                    f"LETTER DETAIL UNAVAILABLE "
                    f"{code} - používám summary"
                )

                details.append(item)

            else:
                details.append(detail)

        safe_collection(
            "Letters",
            "letter",
            details,
            (
                "code",
                "name",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Letters: {exc}"
        )

    # -------------------------------------------------
    # NORMALIZATION RULES
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/normalization-rules"
        )

        safe_collection(
            "Normalization Rules",
            "normalization_rule",
            extract_list(
                data,
                "normalization_rule",
            ),
            (
                "id",
                "name",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            "ERROR Normalization Rules: "
            f"{exc}"
        )

    # -------------------------------------------------
    # DEPOSIT PROFILES
    # -------------------------------------------------

    try:
        data = api.get(
            "/conf/deposit-profiles"
        )

        summaries = extract_list(
            data,
            "deposit_profile",
        )

        details = []

        for item in summaries:
            profile_id = stable_name(
                item,
                (
                    "id",
                    "profile_id",
                ),
            )

            if not profile_id:
                details.append(item)
                continue

            try:
                detail = api.get(
                    "/conf/deposit-profiles/"
                    + quote(
                        profile_id,
                        safe="",
                    )
                )

                details.append(detail)

            except Exception as exc:
                totals["errors"] += 1

                log(
                    "ERROR Deposit Profile "
                    f"{profile_id}: {exc}"
                )

                details.append(item)

        safe_collection(
            "Deposit Profiles",
            "deposit_profile",
            details,
            (
                "id",
                "profile_id",
                "name",
            ),
        )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Deposit Profiles: "
            f"{exc}"
        )

    # -------------------------------------------------
    # SCHEDULED JOBS
    #
    # Sledujeme konfiguraci jobu, ne provoz.
    #
    # DŮLEŽITÉ:
    # Alma může při deaktivaci/aktivaci nebo jiné operaci přegenerovat
    # technická ID celé sady Scheduled Jobs. ID proto používáme pouze
    # pro GET detailu, ale stabilní auditní klíč je název jobu.
    #
    # normalize_payload() navíc ignoruje next_run, id a creator.
    # -------------------------------------------------

    try:
        summaries = get_all_scheduled_jobs(
            api
        )

        details = []

        for item in summaries:
            job_id = stable_name(
                item,
                (
                    "id",
                ),
            )

            if not job_id:
                continue

            try:
                detail = api.get(
                    "/conf/jobs/"
                    + quote(
                        job_id,
                        safe="",
                    )
                )

                details.append(
                    detail
                )

            except Exception as exc:
                # Alma může mezi listem a detailem Scheduled Jobs
                # přegenerovat technické S... id. Detail pak krátce
                # vrátí 400 Invalid job id, i když job stále existuje.
                # Summary je pro audit bezpečný fallback: id/link/next_run
                # a schedule.desc stejně normalizace ignoruje.
                log(
                    f"Scheduled Job detail unavailable "
                    f"{job_id} - používám summary: {exc}"
                )

                details.append(
                    item
                )

        if scheduled_job_has_legacy_baseline(
            conn
        ):
            count = rebaseline_scheduled_jobs(
                conn,
                details,
                detected_at,
                cfg[
                    "redact_patterns"
                ],
            )

            totals["baseline"] += count
            totals["objects"] += count

            log(
                "Scheduled Jobs: nový stabilní baseline "
                f"{count} objektů "
                "(bez zápisu změn)"
            )

        else:
            initialized = scope_initialized(
                conn,
                "scheduled_job",
            )

            seen = set()
            stats = {
                "baseline": 0,
                "unchanged": 0,
                "added": 0,
                "updated": 0,
                "deleted": 0,
            }

            for detail in details:
                identity = scheduled_job_identity(
                    detail
                )

                if not identity:
                    totals["errors"] += 1
                    log(
                        "ERROR Scheduled Job bez "
                        "stabilní identity"
                    )
                    continue

                if identity in seen:
                    raise RuntimeError(
                        "Duplicitní Scheduled Job klíč: "
                        + identity
                    )

                seen.add(identity)

                status = process_config_object(
                    conn,
                    detected_at,
                    "scheduled_job",
                    identity,
                    detail,
                    cfg[
                        "redact_patterns"
                    ],
                    initialized,
                )

                status_key = status.lower()

                if status_key in stats:
                    stats[status_key] += 1

            stats["deleted"] += finish_object_scope(
                conn,
                detected_at,
                "scheduled_job",
                seen,
                initialized,
            )

            conn.commit()
            add_stats(stats)

            changed = (
                stats["added"]
                + stats["updated"]
                + stats["deleted"]
            )

            if changed:
                log(
                    f"CHANGED "
                    f"{'Scheduled Jobs':<24} "
                    f"{changed} změn"
                )

    except Exception as exc:
        totals["errors"] += 1

        log(
            f"ERROR Scheduled Jobs: "
            f"{exc}"
        )

    # Relations jsou zatím záměrně vynechány.
    # Endpoint vyžaduje scope a váš tenant odmítl "All".
    # Doplníme po ověření konkrétních scope hodnot.

    return totals


def audit_primo(
    cfg,
    api,
    conn,
    detected_at,
):
    stats = {
        "views": 0,
        "baseline": 0,
        "unchanged": 0,
        "added": 0,
        "updated": 0,
        "errors": 0,
    }

    views = cfg.get(
        "primo_views",
        [],
    )

    if not views:
        return stats

    initialized = scope_initialized(
        conn,
        "primo_view",
    )

    all_ok = True

    log("")
    log(
        "Načítám konfiguraci Primo VE ..."
    )

    for vid in views:
        stats["views"] += 1

        try:
            data = api.get(
                "/configuration/vid/"
                + quote(
                    vid,
                    safe="",
                ),
                params={
                    "locale": "ALL",
                },
            )

            wrapped = {
                "_audit_key": vid,
                "configuration": data,
            }

            status = process_config_object(
                conn,
                detected_at,
                "primo_view",
                vid,
                wrapped,
                cfg["redact_patterns"],
                initialized,
            )

            status_key = status.lower()

            if status_key in stats:
                stats[status_key] += 1

            if status in (
                "ADDED",
                "UPDATED",
            ):
                log(
                    f"CHANGED Primo View          "
                    f"{vid} ({status})"
                )

            conn.commit()

        except Exception as exc:
            conn.rollback()
            all_ok = False
            stats["errors"] += 1

            log(
                f"ERROR Primo View {vid}: "
                f"{exc}"
            )

    # Primo Configuration API neumí vypsat všechna Views.
    # Proto záměrně nevyhodnocujeme OBJECT_DELETED podle
    # chybějícího VID v konfiguraci skriptu. Po úspěšném
    # prvním načtení pouze označíme scope jako inicializovaný.
    if not initialized and all_ok:
        mark_scope_initialized(
            conn,
            "primo_view",
        )
        conn.commit()

    return stats



def run_jobs_only(
    cfg,
    api,
    conn,
):
    """Spustí pouze audit Scheduled Jobs.

    Používá stejnou identitu a normalizaci jako hlavní audit, ale
    nenačítá Code/Mapping Tables, ostatní extended objekty ani Primo.
    Je určen hlavně pro rychlé ověření změn Scheduled Jobs.
    """
    detected_at = utc_now()

    stats = {
        "objects": 0,
        "baseline": 0,
        "unchanged": 0,
        "added": 0,
        "updated": 0,
        "deleted": 0,
        "detail_fallback": 0,
        "errors": 0,
    }

    log("Načítám pouze Scheduled Jobs ...")

    try:
        summaries = get_all_scheduled_jobs(
            api
        )

        details = []

        for item in summaries:
            job_id = stable_name(
                item,
                (
                    "id",
                ),
            )

            if not job_id:
                stats["errors"] += 1
                log(
                    "ERROR Scheduled Job bez id v summary"
                )
                continue

            try:
                detail = api.get(
                    "/conf/jobs/"
                    + quote(
                        job_id,
                        safe="",
                    )
                )

                details.append(
                    detail
                )

            except Exception as exc:
                # Technické id Scheduled Job se může změnit i mezi
                # načtením seznamu a následným GET detailu. V tom případě
                # použijeme summary, aby job falešně nezmizel z auditu.
                stats["detail_fallback"] += 1

                log(
                    f"Scheduled Job detail unavailable "
                    f"{job_id} - používám summary: {exc}"
                )

                details.append(
                    item
                )

        if scheduled_job_has_legacy_baseline(
            conn
        ):
            count = rebaseline_scheduled_jobs(
                conn,
                details,
                detected_at,
                cfg[
                    "redact_patterns"
                ],
            )

            stats["objects"] = count
            stats["baseline"] = count

            log(
                "Scheduled Jobs: nový stabilní baseline "
                f"{count} objektů "
                "(bez zápisu změn)"
            )

        else:
            initialized = scope_initialized(
                conn,
                "scheduled_job",
            )

            seen = set()

            for detail in details:
                identity = scheduled_job_identity(
                    detail
                )

                if not identity:
                    stats["errors"] += 1
                    log(
                        "ERROR Scheduled Job bez "
                        "stabilní identity"
                    )
                    continue

                if identity in seen:
                    stats["errors"] += 1
                    log(
                        "ERROR Duplicitní Scheduled Job klíč: "
                        + identity
                    )
                    continue

                seen.add(identity)

                status = process_config_object(
                    conn,
                    detected_at,
                    "scheduled_job",
                    identity,
                    detail,
                    cfg[
                        "redact_patterns"
                    ],
                    initialized,
                )

                stats["objects"] += 1

                status_key = status.lower()

                if status_key in stats:
                    stats[status_key] += 1

            stats["deleted"] += finish_object_scope(
                conn,
                detected_at,
                "scheduled_job",
                seen,
                initialized,
            )

            conn.commit()

    except Exception as exc:
        conn.rollback()
        stats["errors"] += 1
        log(
            f"ERROR Scheduled Jobs: {exc}"
        )

    log("")
    log("=" * 70)
    log("SOUHRN - POUZE SCHEDULED JOBS")
    log("=" * 70)

    log(
        f"Scheduled Jobs:         "
        f"{stats['objects']}"
    )
    log(
        f"Nový baseline:          "
        f"{stats['baseline']}"
    )
    log(
        f"Beze změny:             "
        f"{stats['unchanged']}"
    )
    log(
        f"Přidáno:                "
        f"{stats['added']}"
    )
    log(
        f"Upraveno:               "
        f"{stats['updated']}"
    )
    log(
        f"Smazáno:                "
        f"{stats['deleted']}"
    )
    log(
        f"Detail fallback:        "
        f"{stats['detail_fallback']}"
    )
    log(
        f"Chyb:                   "
        f"{stats['errors']}"
    )
    log("")
    log(
        f"Alma API volání:        "
        f"{api.calls}"
    )
    log(
        f"Alma API remaining:     "
        f"{api.remaining or 'neuvedeno'}"
    )
    log(
        f"Databáze:               "
        f"{cfg['database']}"
    )

    return (
        1
        if stats["errors"]
        else 0
    )


def run_primo_only(
    cfg,
    conn,
    primo_api,
):
    detected_at = utc_now()

    if not cfg.get(
        "primo_enabled"
    ):
        log(
            "Primo audit je v konfiguraci vypnutý."
        )
        return 1

    if primo_api is None:
        log(
            "Primo API není inicializováno."
        )
        return 1

    primo = audit_primo(
        cfg,
        primo_api,
        conn,
        detected_at,
    )

    log("")
    log("=" * 70)
    log("SOUHRN - POUZE PRIMO")
    log("=" * 70)

    log(
        f"Primo Views:            "
        f"{primo['views']}"
    )

    log(
        f"Nový baseline Primo:    "
        f"{primo['baseline']}"
    )

    log(
        f"Beze změny Primo:       "
        f"{primo['unchanged']}"
    )

    log(
        f"Přidáno Primo Views:    "
        f"{primo['added']}"
    )

    log(
        f"Upraveno Primo Views:   "
        f"{primo['updated']}"
    )

    log(
        f"Chyb Primo auditu:      "
        f"{primo['errors']}"
    )

    log("")
    log(
        f"Primo API volání:       "
        f"{primo_api.calls}"
    )

    log(
        f"Primo API remaining:    "
        f"{primo_api.remaining or 'neuvedeno'}"
    )

    log(
        f"Databáze:               "
        f"{cfg['database']}"
    )

    return (
        1
        if primo["errors"]
        else 0
    )


def code_table_object_name(
    table_name,
    language=None,
):
    """Stable display/audit name for a language-specific Code Table."""
    if language:
        return f"{table_name} [{language}]"

    return table_name


def cleanup_legacy_code_table_baselines(
    conn,
    expected_names,
):
    """Silently remove stale Code Table baselines after enabling languages.

    Older versions stored Code Tables only as ``TableName``. Once explicit
    languages are enabled, the new keys are ``TableName [cs]`` etc. We do
    not want this key migration to create false historical changes.
    """
    rows = conn.execute(
        """
        SELECT object_name
        FROM current_object
        WHERE object_type = 'code'
        """
    ).fetchall()

    removed = 0

    expected_bases = {
        re.sub(
            r" \[[A-Za-z]{2,3}(?:-[A-Za-z]{2})?\]$",
            "",
            name,
        )
        for name in expected_names
    }

    for row in rows:
        name = str(row["object_name"])

        if name in expected_names:
            continue

        match = re.match(
            r"^(.*) \[([A-Za-z]{2,3}(?:-[A-Za-z]{2})?)\]$",
            name,
        )

        if match:
            base_name = match.group(1).strip()
            should_remove = base_name in expected_bases
        else:
            # Legacy unsuffixed key: remove only if the same table now has
            # at least one explicitly configured language variant.
            should_remove = name in expected_bases

        if not should_remove:
            continue

        conn.execute(
            """
            DELETE FROM current_object
            WHERE object_type = 'code'
              AND object_name = ?
            """,
            (name,),
        )
        removed += 1

    if removed:
        conn.commit()

    return removed


def run_audit(
    cfg,
    api,
    conn,
    primo_api=None,
    summary_title="SOUHRN",
):
    detected_at = utc_now()

    stats = {
        "tables": 0,
        "baseline": 0,
        "unchanged": 0,
        "changed_tables": 0,
        "changes": 0,
        "errors": 0,
    }

    if cfg["include_code"]:
        log(
            "Načítám seznam Code Tables ..."
        )

        code_tables = build_code_table_list(
            api,
            conn,
            cfg["extra_code_tables"],
        )

        code_languages = []
        seen_languages = set()

        for language in cfg.get(
            "code_table_languages",
            [],
        ):
            language = str(language).strip().lower()

            if not language or language in seen_languages:
                continue

            seen_languages.add(language)
            code_languages.append(language)

        # Empty list preserves the historical behavior: one GET without
        # ``lang``, which means the institution default language.
        language_variants = (
            code_languages
            if code_languages
            else [None]
        )

        expected_code_names = {
            code_table_object_name(
                table["name"],
                language,
            )
            for table in code_tables
            for language in language_variants
        }

        if code_languages:
            log(
                "Code Tables - jazyky: "
                + ", ".join(code_languages)
            )

        for table in code_tables:
            name = table["name"]
            base_display_name = (
                table.get("display_name")
                or name
            )

            for language in language_variants:
                stats["tables"] += 1
                object_name = code_table_object_name(
                    name,
                    language,
                )
                display_name = code_table_object_name(
                    base_display_name,
                    language,
                )

                try:
                    payload = api.get_code_table(
                        name,
                        lang=language,
                    )

                    # The detail endpoint also documents ``description``.
                    # Prefer it when present; otherwise keep the label from
                    # GET /conf/code-tables. This is generic and avoids
                    # hard-coded mappings such as JobTitles -> Job Categories.
                    payload_description = (
                        str(
                            payload.get(
                                "description",
                                "",
                            )
                        ).strip()
                        if isinstance(payload, dict)
                        else ""
                    )

                    if payload_description:
                        display_name = code_table_object_name(
                            payload_description,
                            language,
                        )

                    save_object_label(
                        conn,
                        "code",
                        object_name,
                        display_name,
                        detected_at,
                    )

                    status, changes = (
                        process_table_object(
                            conn,
                            detected_at,
                            "code",
                            object_name,
                            payload,
                            cfg[
                                "redact_patterns"
                            ],
                        )
                    )

                    register_table_status(
                        stats,
                        status,
                        changes,
                    )

                    if status == "CHANGED":
                        log(
                            f"CHANGED CODE    "
                            f"{object_name}: "
                            f"{changes} změn"
                        )

                    conn.commit()

                except Exception as exc:
                    conn.rollback()

                    stats["errors"] += 1

                    log(
                        f"ERROR CODE "
                        f"{object_name}: {exc}"
                    )

        # Once explicit languages are enabled, old unsuffixed baselines
        # (and baselines for languages removed from the config) are obsolete.
        # Remove them silently so enabling this feature does not generate
        # artificial ROW/OBJECT changes.
        if code_languages:
            removed = cleanup_legacy_code_table_baselines(
                conn,
                expected_code_names,
            )

            if removed:
                log(
                    "Code Tables - odstraněno starých baseline: "
                    f"{removed}"
                )

    if cfg["include_mapping"]:
        log(
            "Načítám seznam Mapping Tables ..."
        )

        mapping_tables = (
            build_mapping_table_list(
                api,
                conn,
                cfg[
                    "extra_mapping_tables"
                ],
            )
        )

        for code in mapping_tables:
            stats["tables"] += 1

            try:
                payload = (
                    api.get_mapping_table(
                        code
                    )
                )

                status, changes = (
                    process_table_object(
                        conn,
                        detected_at,
                        "mapping",
                        code,
                        payload,
                        cfg[
                            "redact_patterns"
                        ],
                    )
                )

                register_table_status(
                    stats,
                    status,
                    changes,
                )

                if status == "CHANGED":
                    log(
                        f"CHANGED MAPPING "
                        f"{code}: "
                        f"{changes} změn"
                    )

                conn.commit()

            except Exception as exc:
                conn.rollback()

                stats["errors"] += 1

                log(
                    f"ERROR MAPPING "
                    f"{code}: {exc}"
                )

    extended = None

    if cfg["include_extended"]:
        extended = audit_extended(
            cfg,
            api,
            conn,
            detected_at,
        )

    primo = None

    if (
        cfg.get("primo_enabled")
        and primo_api is not None
    ):
        primo = audit_primo(
            cfg,
            primo_api,
            conn,
            detected_at,
        )

    log("")
    log("=" * 70)
    log(summary_title)
    log("=" * 70)

    if (
        cfg.get("include_code")
        or cfg.get("include_mapping")
    ):
        if (
            cfg.get("include_code")
            and not cfg.get("include_mapping")
        ):
            table_label = "Code Tables"
        elif (
            cfg.get("include_mapping")
            and not cfg.get("include_code")
        ):
            table_label = "Mapping Tables"
        else:
            table_label = "Code/Mapping tabulek"

        log(
            f"{table_label}:"
            f"{' ' * max(1, 23 - len(table_label))}"
            f"{stats['tables']}"
        )

        log(
            f"Nový baseline tabulek:  "
            f"{stats['baseline']}"
        )

        log(
            f"Beze změny tabulek:     "
            f"{stats['unchanged']}"
        )

        log(
            f"Změněných tabulek:      "
            f"{stats['changed_tables']}"
        )

        log(
            f"Změn řádků/tabulek:     "
            f"{stats['changes']}"
        )

    if extended is not None:
        log("")
        log(
            f"Dalších objektů:        "
            f"{extended['objects']}"
        )

        log(
            f"Nový baseline objektů:  "
            f"{extended['baseline']}"
        )

        log(
            f"Beze změny objektů:     "
            f"{extended['unchanged']}"
        )

        log(
            f"Přidáno objektů:        "
            f"{extended['added']}"
        )

        log(
            f"Upraveno objektů:       "
            f"{extended['updated']}"
        )

        log(
            f"Smazáno objektů:        "
            f"{extended['deleted']}"
        )

        log(
            f"Chyb rozšířeného auditu:"
            f" {extended['errors']}"
        )

    if primo is not None:
        log("")
        log(
            f"Primo Views:            "
            f"{primo['views']}"
        )

        log(
            f"Nový baseline Primo:    "
            f"{primo['baseline']}"
        )

        log(
            f"Beze změny Primo:       "
            f"{primo['unchanged']}"
        )

        log(
            f"Přidáno Primo Views:    "
            f"{primo['added']}"
        )

        log(
            f"Upraveno Primo Views:   "
            f"{primo['updated']}"
        )

        log(
            f"Chyb Primo auditu:      "
            f"{primo['errors']}"
        )

    total_errors = (
        stats["errors"]
        + (
            extended["errors"]
            if extended is not None
            else 0
        )
        + (
            primo["errors"]
            if primo is not None
            else 0
        )
    )

    primo_calls = (
        primo_api.calls
        if primo_api is not None
        else 0
    )

    log("")
    log(
        f"Alma API volání:        "
        f"{api.calls}"
    )

    log(
        f"Primo API volání:       "
        f"{primo_calls}"
    )

    log(
        f"API volání celkem:      "
        f"{api.calls + primo_calls}"
    )

    log(
        f"Alma API remaining:     "
        f"{api.remaining or 'neuvedeno'}"
    )

    if primo_api is not None:
        log(
            f"Primo API remaining:    "
            f"{primo_api.remaining or 'neuvedeno'}"
        )

    log(
        f"Chyb celkem:            "
        f"{total_errors}"
    )

    log(
        f"Databáze:               "
        f"{cfg['database']}"
    )

    return (
        1
        if total_errors
        else 0
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Audit konfigurace Alma"
        )
    )

    parser.add_argument(
        "--discover",
        action="store_true",
        help=(
            "Provede discovery kandidátních "
            "Code/Mapping Tables."
        ),
    )

    parser.add_argument(
        "--primo",
        action="store_true",
        help=(
            "Spustí pouze audit Primo VE Views "
            "bez Alma auditu."
        ),
    )

    parser.add_argument(
        "--jobs",
        action="store_true",
        help=(
            "Spustí pouze audit Alma Scheduled Jobs "
            "bez ostatní konfigurace a bez Prima."
        ),
    )

    parser.add_argument(
        "--codetables",
        action="store_true",
        help=(
            "Spustí pouze audit Alma Code Tables "
            "(včetně jazykových variant podle konfigurace)."
        ),
    )

    parser.add_argument(
        "--extended",
        action="store_true",
        help=(
            "Spustí pouze rozšířenou konfiguraci Alma "
            "bez Code/Mapping Tables a bez Prima."
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    cfg = load_config()

    lock_handle = None
    conn = None

    try:
        lock_handle = acquire_audit_lock(
            cfg["lock_file"],
            cfg["lock_wait_seconds"],
        )

        conn = connect_db(
            cfg["database"]
        )

        api = AlmaAPI(
            cfg
        )

        primo_api = None

        if cfg.get(
            "primo_enabled"
        ):
            primo_cfg = dict(
                cfg
            )

            primo_cfg[
                "api_base"
            ] = cfg[
                "primo_api_base"
            ]

            primo_api = AlmaAPI(
                primo_cfg
            )

        selected_modes = sum(
            (
                1 if args.discover else 0,
                1 if args.primo else 0,
                1 if args.jobs else 0,
                1 if args.codetables else 0,
                1 if args.extended else 0,
            )
        )

        if selected_modes > 1:
            raise SystemExit(
                "Parametry --discover, --primo, --jobs, "
                "--codetables a --extended nelze použít současně."
            )

        if args.discover:
            return run_discovery(
                cfg,
                api,
                conn,
            )

        if args.primo:
            return run_primo_only(
                cfg,
                conn,
                primo_api,
            )

        if args.jobs:
            return run_jobs_only(
                cfg,
                api,
                conn,
            )

        if args.codetables:
            test_cfg = dict(cfg)
            test_cfg["include_code"] = True
            test_cfg["include_mapping"] = False
            test_cfg["include_extended"] = False
            test_cfg["primo_enabled"] = False

            return run_audit(
                test_cfg,
                api,
                conn,
                primo_api=None,
                summary_title="SOUHRN - POUZE CODE TABLES",
            )

        if args.extended:
            test_cfg = dict(cfg)
            test_cfg["include_code"] = False
            test_cfg["include_mapping"] = False
            test_cfg["include_extended"] = True
            test_cfg["primo_enabled"] = False

            return run_audit(
                test_cfg,
                api,
                conn,
                primo_api=None,
                summary_title="SOUHRN - POUZE ROZŠÍŘENÁ KONFIGURACE",
            )

        return run_audit(
            cfg,
            api,
            conn,
            primo_api=primo_api,
        )

    finally:
        if conn is not None:
            conn.close()

        release_audit_lock(
            lock_handle
        )


if __name__ == "__main__":
    sys.exit(
        main()
    )