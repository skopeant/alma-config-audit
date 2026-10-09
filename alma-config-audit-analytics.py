#!/usr/bin/env python3

import argparse
import configparser
import copy
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import parse_qs, urlparse

import requests


CONFIG_FILE = "/etc/alma-config-audit.conf"


TOU_EXPECTED = [
    "TOU ID",
    "TOU Type",
    "TOU Description",
    "TOU Creation Date",
    "TOU Modification Date",
    "TOU Creator",
    "TOU Modified By",
    "Policy ID",
    "Policy Type",
    "Policy Name",
    "Policy Description",
    "Policy Unit of Measurement",
    "Policy Value",
    "Policy Constant",
    "Policy Additional Data",
    "Policy Active",
    "Policy Is Default Value",
    "Policy Creation Date",
    "Policy Modification Date",
    "Policy Creator",
    "Policy Modified By",
]

RULE_EXPECTED = [
    "Rule ID",
    "Rule Name",
    "Rule Type",
    "Is Default",
    "Is Active",
    "Rule Creation Date",
    "Rule Modification Date",
    "Rule Creator",
    "Rule Modified By",
    "Rule Parameter ID",
    "Rule Parameter Key",
    "Rule Parameter Modification Date",
    "Rule Parameter Modified By",
    "Rule Parameter Value",
    "Operator Name",
]


CONFIG_EVENTS_EXPECTED = [
    "Event Category",
    "Event Creator",
    "Event Key Name",
    "Event Key Value",
    "Event Module",
    "Event Type",
    "Event Sub Module",
    "Event Description",
    "Event Id",
    "Event Date",
    "Event Date and Time",
]


def log(msg=""):
    print(msg, flush=True)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )


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


def clean_text(value):
    if value is None:
        return None

    value = str(value).strip()

    if value == "":
        return None

    return value


def safe_id(value):
    value = clean_text(value)

    if value is None:
        return None

    # OBI někdy číselné identifikátory vrací jako desetinné číslo.
    if value.endswith(".0"):
        candidate = value[:-2]

        if candidate.isdigit():
            return candidate

    return value


def normalize_report_path(value):
    """
    Přijme buď čistou Analytics cestu /shared/..., nebo celý URL z Analytics UI.
    """
    value = clean_text(value)

    if not value:
        return None

    if value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = urlparse(value)
        params = parse_qs(
            parsed.query
        )

        paths = params.get(
            "path",
            [],
        )

        if not paths:
            raise RuntimeError(
                "Analytics URL neobsahuje parametr path."
            )

        return paths[0]

    return value


def load_config():
    cfg = configparser.ConfigParser()

    if not cfg.read(
        CONFIG_FILE
    ):
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

    database = cfg.get(
        "audit",
        "database",
        fallback=(
            "/var/lib/alma-config-audit/"
            "audit.sqlite3"
        ),
    )

    return {
        "api_base": api_base,
        "api_key": api_key,

        "database": database,

        "lock_file": cfg.get(
            "audit",
            "lock_file",
            fallback=(
                "/var/lib/alma-config-audit/"
                "audit.lock"
            ),
        ),

        "lock_wait_seconds": cfg.getint(
            "audit",
            "lock_wait_seconds",
            fallback=300,
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

        "analytics_enabled": cfg.getboolean(
            "analytics",
            "enabled",
            fallback=False,
        ),

        "tou_policies_path": normalize_report_path(
            cfg.get(
                "analytics",
                "tou_policies_path",
                fallback="",
            )
        ),

        "rules_path": normalize_report_path(
            cfg.get(
                "analytics",
                "rules_path",
                fallback="",
            )
        ),

        "configuration_events_path": normalize_report_path(
            cfg.get(
                "analytics",
                "configuration_events_path",
                fallback="",
            )
        ),

        "configuration_events_match_minutes": cfg.getint(
            "analytics",
            "configuration_events_match_minutes",
            fallback=360,
        ),

        # Event Date and Time z Alma Analytics je bez informace
        # o časovém pásmu. Pro zpětnou kompatibilitu používáme
        # Europe/Prague, pokud parametr v konfiguraci chybí.
        "configuration_events_timezone": cfg.get(
            "analytics",
            "configuration_events_timezone",
            fallback="Europe/Prague",
        ).strip() or "Europe/Prague",

        "analytics_limit": cfg.getint(
            "analytics",
            "limit",
            fallback=1000,
        ),
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
            analytics_details_json TEXT,

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

    # Migrace pro instalace se starší databází. SQLite CREATE TABLE IF NOT
    # EXISTS nové sloupce do existující tabulky nepřidá, proto jej doplníme
    # bezpečně zde. Hlavní auditní skript může tento sloupec ignorovat.
    change_log_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(change_log)").fetchall()
    }
    if "analytics_details_json" not in change_log_columns:
        conn.execute(
            "ALTER TABLE change_log ADD COLUMN analytics_details_json TEXT"
        )
        conn.commit()

    return conn


def acquire_audit_lock(
    lock_file,
    wait_seconds=300,
):
    """
    Stejný lock používá alma-config-audit.py i tento Analytics audit.
    Chrání SQLite i při ručním spuštění obou skriptů současně.
    """
    lock_dir = os.path.dirname(
        lock_file
    )

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


def local_name(tag):
    if "}" in tag:
        return tag.rsplit(
            "}",
            1,
        )[1]

    return tag


def attr_by_local_name(
    element,
    attr_name,
):
    for key, value in element.attrib.items():
        if local_name(
            key
        ) == attr_name:
            return value

    return None


class AnalyticsAPI:
    def __init__(self, cfg):
        self.base = cfg[
            "api_base"
        ]
        self.key = cfg[
            "api_key"
        ]
        self.timeout = cfg[
            "timeout"
        ]
        self.delay = cfg[
            "request_delay"
        ]
        self.limit = max(
            25,
            min(
                1000,
                cfg[
                    "analytics_limit"
                ],
            ),
        )

        self.session = requests.Session()

        self.calls = 0
        self.remaining = None

    def request_page(
        self,
        report_path=None,
        token=None,
    ):
        params = {
            "apikey": self.key,
            "limit": self.limit,
            "col_names": "true",
        }

        if token:
            params[
                "token"
            ] = token
        else:
            params[
                "path"
            ] = report_path

        response = self.session.get(
            self.base
            + "/analytics/reports",
            params=params,
            timeout=self.timeout,
        )

        self.calls += 1

        remaining = response.headers.get(
            "X-Exl-Api-Remaining"
        )

        if remaining:
            self.remaining = remaining

        if self.delay:
            time.sleep(
                self.delay
            )

        if response.status_code != 200:
            raise RuntimeError(
                "Analytics API HTTP "
                f"{response.status_code}: "
                f"{response.text[:1000]}"
            )

        return response.text

    def fetch_report(
        self,
        report_path,
    ):
        all_rows = []
        headers = None
        token = None
        pages = 0

        while True:
            pages += 1

            if pages > 200:
                raise RuntimeError(
                    "Analytics pagination překročila 200 stran."
                )

            xml_text = self.request_page(
                report_path=(
                    report_path
                    if token is None
                    else None
                ),
                token=token,
            )

            page_rows, page_headers, page_token, finished = (
                parse_analytics_xml(
                    xml_text,
                    headers=headers,
                )
            )

            if page_headers:
                headers = page_headers

            all_rows.extend(
                page_rows
            )

            if finished:
                break

            if token is None:
                token = page_token

            if not token:
                raise RuntimeError(
                    "Analytics vrací IsFinished=false, "
                    "ale neposkytl ResumptionToken."
                )

        return all_rows, (
            headers
            if headers is not None
            else {}
        )


def parse_analytics_xml(
    xml_text,
    headers=None,
):
    try:
        root = ET.fromstring(
            xml_text
        )
    except ET.ParseError as exc:
        raise RuntimeError(
            "Analytics API vrátil neplatné XML: "
            f"{exc}"
        ) from exc

    # API může chybu vrátit uvnitř XML i při HTTP 200.
    error_messages = []

    for elem in root.iter():
        name = local_name(
            elem.tag
        ).lower()

        if name in (
            "errormessage",
            "errorcode",
        ):
            value = clean_text(
                elem.text
            )

            if value:
                error_messages.append(
                    value
                )

    query_result = None

    for elem in root.iter():
        if local_name(
            elem.tag
        ) == "QueryResult":
            query_result = elem
            break

    if query_result is None:
        if error_messages:
            raise RuntimeError(
                "Analytics API chyba: "
                + " | ".join(
                    error_messages
                )
            )

        raise RuntimeError(
            "Analytics XML neobsahuje QueryResult."
        )

    is_finished = None
    resumption_token = None

    for child in query_result:
        name = local_name(
            child.tag
        )

        if name == "IsFinished":
            is_finished = (
                clean_text(
                    child.text
                )
                or ""
            ).lower() == "true"

        elif name == "ResumptionToken":
            resumption_token = clean_text(
                child.text
            )

    discovered_headers = {}

    for elem in root.iter():
        if local_name(
            elem.tag
        ) != "element":
            continue

        column_name = elem.attrib.get(
            "name"
        )

        if (
            not column_name
            or not column_name.startswith(
                "Column"
            )
        ):
            continue

        heading = attr_by_local_name(
            elem,
            "columnHeading",
        )

        if heading:
            discovered_headers[
                column_name
            ] = heading

    if discovered_headers:
        headers = discovered_headers

    if headers is None:
        headers = {}

    rows = []

    for row_elem in root.iter():
        if local_name(
            row_elem.tag
        ) != "Row":
            continue

        row = {}

        for child in row_elem:
            column_name = local_name(
                child.tag
            )

            if not column_name.startswith(
                "Column"
            ):
                continue

            heading = headers.get(
                column_name,
                column_name,
            )

            # Column0 s nadpisem "0" je technický sloupec OBI.
            if (
                column_name == "Column0"
                and heading in (
                    "0",
                    "Column0",
                )
            ):
                continue

            row[
                heading
            ] = clean_text(
                child.text
            )

        rows.append(
            row
        )

    if is_finished is None:
        # Při jediné stránce by měla být hodnota vždy přítomná,
        # ale bezpečně skončíme, pokud není token.
        is_finished = (
            not resumption_token
        )

    return (
        rows,
        headers,
        resumption_token,
        is_finished,
    )


def require_columns(
    rows,
    headers,
    required,
    report_label,
):
    available = set(
        headers.values()
    )

    # Pokud API z nějakého důvodu neposlalo schema,
    # zkusíme názvy získat z prvního řádku.
    if not available and rows:
        available = set(
            rows[0].keys()
        )

    missing = [
        column
        for column in required
        if column not in available
    ]

    if missing:
        raise RuntimeError(
            f"{report_label}: chybí sloupce: "
            + ", ".join(
                missing
            )
        )


def pick(
    row,
    key,
):
    return clean_text(
        row.get(
            key
        )
    )


def build_tou_objects(rows):
    tou_by_id = {}
    policies = {}

    for row in rows:
        tou_id = safe_id(
            row.get(
                "TOU ID"
            )
        )

        policy_id = safe_id(
            row.get(
                "Policy ID"
            )
        )

        if not tou_id:
            continue

        tou = {
            "tou_id": tou_id,
            "tou_type": pick(
                row,
                "TOU Type",
            ),
            "tou_description": pick(
                row,
                "TOU Description",
            ),
            "tou_creation_date": pick(
                row,
                "TOU Creation Date",
            ),
            "tou_modification_date": pick(
                row,
                "TOU Modification Date",
            ),
            "tou_creator": pick(
                row,
                "TOU Creator",
            ),
            "tou_modified_by": pick(
                row,
                "TOU Modified By",
            ),
        }

        existing = tou_by_id.get(
            tou_id
        )

        if existing is None:
            tou_by_id[
                tou_id
            ] = tou
        else:
            # Pokud se metadata TOU v jednotlivých řádcích liší,
            # vezmeme neprázdnou novější reprezentaci.
            for key, value in tou.items():
                if value is not None:
                    existing[
                        key
                    ] = value

        if not policy_id:
            continue

        audit_key = (
            f"{tou_id}/{policy_id}"
        )

        policy = {
            "_audit_key": audit_key,

            # Kontext pro detail ve webu.
            # Do policy hashe vstupuje pouze tou_id,
            # takže změna názvu/typu TOU nevytvoří změnu všech Policies.
            "tou_id": tou_id,
            "tou_type": pick(
                row,
                "TOU Type",
            ),
            "tou_description": pick(
                row,
                "TOU Description",
            ),

            "policy_id": policy_id,
            "policy_type": pick(
                row,
                "Policy Type",
            ),
            "policy_name": pick(
                row,
                "Policy Name",
            ),
            "policy_description": pick(
                row,
                "Policy Description",
            ),
            "policy_unit_of_measurement": pick(
                row,
                "Policy Unit of Measurement",
            ),
            "policy_value": pick(
                row,
                "Policy Value",
            ),
            "policy_constant": pick(
                row,
                "Policy Constant",
            ),
            "policy_additional_data": pick(
                row,
                "Policy Additional Data",
            ),
            "policy_active": pick(
                row,
                "Policy Active",
            ),
            "policy_is_default_value": pick(
                row,
                "Policy Is Default Value",
            ),
            "policy_creation_date": pick(
                row,
                "Policy Creation Date",
            ),
            "policy_modification_date": pick(
                row,
                "Policy Modification Date",
            ),
            "policy_creator": pick(
                row,
                "Policy Creator",
            ),
            "policy_modified_by": pick(
                row,
                "Policy Modified By",
            ),
        }

        policies[
            audit_key
        ] = policy

    return (
        list(
            tou_by_id.values()
        ),
        list(
            policies.values()
        ),
    )


def build_rule_objects(rows):
    result = {}

    for row in rows:
        rule_id = safe_id(
            row.get(
                "Rule ID"
            )
        )

        if not rule_id:
            continue

        obj = {
            "rule_id": rule_id,
            "rule_name": pick(
                row,
                "Rule Name",
            ),
            "rule_type": pick(
                row,
                "Rule Type",
            ),
            "is_default": pick(
                row,
                "Is Default",
            ),
            "is_active": pick(
                row,
                "Is Active",
            ),
            "rule_creation_date": pick(
                row,
                "Rule Creation Date",
            ),
            "rule_modification_date": pick(
                row,
                "Rule Modification Date",
            ),
            "rule_creator": pick(
                row,
                "Rule Creator",
            ),
            "rule_modified_by": pick(
                row,
                "Rule Modified By",
            ),
            "rule_parameter_id": safe_id(
                row.get(
                    "Rule Parameter ID"
                )
            ),
            "rule_parameter_key": pick(
                row,
                "Rule Parameter Key",
            ),
            "rule_parameter_modification_date": pick(
                row,
                "Rule Parameter Modification Date",
            ),
            "rule_parameter_modified_by": pick(
                row,
                "Rule Parameter Modified By",
            ),
            "rule_parameter_value": pick(
                row,
                "Rule Parameter Value",
            ),
            "operator_name": pick(
                row,
                "Operator Name",
            ),
        }

        result[
            rule_id
        ] = obj

    return list(
        result.values()
    )


def substantive_payload(
    object_type,
    payload,
):
    if object_type == "tou":
        return {
            "tou_id": payload.get(
                "tou_id"
            ),
            "tou_type": payload.get(
                "tou_type"
            ),
            "tou_description": payload.get(
                "tou_description"
            ),
        }

    if object_type == "tou_policy":
        return {
            "tou_id": payload.get(
                "tou_id"
            ),
            "policy_id": payload.get(
                "policy_id"
            ),
            "policy_type": payload.get(
                "policy_type"
            ),
            "policy_name": payload.get(
                "policy_name"
            ),
            "policy_description": payload.get(
                "policy_description"
            ),
            "policy_unit_of_measurement": payload.get(
                "policy_unit_of_measurement"
            ),
            "policy_value": payload.get(
                "policy_value"
            ),
            "policy_constant": payload.get(
                "policy_constant"
            ),
            "policy_additional_data": payload.get(
                "policy_additional_data"
            ),
            "policy_active": payload.get(
                "policy_active"
            ),
            "policy_is_default_value": payload.get(
                "policy_is_default_value"
            ),
        }

    if object_type == "fulfillment_rule":
        return {
            "rule_id": payload.get(
                "rule_id"
            ),
            "rule_name": payload.get(
                "rule_name"
            ),
            "rule_type": payload.get(
                "rule_type"
            ),
            "is_default": payload.get(
                "is_default"
            ),
            "is_active": payload.get(
                "is_active"
            ),
            "rule_parameter_id": payload.get(
                "rule_parameter_id"
            ),
            "rule_parameter_key": payload.get(
                "rule_parameter_key"
            ),
            "rule_parameter_value": payload.get(
                "rule_parameter_value"
            ),
            "operator_name": payload.get(
                "operator_name"
            ),
        }

    return copy.deepcopy(
        payload
    )


def changed_keys(
    object_type,
    before,
    after,
):
    b = substantive_payload(
        object_type,
        before,
    )
    a = substantive_payload(
        object_type,
        after,
    )

    keys = set(
        b.keys()
    ) | set(
        a.keys()
    )

    return sorted(
        key
        for key in keys
        if b.get(
            key
        ) != a.get(
            key
        )
    )


def event_metadata(
    object_type,
    payload,
    changed=None,
):
    changed = changed or []

    if object_type == "tou":
        return (
            payload.get(
                "tou_modification_date"
            ),
            payload.get(
                "tou_modified_by"
            ),
            payload.get(
                "tou_description"
            ),
        )

    if object_type == "tou_policy":
        description = " | ".join(
            x
            for x in (
                payload.get(
                    "tou_description"
                ),
                payload.get(
                    "policy_type"
                ),
                payload.get(
                    "policy_name"
                ),
            )
            if x
        )

        return (
            payload.get(
                "policy_modification_date"
            ),
            payload.get(
                "policy_modified_by"
            ),
            description or None,
        )

    if object_type == "fulfillment_rule":
        parameter_changed = any(
            key.startswith(
                "rule_parameter_"
            )
            or key == "operator_name"
            for key in changed
        )

        if parameter_changed:
            event_at = (
                payload.get(
                    "rule_parameter_modification_date"
                )
                or payload.get(
                    "rule_modification_date"
                )
            )

            user = (
                payload.get(
                    "rule_parameter_modified_by"
                )
                or payload.get(
                    "rule_modified_by"
                )
            )
        else:
            event_at = payload.get(
                "rule_modification_date"
            )

            user = payload.get(
                "rule_modified_by"
            )

        description = " | ".join(
            x
            for x in (
                payload.get(
                    "rule_name"
                ),
                payload.get(
                    "rule_parameter_key"
                ),
                payload.get(
                    "rule_parameter_value"
                ),
            )
            if x
        )

        return (
            event_at,
            user,
            description or None,
        )

    return (
        None,
        None,
        None,
    )


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


def initialize_scope(
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
        ON CONFLICT(object_type)
        DO NOTHING
        """,
        (
            object_type,
            utc_now(),
        ),
    )


def object_key(
    object_type,
    payload,
):
    if object_type == "tou":
        return safe_id(
            payload.get(
                "tou_id"
            )
        )

    if object_type == "tou_policy":
        return clean_text(
            payload.get(
                "_audit_key"
            )
        )

    if object_type == "fulfillment_rule":
        return safe_id(
            payload.get(
                "rule_id"
            )
        )

    return None



def get_zoneinfo(name):
    name = clean_text(name) or "Europe/Prague"
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise RuntimeError(
            "Neznámé časové pásmo pro Configuration Events: "
            f"{name}"
        ) from exc


def parse_event_datetime(value, naive_timezone=timezone.utc):
    """
    Převede datum/čas na timezone-aware UTC datetime.

    Hodnoty s vlastním offsetem/Z respektují tento offset.
    Hodnoty bez offsetu se interpretují v naive_timezone.

    DŮLEŽITÉ:
    - detected_at z lokálního auditu je ISO s +00:00 a tímto převodem
      není ovlivněn;
    - Event Date and Time z API_conf_USER je bez timezone a volající mu
      předává časové pásmo instituce (výchozí Europe/Prague);
    - historický import TOU/Policies/Rules tuto funkci nepoužívá pro
      Modification Date, takže se jeho historické záznamy nepřepočítávají.
    """
    value = clean_text(value)
    if not value:
        return None

    try:
        number = float(value)
        if 20000 < number < 100000:
            base = datetime(1899, 12, 30)
            parsed = base + timedelta(days=number)
            return parsed.replace(
                tzinfo=naive_timezone
            ).astimezone(timezone.utc)
    except (TypeError, ValueError):
        pass

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=naive_timezone)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ):
        try:
            parsed = datetime.strptime(normalized, fmt)
            return parsed.replace(
                tzinfo=naive_timezone
            ).astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def normalize_table_identity(value):
    """
    Normalizuje technický/display název tabulky pro bezpečné porovnání.

    Příklady:
      User Area Links              -> userarealinks
      UserAreaLinks                -> userarealinks
      JobTitles [cs]               -> jobtitles
    """
    value = clean_text(value)
    if not value:
        return None

    # Jazykový suffix používá hlavní audit u vícejazyčných Code Tables.
    if value.endswith("]") and " [" in value:
        base, suffix = value.rsplit(" [", 1)
        language = suffix[:-1]
        if language and len(language) <= 10:
            value = base

    return "".join(
        ch.lower()
        for ch in value
        if ch.isalnum()
    ) or None


def changed_json_paths(before, after, prefix=()):
    """Vrátí list cest, na kterých se dvě JSON struktury liší."""
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        keys = set(before.keys()) | set(after.keys())
        for key in sorted(keys, key=lambda item: str(item)):
            if key not in before or key not in after:
                result.append(prefix + (str(key),))
                continue
            result.extend(
                changed_json_paths(
                    before[key],
                    after[key],
                    prefix + (str(key),),
                )
            )
        return result

    # Seznam považujeme za jednu hodnotu. Pro Primo potřebujeme znát
    # tabulku, nikoli jednotlivý index řádku v jejím payloadu.
    if isinstance(before, list) and isinstance(after, list):
        if canonical_json(before) != canonical_json(after):
            return [prefix]
        return []

    if before != after:
        return [prefix]

    return []


def primo_changed_mapping_tables(before, after):
    """
    Z diffu primo_view zjistí změněné Mapping Tables.

    Enrichment je povolen pouze tehdy, když všechny změněné cesty patří
    pod configuration.mapping-tables.<název tabulky>. Pokud se současně
    změnila jiná část View, vrací supported=False a autora nedoplňujeme.
    """
    paths = changed_json_paths(before, after)
    if not paths:
        return set(), False

    tables = set()
    unsupported = False

    for path in paths:
        mapping_index = None
        for index, part in enumerate(path):
            if normalize_table_identity(part) == "mappingtables":
                mapping_index = index
                break

        if mapping_index is None or mapping_index + 1 >= len(path):
            unsupported = True
            continue

        # Uznáváme pouze změny uvnitř configuration.mapping-tables.
        # Pokud je mapping-tables zanořeno jinde, raději nic nepřiřadíme.
        normalized_prefix = [
            normalize_table_identity(part)
            for part in path[:mapping_index]
        ]
        if "configuration" not in normalized_prefix:
            unsupported = True
            continue

        table_name = clean_text(path[mapping_index + 1])
        if table_name:
            tables.add(table_name)
        else:
            unsupported = True

    return tables, not unsupported and bool(tables)


def build_configuration_events(rows, event_timezone):
    grouped = {}

    for row in rows:
        event_id = pick(row, "Event Id")
        if not event_id:
            continue

        event = grouped.setdefault(
            event_id,
            {
                "event_id": event_id,
                "creator": pick(row, "Event Creator"),
                "event_at_raw": pick(row, "Event Date and Time"),
                "description": pick(row, "Event Description"),
                "event_type": pick(row, "Event Type"),
                "module": pick(row, "Event Module"),
                "sub_module": pick(row, "Event Sub Module"),
                "keys": {},
            },
        )

        key_name = pick(row, "Event Key Name")
        key_value = pick(row, "Event Key Value")

        if key_name:
            event["keys"][key_name] = key_value

        if key_name == "USER_NAME" and key_value:
            event["creator"] = key_value

    result = []
    mapping_descriptions = {
        "Mapping table updated",
        "mapping table customized",
        "mapping table restoration",
        "mapping table row customized",
        "mapping table row restored",
    }

    for event in grouped.values():
        description = (event.get("description") or "").strip()
        table_name = (
            event.get("keys", {}).get("TABLE_NAME") or ""
        ).strip()

        # Události bez TABLE_NAME mohou být v reportu užitečné pro ruční
        # diagnostiku, ale pro automatické přiřazení autora nejsou bezpečné.
        if not table_name:
            continue

        if description == "Code table updated":
            object_type = "code"
        elif description in mapping_descriptions:
            object_type = "mapping"
        else:
            continue

        event_at = parse_event_datetime(
            event.get("event_at_raw"),
            naive_timezone=event_timezone,
        )
        creator = clean_text(event.get("creator"))

        if event_at is None or not creator:
            continue

        result.append(
            {
                "event_id": event["event_id"],
                "event_at": event_at,
                "event_at_raw": event["event_at_raw"],
                "creator": creator,
                "description": description,
                "object_type": object_type,
                "object_name": table_name,
                "object_identity": normalize_table_identity(table_name),
            }
        )

    return result


def events_before_detection(events, detected_at, window):
    """
    Vrátí pouze eventy, které nastaly před zachycením změny auditem
    a nejvýše match window před ním. Událost po detected_at se nikdy
    nepoužije k přiřazení autora.
    """
    lower_bound = detected_at - window
    return [
        event
        for event in events
        if lower_bound <= event["event_at"] <= detected_at
    ]


def enrich_configuration_change_authors(
    conn,
    events,
    match_minutes=360,
):
    window = timedelta(minutes=max(1, int(match_minutes)))

    by_object = {}
    mapping_by_identity = {}

    for event in events:
        object_identity = normalize_table_identity(event["object_name"])
        if object_identity:
            key = (event["object_type"], object_identity)
            by_object.setdefault(key, []).append(event)

        if event["object_type"] == "mapping" and event.get("object_identity"):
            mapping_by_identity.setdefault(
                event["object_identity"],
                [],
            ).append(event)

    rows = conn.execute(
        """
        SELECT
            id,
            detected_at,
            object_type,
            object_name,
            before_json,
            after_json
        FROM change_log
        WHERE (
                object_type IN ('code', 'mapping')
                AND (analytics_user IS NULL OR TRIM(analytics_user) = '')
              )
           OR (
                object_type = 'primo_view'
                AND (
                    analytics_user IS NULL
                    OR TRIM(analytics_user) = ''
                    OR analytics_details_json IS NULL
                    OR TRIM(analytics_details_json) = ''
                )
              )
        ORDER BY detected_at, object_type, object_name, id
        """
    ).fetchall()

    groups = {}
    for row in rows:
        key = (
            row["detected_at"],
            row["object_type"],
            row["object_name"],
        )
        groups.setdefault(key, []).append(row)

    stats = {
        "groups_checked": len(groups),
        "groups_enriched": 0,
        "rows_enriched": 0,
        "ambiguous": 0,
        "no_match": 0,
        "bad_detected_at": 0,
        "primo_checked": 0,
        "primo_enriched": 0,
        "primo_unsupported_diff": 0,
        "primo_incomplete": 0,
        "primo_multiple_users": 0,
        "primo_multiuser_enriched": 0,
    }

    for (detected_raw, object_type, object_name), group_rows in groups.items():
        detected_at = parse_event_datetime(
            detected_raw,
            naive_timezone=timezone.utc,
        )
        if detected_at is None:
            stats["bad_detected_at"] += 1
            continue

        ids = [row["id"] for row in group_rows]
        analytics_details_json = None

        if object_type in ("code", "mapping"):
            identity = normalize_table_identity(object_name)
            candidates = events_before_detection(
                by_object.get((object_type, identity), []),
                detected_at,
                window,
            )

            if not candidates:
                stats["no_match"] += 1
                continue

            users = {
                event["creator"]
                for event in candidates
                if event.get("creator")
            }

            # Pokud tutéž tabulku v jednom auditním okně měnilo více lidí,
            # jeden autor by byl zavádějící. Nevyplníme nic.
            if len(users) != 1:
                stats["ambiguous"] += 1
                continue

            candidates.sort(
                key=lambda event: event["event_at"],
                reverse=True,
            )
            best = candidates[0]
            analytics_event_id = "configuration-event:" + best["event_id"]
            analytics_event_at = best["event_at_raw"]
            analytics_user = best["creator"]
            analytics_description = best["description"]

        elif object_type == "primo_view":
            stats["primo_checked"] += 1

            changed_tables = set()
            supported = True

            # Jedna skupina může obsahovat více change_log řádků stejného
            # View/detected_at. Všechny musí být vysvětlitelné Mapping Tables.
            for row in group_rows:
                try:
                    before = json.loads(row["before_json"]) \
                        if row["before_json"] else None
                    after = json.loads(row["after_json"]) \
                        if row["after_json"] else None
                except Exception:
                    supported = False
                    break

                if before is None or after is None:
                    supported = False
                    break

                row_tables, row_supported = primo_changed_mapping_tables(
                    before,
                    after,
                )
                if not row_supported:
                    supported = False
                    break

                changed_tables.update(row_tables)

            if not supported or not changed_tables:
                stats["primo_unsupported_diff"] += 1
                continue

            matched_events = []
            table_details = {}
            incomplete = False

            for table_name in sorted(changed_tables):
                identity = normalize_table_identity(table_name)
                candidates = events_before_detection(
                    mapping_by_identity.get(identity, []),
                    detected_at,
                    window,
                )

                if not candidates:
                    # Když pro jedinou změněnou Mapping Table nemáme event,
                    # nedoplňujeme ani souhrnného autora. Raději žádný autor
                    # než částečně odvozený a potenciálně zavádějící údaj.
                    incomplete = True
                    break

                candidates = sorted(
                    candidates,
                    key=lambda event: event["event_at"],
                )
                matched_events.extend(candidates)

                table_users = sorted({
                    event["creator"]
                    for event in candidates
                    if event.get("creator")
                })

                if len(table_users) > 1:
                    stats["primo_multiple_users"] += 1

                table_details[table_name] = {
                    "users": table_users,
                    "events": [
                        {
                            "event_id": event["event_id"],
                            "event_at": event["event_at"].isoformat(),
                            "event_at_raw": event["event_at_raw"],
                            "user": event["creator"],
                            "description": event["description"],
                        }
                        for event in candidates
                    ],
                }

            if incomplete:
                stats["primo_incomplete"] += 1
                continue

            all_users = sorted({
                user
                for detail in table_details.values()
                for user in detail["users"]
            })

            if not all_users:
                stats["primo_incomplete"] += 1
                continue

            # V přehledu zachováme všechny doložené autory. Pokud různé
            # Mapping Tables (nebo jednu tabulku) v auditním okně měnilo
            # více lidí, zobrazí se např. "NOVAK / SKOPEC". Detailní vazba
            # tabulka -> event -> uživatel zůstává v analytics_details_json.
            analytics_user = " / ".join(all_users)
            if len(all_users) > 1:
                stats["primo_multiuser_enriched"] += 1

            unique_events = {
                event["event_id"]: event
                for event in matched_events
            }
            ordered_events = sorted(
                unique_events.values(),
                key=lambda event: event["event_at"],
            )

            latest = ordered_events[-1]
            analytics_event_id = (
                "configuration-events:"
                + ",".join(event["event_id"] for event in ordered_events)
            )
            analytics_event_at = latest["event_at_raw"]
            analytics_description = (
                "Primo mapping tables: "
                + ", ".join(sorted(changed_tables))
            )
            analytics_details_json = json.dumps(
                {
                    "version": 1,
                    "mapping_tables": table_details,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            stats["primo_enriched"] += 1

        else:
            continue

        placeholders = ",".join("?" for _ in ids)

        if object_type == "primo_view":
            conn.execute(
                f"""
                UPDATE change_log
                SET analytics_event_id = ?,
                    analytics_event_at = ?,
                    analytics_user = ?,
                    analytics_description = ?,
                    analytics_details_json = ?,
                    enriched = 1
                WHERE id IN ({placeholders})
                """,
                (
                    analytics_event_id,
                    analytics_event_at,
                    analytics_user,
                    analytics_description,
                    analytics_details_json,
                    *ids,
                ),
            )
        else:
            conn.execute(
                f"""
                UPDATE change_log
                SET analytics_event_id = ?,
                    analytics_event_at = ?,
                    analytics_user = ?,
                    analytics_description = ?,
                    enriched = 1
                WHERE id IN ({placeholders})
                  AND (analytics_user IS NULL OR TRIM(analytics_user) = '')
                """,
                (
                    analytics_event_id,
                    analytics_event_at,
                    analytics_user,
                    analytics_description,
                    *ids,
                ),
            )

        stats["groups_enriched"] += 1
        stats["rows_enriched"] += len(ids)

    conn.commit()
    return stats


def run_configuration_events_enrichment(cfg, api, conn):
    path = cfg.get("configuration_events_path")
    if not path:
        return None

    log("")
    log(
        "Načítám Analytics: Configuration Events pro doplnění "
        "uživatele změny ..."
    )

    rows, headers = api.fetch_report(path)
    require_columns(
        rows,
        headers,
        CONFIG_EVENTS_EXPECTED,
        "Configuration Events",
    )

    event_timezone = get_zoneinfo(
        cfg.get("configuration_events_timezone")
    )
    events = build_configuration_events(
        rows,
        event_timezone=event_timezone,
    )
    stats = enrich_configuration_change_authors(
        conn,
        events,
        match_minutes=cfg["configuration_events_match_minutes"],
    )
    stats["analytics_rows"] = len(rows)
    stats["usable_events"] = len(events)

    log(f"Configuration Events řádků: {len(rows)}")
    log(f"Použitelných eventů:       {len(events)}")
    log(
        "Časové pásmo eventů:      "
        f"{cfg['configuration_events_timezone']}"
    )
    log(f"Doplněno skupin změn:      {stats['groups_enriched']}")
    log(f"Doplněno change_log řádků: {stats['rows_enriched']}")
    log(f"Nejednoznačných shod:      {stats['ambiguous']}")
    log(f"Primo skupin kontrolováno: {stats['primo_checked']}")
    log(f"Primo skupin doplněno:     {stats['primo_enriched']}")
    log(f"Primo nepodporovaný diff:  {stats['primo_unsupported_diff']}")
    log(f"Primo neúplná shoda:       {stats['primo_incomplete']}")
    log(f"Primo tabulek s více už.:  {stats['primo_multiple_users']}")
    log(f"Primo multi-user doplněno: {stats['primo_multiuser_enriched']}")

    return stats


def record_change(
    conn,
    detected_at,
    object_type,
    object_name,
    change_type,
    before=None,
    after=None,
    analytics_event_at=None,
    analytics_user=None,
    analytics_description=None,
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
            after_json,
            analytics_event_id,
            analytics_event_at,
            analytics_user,
            analytics_description,
            enriched
        )
        VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            detected_at,
            object_type,
            object_name,
            change_type,
            json_for_db(
                before
            ),
            json_for_db(
                after
            ),
            object_name,
            analytics_event_at,
            analytics_user,
            analytics_description,
        ),
    )


def process_object(
    conn,
    detected_at,
    object_type,
    payload,
    initialized,
):
    key = object_key(
        object_type,
        payload,
    )

    if not key:
        return None

    substantive = substantive_payload(
        object_type,
        payload,
    )

    new_hash = hash_payload(
        substantive
    )

    old = conn.execute(
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
            key,
        ),
    ).fetchone()

    full_json = canonical_json(
        payload
    )

    if old is None:
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
                key,
                new_hash,
                full_json,
                detected_at,
            ),
        )

        if initialized:
            event_at, user, description = event_metadata(
                object_type,
                payload,
            )

            record_change(
                conn,
                detected_at,
                object_type,
                key,
                "OBJECT_ADDED",
                before=None,
                after=payload,
                analytics_event_at=event_at,
                analytics_user=user,
                analytics_description=description,
            )

            return "added"

        return "baseline"

    try:
        old_payload = json.loads(
            old[
                "payload_json"
            ]
        )
    except Exception:
        old_payload = {}

    if old[
        "object_hash"
    ] == new_hash:
        # Aktualizujeme i full payload: metadata Modified By/Date
        # se tak udrží aktuální, aniž by samy vytvářely změnu.
        conn.execute(
            """
            UPDATE current_object
            SET
                payload_json = ?,
                captured_at = ?
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                full_json,
                detected_at,
                object_type,
                key,
            ),
        )

        return "unchanged"

    changed = changed_keys(
        object_type,
        old_payload,
        payload,
    )

    event_at, user, description = event_metadata(
        object_type,
        payload,
        changed=changed,
    )

    record_change(
        conn,
        detected_at,
        object_type,
        key,
        "OBJECT_UPDATED",
        before=old_payload,
        after=payload,
        analytics_event_at=event_at,
        analytics_user=user,
        analytics_description=description,
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
            new_hash,
            full_json,
            detected_at,
            object_type,
            key,
        ),
    )

    return "updated"


def finish_scope(
    conn,
    detected_at,
    object_type,
    seen,
    initialized,
):
    deleted = 0

    if not initialized:
        initialize_scope(
            conn,
            object_type,
        )

        return deleted

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

    for row in rows:
        key = row[
            "object_name"
        ]

        if key in seen:
            continue

        try:
            old_payload = json.loads(
                row[
                    "payload_json"
                ]
            )
        except Exception:
            old_payload = {}

        record_change(
            conn,
            detected_at,
            object_type,
            key,
            "OBJECT_DELETED",
            before=old_payload,
            after=None,
            analytics_event_at=None,
            analytics_user=None,
            analytics_description=None,
        )

        conn.execute(
            """
            DELETE FROM current_object
            WHERE object_type = ?
              AND object_name = ?
            """,
            (
                object_type,
                key,
            ),
        )

        deleted += 1

    return deleted


def audit_objects(
    conn,
    detected_at,
    object_type,
    objects,
):
    initialized = scope_initialized(
        conn,
        object_type,
    )

    stats = {
        "baseline": 0,
        "unchanged": 0,
        "added": 0,
        "updated": 0,
        "deleted": 0,
    }

    seen = set()

    for payload in objects:
        key = object_key(
            object_type,
            payload,
        )

        if not key:
            continue

        seen.add(
            key
        )

        status = process_object(
            conn,
            detected_at,
            object_type,
            payload,
            initialized,
        )

        if status in stats:
            stats[
                status
            ] += 1

    stats[
        "deleted"
    ] += finish_scope(
        conn,
        detected_at,
        object_type,
        seen,
        initialized,
    )

    conn.commit()

    return stats


def log_stats(
    label,
    stats,
):
    changed = (
        stats[
            "added"
        ]
        + stats[
            "updated"
        ]
        + stats[
            "deleted"
        ]
    )

    log(
        f"{label:<24} "
        f"objektů={sum(stats.values())} "
        f"baseline={stats['baseline']} "
        f"beze změny={stats['unchanged']} "
        f"přidáno={stats['added']} "
        f"upraveno={stats['updated']} "
        f"smazáno={stats['deleted']}"
    )

    return changed



def history_event_id(
    object_type,
    object_name,
    event_at,
    user,
):
    raw = "|".join(
        [
            "HISTORY_MODIFIED",
            object_type or "",
            object_name or "",
            event_at or "",
            user or "",
        ]
    )

    return (
        "history:"
        + hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()
    )


def history_event_exists(
    conn,
    object_type,
    object_name,
    event_at,
    event_id,
):
    # 1) Už importovaná historická událost.
    row = conn.execute(
        """
        SELECT 1
        FROM change_log
        WHERE analytics_event_id = ?
        LIMIT 1
        """,
        (
            event_id,
        ),
    ).fetchone()

    if row is not None:
        return True

    # 2) Stejnou změnu už zachytil běžný Analytics audit.
    # Tím zabráníme duplicitě při použití --import-history po výpadku.
    row = conn.execute(
        """
        SELECT 1
        FROM change_log
        WHERE object_type = ?
          AND object_name = ?
          AND analytics_event_at = ?
          AND change_type <> 'HISTORY_MODIFIED'
        LIMIT 1
        """,
        (
            object_type,
            object_name,
            event_at,
        ),
    ).fetchone()

    return row is not None


def current_object_row(
    conn,
    object_type,
    object_name,
):
    return conn.execute(
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


def upsert_current_object(
    conn,
    detected_at,
    object_type,
    object_name,
    payload,
):
    substantive = substantive_payload(
        object_type,
        payload,
    )

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
        ON CONFLICT (
            object_type,
            object_name
        )
        DO UPDATE SET
            object_hash = excluded.object_hash,
            payload_json = excluded.payload_json,
            captured_at = excluded.captured_at
        """,
        (
            object_type,
            object_name,
            hash_payload(
                substantive
            ),
            canonical_json(
                payload
            ),
            detected_at,
        ),
    )


def import_history_objects(
    conn,
    detected_at,
    object_type,
    objects,
):
    stats = {
        "imported": 0,
        "with_before": 0,
        "without_before": 0,
        "skipped_existing": 0,
        "skipped_no_date": 0,
    }

    for payload in objects:
        key = object_key(
            object_type,
            payload,
        )

        if not key:
            continue

        event_at, user, description = event_metadata(
            object_type,
            payload,
        )

        if not event_at:
            stats[
                "skipped_no_date"
            ] += 1
            continue

        event_id = history_event_id(
            object_type,
            key,
            event_at,
            user,
        )

        if history_event_exists(
            conn,
            object_type,
            key,
            event_at,
            event_id,
        ):
            stats[
                "skipped_existing"
            ] += 1
            continue

        old = current_object_row(
            conn,
            object_type,
            key,
        )

        before = None
        has_real_before = False

        if old is not None:
            try:
                old_payload = json.loads(
                    old[
                        "payload_json"
                    ]
                )
            except Exception:
                old_payload = {}

            old_hash = hash_payload(
                substantive_payload(
                    object_type,
                    old_payload,
                )
            )

            new_hash = hash_payload(
                substantive_payload(
                    object_type,
                    payload,
                )
            )

            if old_hash != new_hash:
                # Typický případ po výpadku:
                # starý snapshot je skutečné Before a dnešní Analytics
                # poskytují nové After + datum/uživatele změny.
                before = old_payload
                has_real_before = True

        conn.execute(
            """
            INSERT INTO change_log (
                detected_at,
                object_type,
                object_name,
                change_type,
                row_key,
                before_json,
                after_json,
                analytics_event_id,
                analytics_event_at,
                analytics_user,
                analytics_description,
                enriched
            )
            VALUES (?, ?, ?, 'HISTORY_MODIFIED', NULL, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                detected_at,
                object_type,
                key,
                json_for_db(
                    before
                ),
                json_for_db(
                    payload
                ),
                event_id,
                event_at,
                user,
                description,
            ),
        )

        # Pokud --import-history doplňuje změnu po výpadku a máme
        # staré Before, posuneme zároveň current_object na nový stav.
        # Následující běžný audit pak stejnou změnu nezapíše znovu.
        if has_real_before:
            upsert_current_object(
                conn,
                detected_at,
                object_type,
                key,
                payload,
            )

            stats[
                "with_before"
            ] += 1
        else:
            stats[
                "without_before"
            ] += 1

        stats[
            "imported"
        ] += 1

    conn.commit()

    return stats


def run_history_import(
    cfg,
    api,
    conn,
):
    if not cfg[
        "analytics_enabled"
    ]:
        log(
            "Analytics audit je v konfiguraci vypnutý "
            "([analytics] enabled = false)."
        )
        return 0

    if not cfg[
        "tou_policies_path"
    ]:
        raise RuntimeError(
            "Chybí [analytics] tou_policies_path."
        )

    if not cfg[
        "rules_path"
    ]:
        raise RuntimeError(
            "Chybí [analytics] rules_path."
        )

    detected_at = utc_now()

    log(
        "Načítám Analytics pro historický import: "
        "TOU + Policies ..."
    )

    tou_rows, tou_headers = api.fetch_report(
        cfg[
            "tou_policies_path"
        ]
    )

    require_columns(
        tou_rows,
        tou_headers,
        TOU_EXPECTED,
        "TOU + Policies",
    )

    tou_objects, policy_objects = build_tou_objects(
        tou_rows
    )

    log(
        "Načítám Analytics pro historický import: "
        "Fulfillment Rules ..."
    )

    rule_rows, rule_headers = api.fetch_report(
        cfg[
            "rules_path"
        ]
    )

    require_columns(
        rule_rows,
        rule_headers,
        RULE_EXPECTED,
        "Fulfillment Rules",
    )

    rule_objects = build_rule_objects(
        rule_rows
    )

    log("")
    log(
        "Importuji poslední známé historické události "
        "z Modification Date / Modified By ..."
    )

    tou_stats = import_history_objects(
        conn,
        detected_at,
        "tou",
        tou_objects,
    )

    policy_stats = import_history_objects(
        conn,
        detected_at,
        "tou_policy",
        policy_objects,
    )

    rule_stats = import_history_objects(
        conn,
        detected_at,
        "fulfillment_rule",
        rule_objects,
    )

    def history_line(
        label,
        stats,
    ):
        log(
            f"{label:<24} "
            f"importováno={stats['imported']} "
            f"s Before={stats['with_before']} "
            f"bez Before={stats['without_before']} "
            f"již existuje={stats['skipped_existing']} "
            f"bez data={stats['skipped_no_date']}"
        )

    log("")
    log("=" * 70)
    log("HISTORICKÝ IMPORT - SOUHRN")
    log("=" * 70)

    history_line(
        "Terms of Use",
        tou_stats,
    )
    history_line(
        "TOU Policies",
        policy_stats,
    )
    history_line(
        "Fulfillment Rules",
        rule_stats,
    )

    total_imported = (
        tou_stats[
            "imported"
        ]
        + policy_stats[
            "imported"
        ]
        + rule_stats[
            "imported"
        ]
    )

    total_with_before = (
        tou_stats[
            "with_before"
        ]
        + policy_stats[
            "with_before"
        ]
        + rule_stats[
            "with_before"
        ]
    )

    log("")
    log(
        f"Historických událostí:    {total_imported}"
    )
    log(
        f"Z toho skutečné Before:   {total_with_before}"
    )
    log(
        f"Analytics API volání:     {api.calls}"
    )
    log(
        "API remaining:            "
        f"{api.remaining or 'neuvedeno'}"
    )
    log(
        f"Databáze:                 {cfg['database']}"
    )

    return 0


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Audit TOU/Policies a Fulfillment Rules "
            "z Alma Analytics"
        )
    )

    parser.add_argument(
        "--import-history",
        action="store_true",
        help=(
            "Jednorázově doplní poslední známé historické "
            "události podle Modification Date / Modified By. "
            "Pokud existuje starší lokální snapshot s jinou "
            "hodnotou, použije jej jako skutečné Before."
        ),
    )

    parser.add_argument(
        "--enrich-configuration-events",
        action="store_true",
        help=(
            "Spustí pouze volitelné doplnění uživatele/času "
            "k lokálním Code/Mapping změnám z Analytics System Events. "
            "Vyžaduje [analytics] configuration_events_path."
        ),
    )

    return parser.parse_args()

def run_audit(
    cfg,
    api,
    conn,
):
    if not cfg[
        "analytics_enabled"
    ]:
        log(
            "Analytics audit je v konfiguraci vypnutý "
            "([analytics] enabled = false)."
        )

        return 0

    if not cfg[
        "tou_policies_path"
    ]:
        raise RuntimeError(
            "Chybí [analytics] tou_policies_path."
        )

    if not cfg[
        "rules_path"
    ]:
        raise RuntimeError(
            "Chybí [analytics] rules_path."
        )

    detected_at = utc_now()

    log(
        "Načítám Analytics: TOU + Policies ..."
    )

    tou_rows, tou_headers = api.fetch_report(
        cfg[
            "tou_policies_path"
        ]
    )

    require_columns(
        tou_rows,
        tou_headers,
        TOU_EXPECTED,
        "TOU + Policies",
    )

    tou_objects, policy_objects = build_tou_objects(
        tou_rows
    )

    log(
        f"Analytics TOU řádků:      {len(tou_rows)}"
    )
    log(
        f"TOU objektů:              {len(tou_objects)}"
    )
    log(
        f"TOU/Policy objektů:       {len(policy_objects)}"
    )

    log("")
    log(
        "Načítám Analytics: Fulfillment Rules ..."
    )

    rule_rows, rule_headers = api.fetch_report(
        cfg[
            "rules_path"
        ]
    )

    require_columns(
        rule_rows,
        rule_headers,
        RULE_EXPECTED,
        "Fulfillment Rules",
    )

    rule_objects = build_rule_objects(
        rule_rows
    )

    log(
        f"Analytics Rules řádků:    {len(rule_rows)}"
    )
    log(
        f"Rule objektů:             {len(rule_objects)}"
    )

    log("")
    log(
        "Zapisuji snapshot/diff do společné DB ..."
    )

    tou_stats = audit_objects(
        conn,
        detected_at,
        "tou",
        tou_objects,
    )

    policy_stats = audit_objects(
        conn,
        detected_at,
        "tou_policy",
        policy_objects,
    )

    rule_stats = audit_objects(
        conn,
        detected_at,
        "fulfillment_rule",
        rule_objects,
    )

    if cfg.get("configuration_events_path"):
        try:
            run_configuration_events_enrichment(
                cfg,
                api,
                conn,
            )
        except Exception as exc:
            # Volitelný enrichment nesmí rozbít hlavní Analytics audit.
            log(
                "WARN Configuration Events enrichment přeskočen: "
                f"{exc}"
            )

    log("")
    log("=" * 70)
    log("ANALYTICS AUDIT - SOUHRN")
    log("=" * 70)

    total_changes = 0

    total_changes += log_stats(
        "Terms of Use",
        tou_stats,
    )

    total_changes += log_stats(
        "TOU Policies",
        policy_stats,
    )

    total_changes += log_stats(
        "Fulfillment Rules",
        rule_stats,
    )

    log("")
    log(
        f"Analytics API volání:     {api.calls}"
    )
    log(
        "API remaining:            "
        f"{api.remaining or 'neuvedeno'}"
    )
    log(
        f"Změn celkem:              {total_changes}"
    )
    log(
        f"Databáze:                 {cfg['database']}"
    )

    return 0


def main():
    args = parse_args()
    cfg = load_config()

    lock_handle = None
    conn = None

    try:
        lock_handle = acquire_audit_lock(
            cfg[
                "lock_file"
            ],
            cfg[
                "lock_wait_seconds"
            ],
        )

        conn = connect_db(
            cfg[
                "database"
            ]
        )

        api = AnalyticsAPI(
            cfg
        )

        if args.enrich_configuration_events:
            if not cfg["analytics_enabled"]:
                log(
                    "Analytics audit je v konfiguraci vypnutý "
                    "([analytics] enabled = false)."
                )
                return 0

            if not cfg.get("configuration_events_path"):
                log(
                    "Configuration Events enrichment je vypnutý: "
                    "chybí [analytics] configuration_events_path."
                )
                return 0

            stats = run_configuration_events_enrichment(
                cfg,
                api,
                conn,
            )

            log("")
            log("=" * 70)
            log("CONFIGURATION EVENTS ENRICHMENT - SOUHRN")
            log("=" * 70)
            log(
                "Doplněno skupin změn:      "
                f"{stats['groups_enriched']}"
            )
            log(
                "Doplněno change_log řádků: "
                f"{stats['rows_enriched']}"
            )
            log(f"Analytics API volání:       {api.calls}")
            log(
                "API remaining:              "
                f"{api.remaining or 'neuvedeno'}"
            )
            return 0

        if args.import_history:
            return run_history_import(
                cfg,
                api,
                conn,
            )

        return run_audit(
            cfg,
            api,
            conn,
        )

    finally:
        if conn is not None:
            conn.close()

        release_audit_lock(
            lock_handle
        )


if __name__ == "__main__":
    try:
        sys.exit(
            main()
        )
    except KeyboardInterrupt:
        log(
            "Přerušeno uživatelem."
        )
        sys.exit(130)
    except Exception as exc:
        log(
            f"CHYBA: {exc}"
        )
        sys.exit(1)
