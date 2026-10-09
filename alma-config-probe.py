#!/usr/bin/env python3

import configparser
import json
import sys
import time
from urllib.parse import quote

import requests


CONFIG_FILE = "/etc/alma-config-audit.conf"


def log(msg=""):
    print(msg, flush=True)


def load_config():
    cfg = configparser.ConfigParser()

    if not cfg.read(CONFIG_FILE):
        raise RuntimeError(
            f"Nelze načíst konfiguraci {CONFIG_FILE}"
        )

    return {
        "base": cfg.get(
            "alma",
            "api_base",
        ).rstrip("/"),
        "key": cfg.get(
            "alma",
            "api_key",
        ).strip(),
        "timeout": cfg.getint(
            "audit",
            "timeout",
            fallback=60,
        ),
        "delay": cfg.getfloat(
            "audit",
            "request_delay",
            fallback=0.10,
        ),
    }


class Alma:
    def __init__(self, cfg):
        self.base = cfg["base"]
        self.key = cfg["key"]
        self.timeout = cfg["timeout"]
        self.delay = cfg["delay"]
        self.session = requests.Session()
        self.calls = 0
        self.remaining = None

    def get(self, path, params=None):
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

        return response


def summarize_value(value):
    if isinstance(value, dict):
        return (
            f"object keys="
            f"{list(value.keys())[:20]}"
        )

    if isinstance(value, list):
        return (
            f"list count={len(value)}"
        )

    if value is None:
        return "null"

    text = str(value)

    if len(text) > 100:
        text = text[:100] + "..."

    return repr(text)


def show_json_shape(label, response):
    log("")
    log("=" * 78)
    log(label)
    log("=" * 78)

    log(
        f"HTTP: {response.status_code}"
    )

    if not response.ok:
        body = response.text[:500]

        log(
            f"ERROR BODY: {body}"
        )

        return None

    try:
        data = response.json()

    except Exception:
        log(
            "Odpověď není JSON."
        )

        log(
            response.text[:500]
        )

        return None

    if isinstance(data, dict):
        log(
            "TOP LEVEL KEYS:"
        )

        for key, value in data.items():
            log(
                f"  {key}: "
                f"{summarize_value(value)}"
            )

    else:
        log(
            f"TOP LEVEL TYPE: "
            f"{type(data).__name__}"
        )

    return data


def first_list(data):
    if not isinstance(data, dict):
        return None, []

    for key, value in data.items():
        if isinstance(value, list):
            return key, value

    return None, []


def show_first_items(data, max_items=3):
    key, items = first_list(data)

    if not items:
        log(
            "Žádný seznam položek."
        )
        return

    log("")
    log(
        f"LIST: {key}"
    )

    log(
        f"COUNT IN RESPONSE: "
        f"{len(items)}"
    )

    for index, item in enumerate(
        items[:max_items],
        start=1,
    ):
        log("")
        log(
            f"ITEM #{index}"
        )

        if isinstance(item, dict):
            for k, v in item.items():
                # Nechceme vypisovat možné secrets.
                name = k.lower()

                if any(
                    sensitive in name
                    for sensitive in (
                        "password",
                        "secret",
                        "token",
                        "apikey",
                        "api_key",
                        "key",
                    )
                ):
                    log(
                        f"  {k}: <REDACTED>"
                    )
                    continue

                log(
                    f"  {k}: "
                    f"{summarize_value(v)}"
                )

        else:
            log(
                f"  {summarize_value(item)}"
            )


def extract_library_codes(data):
    if not isinstance(data, dict):
        return []

    candidates = []

    for value in data.values():
        if not isinstance(value, list):
            continue

        for item in value:
            if not isinstance(item, dict):
                continue

            for key in (
                "code",
                "library_code",
                "value",
            ):
                if (
                    key in item
                    and item[key]
                ):
                    val = item[key]

                    if isinstance(val, dict):
                        val = val.get(
                            "value"
                        )

                    if val:
                        candidates.append(
                            str(val)
                        )
                        break

    return list(
        dict.fromkeys(candidates)
    )


def probe_simple(
    alma,
    label,
    path,
    params=None,
):
    response = alma.get(
        path,
        params=params,
    )

    data = show_json_shape(
        label,
        response,
    )

    if data is not None:
        show_first_items(
            data
        )

    return data


def main():
    cfg = load_config()

    alma = Alma(cfg)

    log(
        "Alma Configuration API probe"
    )

    log(
        "Citlivé hodnoty se nevypisují."
    )

    log("")

    libraries = probe_simple(
        alma,
        "LIBRARIES",
        "/conf/libraries",
    )

    library_codes = (
        extract_library_codes(
            libraries
        )
    )

    log("")
    log(
        "NALEZENÉ LIBRARY CODES:"
    )

    if library_codes:
        for code in library_codes:
            log(
                f"  {code}"
            )
    else:
        log(
            "  žádné"
        )

    for library_code in library_codes:
        safe = quote(
            library_code,
            safe="",
        )

        probe_simple(
            alma,
            (
                f"LIBRARY DETAIL "
                f"{library_code}"
            ),
            f"/conf/libraries/{safe}",
        )

        probe_simple(
            alma,
            (
                f"LOCATIONS "
                f"{library_code}"
            ),
            (
                f"/conf/libraries/"
                f"{safe}/locations"
            ),
        )

        probe_simple(
            alma,
            (
                f"CIRC DESKS "
                f"{library_code}"
            ),
            (
                f"/conf/libraries/"
                f"{safe}/circ-desks"
            ),
        )

    probe_simple(
        alma,
        "GENERAL CONFIGURATION",
        "/conf/general",
    )

    probe_simple(
        alma,
        "DEPARTMENTS",
        "/conf/departments",
        params={
            "view": "brief",
        },
    )

    probe_simple(
        alma,
        "INTEGRATION PROFILES",
        "/conf/integration-profiles",
        params={
            "limit": 100,
            "offset": 0,
        },
    )

    probe_simple(
        alma,
        "IMPORT PROFILES",
        "/conf/md-import-profiles",
    )

    probe_simple(
        alma,
        "PRINTERS",
        "/conf/printers",
        params={
            "limit": 100,
            "offset": 0,
        },
    )

    probe_simple(
        alma,
        "LETTERS",
        "/conf/letters",
    )

    probe_simple(
        alma,
        "NORMALIZATION RULES",
        "/conf/normalization-rules",
    )

    probe_simple(
        alma,
        "DEPOSIT PROFILES",
        "/conf/deposit-profiles",
    )

    probe_simple(
        alma,
        "RELATIONS",
        "/conf/relations",
    )

    log("")
    log("=" * 78)
    log("SOUHRN")
    log("=" * 78)

    log(
        f"API volání: "
        f"{alma.calls}"
    )

    log(
        f"X-Exl-Api-Remaining: "
        f"{alma.remaining or 'neuvedeno'}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )