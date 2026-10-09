#!/usr/bin/env python3
"""Extract likely Alma configuration table names from an Analytics XLSX/CSV export.

The script uses only the Python standard library. It looks either for a TABLE_NAME
column or for rows where Event Key Name == TABLE_NAME and then reads Event Key Value.
"""

import csv
import os
import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main", "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
REL_NS = {"p": "http://schemas.openxmlformats.org/package/2006/relationships"}


def col_index(cell_ref):
    letters = re.match(r"[A-Z]+", cell_ref).group(0)
    result = 0
    for c in letters:
        result = result * 26 + (ord(c) - 64)
    return result - 1


def read_xlsx(path):
    sheets = []
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("a:si", NS):
                shared.append("".join(t.text or "" for t in si.findall(".//a:t", NS)))

        workbook = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        relmap = {x.attrib["Id"]: x.attrib["Target"] for x in rels.findall("p:Relationship", REL_NS)}

        for sheet in workbook.findall("a:sheets/a:sheet", NS):
            name = sheet.attrib.get("name", "Sheet")
            rid = sheet.attrib.get("{%s}id" % NS["r"])
            target = relmap[rid]
            if not target.startswith("xl/"):
                target = "xl/" + target.lstrip("/")
            root = ET.fromstring(z.read(target))
            rows = []
            for row in root.findall(".//a:sheetData/a:row", NS):
                values = {}
                for c in row.findall("a:c", NS):
                    idx = col_index(c.attrib["r"])
                    cell_type = c.attrib.get("t")
                    v = c.find("a:v", NS)
                    text = ""
                    if cell_type == "inlineStr":
                        text = "".join(t.text or "" for t in c.findall(".//a:t", NS))
                    elif v is not None:
                        raw = v.text or ""
                        if cell_type == "s" and raw.isdigit():
                            text = shared[int(raw)]
                        else:
                            text = raw
                    values[idx] = text
                if values:
                    width = max(values) + 1
                    rows.append([values.get(i, "") for i in range(width)])
            sheets.append((name, rows))
    return sheets


def read_csv_file(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t,")
        return [(Path(path).name, list(csv.reader(f, dialect)))]


def norm(s):
    return re.sub(r"\s+", " ", str(s or "").strip()).lower()


def extract(rows):
    if not rows:
        return set(), 0
    header = rows[0]
    h = {norm(name): i for i, name in enumerate(header)}
    result = set()
    config_rows = 0

    def get(row, name):
        i = h.get(norm(name))
        return row[i].strip() if i is not None and i < len(row) else ""

    direct = h.get("table_name")
    if direct is not None:
        for row in rows[1:]:
            if direct < len(row) and row[direct].strip():
                result.add(row[direct].strip())
                config_rows += 1
        return result, config_rows

    if "event key name" in h and "event key value" in h:
        for row in rows[1:]:
            module = get(row, "Event Module")
            submodule = get(row, "Event Sub Module")
            if module and norm(module) != "administration":
                continue
            if submodule and norm(submodule) != "configuration":
                continue
            if norm(get(row, "Event Key Name")) == "table_name":
                value = get(row, "Event Key Value")
                if value:
                    result.add(value)
                    config_rows += 1
    return result, config_rows


def main():
    if len(sys.argv) < 2:
        print(f"Použití: {sys.argv[0]} export.xlsx [vystup.txt]", file=sys.stderr)
        return 2
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(src)), "alma-config-audit-discover.txt")

    sheets = read_csv_file(src) if src.lower().endswith(".csv") else read_xlsx(src)
    names = set()
    rows_total = 0
    header_sheets = 0
    for _, rows in sheets:
        found, count = extract(rows)
        if rows:
            header_sheets += 1
        names |= found
        rows_total += count

    with open(out, "w", encoding="utf-8") as f:
        for name in sorted(names):
            f.write(name + "\n")

    print(f"Listů nalezeno: {len(sheets)}")
    print(f"Listů s hlavičkou: {header_sheets}")
    print(f"Řádků konfigurace: {rows_total}")
    print(f"TABLE_NAME nalezeno: {len(names)}")
    for name in sorted(names):
        print(name)
    print(f"Výstup: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
