# Changelog

## 1.2.0 - 2026-10-09
- Added Primo VE Configuration Events enrichment at the changed Mapping Table level.
- Added support for multiple authors (`NOVAK / SKOPEC`).
- Added `analytics_details_json` with Mapping Table → event → author → time details.
- Added `configuration_events_timezone`; default is `Europe/Prague`.
- Expanded accepted Mapping Table event descriptions and documented a 10-day Analytics report window.
- Updated web detail to display Analytics attribution for Primo Mapping Tables.
- Preserved conservative matching: no partial Primo attribution and no time-only guessing.

## 1.1.0 - 2026-10-03
- Added optional Code/Mapping Configuration Events enrichment.
- Added multilingual Code Table auditing and friendly Code Table labels.
- Added focused `--codetables` and `--extended` modes.

## 1.0.0 - 2026-10-02
- Stabilized Scheduled Jobs and added `--jobs`.

## 0.5.0 - 2026-10-01
- Stabilized Primo VE diffs, shared lock and SQLite operation.

## 0.4.0 - 2026-10-01
- Added Alma Analytics TOU, Policies, Fulfillment Rules and history import.

## 0.3.0 - 2026-09-30
- Added Primo VE View audit.

## 0.2.0 - 2026-09-29
- Added extended Alma configuration objects.

## 0.1.0 - 2026-09-25
- Initial Code/Mapping audit, SQLite history and PHP web.
