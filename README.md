# Alma / Primo VE / Analytics Configuration Audit

**Current version:** 1.2.1  
**Release date:** 2026-10-19

A portable configuration change audit for Ex Libris Alma, optionally Primo VE, with an Alma Analytics supplement for Fulfillment configuration that is not exposed by the public Configuration REST API.

**Česky:** [README.cs.md](README.cs.md)  
**GitHub:** https://github.com/skopeant/alma-config-audit

The package intentionally contains no API key, web credentials, systemd timer, or cron configuration. Scheduling and web access protection should be configured by the administrator of the target server.

## Included files

- `alma-config-audit.py` – main snapshot/diff audit for Alma and optionally Primo VE.
- `alma-config-audit-analytics.py` – supplementary Alma Analytics audit for Terms of Use, TOU Policies, and Fulfillment Rules; it can also enrich Code/Mapping and Primo VE changes with Configuration Events.
- `alma-config-probe.py` – diagnostic helper for available Alma Configuration API objects.
- `alma-config-discover-from-xlsx.py` – helper for extracting Code/Mapping Table names from an Alma Analytics System Events export.
- `alma-config-audit.conf.example` – shared configuration template without an API key.
- `examples/alma-config-audit-discover.txt.example` – example list of additional tables for discovery.
- `web/` – PHP interface over the shared SQLite database. The detail page recursively expands nested JSON, supports Analytics history, and displays event time/user. Since 1.2.0 it can also show Analytics events attributed to individual changed Primo VE Mapping Tables.

### Web configuration

The web interface works immediately with the safe defaults in `web/config.php.example`. For a local installation, copy it to `web/config.php` and adjust the values as needed. `web/config.php` is ignored by Git, so local settings are not committed.
- `documentation/index.html` – short solution overview.
- `documentation/screenshots/` – screenshots from the reference installation.
- `LICENSE` – MIT License.
- `requirements.txt` – Python dependency (`requests`).

## Architecture

The main audit and Analytics audit are separate scripts, but they share:

- one configuration file, `/etc/alma-config-audit.conf`,
- one SQLite database,
- one process lock,
- one web interface.

Both scripts use SQLite WAL + `busy_timeout` and a shared advisory lock. If they are started at the same time, the second process waits; an additional `flock` wrapper around systemd `ExecStart` is therefore unnecessary.

## Alma REST API coverage

The main script audits, among other objects:

- Code Tables and Mapping Tables,
- Libraries and library details,
- Locations,
- Circulation Desks and their details,
- General Configuration,
- institution Departments,
- library Departments,
- Integration Profiles,
- Import Profiles,
- Printers,
- Letters,
- Normalization Rules,
- Deposit Profiles,
- Scheduled Jobs.

### Multilingual Code Tables

Alma Code Tables can have separate translations for institution languages. The Alma API supports the `lang` parameter; without it, only the institution default language is returned. To audit translations as well, configure for example:

```ini
[audit]
code_table_languages = cs,en
```

Each language variant is then stored independently, for example `UserGroups [cs]` and `UserGroups [en]`. When multilingual auditing is enabled for the first time, the previous single-language baseline is removed silently so that the keying change itself does not create false history.

If `code_table_languages` is empty, the original behavior is preserved and only the institution default language is loaded. Each additional language adds approximately one API request per Code Table.

### Scheduled Jobs

Operational or unstable values `id`, `link`, `next_run`, `creator`, and the textual `schedule.desc` are intentionally ignored. Stable job identity is built from:

```text
category.value + type.value + name + schedule.value
```

This distinguishes jobs with the same name while avoiding false changes caused by regenerated internal IDs. Scheduled Jobs can be checked separately with `--jobs`.

The **Active / Inactive** state of Fulfillment Scheduled Jobs is not exposed by the public Alma Jobs API and is therefore not audited in this version.

## Terms of Use and Fulfillment Rules via Alma Analytics

Some Fulfillment configuration is not available through the public Alma Configuration REST API. The optional `alma-config-audit-analytics.py` script reads custom Alma Analytics analyses.

### Important: Repeat Values

For **all columns** in all Analytics analyses used by this tool, enable **Repeat Values**. This applies to:

- `API_conf_TOU_Policies`,
- `API_conf_Rule`,
- the optional Configuration Events analysis (named `API_conf_USER` in the reference installation).

The script treats every exported row as a complete record. If Analytics suppresses repeated values and leaves subsequent cells blank, context such as `TOU ID`, `Rule ID`, `Event Id`, `Event Description`, or `Event Creator` may be lost. The tool intentionally does not fill blank cells from the previous row.

### TOU + Policies analysis

Required columns:

```text
TOU ID
TOU Type
TOU Description
TOU Creation Date
TOU Modification Date
TOU Creator
TOU Modified By
Policy ID
Policy Type
Policy Name
Policy Description
Policy Unit of Measurement
Policy Value
Policy Constant
Policy Additional Data
Policy Active
Policy Is Default Value
Policy Creation Date
Policy Modification Date
Policy Creator
Policy Modified By
```

The script creates objects of type `tou` and `tou_policy`. A policy is identified by `TOU ID / Policy ID` so that the same Policy ID in different TOU contexts is not merged into one object.

### Fulfillment Rules analysis

Required columns:

```text
Rule ID
Rule Name
Rule Type
Is Default
Is Active
Rule Creation Date
Rule Modification Date
Rule Creator
Rule Modified By
Rule Parameter ID
Rule Parameter Key
Rule Parameter Modification Date
Rule Parameter Modified By
Rule Parameter Value
Operator Name
```

The script creates objects of type `fulfillment_rule`.

### Analytics configuration

Example:

```ini
[analytics]
enabled = true
tou_policies_path = /shared/Your Institution/API/API_conf_TOU_Policies
rules_path = /shared/Your Institution/API/API_conf_Rule
limit = 1000
```

The API key must also have permission to use the Alma Analytics API.

Normal run:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py
```

The first run creates a baseline. Subsequent runs store real `Before → After` changes. `Modification Date / Modified By` metadata is used as change time/user, but metadata-only changes do not create a configuration diff.

## Friendly Code Table names in the web UI

The technical Code Table name returned by the API remains the stable internal key (for example `JobTitles`), while the web UI can display the description returned by the Configuration API (for example `Job Categories`). Labels are stored in the auxiliary `object_label` table. The web UI is backward-compatible: if an older database does not contain `object_label`, it falls back to the technical name.

## Optional Configuration Events enrichment

A custom Alma Analytics analysis over **System Events / Configuration** can enrich already captured local Code Table, Mapping Table, and Primo VE changes with the user and a more precise event time.

The feature is disabled until `configuration_events_path` is configured. Installations without this report continue to work as before and make no additional Configuration Events API request.

Required columns:

```text
Event Category
Event Creator
Event Key Name
Event Key Value
Event Module
Event Type
Event Sub Module
Event Description
Event Id
Event Date
Event Date and Time
```

Enable **Repeat Values** for all columns. Column order does not matter.

Recommended `Event Description` filter values:

```text
Code table updated
Mapping table updated
mapping table customized
mapping table restoration
mapping table row customized
mapping table row restored
```

Recommended 10-day time filter:

```sql
"Event Date"."Event Date and Time" >= TIMESTAMPADD(SQL_TSI_DAY, -10, CURRENT_DATE)
```

Recommended sorting:

1. `Event Date and Time` – descending,
2. `Event Id` – additional descending sort,
3. `Event Key Name` – additional ascending sort.

Example:

```ini
[analytics]
enabled = true
tou_policies_path = /shared/Your Institution/API/API_conf_TOU_Policies
rules_path = /shared/Your Institution/API/API_conf_Rule
configuration_events_path = /shared/Your Institution/API/API_conf_USER
configuration_events_match_minutes = 360
configuration_events_timezone = Europe/Prague
limit = 1000
```

Matching is deliberately conservative. Code/Mapping Table enrichment requires a matching `TABLE_NAME` and an event within the allowed window **before** local audit detection. Primo VE enrichment first identifies the Mapping Tables actually changed inside the View; every changed Mapping Table must have a matching Configuration Event. If any table cannot be explained, the Primo author is left blank rather than partially attributed. Events are never assigned by time proximity alone.

If several authors are involved, the summary is preserved, for example `NOVAK / SKOPEC`. Exact Mapping Table → event → author → time associations are stored in `analytics_details_json`.

`Event Date and Time` from Configuration Events does not contain timezone information. `configuration_events_timezone` specifies the local timezone in which that value must be interpreted. If the parameter is missing or empty, the script uses `Europe/Prague`. Historical `Modification Date` values from TOU/Policies/Fulfillment Rules are not affected by this setting.

### Primo VE enrichment

Since version 1.2.0, Configuration Events can safely enrich locally captured `primo_view` changes. The script compares Before/After, identifies changed tables under `configuration.mapping-tables.*`, normalizes their names, and matches them against Analytics `TABLE_NAME` values.

The web detail can display author/time information at the **Mapping Table level**. This does not claim authorship of an individual inner row when Analytics only proves that the Mapping Table was changed.

Run only Configuration Events enrichment:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py --enrich-configuration-events
```

During a normal Analytics audit, enrichment runs automatically only when `configuration_events_path` is non-empty. Failure of this optional report is treated as a warning and does not break the TOU / Policies / Fulfillment Rules audit.

## One-time history import

Run manually:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py --import-history
```

This mode is intended for initial history population or after a longer Analytics audit outage. It can add the latest known change from current Analytics data using `Modification Date / Modified By` as `HISTORY_MODIFIED`. If an older local snapshot with a different value exists, it can be used as the real `Before`; otherwise the historical event is shown without inventing an unknown previous value.

The mode is idempotent and repeated execution should not create duplicate historical events.

## Primo VE audit

Primo VE auditing is optional. For every configured VID, configuration is loaded through the Primo Configuration API and stored as a `primo_view` object.

This can capture changes in Search Profiles / Scopes, tabs, Advanced Search, Brief/Full Record configuration, View Properties, feature flags, authentication, and customization configuration exposed by the API.

The Primo Configuration API does not reliably list all Views, so VIDs are configured manually.

## Known limitations and intentional exclusions

### Library Open Hours

`Library Open Hours` are intentionally not audited. The endpoint returns a rolling calendar of specific dates, which would create daily false `OBJECT_UPDATED` changes without any administrator action.

### Integration Profile operational parameters

`lastProcessDirectory` is ignored globally because it is an operational value from the last integration process run rather than a configuration change.

### ILL_EMAIL_TO_USER

In the reference environment, `ILL_EMAIL_TO_USER` appears in the Letters list but its detail endpoint is unavailable. The script uses the summary and continues; the diagnostic message is not a run failure.

### Analytics latency and history

Alma Analytics data is available after ETL, so a change may not appear immediately. The Analytics script is therefore normally scheduled less frequently than the REST audit, for example once per day after Analytics refresh.

A current Analytics snapshot usually contains the current state and the latest `Modification Date / Modified By`, not every historical version. Missing intermediate states cannot be reconstructed unless they were captured by a local snapshot.

## API usage

API consumption depends on the institution. In the reference installation, a full main audit is approximately:

```text
Alma REST API:            ~643
Primo Configuration API: 3
Main run total:           ~646
```

The TOU/Policies and Fulfillment Rules Analytics reports each normally require one API request when they contain fewer than 1000 rows. Enabling Configuration Events normally adds another Analytics request. Larger reports use resumption-token pagination.

With multilingual Code Tables such as `code_table_languages = cs,en`, each additional language adds approximately one GET request per Code Table. With about 196 Code Tables, a second language therefore adds roughly 196 API requests to a full main run.

## Focused test modes

A full audit is not required for every test:

```bash
python3 /opt/alma-config-audit/alma-config-audit.py --codetables
python3 /opt/alma-config-audit/alma-config-audit.py --extended
python3 /opt/alma-config-audit/alma-config-audit.py --primo
python3 /opt/alma-config-audit/alma-config-audit.py --jobs
```

`--codetables` checks only Code Tables including configured languages. `--extended` checks only extended Alma configuration.

## Version history

- **1.2.1 (2026-10-19)** – fixed false Primo VE `OBJECT_UPDATED` events caused by non-deterministic row ordering in the `Rapido Self Registration Optional Parameters` Mapping Table; real value changes remain detectable.
- **1.2.0 (2026-10-09)** – Primo VE Configuration Events enrichment at changed Mapping Table level, multiple authors, `analytics_details_json`, correct local-time interpretation via `configuration_events_timezone`, expanded Mapping Table event types, recommended 10-day report window, and Primo Analytics details in the web UI.
- **1.1.0 (2026-10-03)** – optional Code/Mapping Configuration Events enrichment, documented Analytics Repeat Values/filters/sorting, multilingual Code Tables via `code_table_languages`, friendly Code Table labels, and focused `--codetables` / `--extended` modes.
- **1.0.0** – Scheduled Jobs stabilization, `--jobs`, operational-noise filtering, and clearer Integration Profile display.
- **0.5.0** – Primo VE diff stabilization, shared lock/SQLite WAL, and improved web diffs.
- **0.4.0** – Alma Analytics for Terms of Use, TOU Policies, Fulfillment Rules, and history import.
- **0.3.0** – Primo VE View audit through the Primo Configuration API.
- **0.2.0** – extended Alma configuration objects.
- **0.1.0** – initial Code/Mapping audit, SQLite history, Before/After, and PHP web UI.

## License

MIT. See [LICENSE](LICENSE).
