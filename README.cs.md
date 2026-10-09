# Alma / Primo VE / Analytics Configuration Audit

**Aktuální verze:** 1.2.0  
**Datum vydání:** 2026-10-09

Přenositelný balíček pro průběžný audit změn konfigurace Ex Libris Alma, volitelně Primo VE a doplňkově Alma Analytics pro části Fulfillment konfigurace, které veřejné Configuration REST API neposkytuje.

**GitHub:** https://github.com/skopeant/alma-config-audit

Balíček je záměrně bez API klíče, bez přihlašování k webu a bez systemd timeru nebo cronu. Způsob plánování spouštění a zabezpečení webu si nastaví správce cílového serveru podle svého prostředí.

## Co balíček obsahuje

- `alma-config-audit.py` – hlavní snapshot/diff audit Alma + volitelně Primo VE.
- `alma-config-audit-analytics.py` – doplňkový audit nad Alma Analytics pro Terms of Use, TOU Policies a Fulfillment Rules.
- `alma-config-probe.py` – diagnostika dostupných Alma Configuration API objektů.
- `alma-config-discover-from-xlsx.py` – pomocný skript pro získání názvů Code/Mapping Tables z exportu Alma Analytics System Events.
- `alma-config-audit.conf.example` – společný vzor konfigurace bez API klíče.
- `examples/alma-config-audit-discover.txt.example` – vzor seznamu dodatečných tabulek pro discovery.
- `web/` – PHP rozhraní nad společnou SQLite databází. Detail změny umí rekurzivně rozpadnout vnořený JSON, pracuje i s Analytics historií a zobrazuje čas/uživatele změny. Od verze 1.2.0 umí u Primo VE zobrazit také Analytics události přiřazené ke konkrétní změněné Mapping Table.

### Konfigurace webu

Webové rozhraní funguje ihned s bezpečnými výchozími hodnotami z `web/config.php.example`. Pro místní instalaci jej zkopírujte jako `web/config.php` a podle potřeby upravte hodnoty. Soubor `web/config.php` Git ignoruje, takže lokální nastavení se necommitne.
- `documentation/index.html` – stručný popis řešení.
- `documentation/screenshots/` – ukázky z referenčního provozu.
- `LICENSE` – licence MIT.
- `requirements.txt` – Python závislost `requests`.

## Architektura

Hlavní a Analytics audit jsou dva samostatné skripty, ale používají:

- jeden konfigurační soubor `/etc/alma-config-audit.conf`,
- jednu SQLite databázi,
- jeden společný process lock,
- stejné webové rozhraní.

Oba skripty používají SQLite WAL + `busy_timeout` a společný advisory lock. Pokud jsou spuštěny současně, druhý proces počká; není proto nutné obalovat systemd `ExecStart` dalším `flock`.

## Co audit sleduje přes Alma REST API

Hlavní skript sleduje zejména:

- Code Tables a Mapping Tables,
- Libraries a jejich detail,
- Locations,
- Circulation Desks a jejich detail,
- General Configuration,
- institucionální Departments,
- Departments jednotlivých knihoven,
- Integration Profiles,
- Import Profiles,
- Printers,
- Letters,
- Normalization Rules,
- Deposit Profiles,
- Scheduled Jobs.

### Vícejazyčné Code Tables

Alma Code Tables mohou mít samostatné překlady pro jednotlivé jazyky instituce. Alma API podporuje parametr `lang`; bez něj vrací pouze výchozí jazyk instituce. Pokud chcete auditovat i překlady, nastavte například:

```ini
[audit]
code_table_languages = cs,en
```

Pak se každá Code Table ukládá jako samostatná jazyková varianta, například `UserGroups [cs]` a `UserGroups [en]`. Změna českého překladu se tak zaznamená nezávisle na anglické variantě. Při prvním zapnutí se staré jednojazyčné baseline odstraní **tiše**, aby změna způsobu klíčování sama nevytvořila falešnou historii.

Pokud je `code_table_languages` prázdné, zachová se původní chování a načítá se pouze výchozí jazyk instituce. Každý další jazyk znamená přibližně jedno další API volání na každou Code Table.

U Scheduled Jobs se záměrně ignorují provozní nebo nestabilní hodnoty `id`, `link`, `next_run`, `creator` a textový popis `schedule.desc`. Stabilní identita jobu se skládá z `category.value + type.value + name + schedule.value`; tím se rozlišují i joby se stejným názvem a zároveň se eliminují falešné změny způsobené přegenerováním interních ID. Pro rychlou kontrolu lze spustit pouze Scheduled Jobs pomocí `--jobs`.

Stav **Active / Inactive** u Fulfillment Scheduled Jobs veřejné Alma Jobs API nevrací. V Alma UI je veden odděleně od `schedule.value`, proto se v této verzi neaudituje.

## Terms of Use a Fulfillment Rules přes Alma Analytics

### Důležité nastavení Analytics: opakování hodnot

Ve **všech třech Analytics analýzách** používaných tímto nástrojem musí být u **všech sloupců zapnuté opakování hodnot (Repeat Values)**:

- `API_conf_TOU_Policies`,
- `API_conf_Rule`,
- volitelná Configuration Events analýza (na ČVUT `API_conf_USER`).

Skript zpracovává každý exportovaný řádek jako samostatný úplný záznam. Pokud Analytics potlačí opakující se hodnoty a v dalších řádcích je nechá prázdné, může chybět kontext například `TOU ID`, `Rule ID`, `Event Id`, `Event Description` nebo `Event Creator`. Nástroj proto záměrně nedoplňuje prázdné buňky hodnotou z předchozího řádku.

Doporučení: v nastavení každého sloupce analýzy nastavte **Repeat Values / Opakovat hodnoty**.


Některé části Fulfillment konfigurace nejsou dostupné přes veřejné Alma Configuration REST API. Proto lze zapnout druhý skript `alma-config-audit-analytics.py`, který čte dvě vlastní Alma Analytics analýzy.

### Analýza TOU + Policies

Analýza musí vracet tyto sloupce:

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

Skript z nich vytváří objekty typu:

```text
tou
tou_policy
```

Policy je identifikována kombinací `TOU ID / Policy ID`, aby se stejné Policy ID v různém TOU kontextu neslilo do jednoho objektu.

### Analýza Fulfillment Rules

Analýza musí vracet:

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

Skript z nich vytváří objekty typu:

```text
fulfillment_rule
```

### Analytics konfigurace

Do společného INI se doplní například:

```ini
[analytics]
enabled = true
tou_policies_path = /shared/Your Institution/API/API_conf_TOU_Policies
rules_path = /shared/Your Institution/API/API_conf_Rule
limit = 1000
```

API key musí mít také oprávnění k Alma Analytics API.

Běžný běh:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py
```

První běh pouze vytvoří baseline. Další běhy ukládají skutečné `Before → After`. Metadata `Modification Date / Modified By` se používají jako čas a uživatel změny, ale jejich samotná změna nevytváří konfigurační diff.

### Uživatelské názvy Code Tables ve webu

Technický název Code Table z API zůstává stabilním interním klíčem (např. `JobTitles`), ale web může zobrazit popis vrácený Configuration API (např. `Job Categories`). Popisky se ukládají do pomocné tabulky `object_label`. Web je zpětně kompatibilní: pokud starší databáze `object_label` nemá, automaticky použije technický název.

### Volitelné doplnění uživatele změny z Configuration Events

Pokud je v Alma Analytics vytvořena analýza nad **System Events / Configuration**, lze jí volitelně doplnit uživatele a přesnější čas k již zachyceným lokálním změnám Code Tables a Mapping Tables.

Funkce je záměrně **vypnutá, dokud není v konfiguraci nastaven `configuration_events_path`**. Instalace, která tento Analytics report nemá, tedy funguje stejně jako dříve a neprovede žádné dodatečné API volání.

Požadované sloupce analýzy:

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

U **všech sloupců** této analýzy nastavte `Repeat Values / Opakování hodnot`. Pořadí sloupců není pro skript důležité.

Doporučené filtry:

- `Event Description` hodnoty `Code table updated`, `Mapping table updated`, `mapping table customized`, `mapping table restoration`, `mapping table row customized` a `mapping table row restored`,
- čas za posledních 10 dní pomocí rozšířeného SQL filtru:

```sql
"Event Date"."Event Date and Time" >= TIMESTAMPADD(SQL_TSI_DAY, -10, CURRENT_DATE)
```

Doporučené řazení (není funkčně nutné):

1. `Event Date and Time` – **Seřadit sestupně**,
2. `Event Id` – **Přidat sestupné řazení**,
3. `Event Key Name` – **Přidat vzestupné řazení**.

Příklad konfigurace:

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

Matching je konzervativní. U Code/Mapping Tables se vyžaduje odpovídající `TABLE_NAME` a událost v povoleném časovém okně před detekcí auditem. U Primo VE se z Before/After nejprve určí konkrétní změněné Mapping Tables uvnitř View a každá z nich musí mít odpovídající Configuration Event; pokud některá chybí, autor se nedoplní. Více autorů se zachová jako souhrn (např. `NOVAK / SKOPEC`) a přesná vazba Mapping Table → event → autor → čas se ukládá do `analytics_details_json`. Události se nepřiřazují pouze podle časové blízkosti.

`Event Date and Time` z Configuration Events neobsahuje informaci o časovém pásmu. Parametr `configuration_events_timezone` určuje, v jakém lokálním pásmu se má hodnota interpretovat; pokud parametr chybí nebo je prázdný, skript používá `Europe/Prague`. Historické `Modification Date` z TOU/Policies/Fulfillment Rules se tímto nastavením nemění.

### Primo VE enrichment z Configuration Events

Od verze 1.2.0 lze Configuration Events použít také pro bezpečné doplnění autora k lokálně zachyceným změnám `primo_view`. Skript porovnává Before/After, určí změněné tabulky pod `configuration.mapping-tables.*` a páruje je s Analytics `TABLE_NAME` po normalizaci názvu. Pokud je změněných tabulek více, musí být doloženy všechny. Web může z `analytics_details_json` zobrazit autora a časy na úrovni příslušné Mapping Table; nejde o tvrzení o autorství jednotlivého vnitřního řádku.

Samostatný test enrichmentu bez TOU/Fulfillment auditu:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py --enrich-configuration-events
```

Při běžném Analytics auditu se enrichment spustí automaticky pouze tehdy, když `configuration_events_path` není prázdný. Chyba tohoto volitelného reportu je pouze varování a nerozbije audit TOU / Policies / Fulfillment Rules.

### Jednorázový historický import

Ručně lze spustit:

```bash
python3 /opt/alma-config-audit/alma-config-audit-analytics.py --import-history
```

Tento režim je určen:

- pro jednorázové naplnění historie při prvním nasazení,
- případně po delším výpadku Analytics auditu.

Z aktuálních Analytics dat umí doplnit poslední známou změnu podle `Modification Date / Modified By` jako `HISTORY_MODIFIED`. Pokud před spuštěním existuje starší lokální snapshot s jinou hodnotou, lze jej použít jako skutečné `Before`; jinak se historická událost zobrazí korektně bez neznámé předchozí hodnoty.

Režim je idempotentní a opakované spuštění nemá vytvářet stejné historické události znovu.

## Audit Primo VE

Primo VE audit je volitelný. Pro každý zadaný VID se načítá konfigurace přes Primo Configuration API a ukládá se jako objekt `primo_view`.

Zachytit lze například změny Search Profiles / Scopes, tabů, Advanced Search, Brief/Full Record konfigurace, View Properties, feature flags, autentizace a customization.

Primo Configuration API neumí spolehlivě vypsat všechny Views, proto se VID zadávají ručně.

## Výjimky a známá omezení

### Library Open Hours

`Library Open Hours` se záměrně neauditují. Endpoint vrací klouzavý kalendář konkrétních dnů, takže by bez ruční změny vznikaly každodenní falešné `OBJECT_UPDATED`.

### Provozní parametry integračních profilů

Parametr `lastProcessDirectory` se ignoruje globálně, protože jde o technický údaj posledního běhu integračního procesu a jeho automatická změna není změnou konfigurace.

### ILL_EMAIL_TO_USER

V referenčním prostředí se `ILL_EMAIL_TO_USER` objeví v seznamu Letters, ale detail endpoint není dostupný. Skript použije summary a pokračuje. Diagnostická hláška není chybou běhu.

### Analytics

Alma Analytics pracují s daty po ETL, takže změna nemusí být dostupná okamžitě. Analytics skript je proto vhodné plánovat méně často než hlavní REST audit, například jednou denně po aktualizaci Analytics dat.

Dnešní Analytics snapshot obvykle obsahuje aktuální stav a poslední `Modification Date / Modified By`, nikoli kompletní historické verze každé hodnoty. Proto nelze zpětně dopočítat neexistující mezistavy, pokud nebyly zachyceny lokálním snapshotem.

## API spotřeba

Spotřeba závisí na instituci. V referenční instalaci je hlavní kompletní běh přibližně:

```text
Alma REST API:            cca 643
Primo Configuration API: 3
Celkem hlavní běh:        cca 646
```

Analýzy TOU/Policies a Fulfillment Rules při méně než 1000 řádcích obvykle spotřebují po jednom API požadavku. Pokud je zapnutý Configuration Events enrichment, přidá se zpravidla další Analytics API požadavek. Při větších reportech se použije stránkování přes resumption token.

Pokud zapnete vícejazyčné Code Tables pomocí například `code_table_languages = cs,en`, každý další jazyk přidá přibližně jedno GET volání na každou Code Table. V referenční instalaci s cca 196 Code Tables tedy druhý jazyk znamená zhruba +196 API volání na kompletní hlavní běh.

## Historie verzí

- **1.2.0 (2026-10-09)** – enrichment Primo VE změn z Analytics Configuration Events na úrovni konkrétních Mapping Tables, podpora více autorů, `analytics_details_json`, správná interpretace lokálního času přes `configuration_events_timezone`, rozšířené typy Mapping Table eventů, 10denní doporučené okno reportu a zobrazení Primo Analytics detailů ve webu.
- **1.1.0 (2026-10-03)** – volitelný enrichment Code/Mapping změn z Analytics Configuration Events (`API_conf_USER` na ČVUT), dokumentované Repeat Values/filtry/řazení Analytics, vícejazyčný audit Code Tables přes `code_table_languages` (např. `cs,en`), přívětivé názvy Code Tables z API a rychlé testovací režimy `--codetables` a `--extended`.
- **0.1.0** – základní audit Code/Mapping Tables, SQLite, Before/After a PHP web.
- **0.2.0** – rozšířená konfigurace Almy (knihovny, lokace, oddělení, profily, tiskárny, dopisy a další objekty).
- **0.3.0** – audit Primo VE Views přes Primo Configuration API.
- **0.4.0** – Alma Analytics pro Terms of Use, TOU Policies a Fulfillment Rules + historický import.
- **0.5.0** – stabilizace diffů, společný lock/SQLite WAL a přesnější webové zobrazení.
- **1.0.0** – stabilizace Scheduled Jobs, režim `--jobs`, odfiltrování provozního šumu a přehlednější Integration Profiles.

### Názvy Code Tables ve webu

Audit používá jako stabilní technický klíč název Code Table z API (např. `JobTitles`), ale pro zobrazení ve webu ukládá obecný popis vrácený endpointem `GET /conf/code-tables` / detailem Code Table. Není tedy potřeba ručně mapovat jednotlivé interní názvy na názvy z Alma UI; pokud API poskytuje popis, web jej použije automaticky.

## Rychlé testovací režimy

Pro ověřování změn není nutné vždy spouštět celý audit:

```bash
python3 /opt/alma-config-audit/alma-config-audit.py --codetables
python3 /opt/alma-config-audit/alma-config-audit.py --extended
python3 /opt/alma-config-audit/alma-config-audit.py --primo
python3 /opt/alma-config-audit/alma-config-audit.py --jobs
```

`--codetables` kontroluje pouze Code Tables včetně nastavených jazyků. `--extended` kontroluje pouze rozšířenou Alma konfiguraci.

