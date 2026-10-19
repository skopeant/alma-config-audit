<?php

declare(strict_types=1);

$configFile = __DIR__ . '/config.php';

if (is_file($configFile)) {
    require $configFile;
} else {
    require __DIR__ . '/config.php.example';
}

date_default_timezone_set(AUDIT_TIMEZONE);

function h($value): string
{
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

function jsonData(?string $value)
{
    if ($value === null || $value === '') {
        return null;
    }

    $decoded = json_decode($value, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        return null;
    }

    return $decoded;
}


function displayObjectName(array $row, $before, $after): string
{
    if (($row['object_type'] ?? '') === 'integration_profile') {
        foreach ([$after, $before] as $payload) {
            if (!is_array($payload)) {
                continue;
            }

            $name = trim((string)($payload['name'] ?? ''));
            $code = trim((string)($payload['code'] ?? ''));

            if ($name !== '' && $code !== '') {
                return $name . ' (' . $code . ')';
            }

            if ($name !== '') {
                return $name;
            }

            if ($code !== '') {
                return $code;
            }
        }
    }

    $displayName = trim((string)($row['display_name'] ?? ''));
    if ($displayName !== '') {
        return $displayName;
    }

    return (string)($row['object_name'] ?? '—');
}


function formatDetected(?string $value): string
{
    if (!$value) {
        return '—';
    }

    try {
        $dt = new DateTimeImmutable($value);
        return $dt
            ->setTimezone(new DateTimeZone(AUDIT_TIMEZONE))
            ->format('d.m.Y H:i:s');
    } catch (Throwable $e) {
        return $value;
    }
}

function extractUser(array $row, $before, $after): string
{
    if (!empty($row['analytics_user'])) {
        return (string)$row['analytics_user'];
    }

    foreach ([$after, $before] as $payload) {
        if (!is_array($payload)) {
            continue;
        }

        if (!empty($payload['updated_by'])) {
            return (string)$payload['updated_by'];
        }

        if (!empty($payload['operator']) && is_string($payload['operator'])) {
            return (string)$payload['operator'];
        }
    }

    return '—';
}

function isAssoc(array $array): bool
{
    if ($array === []) {
        return false;
    }

    return array_keys($array) !== range(0, count($array) - 1);
}

function valuesIdentical($a, $b): bool
{
    return $a === $b;
}

function valueType($value): string
{
    if ($value === null) {
        return 'null';
    }

    if (is_bool($value)) {
        return 'bool';
    }

    if (is_int($value) || is_float($value)) {
        return 'number';
    }

    if (is_string($value)) {
        return 'string';
    }

    if (is_array($value)) {
        return isAssoc($value) ? 'object' : 'array';
    }

    return gettype($value);
}

/*
 * Rekurzivní diff JSON.
 *
 * Důležitá vlastnost:
 * - pokud celý objekt/klíč přibyl nebo zmizel, nevypisujeme stovky jeho
 *   podřízených položek; zobrazíme jej jako jednu změnu,
 * - pokud existoval před i po, jdeme dovnitř a ukážeme přesnou cestu,
 * - jednoduché seznamy hodnot zobrazíme jako jednu změnu a zvlášť umíme
 *   vypsat přidané/odebrané hodnoty.
 */

/*
 * Stabilní klíč pro seznam řádků Primo mapping tables.
 *
 * Primo API vrací mapping tables jako seznam objektů:
 * source1...source6 + target. Pro audit je "source*" identita řádku
 * a "target" typicky jeho hodnota. Díky tomu umíme místo dvou dlouhých
 * JSON seznamů ukázat například:
 *
 *   View Properties [enable_recent_scopes].target   false -> true
 */
function mappingRowIdentity(array $row): ?string
{
    $parts = [];

    for ($i = 1; $i <= 6; $i++) {
        $key = 'source' . $i;

        if (
            array_key_exists($key, $row)
            && $row[$key] !== null
            && (string)$row[$key] !== ''
        ) {
            $parts[$key] = (string)$row[$key];
        }
    }

    if (!$parts) {
        return null;
    }

    return (string)json_encode(
        $parts,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );
}

function mappingRowLabel(array $row): string
{
    $parts = [];

    /*
     * source1 bývá často VID a na stránce už ho vidíme jako název
     * objektu. Pokud existuje source2, je pro člověka obvykle
     * nejvýstižnější (např. enable_recent_scopes).
     */
    for ($i = 2; $i <= 6; $i++) {
        $key = 'source' . $i;

        if (
            array_key_exists($key, $row)
            && $row[$key] !== null
            && (string)$row[$key] !== ''
        ) {
            $parts[] = (string)$row[$key];
        }
    }

    if (!$parts && isset($row['source1'])) {
        $parts[] = (string)$row['source1'];
    }

    if (!$parts) {
        return 'řádek';
    }

    return implode(' | ', $parts);
}

function mappingRowsByIdentity(array $rows): ?array
{
    $result = [];

    foreach ($rows as $row) {
        if (!is_array($row) || !isAssoc($row)) {
            return null;
        }

        $identity = mappingRowIdentity($row);

        if ($identity === null) {
            return null;
        }

        /*
         * Pokud by měla tabulka duplicitní identitu source1...source6,
         * nepokoušíme se ji "chytře" párovat. Bezpečně spadneme na
         * původní zobrazení celého seznamu.
         */
        if (array_key_exists($identity, $result)) {
            return null;
        }

        $result[$identity] = $row;
    }

    return $result;
}


function parameterRowIdentity(array $row): ?string
{
    $name = $row['name'] ?? null;

    if (!is_array($name)) {
        return null;
    }

    $nameValue = trim((string)($name['value'] ?? ''));

    if ($nameValue === '') {
        return null;
    }

    $actionValue = '';

    if (
        isset($row['action'])
        && is_array($row['action'])
    ) {
        $actionValue = trim(
            (string)($row['action']['value'] ?? '')
        );
    }

    return $actionValue . '|' . $nameValue;
}

function parameterRowLabel(array $row): string
{
    $name = $row['name'] ?? null;

    if (
        is_array($name)
        && trim((string)($name['value'] ?? '')) !== ''
    ) {
        return trim((string)$name['value']);
    }

    return 'parameter';
}

function parameterRowsByIdentity(array $rows): ?array
{
    $result = [];

    foreach ($rows as $row) {
        if (!is_array($row) || !isAssoc($row)) {
            return null;
        }

        $identity = parameterRowIdentity($row);

        if ($identity === null) {
            return null;
        }

        if (array_key_exists($identity, $result)) {
            return null;
        }

        $result[$identity] = $row;
    }

    return $result;
}


function jsonDiff($before, $after, string $path = ''): array
{
    if (valuesIdentical($before, $after)) {
        return [];
    }

    $beforeIsArray = is_array($before);
    $afterIsArray  = is_array($after);

    if (!$beforeIsArray || !$afterIsArray) {
        return [[
            'path'   => $path !== '' ? $path : '(kořen)',
            'before' => $before,
            'after'  => $after,
            'kind'   => 'changed',
        ]];
    }

    $beforeAssoc = isAssoc($before);
    $afterAssoc  = isAssoc($after);

    /*
     * Objekt/dictionary: porovnáváme klíče.
     */
    if ($beforeAssoc && $afterAssoc) {
        $result = [];

        $keys = array_unique(
            array_merge(
                array_keys($before),
                array_keys($after)
            )
        );

        sort($keys, SORT_NATURAL | SORT_FLAG_CASE);

        foreach ($keys as $key) {
            $childPath = $path === ''
                ? (string)$key
                : $path . '.' . $key;

            $hasBefore = array_key_exists($key, $before);
            $hasAfter  = array_key_exists($key, $after);

            if (!$hasBefore) {
                $result[] = [
                    'path'   => $childPath,
                    'before' => null,
                    'after'  => $after[$key],
                    'kind'   => 'added',
                ];
                continue;
            }

            if (!$hasAfter) {
                $result[] = [
                    'path'   => $childPath,
                    'before' => $before[$key],
                    'after'  => null,
                    'kind'   => 'deleted',
                ];
                continue;
            }

            $result = array_merge(
                $result,
                jsonDiff(
                    $before[$key],
                    $after[$key],
                    $childPath
                )
            );
        }

        return $result;
    }

    /*
     * Jednoduché seznamy scalar/null hodnot.
     * Když se například do available-tabs přidá "Research", zobrazíme
     * přímo "+ Research" místo dvou dlouhých JSONů.
     */
    $beforeSimple = true;
    foreach ($before as $item) {
        if (is_array($item) || is_object($item)) {
            $beforeSimple = false;
            break;
        }
    }

    $afterSimple = true;
    foreach ($after as $item) {
        if (is_array($item) || is_object($item)) {
            $afterSimple = false;
            break;
        }
    }

    if ($beforeSimple && $afterSimple) {
        $added = array_values(
            array_udiff(
                $after,
                $before,
                static function ($a, $b): int {
                    return strcmp(
                        json_encode($a, JSON_UNESCAPED_UNICODE),
                        json_encode($b, JSON_UNESCAPED_UNICODE)
                    );
                }
            )
        );

        $removed = array_values(
            array_udiff(
                $before,
                $after,
                static function ($a, $b): int {
                    return strcmp(
                        json_encode($a, JSON_UNESCAPED_UNICODE),
                        json_encode($b, JSON_UNESCAPED_UNICODE)
                    );
                }
            )
        );

        if ($added || $removed) {
            $partsBefore = [];
            $partsAfter = [];

            foreach ($removed as $item) {
                $partsBefore[] = '− ' . displayValue($item, false);
            }

            foreach ($added as $item) {
                $partsAfter[] = '+ ' . displayValue($item, false);
            }

            return [[
                'path'   => $path !== '' ? $path : '(kořen)',
                'before' => $partsBefore
                    ? implode("\n", $partsBefore)
                    : '—',
                'after'  => $partsAfter
                    ? implode("\n", $partsAfter)
                    : '—',
                'kind'   => 'list_changed',
                'already_formatted' => true,
            ]];
        }
    }


    /*
     * Seznam parametrů Integration Profiles a podobných objektů.
     *
     * Řádky párujeme podle action.value + name.value. Díky tomu se
     * místo celého JSON seznamu zobrazí například:
     *
     *   parameter.lastProcessDirectory
     *   2026-09-30 -> 2026-10-01
     */
    if ($path === 'parameter') {
        $beforeParameters = parameterRowsByIdentity($before);
        $afterParameters  = parameterRowsByIdentity($after);

        if (
            $beforeParameters !== null
            && $afterParameters !== null
        ) {
            $result = [];

            $keys = array_unique(
                array_merge(
                    array_keys($beforeParameters),
                    array_keys($afterParameters)
                )
            );

            sort($keys, SORT_STRING);

            foreach ($keys as $key) {
                $hasBefore = array_key_exists(
                    $key,
                    $beforeParameters
                );
                $hasAfter = array_key_exists(
                    $key,
                    $afterParameters
                );

                $sample = $hasAfter
                    ? $afterParameters[$key]
                    : $beforeParameters[$key];

                $label = parameterRowLabel($sample);
                $rowPath = 'parameter.' . $label;

                if (!$hasBefore) {
                    $result[] = [
                        'path'   => $rowPath,
                        'before' => null,
                        'after'  => $afterParameters[$key]['value']
                            ?? $afterParameters[$key],
                        'kind'   => 'added',
                    ];
                    continue;
                }

                if (!$hasAfter) {
                    $result[] = [
                        'path'   => $rowPath,
                        'before' => $beforeParameters[$key]['value']
                            ?? $beforeParameters[$key],
                        'after'  => null,
                        'kind'   => 'deleted',
                    ];
                    continue;
                }

                $beforeComparable = $beforeParameters[$key];
                $afterComparable  = $afterParameters[$key];

                /*
                 * name určuje identitu parametru, proto ho v diffu
                 * neopakujeme. action ponecháváme - pokud by se opravdu
                 * změnila, audit ji stále ukáže.
                 */
                unset(
                    $beforeComparable['name'],
                    $afterComparable['name']
                );

                /*
                 * Nejběžnější případ: změnila se pouze hodnota.
                 * Zobrazíme čisté parameter.<name> bez ".value".
                 */
                $beforeWithoutValue = $beforeComparable;
                $afterWithoutValue = $afterComparable;

                unset(
                    $beforeWithoutValue['value'],
                    $afterWithoutValue['value']
                );

                if (
                    valuesIdentical(
                        $beforeWithoutValue,
                        $afterWithoutValue
                    )
                    && !valuesIdentical(
                        $beforeComparable['value'] ?? null,
                        $afterComparable['value'] ?? null
                    )
                ) {
                    $result[] = [
                        'path'   => $rowPath,
                        'before' => $beforeComparable['value'] ?? null,
                        'after'  => $afterComparable['value'] ?? null,
                        'kind'   => 'changed',
                    ];
                    continue;
                }

                $result = array_merge(
                    $result,
                    jsonDiff(
                        $beforeComparable,
                        $afterComparable,
                        $rowPath
                    )
                );
            }

            return $result;
        }
    }

    /*
     * Seznam objektů z Primo mapping tables.
     *
     * Pokud mají všechny řádky stabilní identitu source1...source6,
     * párujeme je podle ní a ukážeme jen skutečně změněné hodnoty.
     * Tím se například 30řádková View Properties změna zkrátí na:
     *
     *   ...View Properties [enable_recent_scopes].target
     *   false -> true
     */
    $beforeMapped = mappingRowsByIdentity($before);
    $afterMapped  = mappingRowsByIdentity($after);

    if ($beforeMapped !== null && $afterMapped !== null) {
        $result = [];

        $keys = array_unique(
            array_merge(
                array_keys($beforeMapped),
                array_keys($afterMapped)
            )
        );

        sort($keys, SORT_STRING);

        foreach ($keys as $key) {
            $hasBefore = array_key_exists(
                $key,
                $beforeMapped
            );

            $hasAfter = array_key_exists(
                $key,
                $afterMapped
            );

            $sample = $hasAfter
                ? $afterMapped[$key]
                : $beforeMapped[$key];

            $label = mappingRowLabel(
                $sample
            );

            $rowPath = (
                $path !== ''
                    ? $path
                    : '(kořen)'
            ) . ' [' . $label . ']';

            if (!$hasBefore) {
                $result[] = [
                    'path'   => $rowPath,
                    'before' => null,
                    'after'  => (
                        array_key_exists(
                            'target',
                            $afterMapped[$key]
                        )
                            ? $afterMapped[$key]['target']
                            : $afterMapped[$key]
                    ),
                    'kind'   => 'added',
                ];
                continue;
            }

            if (!$hasAfter) {
                $result[] = [
                    'path'   => $rowPath,
                    'before' => (
                        array_key_exists(
                            'target',
                            $beforeMapped[$key]
                        )
                            ? $beforeMapped[$key]['target']
                            : $beforeMapped[$key]
                    ),
                    'after'  => null,
                    'kind'   => 'deleted',
                ];
                continue;
            }

            /*
             * source1...source6 tvoří identitu, takže u spárovaného
             * řádku nás zajímají ostatní hodnoty (nejčastěji target).
             */
            $beforeComparable = $beforeMapped[$key];
            $afterComparable  = $afterMapped[$key];

            for ($i = 1; $i <= 6; $i++) {
                unset(
                    $beforeComparable['source' . $i],
                    $afterComparable['source' . $i]
                );
            }

            $result = array_merge(
                $result,
                jsonDiff(
                    $beforeComparable,
                    $afterComparable,
                    $rowPath
                )
            );
        }

        return $result;
    }

    /*
     * Ostatní seznamy objektů:
     * nemáme bezpečný univerzální stabilní klíč, takže zachováme
     * původní chování a zobrazíme je jako jednu změnu.
     */
    return [[
        'path'   => $path !== '' ? $path : '(kořen)',
        'before' => $before,
        'after'  => $after,
        'kind'   => 'changed',
    ]];
}

function displayValue($value, bool $pretty = true): string
{
    if ($value === null) {
        return '—';
    }

    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }

    if (is_string($value)) {
        return $value;
    }

    if (is_int($value) || is_float($value)) {
        return (string)$value;
    }

    return (string)json_encode(
        $value,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        ($pretty ? JSON_PRETTY_PRINT : 0)
    );
}

function changeLabel(string $changeType): string
{
    return match ($changeType) {
        'ROW_ADDED', 'OBJECT_ADDED'     => 'Přidáno',
        'ROW_DELETED', 'OBJECT_DELETED' => 'Smazáno',
        'ROW_UPDATED', 'OBJECT_UPDATED',
        'TABLE_UPDATE'                  => 'Upraveno',
        'HISTORY_MODIFIED'              => 'Historická změna (Analytics)',
        default                         => $changeType,
    };
}

function isHistoryChange(array $row): bool
{
    return str_starts_with(
        (string)($row['change_type'] ?? ''),
        'HISTORY_'
    );
}

function analyticsDetails(array $row): array
{
    $raw = $row['analytics_details_json'] ?? null;

    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);

    if (!is_array($decoded)) {
        return [];
    }

    return $decoded;
}

function mappingTableAnalyticsForPath(
    string $path,
    array $analyticsDetails
): ?array {
    $tables = $analyticsDetails['mapping_tables'] ?? null;

    if (!is_array($tables) || !$tables) {
        return null;
    }

    /*
     * Delší názvy zkoušíme jako první, aby případný kratší název
     * nebyl omylem přiřazen k delšímu názvu Mapping Table.
     */
    $tableNames = array_keys($tables);
    usort(
        $tableNames,
        static fn(string $a, string $b): int => strlen($b) <=> strlen($a)
    );

    foreach ($tableNames as $tableName) {
        $prefix = 'configuration.mapping-tables.' . $tableName;

        if (!str_starts_with($path, $prefix)) {
            continue;
        }

        $rest = substr($path, strlen($prefix));

        /*
         * Název tabulky musí končit přesně zde nebo následovat cesta
         * do jejího obsahu (tečka / mezera před [identitou řádku]).
         */
        if (
            $rest !== ''
            && !str_starts_with($rest, '.')
            && !str_starts_with($rest, ' [')
            && !str_starts_with($rest, '[')
        ) {
            continue;
        }

        $detail = $tables[$tableName] ?? null;

        if (!is_array($detail)) {
            return null;
        }

        return [
            'table_name' => $tableName,
            'users'      => is_array($detail['users'] ?? null)
                ? $detail['users']
                : [],
            'events'     => is_array($detail['events'] ?? null)
                ? $detail['events']
                : [],
        ];
    }

    return null;
}

function analyticsEventLines(array $mappingInfo): array
{
    $events = $mappingInfo['events'] ?? [];
    $lines = [];

    foreach ($events as $event) {
        if (!is_array($event)) {
            continue;
        }

        $user = trim((string)($event['user'] ?? ''));
        $eventAt = trim((string)($event['event_at'] ?? ''));
        $description = trim((string)($event['description'] ?? ''));

        $parts = [];

        if ($user !== '') {
            $parts[] = $user;
        }

        if ($eventAt !== '') {
            $parts[] = formatDetected($eventAt);
        }

        if ($description !== '') {
            $parts[] = $description;
        }

        if ($parts) {
            $lines[] = implode(' · ', $parts);
        }
    }

    /*
     * Starší/ručně doplněná data mohou mít pouze users bez events.
     */
    if (!$lines) {
        $users = array_values(array_filter(
            array_map(
                static fn($value): string => trim((string)$value),
                $mappingInfo['users'] ?? []
            ),
            static fn(string $value): bool => $value !== ''
        ));

        if ($users) {
            $lines[] = implode(' / ', array_unique($users));
        }
    }

    return $lines;
}

try {
    $pdo = new PDO(
        'sqlite:' . AUDIT_DB_PATH,
        null,
        null,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );

    $pdo->exec('PRAGMA query_only = ON');

    $hasObjectLabel = (bool)$pdo->query(
        "SELECT 1
           FROM sqlite_master
          WHERE type = 'table'
            AND name = 'object_label'
          LIMIT 1"
    )->fetchColumn();
} catch (Throwable $e) {
    http_response_code(500);
    die(
        'Nelze otevřít databázi: '
        . h($e->getMessage())
    );
}

$id = (int)($_GET['id'] ?? 0);

if ($hasObjectLabel) {
    $stmt = $pdo->prepare(
        'SELECT c.*, l.display_name
           FROM change_log c
           LEFT JOIN object_label l
             ON l.object_type = c.object_type
            AND l.object_name = c.object_name
          WHERE c.id = ?'
    );
} else {
    $stmt = $pdo->prepare(
        'SELECT c.*, NULL AS display_name
           FROM change_log c
          WHERE c.id = ?'
    );
}
$stmt->execute([$id]);

$row = $stmt->fetch();

if (!$row) {
    http_response_code(404);
    die('Záznam nebyl nalezen.');
}

$before = jsonData($row['before_json'] ?? null);
$after  = jsonData($row['after_json'] ?? null);

$isHistory = isHistoryChange($row);

$changed = (
    $isHistory && $before === null
        ? []
        : jsonDiff(
            $before ?? [],
            $after ?? []
        )
);

$user = extractUser(
    $row,
    $before,
    $after
);

$analyticsDetails = analyticsDetails($row);

?>
<!doctype html>
<html lang="cs">
<head>
    <meta charset="utf-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >
    <title>Detail změny – <?=h(AUDIT_SITE_TITLE)?></title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            color: #111;
            background: #8f8f8f;
        }

        .wrap {
            max-width: 1500px;
            margin: 22px auto;
            padding: 0;
            background: #fff;
        }

        .header {
            background: #0065bd;
            color: #fff;
            padding: 14px 18px 12px;
        }

        .header-title {
            margin: 0;
            font-size: 24px;
            line-height: 1.1;
            font-weight: 700;
        }

        .header-subtitle {
            margin-top: 3px;
            font-size: 12px;
            font-weight: 600;
        }

        .content {
            padding: 18px 20px 20px;
        }

        a {
            color: #0065bd;
        }

        .card {
            margin-bottom: 18px;
            padding: 16px;
            border: 1px solid #d8d8d8;
            border-radius: 6px;
            background: #fff;
        }

        .back {
            display: inline-block;
            margin-bottom: 14px;
        }

        .meta-grid {
            display: grid;
            grid-template-columns:
                repeat(5, minmax(150px, 1fr));
            gap: 12px;
        }

        .meta-box {
            min-height: 52px;
            padding: 10px;
            border: 1px solid #d6d9dc;
            border-radius: 4px;
            background: #f6f7f8;
        }

        .meta-label {
            margin-bottom: 3px;
            font-size: 11px;
            color: #555;
        }

        .meta-value {
            font-size: 14px;
            font-weight: bold;
            overflow-wrap: anywhere;
        }

        h2 {
            margin: 15px 0 18px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th,
        td {
            padding: 8px 10px;
            border-bottom: 1px solid #d9dde1;
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #eaf0f4;
        }

        .path {
            width: 30%;
            font-weight: bold;
            overflow-wrap: anywhere;
        }

        .before {
            width: 35%;
            background: #fff1f1;
        }

        .after {
            width: 35%;
            background: #effaf2;
        }

        .value {
            margin: 0;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
            font-family:
                Consolas,
                "Courier New",
                monospace;
            font-size: 13px;
        }

        .badge {
            display: inline-block;
            margin-left: 6px;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: normal;
            white-space: nowrap;
        }

        .badge-added {
            background: #dcf5e3;
            color: #176b2c;
        }

        .badge-deleted {
            background: #fde2e2;
            color: #8b1d1d;
        }

        .badge-changed {
            background: #fff1bd;
            color: #705500;
        }

        .analytics-attribution {
            margin-top: 7px;
            padding-top: 6px;
            border-top: 1px solid #d9dde1;
            font-size: 11px;
            font-weight: normal;
            line-height: 1.45;
            color: #444;
        }

        .analytics-attribution-title {
            margin-bottom: 2px;
            font-weight: bold;
            color: #004b8d;
        }

        .analytics-attribution-event {
            overflow-wrap: anywhere;
        }

        .full-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
        }

        .json-box {
            border: 1px solid #d4d9dd;
            border-radius: 5px;
            overflow: hidden;
        }

        .json-title {
            padding: 8px 10px;
            background: #eaf0f4;
            font-weight: bold;
        }

        .json-box pre {
            max-height: 65vh;
            margin: 0;
            padding: 12px;
            overflow: auto;
            white-space: pre;
            font-family:
                Consolas,
                "Courier New",
                monospace;
            font-size: 12px;
            background: #fff;
        }

        .count {
            margin-left: 8px;
            font-size: 14px;
            font-weight: normal;
            color: #555;
        }

        .notice {
            margin-bottom: 18px;
            padding: 12px 14px;
            border-left: 4px solid #0065bd;
            border-radius: 4px;
            background: #eef6fd;
            line-height: 1.45;
        }

        .notice strong {
            color: #004b8d;
        }

        @media (max-width: 1000px) {
            .meta-grid {
                grid-template-columns:
                    repeat(2, minmax(140px, 1fr));
            }

            .full-grid {
                grid-template-columns: 1fr;
            }

            .path {
                width: 25%;
            }
        }

        @media (max-width: 650px) {
            .meta-grid {
                grid-template-columns: 1fr;
            }

            th,
            td {
                padding: 7px;
                font-size: 12px;
            }
        }
    
.site-footer{
    margin-top:18px;
    padding:14px 2px 2px;
    border-top:1px solid #d7d7d7;
    color:#666;
    font-size:12px;
    text-align:center;
}
.site-footer a{
    color:#1f5f99;
    text-decoration:none;
    font-weight:600;
}
.site-footer a:hover{
    text-decoration:underline;
}

</style>
</head>

<body>
<div class="wrap">
    <div class="header">
        <div class="header-title"><?=h(AUDIT_SITE_TITLE)?></div>
        <div class="header-subtitle"><?=h(AUDIT_INSTITUTION)?> · verze 1.2.1</div>
    </div>
    <div class="content">

    <div class="card">
        <a class="back" href="index.php">
            ← zpět na přehled
        </a>

        <div class="meta-grid">
            <div class="meta-box">
                <div class="meta-label">Tabulka</div>
                <div class="meta-value">
                    <?= h(displayObjectName($row, $before, $after)) ?>
                </div>
            </div>

            <div class="meta-box">
                <div class="meta-label">Řádek</div>
                <div class="meta-value">
                    <?= h(
                        !empty($row['row_key'])
                            ? $row['row_key']
                            : '—'
                    ) ?>
                </div>
            </div>

            <div class="meta-box">
                <div class="meta-label">Typ změny</div>
                <div class="meta-value">
                    <?= h(changeLabel(
                        (string)($row['change_type'] ?? '')
                    )) ?>
                </div>
            </div>

            <div class="meta-box">
                <div class="meta-label">Uživatel</div>
                <div class="meta-value">
                    <?= h($user) ?>
                </div>
            </div>

            <?php if (!empty($row['analytics_event_at'])): ?>
            <div class="meta-box">
                <div class="meta-label">Změněno v Almě</div>
                <div class="meta-value">
                    <?= h(formatDetected(
                        $row['analytics_event_at'] ?? null
                    )) ?>
                </div>
            </div>
            <?php endif; ?>

            <div class="meta-box">
                <div class="meta-label">
                    <?= $isHistory ? 'Importováno auditem' : 'Detekováno auditem' ?>
                </div>
                <div class="meta-value">
                    <?= h(formatDetected(
                        $row['detected_at'] ?? null
                    )) ?>
                </div>
            </div>

            <div class="meta-box">
                <div class="meta-label">Typ objektu</div>
                <div class="meta-value">
                    <?= h($row['object_type'] ?? '—') ?>
                </div>
            </div>
        </div>
    </div>

    <?php if ($isHistory): ?>
    <div class="notice">
        <strong>Historická událost z Alma Analytics.</strong>
        <?php if ($before === null): ?>
            Událost byla zpětně doplněna podle údajů
            <em>Modification Date / Modified By</em>.
            Analytics poskytují stav po poslední známé změně,
            ale nikoli předchozí hodnotu, proto zde není možné
            zobrazit spolehlivé Before → After.
        <?php else: ?>
            Událost byla doplněna po výpadku Analytics auditu.
            Hodnota Before pochází z posledního lokálního snapshotu
            a hodnota After z aktuálních Alma Analytics.
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <div class="card">
        <h2>
            <?= ($isHistory && $before === null)
                ? 'Historicky dostupný stav'
                : 'Změněné hodnoty' ?>
            <span class="count">
                (<?= count($changed) ?>)
            </span>
        </h2>

        <table>
            <thead>
            <tr>
                <th>Položka</th>
                <th>Před</th>
                <th>Po</th>
            </tr>
            </thead>

            <tbody>
            <?php if (!$changed): ?>
                <tr>
                    <td colspan="3">
                        <?php if ($isHistory && $before === null): ?>
                            Předchozí hodnota není v Alma Analytics dostupná.
                            Aktuální stav po poslední známé změně je uveden
                            níže v části AFTER.
                        <?php else: ?>
                            Nebyl nalezen rozložitelný rozdíl
                            v datech Before / After.
                        <?php endif; ?>
                    </td>
                </tr>
            <?php else: ?>
                <?php foreach ($changed as $diff): ?>
                    <?php
                    $kind = $diff['kind'] ?? 'changed';

                    $badgeClass = match ($kind) {
                        'added'   => 'badge-added',
                        'deleted' => 'badge-deleted',
                        default   => 'badge-changed',
                    };

                    $badgeText = match ($kind) {
                        'added'        => 'nové',
                        'deleted'      => 'smazané',
                        'list_changed' => 'seznam',
                        default        => 'změna',
                    };

                    $beforeText =
                        !empty($diff['already_formatted'])
                            ? (string)$diff['before']
                            : displayValue($diff['before']);

                    $afterText =
                        !empty($diff['already_formatted'])
                            ? (string)$diff['after']
                            : displayValue($diff['after']);

                    $mappingAnalytics = mappingTableAnalyticsForPath(
                        (string)($diff['path'] ?? ''),
                        $analyticsDetails
                    );

                    $mappingAnalyticsLines = $mappingAnalytics
                        ? analyticsEventLines($mappingAnalytics)
                        : [];
                    ?>

                    <tr>
                        <td class="path">
                            <?= h($diff['path']) ?>
                            <span
                                class="badge <?= h($badgeClass) ?>"
                            >
                                <?= h($badgeText) ?>
                            </span>

                            <?php if ($mappingAnalytics && $mappingAnalyticsLines): ?>
                            <div class="analytics-attribution">
                                <div class="analytics-attribution-title">
                                    Analytics pro Mapping Table
                                    <?= h($mappingAnalytics['table_name']) ?>
                                </div>
                                <?php foreach ($mappingAnalyticsLines as $line): ?>
                                <div class="analytics-attribution-event">
                                    <?= h($line) ?>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>
                        </td>

                        <td class="before">
                            <pre class="value"><?= h($beforeText) ?></pre>
                        </td>

                        <td class="after">
                            <pre class="value"><?= h($afterText) ?></pre>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>
            <?= ($isHistory && $before === null)
                ? 'Dostupný stav z Analytics'
                : 'Kompletní Before / After' ?>
        </h2>

        <div class="full-grid">
            <div class="json-box">
                <div class="json-title">BEFORE</div>
                <pre><?= h(
                    $before === null
                        ? ''
                        : json_encode(
                            $before,
                            JSON_UNESCAPED_UNICODE |
                            JSON_UNESCAPED_SLASHES |
                            JSON_PRETTY_PRINT
                        )
                ) ?></pre>
            </div>

            <div class="json-box">
                <div class="json-title">AFTER</div>
                <pre><?= h(
                    $after === null
                        ? ''
                        : json_encode(
                            $after,
                            JSON_UNESCAPED_UNICODE |
                            JSON_UNESCAPED_SLASHES |
                            JSON_PRETTY_PRINT
                        )
                ) ?></pre>
            </div>
        </div>
    </div>

    </div>
</div>

<div class="site-footer">
    © 2026 Antonín Skopec · Ústřední knihovna ČVUT · <a href="https://github.com/skopeant/alma-config-audit" target="_blank" rel="noopener">GitHub</a>
</div>

</body>
</html>
