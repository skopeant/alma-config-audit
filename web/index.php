<?php
$configFile = __DIR__ . '/config.php';

if (is_file($configFile)) {
    require $configFile;
} else {
    require __DIR__ . '/config.php.example';
}

date_default_timezone_set(AUDIT_TIMEZONE);

function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function jsonData(?string $s): array {
    if (!$s) return [];
    $v = json_decode($s, true);
    return is_array($v) ? $v : [];
}
function scalarText($v): string {
    if (is_array($v)) {
        if (array_key_exists('value', $v) && !is_array($v['value'])) return (string)$v['value'];
        return '';
    }
    return is_scalar($v) ? (string)$v : '';
}
function extractUser(array $row): string {
    if (!empty($row['analytics_user'])) {
        return (string)$row['analytics_user'];
    }

    foreach (['after_json','before_json'] as $field) {
        $d = jsonData($row[$field] ?? null);
        foreach ([
            'updated_by',
            'last_modified_by',
            'creator',
            'tou_modified_by',
            'policy_modified_by',
            'rule_modified_by',
            'rule_parameter_modified_by'
        ] as $key) {
            if (!array_key_exists($key, $d)) continue;
            $v = scalarText($d[$key]);
            if ($v !== '') return $v;
        }
    }

    return '';
}

function eventTime(array $row): string {
    return (string)(
        !empty($row['analytics_event_at'])
            ? $row['analytics_event_at']
            : ($row['detected_at'] ?? '')
    );
}


function displayObjectName(array $row): string
{
    if (($row['object_type'] ?? '') === 'integration_profile') {
        $after = jsonData($row['after_json'] ?? null);
        $before = jsonData($row['before_json'] ?? null);

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

    return (string)($row['object_name'] ?? '');
}

function isHistory(array $row): bool {
    return str_starts_with(
        (string)($row['change_type'] ?? ''),
        'HISTORY_'
    );
}
function fmtTime(string $iso): string {
    try {
        $d = new DateTimeImmutable($iso);
        return $d->setTimezone(new DateTimeZone(AUDIT_TIMEZONE))->format('d.m.Y H:i:s');
    } catch (Throwable $e) { return $iso; }
}

try {
    $pdo = new PDO('sqlite:' . AUDIT_DB_PATH, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
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
    die('Nelze otevřít auditní databázi: ' . h($e->getMessage()));
}

$from = trim($_GET['from'] ?? '');
$to = trim($_GET['to'] ?? '');
$object = trim($_GET['object'] ?? '');
$change = trim($_GET['change'] ?? '');
$user = trim($_GET['user'] ?? '');

$where = [];
$params = [];

$eventExpr = "COALESCE(NULLIF(c.analytics_event_at, ''), c.detected_at)";

if ($from !== '') {
    $where[] = $eventExpr . ' >= :from';
    $params[':from'] = $from . 'T00:00:00';
}
if ($to !== '') {
    $where[] = $eventExpr . ' < :to';
    $next = (new DateTimeImmutable($to))
        ->modify('+1 day')
        ->format('Y-m-d');
    $params[':to'] = $next . 'T00:00:00';
}
if ($object !== '') {
    if ($hasObjectLabel) {
        $where[] = "(c.object_type LIKE :obj OR c.object_name LIKE :obj OR COALESCE(l.display_name, '') LIKE :obj)";
    } else {
        $where[] = "(c.object_type LIKE :obj OR c.object_name LIKE :obj)";
    }

    $params[':obj'] = '%' . $object . '%';
}
if ($change !== '') { $where[] = 'c.change_type = :change'; $params[':change'] = $change; }

if ($hasObjectLabel) {
    $sql = "SELECT c.*, l.display_name
              FROM change_log c
              LEFT JOIN object_label l
                ON l.object_type = c.object_type
               AND l.object_name = c.object_name";
} else {
    $sql = "SELECT c.*, NULL AS display_name
              FROM change_log c";
}
if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
$sql .= " ORDER BY COALESCE(NULLIF(c.analytics_event_at, ''), c.detected_at) DESC, c.id DESC LIMIT 1000";
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
if ($user !== '') {
    $rows = array_values(array_filter($rows, fn($r) => stripos(extractUser($r), $user) !== false));
}

$types = $pdo->query('SELECT DISTINCT change_type FROM change_log ORDER BY change_type')->fetchAll(PDO::FETCH_COLUMN);
?>
<!doctype html>
<html lang="cs">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=h(AUDIT_SITE_TITLE)?></title>
<style>
*{box-sizing:border-box}
body{
    font-family:Arial,Helvetica,sans-serif;
    margin:0;
    background:#8f8f8f;
    color:#111;
}
.page{
    max-width:1500px;
    margin:22px auto;
    background:#fff;
}
.header{
    background:#0065bd;
    color:#fff;
    padding:14px 18px 12px;
}
.header h1{
    margin:0;
    font-size:24px;
    line-height:1.1;
    font-weight:700;
}
.header .subtitle{
    margin-top:3px;
    font-size:12px;
    font-weight:600;
}
.content{
    padding:18px 20px 20px;
}
.muted{color:#666}
.card{
    background:#fff;
    border:1px solid #d6d6d6;
    border-radius:5px;
    padding:16px;
    margin:0 0 16px;
}
form{
    display:flex;
    gap:10px;
    flex-wrap:wrap;
    align-items:end;
}
label{
    font-size:12px;
    color:#111;
    display:block;
    margin-bottom:4px;
}
input,select,button{
    height:34px;
    padding:6px 9px;
    border:1px solid #aaa;
    border-radius:3px;
    background:#fff;
    font-size:13px;
}
button{
    background:#0065bd;
    color:#fff;
    border-color:#0065bd;
    cursor:pointer;
    font-weight:600;
}
.reset{
    display:inline-flex;
    align-items:center;
    height:34px;
    padding:0 11px;
    border-radius:3px;
    background:#666;
    color:#fff;
    text-decoration:none;
    font-size:13px;
    font-weight:600;
}
.summary{
    margin:0 0 9px;
    font-size:13px;
}
table{
    width:100%;
    border-collapse:collapse;
    background:#fff;
}
th,td{
    padding:7px 8px;
    border-bottom:1px solid #d8d8d8;
    text-align:left;
    vertical-align:top;
    font-size:12px;
}
th{
    background:#e8f0f6;
    font-weight:700;
    position:sticky;
    top:0;
}
a{
    color:#0065bd;
}
.tag{
    display:inline-block;
    padding:2px 5px;
    border-radius:3px;
    background:#eeeeee;
    font-family:Arial,Helvetica,sans-serif;
    font-size:11px;
    font-weight:700;
}
.tag-history{
    background:#e8f1fb;
    color:#00569c;
}
.scroll{
    overflow:auto;
    max-height:72vh;
}
.history-note{
    margin-top:3px;
    color:#666;
    font-size:10px;
}
@media (max-width:800px){
    .page{margin:0}
    .content{padding:12px}
    .header{padding:12px}
    th,td{font-size:11px;padding:6px}
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
<div class="page">
<div class="header">
    <h1><?=h(AUDIT_SITE_TITLE)?></h1>
    <div class="subtitle"><?=h(AUDIT_INSTITUTION)?> · verze 1.2.0</div>
</div>
<div class="content">
<div class="card"><form method="get">
<div><label>Od</label><input type="date" name="from" value="<?=h($from)?>"></div>
<div><label>Do</label><input type="date" name="to" value="<?=h($to)?>"></div>
<div><label>Objekt / název</label><input name="object" value="<?=h($object)?>" placeholder="location, library_department, scheduled_job..."></div>
<div><label>Uživatel</label><input name="user" value="<?=h($user)?>"></div>
<div><label>Změna</label><select name="change"><option value="">vše</option><?php foreach($types as $t): ?><option value="<?=h($t)?>" <?=$change===$t?'selected':''?>><?=h($t)?></option><?php endforeach; ?></select></div>
<div><button type="submit">Filtrovat</button></div>
<div><a class="reset" href="index.php">Zrušit</a></div>
</form></div>
<div class="card"><div class="summary">Nalezeno změn: <?=count($rows)?></div><div class="scroll"><table><thead><tr><th>Detekováno</th><th>Uživatel</th><th>Tabulka</th><th>Řádek</th><th>Změna</th><th></th></tr></thead><tbody>
<?php foreach($rows as $r): ?>
<tr>
<td>
    <?=h(fmtTime(eventTime($r)))?>
    <?php if (isHistory($r)): ?>
        <div class="history-note">historie z Analytics</div>
    <?php endif; ?>
</td>
<td><?=h(extractUser($r))?></td>
<td><?=h(displayObjectName($r))?></td>
<td><?=h($r['row_key'] ?? '')?></td>
<td><span class="tag <?=isHistory($r)?'tag-history':''?>"><?=h($r['change_type'])?></span></td>
<td><a href="detail.php?id=<?=urlencode($r['id'])?>">Detail</a></td>
</tr>
<?php endforeach; ?>
<?php if(!$rows): ?><tr><td colspan="6">Žádné změny.</td></tr><?php endif; ?>
</tbody></table></div></div>
</div>
</div>

<div class="site-footer">
    © 2026 Antonín Skopec · Ústřední knihovna ČVUT · <a href="https://github.com/skopeant/alma-config-audit" target="_blank" rel="noopener">GitHub</a>
</div>

</body></html>
