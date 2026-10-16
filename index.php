<?php
declare(strict_types=1);

/*
 * Network Documentation Audit Tool
 * Single-file, dependency-free PHP application.
 * Requires PHP 7.4+ with standard JSON and session support. No optional PHP extensions are used.
 */

const APP_NAME = 'Network Documentation Audit';
const APP_VERSION = '1.0.0';
const DATA_DIR = __DIR__ . '/tenant';
const STORAGE_DIR = __DIR__ . '/storage';
const USERS_FILE = STORAGE_DIR . '/users.json';
const AUDIT_FILE = STORAGE_DIR . '/audit.jsonl';
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const INPUT_FILES = ['assets', 'networks', 'connections', 'locations', 'findings', 'notes'];

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_name('netaudit_session');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

function ensure_dir(string $path): void
{
    if (!is_dir($path) && !mkdir($path, 0750, true) && !is_dir($path))
        throw new RuntimeException('Verzeichnis konnte nicht erstellt werden.');
}
function bootstrap(): void
{
    ensure_dir(DATA_DIR);
    ensure_dir(STORAGE_DIR);
    ensure_dir(STORAGE_DIR . '/sessions');
    ensure_dir(STORAGE_DIR . '/revisions');
    ensure_dir(STORAGE_DIR . '/locks');
    if (!file_exists(USERS_FILE))
        atomic_write(USERS_FILE, "[]\n");
    foreach ([DATA_DIR, STORAGE_DIR] as $dir) {
        $deny = $dir . '/.htaccess';
        if (!file_exists($deny))
            @file_put_contents($deny, "Options -Indexes\n<FilesMatch \\\"\\.(php|phtml|phar)$\\\">\nRequire all denied\n</FilesMatch>\n");
    }
}
function json_read(string $file, array $default = []): array
{
    if (!is_file($file))
        return $default;
    $raw = file_get_contents($file);
    if ($raw === false || trim($raw) === '')
        return $default;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}
function atomic_write(string $file, string $content): void
{
    ensure_dir(dirname($file));
    $lockFile = STORAGE_DIR . '/locks/' . hash('sha256', $file) . '.lock';
    $lock = fopen($lockFile, 'c');
    if (!$lock)
        throw new RuntimeException('Sperrdatei konnte nicht geöffnet werden.');
    try {
        if (!flock($lock, LOCK_EX))
            throw new RuntimeException('Dateisperre fehlgeschlagen.');
        $tmp = tempnam(dirname($file), '.tmp-');
        if ($tmp === false)
            throw new RuntimeException('Temporäre Datei konnte nicht erstellt werden.');
        if (file_put_contents($tmp, $content, LOCK_EX) === false) {
            @unlink($tmp);
            throw new RuntimeException('Datei konnte nicht geschrieben werden.');
        }
        @chmod($tmp, 0640);
        if (!rename($tmp, $file)) {
            @unlink($tmp);
            throw new RuntimeException('Datei konnte nicht ersetzt werden.');
        }
        flock($lock, LOCK_UN);
    } finally {
        fclose($lock);
    }
}
function json_write(string $file, array $data, ?string $tenant = null, ?string $kind = null): void
{
    $encoded = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($encoded === false)
        throw new RuntimeException('JSON konnte nicht erzeugt werden.');
    if (is_file($file) && $tenant && $kind) {
        $revDir = STORAGE_DIR . '/revisions/' . safe_id($tenant) . '/' . $kind;
        ensure_dir($revDir);
        @copy($file, $revDir . '/' . date('Ymd_His') . '_' . bin2hex(random_bytes(3)) . '.json');
    }
    atomic_write($file, $encoded . "\n");
}
function e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function safe_id(string $id): string
{
    $id = strtolower(trim($id));
    if (!preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/', $id))
        throw new InvalidArgumentException('ID: 2-64 Zeichen, nur a-z, 0-9 und Bindestrich.');
    return $id;
}
function new_id(string $prefix): string
{
    return $prefix . '-' . date('YmdHis') . '-' . bin2hex(random_bytes(3));
}
function now(): string
{
    return date(DATE_ATOM);
}
function csrf(): string
{
    if (empty($_SESSION['csrf']))
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function verify_csrf(): void
{
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', (string) $_POST['csrf']))
        throw new RuntimeException('Ungültige Sitzung. Seite neu laden.');
}
function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}
function audit_log(string $action, string $tenant = '', string $object = '', array $changes = []): void
{
    $row = ['timestamp' => now(), 'user' => $_SESSION['user']['username'] ?? 'system', 'tenant' => $tenant, 'action' => $action, 'object_id' => $object, 'changed_fields' => $changes, 'ip' => $_SERVER['REMOTE_ADDR'] ?? ''];
    file_put_contents(AUDIT_FILE, json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
}
function users(): array
{
    return json_read(USERS_FILE);
}
function logged_in(): bool
{
    return isset($_SESSION['user']);
}
function require_login(): void
{
    if (!logged_in()) {
        header('Location: ?');
        exit;
    }
}
function tenant_path(string $id): string
{
    $id = safe_id($id);
    $base = realpath(DATA_DIR);
    if ($base === false)
        throw new RuntimeException('Tenant-Basis fehlt.');
    $path = DATA_DIR . '/' . $id;
    if (!is_dir($path))
        throw new InvalidArgumentException('Tenant nicht gefunden.');
    $real = realpath($path);
    if ($real === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0)
        throw new RuntimeException('Ungültiger Tenant-Pfad.');
    return $real;
}
function tenant_data(string $id): array
{
    return json_read(tenant_path($id) . '/tenant.json');
}
function all_tenants(): array
{
    $out = [];
    foreach (glob(DATA_DIR . '/*/tenant.json') ?: [] as $f) {
        $t = json_read($f);
        if (!empty($t['id']))
            $out[$t['id']] = $t;
    }
    uasort($out, fn($a, $b) => strnatcasecmp($a['name'] ?? '', $b['name'] ?? ''));
    return $out;
}
function tenant_descendants(string $id, array $all): array
{
    $ids = [$id];
    $added = true;
    while ($added) {
        $added = false;
        foreach ($all as $k => $t)
            if (in_array($t['parent'] ?? null, $ids, true) && !in_array($k, $ids, true)) {
                $ids[] = $k;
                $added = true;
            }
    }
    return $ids;
}
function input_file(string $tenant, string $kind): string
{
    if (!in_array($kind, INPUT_FILES, true))
        throw new InvalidArgumentException('Ungültiger Datentyp.');
    return tenant_path($tenant) . '/input/' . $kind . '.json';
}
function items(string $tenant, string $kind): array
{
    return json_read(input_file($tenant, $kind));
}
function save_items(string $tenant, string $kind, array $rows): void
{
    json_write(input_file($tenant, $kind), array_values($rows), $tenant, 'input/' . $kind);
}
function create_tenant(array $p): string
{
    $id = safe_id((string) ($p['id'] ?? ''));
    $name = trim((string) ($p['name'] ?? ''));
    if ($name === '')
        throw new InvalidArgumentException('Name fehlt.');
    $path = DATA_DIR . '/' . $id;
    if (file_exists($path))
        throw new InvalidArgumentException('Tenant-ID existiert bereits.');
    $parent = trim((string) ($p['parent'] ?? ''));
    if ($parent !== '')
        tenant_path($parent);
    ensure_dir($path . '/input/attachments');
    ensure_dir($path . '/input/tenant-icon');
    ensure_dir($path . '/output/exports');
    $meta = ['id' => $id, 'name' => $name, 'type' => (string) ($p['type'] ?? 'customer'), 'parent' => $parent ?: null, 'status' => 'active', 'created_at' => now(), 'updated_at' => now()];
    json_write($path . '/tenant.json', $meta);
    foreach (INPUT_FILES as $kind)
        json_write($path . '/input/' . $kind . '.json', []);
    audit_log('tenant.create', $id, $id, array_keys($meta));
    return $id;
}
function find_index(array $rows, string $id): int
{
    foreach ($rows as $i => $r)
        if (($r['id'] ?? '') === $id)
            return $i;
    return -1;
}
function csv_list(string $v): array
{
    return array_values(array_filter(array_map('trim', preg_split('/[,;\n]+/', $v) ?: []), fn($x) => $x !== ''));
}
function bool_post(string $key): bool
{
    return isset($_POST[$key]) && $_POST[$key] === '1';
}
function utf8_cut(string $value, int $max): string
{
    if ($max <= 0 || $value === '')
        return '';
    if (preg_match_all('/./us', $value, $characters) === false)
        return substr($value, 0, $max);
    return implode('', array_slice($characters[0], 0, $max));
}
function clean_text(string $v, int $max = 5000): string
{
    return utf8_cut(trim($v), $max);
}
function text_cut(string $v, int $max): string
{
    return utf8_cut($v, $max);
}
function detect_upload_type(string $file, bool $iconOnly = false): ?string
{
    $h = @fopen($file, 'rb');
    if ($h === false)
        return null;
    $head = fread($h, 8192);
    fclose($h);
    if ($head === false)
        return null;
    if (strncmp($head, "\xFF\xD8\xFF", 3) === 0)
        return 'jpg';
    if (strncmp($head, "\x89PNG\x0D\x0A\x1A\x0A", 8) === 0)
        return 'png';
    if ($iconOnly)
        return null;
    if (strncmp($head, '%PDF-', 5) === 0)
        return 'pdf';
    if (strpos($head, "\0") !== false || ($head !== '' && preg_match('//u', $head) !== 1))
        return null;
    $line = strtok($head, "\r\n");
    if ($line !== false && (strpos($line, ',') !== false || strpos($line, ';') !== false || strpos($line, "\t") !== false))
        return 'csv';
    return 'txt';
}
function tenant_icon_data(array $tenant): string
{
    $name = (string) ($tenant['icon'] ?? '');
    if ($name === '' || !preg_match('/^[a-zA-Z0-9._-]+$/', $name))
        return '';
    $file = tenant_path((string) $tenant['id']) . '/input/tenant-icon/' . $name;
    if (!is_file($file))
        return '';
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $mime = $ext === 'png' ? 'image/png' : ($ext === 'jpg' ? 'image/jpeg' : '');
    if ($mime === '')
        return '';
    $raw = file_get_contents($file);
    return $raw === false ? '' : 'data:' . $mime . ';base64,' . base64_encode($raw);
}
function tenant_path_chain(string $id, array $all): array
{
    $chain = [];
    $seen = [];
    while (isset($all[$id]) && !isset($seen[$id])) {
        $seen[$id] = true;
        array_unshift($chain, $all[$id]);
        $id = (string) ($all[$id]['parent'] ?? '');
    }
    return $chain;
}

function tenant_rows(string $tenant, string $kind, bool $includeChildren = false): array
{
    $all = all_tenants();
    $ids = $includeChildren ? tenant_descendants($tenant, $all) : [$tenant];
    $rows = [];
    foreach ($ids as $tid)
        foreach (items($tid, $kind) as $r) {
            $r['_tenant'] = $tid;
            $rows[] = $r;
        }
    return $rows;
}
function export_outputs(string $tenant, bool $children): void
{
    $all = all_tenants();
    $ids = $children ? tenant_descendants($tenant, $all) : [$tenant];
    $out = tenant_path($tenant) . '/output';
    ensure_dir($out . '/exports');
    $bundle = ['generated_at' => now(), 'tenant' => $tenant, 'included_tenants' => $ids];
    foreach (INPUT_FILES as $k)
        $bundle[$k] = tenant_rows($tenant, $k, $children);
    json_write($out . '/network-audit.json', $bundle, $tenant, 'output');
    $assets = $bundle['assets'];
    $csv = fopen('php://temp', 'r+');
    fputcsv($csv, ['Tenant', 'ID', 'Typ', 'Name', 'Hostname', 'IPv4', 'MAC', 'Hersteller', 'Modell', 'Status']);
    foreach ($assets as $a)
        fputcsv($csv, [$a['_tenant'] ?? $tenant, $a['id'] ?? '', $a['type'] ?? '', $a['name'] ?? '', $a['hostname'] ?? '', implode('|', $a['ipv4'] ?? []), implode('|', $a['mac'] ?? []), $a['manufacturer'] ?? '', $a['model'] ?? '', $a['status'] ?? '']);
    rewind($csv);
    atomic_write($out . '/exports/assets.csv', (string) stream_get_contents($csv));
    fclose($csv);
    $summary = build_summary($tenant, $children);
    atomic_write($out . '/audit-report.html', render_report_html($summary));
    audit_log('output.generate', $tenant, $tenant, ['children' => $children]);
}
function build_summary(string $tenant, bool $children): array
{
    $assets = tenant_rows($tenant, 'assets', $children);
    $findings = tenant_rows($tenant, 'findings', $children);
    $networks = tenant_rows($tenant, 'networks', $children);
    $connections = tenant_rows($tenant, 'connections', $children);
    $types = [];
    foreach ($assets as $a) {
        $k = $a['type'] ?? 'other';
        $types[$k] = ($types[$k] ?? 0) + 1;
    }
    ksort($types);
    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
    foreach ($findings as $f)
        if (($f['status'] ?? 'open') !== 'closed') {
            $k = $f['severity'] ?? 'info';
            $sev[$k] = ($sev[$k] ?? 0) + 1;
        }
    $complete = 0;
    foreach ($assets as $a) {
        $fields = ['name', 'type', 'status'];
        $ok = 0;
        foreach ($fields as $f)
            if (!empty($a[$f]))
                $ok++;
        if (!empty($a['ipv4']) || !empty($a['serial_number']))
            $ok++;
        $complete += $ok / 4;
    }
    return ['tenant' => tenant_data($tenant), 'generated_at' => now(), 'children' => $children, 'assets' => $assets, 'findings' => $findings, 'networks' => $networks, 'connections' => $connections, 'types' => $types, 'severity' => $sev, 'documentation_percent' => count($assets) ? round($complete / count($assets) * 100) : 0];
}
function render_report_html(array $s): string
{
    $t = $s['tenant'];
    $rows = '';
    foreach ($s['findings'] as $f)
        if (($f['status'] ?? 'open') !== 'closed')
            $rows .= '<tr><td>' . e($f['severity'] ?? '') . '</td><td>' . e($f['title'] ?? '') . '</td><td>' . e($f['_tenant'] ?? $t['id']) . '</td><td>' . e($f['status'] ?? '') . '</td></tr>';
    return '<!doctype html><html lang="de"><meta charset="utf-8"><title>Audit ' . e($t['name']) . '</title><style>body{font:14px system-ui;color:#17202b;max-width:1100px;margin:40px auto}h1{border-bottom:2px solid #17202b;padding-bottom:12px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.k{border:1px solid #ccd3db;padding:16px}.n{font-size:28px;font-weight:700}table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccd3db;padding:8px;text-align:left}</style><h1>Netzwerk-Audit: ' . e($t['name']) . '</h1><p>Erstellt: ' . e($s['generated_at']) . '</p><div class="grid"><div class="k"><div class="n">' . count($s['assets']) . '</div>Assets</div><div class="k"><div class="n">' . count($s['networks']) . '</div>Netze</div><div class="k"><div class="n">' . array_sum($s['severity']) . '</div>Offene Findings</div><div class="k"><div class="n">' . e($s['documentation_percent']) . '%</div>Dokumentation</div></div><h2>Offene Feststellungen</h2><table><thead><tr><th>Schwere</th><th>Titel</th><th>Tenant</th><th>Status</th></tr></thead><tbody>' . $rows . '</tbody></table></html>';
}
function svg_map(string $tenant, bool $children): string
{
    $assets = tenant_rows($tenant, 'assets', $children);
    $connections = tenant_rows($tenant, 'connections', $children);
    $by = [];
    foreach ($assets as $a)
        $by[$a['id']] = $a;
    $n = count($assets);
    if ($n === 0)
        return '<div class="empty">Keine Assets für die Netzwerkkarte.</div>';
    $w = max(900, min(1800, $n * 150));
    $h = max(480, ceil($n / 6) * 150);
    $pos = [];
    $cols = max(1, min(6, (int) ceil(sqrt($n * 1.6))));
    $i = 0;
    foreach ($assets as $a) {
        $row = intdiv($i, $cols);
        $col = $i % $cols;
        $pos[$a['id']] = [100 + $col * ($w - 200) / max(1, $cols - 1), 90 + $row * 130];
        $i++;
    }
    $svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="Netzwerkkarte">';
    foreach ($connections as $c) {
        $a = $pos[$c['source_asset'] ?? ''] ?? null;
        $b = $pos[$c['target_asset'] ?? ''] ?? null;
        if ($a && $b)
            $svg .= '<line x1="' . $a[0] . '" y1="' . $a[1] . '" x2="' . $b[0] . '" y2="' . $b[1] . '" class="link"/><text x="' . (($a[0] + $b[0]) / 2) . '" y="' . (($a[1] + $b[1]) / 2 - 5) . '" class="edge">' . e($c['connection_type'] ?? '') . '</text>';
    }
    foreach ($assets as $a) {
        [$x, $y] = $pos[$a['id']];
        $svg .= '<g><rect x="' . ($x - 70) . '" y="' . ($y - 30) . '" width="140" height="60" rx="6"/><text x="' . $x . '" y="' . ($y - 5) . '" class="node-title">' . e(text_cut((string) ($a['name'] ?? $a['id']), 20)) . '</text><text x="' . $x . '" y="' . ($y + 14) . '" class="node-sub">' . e($a['hostname'] ?? ($a['type'] ?? '')) . '</text></g>';
    }
    return $svg . '</svg>';
}

$bootstrapError = '';
try {
    if (version_compare(PHP_VERSION, '7.4.0', '<'))
        throw new RuntimeException('PHP 7.4 oder neuer ist erforderlich. Installiert ist ' . PHP_VERSION . '.');
    bootstrap();
} catch (Throwable $ex) {
    $bootstrapError = $ex->getMessage();
}
if ($bootstrapError !== '') {
    http_response_code(500);
    $safe = htmlspecialchars($bootstrapError, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo '<!doctype html><html lang="de"><meta charset="utf-8"><title>Startfehler</title><style>body{margin:0;background:#090d12;color:#e5edf5;font:14px system-ui;padding:40px}main{max-width:760px;margin:auto;background:#0f151d;border:1px solid #263241;padding:24px}code{color:#7eb6ff}</style><main><h1>Network Audit konnte nicht starten</h1><p>' . $safe . '</p><p>Prüfe PHP-Version und Schreibrechte. Das Verzeichnis <code>' . htmlspecialchars(__DIR__, ENT_QUOTES, 'UTF-8') . '</code> muss für den PHP-Webserver beschreibbar sein.</p></main></html>';
    exit;
}
$error = '';
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verify_csrf();
        $action = (string) ($_POST['action'] ?? '');
        if ($action === 'setup' && count(users()) === 0) {
            $u = trim((string) $_POST['username']);
            $p = (string) $_POST['password'];
            if (!preg_match('/^[a-zA-Z0-9._-]{3,40}$/', $u) || strlen($p) < 12)
                throw new InvalidArgumentException('Benutzername ungültig oder Passwort kürzer als 12 Zeichen.');
            json_write(USERS_FILE, [['username' => $u, 'password_hash' => password_hash($p, PASSWORD_DEFAULT), 'role' => 'admin', 'created_at' => now()]]);
            audit_log('system.setup');
            flash('ok', 'Administrator wurde angelegt.');
            header('Location: ?');
            exit;
        }
        if ($action === 'login') {
            foreach (users() as $u)
                if (hash_equals($u['username'], trim((string) $_POST['username'])) && password_verify((string) $_POST['password'], $u['password_hash'])) {
                    session_regenerate_id(true);
                    $_SESSION['user'] = ['username' => $u['username'], 'role' => $u['role']];
                    audit_log('auth.login');
                    header('Location: ?');
                    exit;
                }
            throw new RuntimeException('Anmeldung fehlgeschlagen.');
        }
        if ($action === 'logout') {
            require_login();
            audit_log('auth.logout');
            $_SESSION = [];
            session_destroy();
            header('Location: ?');
            exit;
        }
        require_login();
        if ($action === 'tenant_create') {
            $id = create_tenant($_POST);
            flash('ok', 'Tenant wurde erstellt.');
            header('Location: ?tenant=' . urlencode($id));
            exit;
        }
        $tenant = safe_id((string) ($_POST['tenant'] ?? ''));
        tenant_path($tenant);
        if ($action === 'tenant_update') {
            $m = tenant_data($tenant);
            $m['name'] = clean_text((string) $_POST['name'], 150);
            $m['type'] = clean_text((string) $_POST['type'], 40);
            $m['status'] = in_array($_POST['status'] ?? 'active', ['active', 'inactive', 'archived'], true) ? $_POST['status'] : 'active';
            $parent = trim((string) ($_POST['parent'] ?? ''));
            if ($parent === $tenant)
                throw new InvalidArgumentException('Tenant kann nicht sein eigener Parent sein.');
            if ($parent !== '')
                tenant_path($parent);
            $m['parent'] = $parent ?: null;
            $m['updated_at'] = now();
            json_write(tenant_path($tenant) . '/tenant.json', $m, $tenant, 'tenant');
            audit_log('tenant.update', $tenant, $tenant, ['name', 'type', 'status', 'parent']);
            flash('ok', 'Tenant gespeichert.');
        } elseif ($action === 'save_item') {
            $kind = (string) $_POST['kind'];
            $rows = items($tenant, $kind);
            $id = trim((string) ($_POST['id'] ?? ''));
            $existingIndex = $id ? find_index($rows, $id) : -1;
            $base = $existingIndex >= 0 ? $rows[$existingIndex] : ['id' => new_id(rtrim($kind, 's')), 'created_at' => now()];
            if ($kind === 'assets') {
                $row = $base + [];
                $row = array_merge($base, ['type' => clean_text((string) $_POST['type'], 60), 'name' => clean_text((string) $_POST['name'], 150), 'hostname' => clean_text((string) $_POST['hostname'], 150), 'fqdn' => clean_text((string) $_POST['fqdn'], 255), 'manufacturer' => clean_text((string) $_POST['manufacturer'], 100), 'model' => clean_text((string) $_POST['model'], 100), 'serial_number' => clean_text((string) $_POST['serial_number'], 100), 'inventory_number' => clean_text((string) $_POST['inventory_number'], 100), 'ipv4' => csv_list((string) $_POST['ipv4']), 'ipv6' => csv_list((string) $_POST['ipv6']), 'mac' => csv_list((string) $_POST['mac']), 'vlan' => clean_text((string) $_POST['vlan'], 100), 'gateway' => clean_text((string) $_POST['gateway'], 100), 'dns' => csv_list((string) $_POST['dns']), 'services' => csv_list((string) $_POST['services']), 'web_url' => clean_text((string) $_POST['web_url'], 500), 'location_id' => clean_text((string) $_POST['location_id'], 100), 'criticality' => $_POST['criticality'] ?? 'normal', 'status' => $_POST['status'] ?? 'active', 'source' => $_POST['source'] ?? 'manual', 'verification' => $_POST['verification'] ?? 'unverified', 'os_version' => clean_text((string) $_POST['os_version'], 150), 'firmware' => clean_text((string) $_POST['firmware'], 150), 'support_end' => clean_text((string) $_POST['support_end'], 20), 'backup' => bool_post('backup'), 'monitoring' => bool_post('monitoring'), 'documented' => bool_post('documented'), 'notes' => clean_text((string) $_POST['notes'])]);
                if ($row['name'] === '')
                    throw new InvalidArgumentException('Asset-Name fehlt.');
            } elseif ($kind === 'networks') {
                $row = array_merge($base, ['name' => clean_text((string) $_POST['name'], 150), 'cidr' => clean_text((string) $_POST['cidr'], 100), 'vlan' => clean_text((string) $_POST['vlan'], 50), 'gateway' => clean_text((string) $_POST['gateway'], 100), 'dns' => csv_list((string) $_POST['dns']), 'purpose' => clean_text((string) $_POST['purpose'], 500), 'status' => $_POST['status'] ?? 'active', 'notes' => clean_text((string) $_POST['notes'])]);
            } elseif ($kind === 'locations') {
                $row = array_merge($base, ['name' => clean_text((string) $_POST['name'], 150), 'building' => clean_text((string) $_POST['building'], 100), 'room' => clean_text((string) $_POST['room'], 100), 'rack' => clean_text((string) $_POST['rack'], 100), 'rack_unit' => clean_text((string) $_POST['rack_unit'], 30), 'patch_panel' => clean_text((string) $_POST['patch_panel'], 100), 'patch_port' => clean_text((string) $_POST['patch_port'], 100), 'notes' => clean_text((string) $_POST['notes'])]);
            } elseif ($kind === 'connections') {
                $row = array_merge($base, ['source_asset' => clean_text((string) $_POST['source_asset'], 100), 'target_asset' => clean_text((string) $_POST['target_asset'], 100), 'connection_type' => clean_text((string) $_POST['connection_type'], 60), 'source_port' => clean_text((string) $_POST['source_port'], 100), 'target_port' => clean_text((string) $_POST['target_port'], 100), 'vlan' => clean_text((string) $_POST['vlan'], 50), 'status' => $_POST['status'] ?? 'confirmed', 'notes' => clean_text((string) $_POST['notes'])]);
                if ($row['source_asset'] === $row['target_asset'])
                    throw new InvalidArgumentException('Quelle und Ziel müssen verschieden sein.');
            } elseif ($kind === 'findings') {
                $row = array_merge($base, ['asset_id' => clean_text((string) $_POST['asset_id'], 100), 'severity' => $_POST['severity'] ?? 'info', 'category' => clean_text((string) $_POST['category'], 80), 'title' => clean_text((string) $_POST['title'], 200), 'description' => clean_text((string) $_POST['description']), 'recommendation' => clean_text((string) $_POST['recommendation']), 'status' => $_POST['status'] ?? 'open']);
            } elseif ($kind === 'notes') {
                $row = array_merge($base, ['title' => clean_text((string) $_POST['title'], 200), 'body' => clean_text((string) $_POST['body'], 10000), 'status' => $_POST['status'] ?? 'open']);
            } else
                throw new InvalidArgumentException('Ungültiger Datentyp.');
            $row['updated_at'] = now();
            if ($existingIndex >= 0)
                $rows[$existingIndex] = $row;
            else
                $rows[] = $row;
            save_items($tenant, $kind, $rows);
            audit_log($kind . '.' . ($existingIndex >= 0 ? 'update' : 'create'), $tenant, $row['id'], array_keys($row));
            flash('ok', 'Eintrag gespeichert.');
        } elseif ($action === 'delete_item') {
            $kind = (string) $_POST['kind'];
            $id = (string) $_POST['id'];
            $rows = items($tenant, $kind);
            $idx = find_index($rows, $id);
            if ($idx < 0)
                throw new InvalidArgumentException('Eintrag nicht gefunden.');
            array_splice($rows, $idx, 1);
            save_items($tenant, $kind, $rows);
            audit_log($kind . '.delete', $tenant, $id);
            flash('ok', 'Eintrag gelöscht.');
        } elseif ($action === 'generate') {
            export_outputs($tenant, bool_post('children'));
            flash('ok', 'Ausgaben wurden neu erzeugt.');
        } elseif ($action === 'upload') {
            if (!isset($_FILES['attachment']) || $_FILES['attachment']['error'] !== UPLOAD_ERR_OK)
                throw new RuntimeException('Upload fehlgeschlagen.');
            $f = $_FILES['attachment'];
            if ($f['size'] > MAX_UPLOAD_BYTES)
                throw new RuntimeException('Datei ist größer als 20 MB.');
            $target = (string) ($_POST['upload_target'] ?? '');
            if ($target === 'tenant_icon') {
                if ($f['size'] > 2 * 1024 * 1024)
                    throw new RuntimeException('Tenant-Icon ist größer als 2 MB.');
                $extension = detect_upload_type($f['tmp_name'], true);
                if ($extension === null)
                    throw new RuntimeException('Als Tenant-Icon sind nur PNG und JPG erlaubt.');
                $dir = tenant_path($tenant) . '/input/tenant-icon';
                ensure_dir($dir);
                foreach (glob($dir . '/*') ?: [] as $old)
                    if (is_file($old))
                        @unlink($old);
                $name = 'icon.' . $extension;
                $dest = $dir . '/' . $name;
                if (!move_uploaded_file($f['tmp_name'], $dest))
                    throw new RuntimeException('Tenant-Icon konnte nicht gespeichert werden.');
                $m = tenant_data($tenant);
                $m['icon'] = $name;
                $m['updated_at'] = now();
                json_write(tenant_path($tenant) . '/tenant.json', $m, $tenant, 'tenant');
                audit_log('tenant.icon.update', $tenant, $tenant);
                flash('ok', 'Tenant-Icon gespeichert.');
            } elseif ($target === 'item_attachment') {
                $kind = (string) ($_POST['kind'] ?? '');
                $itemId = (string) ($_POST['item_id'] ?? '');
                $rows = items($tenant, $kind);
                $idx = find_index($rows, $itemId);
                if ($idx < 0)
                    throw new InvalidArgumentException('Zugehöriger Input-Eintrag wurde nicht gefunden.');
                $extension = detect_upload_type($f['tmp_name'], false);
                if ($extension === null)
                    throw new RuntimeException('Erlaubt sind JPG, PNG, PDF, TXT und CSV.');
                $dir = tenant_path($tenant) . '/input/attachments/' . $kind . '/' . $itemId;
                ensure_dir($dir);
                $name = date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $extension;
                $dest = $dir . '/' . $name;
                if (!move_uploaded_file($f['tmp_name'], $dest))
                    throw new RuntimeException('Anhang konnte nicht gespeichert werden.');
                $rows[$idx]['attachments'] = $rows[$idx]['attachments'] ?? [];
                $rows[$idx]['attachments'][] = ['file' => $name, 'original' => clean_text((string) $f['name'], 180), 'created_at' => now()];
                $rows[$idx]['updated_at'] = now();
                save_items($tenant, $kind, $rows);
                audit_log('attachment.upload', $tenant, $itemId, [$kind, $name]);
                flash('ok', 'Anhang am Input-Eintrag gespeichert.');
            } else
                throw new InvalidArgumentException('Ungültiges Upload-Ziel.');
        }
        header('Location: ?tenant=' . urlencode($tenant) . '&view=' . urlencode((string) ($_POST['return_view'] ?? 'overview')));
        exit;
    }
} catch (Throwable $ex) {
    $error = $ex->getMessage();
}

$hasUsers = count(users()) > 0;
if (!$hasUsers || !logged_in()) {
    ?><!doctype html>
    <html lang="de">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title><?= e(APP_NAME) ?></title>
        <style>
            :root {
                color-scheme: dark;
                --bg: #0b0f14;
                --panel: #111821;
                --line: #263241;
                --text: #e6edf3;
                --muted: #8b9bad;
                --accent: #4e9cff;
                --bad: #ff6174
            }

            * {
                box-sizing: border-box
            }

            body {
                margin: 0;
                background: var(--bg);
                color: var(--text);
                font: 14px system-ui, sans-serif;
                display: grid;
                place-items: center;
                min-height: 100vh
            }

            .login {
                width: min(420px, 92vw);
                background: var(--panel);
                border: 1px solid var(--line);
                padding: 28px;
                border-radius: 8px
            }

            h1 {
                font-size: 20px;
                margin: 0 0 22px
            }

            label {
                display: block;
                color: var(--muted);
                margin: 14px 0 6px
            }

            input {
                width: 100%;
                background: #0d131b;
                border: 1px solid var(--line);
                color: var(--text);
                padding: 11px;
                border-radius: 5px
            }

            button {
                width: 100%;
                margin-top: 20px;
                background: var(--accent);
                border: 0;
                color: #06111d;
                font-weight: 700;
                padding: 11px;
                border-radius: 5px
            }

            .error {
                color: var(--bad);
                margin-bottom: 12px
            }

            .hint {
                color: var(--muted);
                font-size: 12px;
                margin-top: 12px
            }
        </style>
    </head>

    <body>
        <main class="login">
            <h1><?= e(APP_NAME) ?></h1><?php if ($error): ?>
                <div class="error"><?= e($error) ?></div><?php endif; ?>
            <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden" name="action"
                    value="<?= $hasUsers ? 'login' : 'setup' ?>"><label>Benutzername</label><input name="username" required
                    autofocus autocomplete="username"><label>Passwort</label><input type="password" name="password" required
                    minlength="12"
                    autocomplete="<?= $hasUsers ? 'current-password' : 'new-password' ?>"><button><?= $hasUsers ? 'Anmelden' : 'Administrator anlegen' ?></button>
            </form><?php if (!$hasUsers): ?>
                <p class="hint">Ersteinrichtung. Das Passwort muss mindestens 12 Zeichen lang sein.</p><?php endif; ?>
        </main>
    </body>

    </html>
    <?php exit;
}

if (logged_in() && isset($_GET['download'], $_GET['tenant'])) {
    try {
        $downloadTenant = safe_id((string) $_GET['tenant']);
        $mode = (string) $_GET['download'];
        if ($mode === 'report') {
            $files = ['audit-report.html' => 'text/html; charset=utf-8', 'network-audit.json' => 'application/json', 'assets.csv' => 'text/csv; charset=utf-8'];
            $name = (string) ($_GET['file'] ?? '');
            if (!isset($files[$name]))
                throw new RuntimeException('Ungültige Ausgabedatei.');
            $file = tenant_path($downloadTenant) . '/output/' . ($name === 'assets.csv' ? 'exports/' : '') . $name;
            if (!is_file($file))
                throw new RuntimeException('Report wurde noch nicht erzeugt.');
            header('Content-Type: ' . $files[$name]);
            header('Content-Disposition: attachment; filename="' . $name . '"');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
        if ($mode === 'attachment') {
            $kind = (string) ($_GET['kind'] ?? '');
            $itemId = (string) ($_GET['item'] ?? '');
            $fileName = (string) ($_GET['file'] ?? '');
            if (!in_array($kind, INPUT_FILES, true) || !preg_match('/^[a-zA-Z0-9._-]+$/', $fileName))
                throw new RuntimeException('Ungültiger Anhang.');
            $rows = items($downloadTenant, $kind);
            $idx = find_index($rows, $itemId);
            if ($idx < 0)
                throw new RuntimeException('Input-Eintrag fehlt.');
            $found = false;
            $original = $fileName;
            foreach (($rows[$idx]['attachments'] ?? []) as $a)
                if (($a['file'] ?? '') === $fileName) {
                    $found = true;
                    $original = (string) ($a['original'] ?? $fileName);
                    break;
                }
            if (!$found)
                throw new RuntimeException('Anhang ist nicht zugeordnet.');
            $file = tenant_path($downloadTenant) . '/input/attachments/' . $kind . '/' . $itemId . '/' . $fileName;
            if (!is_file($file))
                throw new RuntimeException('Anhang fehlt.');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . str_replace(['"', "\r", "\n"], '_', basename($original)) . '"');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
    } catch (Throwable $ex) {
        http_response_code(404);
        echo e($ex->getMessage());
        exit;
    }
}

$tenants = all_tenants();
$tenant = (string) ($_GET['tenant'] ?? array_key_first($tenants) ?? '');
$view = (string) ($_GET['view'] ?? 'overview');
$allowedViews = ['overview', 'map', 'reports', 'assets', 'networks', 'locations', 'connections', 'findings', 'notes', 'settings'];
if (!in_array($view, $allowedViews, true))
    $view = 'overview';
$current = null;
$summary = null;
$includeChildren = ($_GET['scope'] ?? 'own') === 'all';
if ($tenant !== '') {
    try {
        $tenant = safe_id($tenant);
        $current = tenant_data($tenant);
        $summary = build_summary($tenant, $includeChildren);
    } catch (Throwable $ignored) {
        $tenant = '';
    }
}
$flashes = $_SESSION['flash'] ?? [];
unset($_SESSION['flash']);
function nav_link(string $tenant, string $view, string $label): string
{
    $active = ($_GET['view'] ?? 'overview') === $view ? ' active' : '';
    return '<a class="nav' . $active . '" href="?tenant=' . urlencode($tenant) . '&view=' . $view . '">' . e($label) . '</a>';
}
function field(string $name, string $label, $value = '', string $type = 'text', string $extra = ''): string
{
    return '<label>' . e($label) . '<input type="' . e($type) . '" name="' . e($name) . '" value="' . e($value) . '" ' . $extra . '></label>';
}
function textarea(string $name, string $label, $value = ''): string
{
    return '<label>' . e($label) . '<textarea name="' . e($name) . '">' . e($value) . '</textarea></label>';
}
function selectf(string $name, string $label, array $opts, $value = ''): string
{
    $s = '<label>' . e($label) . '<select name="' . e($name) . '">';
    foreach ($opts as $k => $v)
        $s .= '<option value="' . e($k) . '" ' . ((string) $k === (string) $value ? 'selected' : '') . '>' . e($v) . '</option>';
    return $s . '</select></label>';
}
?>
<!doctype html>
<html lang="de">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <?php $iconData = $current ? tenant_icon_data($current) : '';
    $pageTitle = $current ? ($current['name'] . ' · ' . APP_NAME) : APP_NAME; ?>
    <title><?= e($pageTitle) ?></title><?php if ($iconData): ?>
        <link rel="icon" href="<?= e($iconData) ?>"><?php endif; ?>
    <style>
        :root {
            color-scheme: dark;
            --bg: #080c11;
            --side: #0c1219;
            --panel: #101720;
            --panel2: #151e29;
            --line: #263342;
            --text: #e7edf4;
            --muted: #8b9bad;
            --accent: #55a3ff;
            --ok: #43c487;
            --warn: #e5b34e;
            --bad: #ff6475
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 13px system-ui, -apple-system, sans-serif
        }

        button,
        input,
        select,
        textarea {
            font: inherit
        }

        .shell {
            display: grid;
            grid-template-columns: 282px minmax(0, 1fr);
            min-height: 100vh
        }

        .side {
            background: var(--side);
            border-right: 1px solid var(--line);
            padding: 16px;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow: auto
        }

        .brand {
            font-size: 12px;
            font-weight: 800;
            letter-spacing: .12em;
            padding: 4px 8px 16px
        }

        .caption {
            color: var(--muted);
            font-size: 10px;
            letter-spacing: .1em;
            text-transform: uppercase;
            margin: 16px 8px 6px
        }

        .tenant-node {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text);
            text-decoration: none;
            padding: 7px 8px;
            border-radius: 5px
        }

        .tenant-node:hover,
        .tenant-node.on {
            background: var(--panel2)
        }

        .tree-child {
            margin-left: 14px;
            border-left: 1px solid var(--line);
            padding-left: 6px
        }

        .tenant-mini,
        .tenant-head-icon {
            width: 24px;
            height: 24px;
            border-radius: 5px;
            object-fit: cover;
            background: #1b2734;
            border: 1px solid var(--line)
        }

        .tenant-mini.fallback {
            display: grid;
            place-items: center;
            font-weight: 700;
            color: var(--accent)
        }

        .tenant-head-icon {
            width: 42px;
            height: 42px
        }

        .nav {
            display: block;
            color: var(--muted);
            text-decoration: none;
            padding: 8px 10px;
            border-radius: 5px;
            margin: 1px 0
        }

        .nav:hover,
        .nav.active {
            background: var(--panel2);
            color: var(--text)
        }

        .nav.active {
            box-shadow: inset 2px 0 var(--accent)
        }

        .nav.sub {
            padding-left: 25px;
            font-size: 12px
        }

        .main {
            padding: 24px;
            min-width: 0
        }

        .top {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: center;
            margin-bottom: 18px
        }

        .identity {
            display: flex;
            align-items: center;
            gap: 12px
        }

        .identity h1 {
            font-size: 20px;
            margin: 0
        }

        .crumbs {
            color: var(--muted);
            font-size: 12px;
            margin-top: 4px
        }

        .crumbs a {
            color: var(--muted);
            text-decoration: none
        }

        .toolbar,
        .actions,
        .tabs {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap
        }

        .tabs {
            border-bottom: 1px solid var(--line);
            margin-bottom: 14px
        }

        .tab {
            color: var(--muted);
            text-decoration: none;
            padding: 9px 10px;
            border-bottom: 2px solid transparent
        }

        .tab.on {
            color: var(--text);
            border-color: var(--accent)
        }

        .btn,
        button {
            border: 1px solid var(--line);
            background: #182331;
            color: var(--text);
            padding: 8px 11px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none
        }

        .primary {
            background: var(--accent) !important;
            border-color: var(--accent) !important;
            color: #06111d !important;
            font-weight: 700
        }

        .danger {
            color: #ff8491
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px
        }

        .card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 7px;
            padding: 15px
        }

        .metric {
            font-size: 25px;
            font-weight: 750
        }

        .muted {
            color: var(--muted)
        }

        .small {
            font-size: 11px
        }

        .section {
            margin-top: 14px
        }

        .section h2 {
            font-size: 14px;
            margin: 0 0 13px
        }

        .quick {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px
        }

        .quick a {
            display: block;
            color: var(--text);
            text-decoration: none;
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 7px;
            padding: 16px
        }

        .quick a:hover {
            border-color: #45617e
        }

        .quick strong {
            display: block;
            margin-bottom: 5px
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--panel);
            border: 1px solid var(--line)
        }

        th,
        td {
            text-align: left;
            padding: 9px;
            border-bottom: 1px solid var(--line);
            vertical-align: top
        }

        th {
            font-size: 10px;
            letter-spacing: .07em;
            text-transform: uppercase;
            color: var(--muted)
        }

        tr:hover td {
            background: #121b25
        }

        .pill {
            display: inline-block;
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 2px 7px;
            font-size: 11px
        }

        .critical,
        .high {
            color: var(--bad)
        }

        .medium {
            color: var(--warn)
        }

        .low,
        .ok {
            color: var(--ok)
        }

        .empty {
            text-align: center;
            color: var(--muted);
            padding: 28px;
            border: 1px dashed var(--line)
        }

        dialog {
            width: min(870px, 94vw);
            max-height: 92vh;
            overflow: auto;
            background: var(--panel);
            color: var(--text);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 20px
        }

        dialog::backdrop {
            background: #000b
        }

        dialog h2 {
            font-size: 17px;
            margin: 0 0 16px
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 11px
        }

        label {
            display: block;
            color: var(--muted);
            font-size: 12px
        }

        input,
        select,
        textarea {
            width: 100%;
            margin-top: 5px;
            background: #0a1017;
            border: 1px solid var(--line);
            color: var(--text);
            padding: 8px;
            border-radius: 4px
        }

        textarea {
            min-height: 90px;
            resize: vertical
        }

        .full {
            grid-column: 1/-1
        }

        .actions {
            justify-content: flex-end;
            margin-top: 16px
        }

        .modal-tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 14px;
            border-bottom: 1px solid var(--line)
        }

        .modal-tab {
            border: 0;
            background: transparent;
            color: var(--muted);
            border-radius: 0;
            padding: 9px;
            border-bottom: 2px solid transparent
        }

        .modal-tab.on {
            color: var(--text);
            border-color: var(--accent)
        }

        .form-pane {
            display: none
        }

        .form-pane.on {
            display: grid
        }

        .flash {
            padding: 10px 12px;
            border: 1px solid var(--line);
            background: var(--panel);
            margin-bottom: 10px
        }

        .flash.ok {
            border-color: #276b4c
        }

        .flash.error {
            border-color: #8d3441
        }

        svg {
            width: 100%;
            background: var(--panel);
            border: 1px solid var(--line)
        }

        svg rect {
            fill: #172330;
            stroke: #3b4d60
        }

        .link {
            stroke: #4e667e;
            stroke-width: 2
        }

        .node-title,
        .node-sub,
        .edge {
            fill: #e7edf4;
            text-anchor: middle;
            font-size: 12px
        }

        .node-sub,
        .edge {
            fill: #8b9bad;
            font-size: 10px
        }

        .report-file {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid var(--line)
        }

        .logout {
            width: 100%;
            margin-top: 20px
        }

        @media(max-width:900px) {
            .shell {
                grid-template-columns: 1fr
            }

            .side {
                position: static;
                height: auto
            }

            .grid {
                grid-template-columns: 1fr 1fr
            }

            .quick,
            .form-grid {
                grid-template-columns: 1fr
            }

            .main {
                padding: 14px
            }
        }
    </style>
</head>

<body>
    <div class="shell">
        <aside class="side">
            <div class="brand">NETWORK AUDIT</div>
            <div class="caption">Tenants</div>
            <div><?php
            function render_tree_v2(array $all, ?string $parent, string $active, int $depth = 0): void
            {
                foreach ($all as $id => $t)
                    if (($t['parent'] ?? null) === $parent) {
                        $icon = tenant_icon_data($t);
                        echo '<div class="' . ($depth ? 'tree-child' : '') . '"><a class="tenant-node ' . ($id === $active ? 'on' : '') . '" href="?tenant=' . e($id) . '">' . ($icon ? '<img class="tenant-mini" src="' . e($icon) . '">' : '<span class="tenant-mini fallback">' . e(strtoupper(substr((string) $t['name'], 0, 1))) . '</span>') . '<span>' . e($t['name']) . '</span></a>';
                        render_tree_v2($all, $id, $active, $depth + 1);
                        echo '</div>';
                    }
            }
            render_tree_v2($tenants, null, $tenant); ?></div><button style="width:100%;margin-top:10px"
                onclick="document.getElementById('tenant-new').showModal()">+ Tenant</button>
            <?php if ($current): ?>
                <div class="caption">Übersicht</div><?= nav_link($tenant, 'overview', 'Übersicht') ?><a
                    class="nav sub <?= ($view === 'map' ? 'active' : '') ?>"
                    href="?tenant=<?= e($tenant) ?>&view=map">Netzwerkkarte</a><a
                    class="nav sub <?= ($view === 'reports' ? 'active' : '') ?>"
                    href="?tenant=<?= e($tenant) ?>&view=reports">Reports</a>
                <div class="caption">Assets</div><?= nav_link($tenant, 'assets', 'Assets') ?><a
                    class="nav sub <?= ($view === 'findings' ? 'active' : '') ?>"
                    href="?tenant=<?= e($tenant) ?>&view=findings">Findings</a>
                <div class="caption">System</div><?= nav_link($tenant, 'settings', 'Einstellungen') ?><?php endif; ?>
            <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                    name="action" value="logout"><button class="logout">Abmelden</button></form>
        </aside>
        <main class="main">
            <?php foreach ($flashes as $f): ?>
                <div class="flash <?= e($f['type']) ?>"><?= e($f['message']) ?></div><?php endforeach; ?><?php if ($error): ?>
                <div class="flash error"><?= e($error) ?></div><?php endif; ?>
            <?php if (!$current): ?>
                <div class="empty">Lege einen Tenant an.</div><?php else:
                $chain = tenant_path_chain($tenant, $tenants); ?>
                <header class="top">
                    <div class="identity"><?php if ($iconData): ?><img class="tenant-head-icon"
                                src="<?= e($iconData) ?>"><?php else: ?><span
                                class="tenant-head-icon tenant-mini fallback"><?= e(strtoupper(substr((string) $current['name'], 0, 1))) ?></span><?php endif; ?>
                        <div>
                            <h1><?= e($current['name']) ?></h1>
                            <div class="crumbs"><?php foreach ($chain as $i => $c): ?><?= $i ? ' / ' : '' ?><a
                                        href="?tenant=<?= e($c['id']) ?>"><?= e($c['name']) ?></a><?php endforeach; ?> ·
                                <?= e($current['type']) ?></div>
                        </div>
                    </div>
                    <form method="get"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input type="hidden"
                            name="view" value="<?= e($view) ?>"><select name="scope" onchange="this.form.submit()">
                            <option value="own" <?= $includeChildren ? '' : 'selected' ?>>Nur dieser Tenant</option>
                            <option value="all" <?= $includeChildren ? 'selected' : '' ?>>Mit Sub-Tenants</option>
                        </select></form>
                </header>
                <?php if ($view === 'overview'): ?>
                    <div class="grid">
                        <div class="card">
                            <div class="metric"><?= count($summary['assets']) ?></div>
                            <div class="muted">Assets</div>
                        </div>
                        <div class="card">
                            <div class="metric"><?= count($summary['networks']) ?></div>
                            <div class="muted">Netzwerke</div>
                        </div>
                        <div class="card">
                            <div class="metric"><?= array_sum($summary['severity']) ?></div>
                            <div class="muted">Offene Findings</div>
                        </div>
                        <div class="card">
                            <div class="metric"><?= e($summary['documentation_percent']) ?>%</div>
                            <div class="muted">Dokumentation</div>
                        </div>
                    </div>
                    <section class="section quick"><a
                            href="?tenant=<?= e($tenant) ?>&view=map"><strong>Netzwerkkarte</strong><span class="muted">Topologie
                                aus bestätigten und beobachteten Verbindungen anzeigen.</span></a><a
                            href="?tenant=<?= e($tenant) ?>&view=reports"><strong>Reports</strong><span class="muted">Erzeugte
                                Audit-Ausgaben herunterladen.</span></a></section>
                    <section class="section card">
                        <h2>Offene Risiken</h2><?php foreach ($summary['severity'] as $k => $v): ?><span
                                class="pill <?= e($k) ?>"><?= e($k) ?>: <?= e($v) ?></span> <?php endforeach; ?>
                    </section>
                <?php elseif ($view === 'map'): ?>        <?= svg_map($tenant, $includeChildren) ?>
                <?php elseif ($view === 'reports'): ?>
                    <section class="card">
                        <h2>Reports</h2>
                        <p class="muted">Reports werden aus dem aktuellen Input neu erzeugt und anschließend als Dateien
                            bereitgestellt.</p>
                        <form method="post" class="toolbar"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                                type="hidden" name="action" value="generate"><input type="hidden" name="tenant"
                                value="<?= e($tenant) ?>"><input type="hidden" name="return_view" value="reports"><label
                                style="display:flex;align-items:center;gap:7px"><input style="width:auto;margin:0"
                                    type="checkbox" name="children" value="1" <?= $includeChildren ? 'checked' : '' ?>>Sub-Tenants
                                einschließen</label><button class="primary">Reports erzeugen</button></form>
                        <?php $reportFiles = ['audit-report.html' => 'Auditbericht (HTML)', 'network-audit.json' => 'Gesamtdaten (JSON)', 'assets.csv' => 'Asset-Inventar (CSV)'];
                        foreach ($reportFiles as $rf => $label):
                            $path = tenant_path($tenant) . '/output/' . ($rf === 'assets.csv' ? 'exports/' : '') . $rf; ?>
                            <div class="report-file">
                                <div><strong><?= e($label) ?></strong>
                                    <div class="muted small">
                                        <?= is_file($path) ? 'Erzeugt ' . date('d.m.Y H:i', filemtime($path)) : 'Noch nicht erzeugt' ?></div>
                                </div><?php if (is_file($path)): ?><a class="btn"
                                        href="?tenant=<?= e($tenant) ?>&download=report&file=<?= e($rf) ?>">Download</a><?php endif; ?>
                            </div><?php endforeach; ?>
                    </section>
                <?php elseif (in_array($view, ['assets', 'networks', 'locations', 'connections', 'findings', 'notes'], true)): $rows = tenant_rows($tenant, $view, $includeChildren); ?>
                    <nav class="tabs"><a class="tab <?= $view === 'assets' ? 'on' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=assets">Assets</a><a class="tab <?= $view === 'networks' ? 'on' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=networks">Netzwerke</a><a
                            class="tab <?= $view === 'connections' ? 'on' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=connections">Verbindungen</a><a
                            class="tab <?= $view === 'locations' ? 'on' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=locations">Standorte</a><a
                            class="tab <?= $view === 'notes' ? 'on' : '' ?>" href="?tenant=<?= e($tenant) ?>&view=notes">Notizen</a><a
                            class="tab <?= $view === 'findings' ? 'on' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=findings">Findings</a></nav>
                    <div class="toolbar"><button class="primary" onclick="openEditor('<?= e($view) ?>',{})">+
                            Eintrag</button><span class="muted"><?= count($rows) ?> Einträge</span></div>
                    <table>
                        <thead>
                            <tr><?php if ($includeChildren): ?>
                                    <th>Tenant</th><?php endif; ?>
                                <th>Bezeichnung</th>
                                <th>Details</th>
                                <th>Anhänge</th>
                                <th>Status</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($rows as $r):
                                $label = $r['name'] ?? $r['title'] ?? (($r['source_asset'] ?? '') . ' → ' . ($r['target_asset'] ?? ''));
                                $details = $view === 'assets' ? implode(', ', $r['ipv4'] ?? []) : ($view === 'networks' ? ($r['cidr'] ?? '') : ($view === 'findings' ? ($r['category'] ?? '') : ($r['notes'] ?? $r['body'] ?? ''))); ?>
                                <tr><?php if ($includeChildren): ?>
                                        <td><?= e($r['_tenant'] ?? '') ?></td><?php endif; ?>
                                    <td><strong><?= e($label) ?></strong>
                                        <div class="muted small"><?= e($r['id'] ?? '') ?></div>
                                    </td>
                                    <td><?= e(text_cut((string) $details, 100)) ?></td>
                                    <td><?= count($r['attachments'] ?? []) ?><br><?php foreach (($r['attachments'] ?? []) as $a): ?><a
                                                class="small"
                                                href="?tenant=<?= e($r['_tenant'] ?? $tenant) ?>&download=attachment&kind=<?= e($view) ?>&item=<?= e($r['id']) ?>&file=<?= e($a['file']) ?>"><?= e($a['original'] ?? $a['file']) ?></a><br><?php endforeach; ?>
                                    </td>
                                    <td><span
                                            class="pill <?= e($r['severity'] ?? '') ?>"><?= e($r['status'] ?? $r['verification'] ?? '') ?></span>
                                    </td>
                                    <td><?php if (($r['_tenant'] ?? $tenant) === $tenant): ?><button
                                                onclick='openEditor(<?= json_encode($view) ?>,<?= json_encode($r, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button>
                                            <button
                                                onclick='openAttachment(<?= json_encode($view) ?>,<?= json_encode($r['id']) ?>,<?= json_encode($label) ?>)'>Anhang</button>
                                            <form method="post" style="display:inline"
                                                onsubmit="return confirm('Eintrag wirklich löschen?')"><input type="hidden" name="csrf"
                                                    value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="delete_item"><input
                                                    type="hidden" name="tenant" value="<?= e($tenant) ?>"><input type="hidden" name="kind"
                                                    value="<?= e($view) ?>"><input type="hidden" name="id" value="<?= e($r['id']) ?>"><input
                                                    type="hidden" name="return_view" value="<?= e($view) ?>"><button
                                                    class="danger">Löschen</button></form><?php endif; ?>
                                    </td>
                                </tr><?php endforeach; ?>
                        </tbody>
                    </table><?php if (!$rows): ?>
                        <div class="empty">Noch keine Einträge.</div><?php endif; ?>
                <?php elseif ($view === 'settings'): ?>
                    <div class="grid" style="grid-template-columns:2fr 1fr">
                        <section class="card">
                            <h2>Tenant</h2>
                            <form method="post" class="form-grid"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                                    type="hidden" name="action" value="tenant_update"><input type="hidden" name="tenant"
                                    value="<?= e($tenant) ?>"><?= field('name', 'Name', $current['name'] ?? '', 'text', 'required') ?><?= selectf('type', 'Typ', ['customer' => 'Kunde', 'subsidiary' => 'Tochtergesellschaft', 'branch' => 'Niederlassung', 'department' => 'Abteilung', 'business-unit' => 'Geschäftseinheit', 'external-customer' => 'Externer Kunde'], $current['type'] ?? 'customer') ?><?= selectf('parent', 'Übergeordneter Tenant', ['' => 'Keiner'] + array_map(fn($t) => $t['name'], $tenants), $current['parent'] ?? '') ?><?= selectf('status', 'Status', ['active' => 'Aktiv', 'inactive' => 'Inaktiv', 'archived' => 'Archiviert'], $current['status'] ?? 'active') ?>
                                <div class="actions full"><button class="primary">Speichern</button></div>
                            </form>
                        </section>
                        <section class="card">
                            <h2>Tenant-Icon</h2><?php if ($iconData): ?><img class="tenant-head-icon"
                                    src="<?= e($iconData) ?>"><?php endif; ?>
                            <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf"
                                    value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="upload"><input
                                    type="hidden" name="upload_target" value="tenant_icon"><input type="hidden" name="tenant"
                                    value="<?= e($tenant) ?>"><input type="hidden" name="return_view" value="settings"><label>PNG
                                    oder JPG, maximal 2 MB<input type="file" name="attachment" accept="image/png,image/jpeg"
                                        required></label>
                                <div class="actions"><button class="primary">Icon speichern</button></div>
                            </form>
                        </section>
                    </div><?php endif; ?><?php endif; ?>
        </main>
    </div>
    <dialog id="tenant-new">
        <h2>Tenant anlegen</h2>
        <form method="post" class="form-grid"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                type="hidden" name="action"
                value="tenant_create"><?= field('id', 'ID / Ordnername', '', 'text', 'required pattern="[a-z0-9][a-z0-9-]{1,63}" placeholder="muster-gmbh"') ?><?= field('name', 'Name', '', 'text', 'required') ?><?= selectf('type', 'Typ', ['customer' => 'Kunde', 'subsidiary' => 'Tochtergesellschaft', 'branch' => 'Niederlassung', 'department' => 'Abteilung', 'business-unit' => 'Geschäftseinheit', 'external-customer' => 'Externer Kunde'], 'customer') ?><?= selectf('parent', 'Übergeordneter Tenant', ['' => 'Keiner'] + array_map(fn($t) => $t['name'], $tenants), $tenant) ?>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button class="primary">Anlegen</button>
            </div>
        </form>
    </dialog>
    <dialog id="attachment">
        <h2 id="attachment-title">Anhang hinzufügen</h2>
        <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                type="hidden" name="action" value="upload"><input type="hidden" name="upload_target"
                value="item_attachment"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input type="hidden"
                name="kind"><input type="hidden" name="item_id"><input type="hidden" name="return_view"><label>Bild oder
                Dokument<input type="file" name="attachment"
                    accept="image/png,image/jpeg,application/pdf,text/plain,text/csv" required></label>
            <div class="actions"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button class="primary">Anhängen</button>
            </div>
        </form>
    </dialog>
    <dialog id="editor">
        <h2 id="editor-title">Eintrag</h2>
        <form method="post" id="editor-form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                type="hidden" name="action" value="save_item"><input type="hidden" name="tenant"
                value="<?= e($tenant) ?>"><input type="hidden" name="kind"><input type="hidden" name="id"><input
                type="hidden" name="return_view">
            <div id="modal-tabs" class="modal-tabs"></div>
            <div id="editor-fields"></div>
            <div class="actions"><button type="button"
                    onclick="document.getElementById('editor').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
        </form>
    </dialog>
    <script>
        const assets = <?= json_encode($current ? items($tenant, 'assets') : [], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>, locations = <?= json_encode($current ? items($tenant, 'locations') : [], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>;
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        const input = (n, l, v = '', type = 'text', x = '') => `<label>${esc(l)}<input type="${type}" name="${esc(n)}" value="${esc(v)}" ${x}></label>`, area = (n, l, v = '') => `<label class="full">${esc(l)}<textarea name="${esc(n)}">${esc(v)}</textarea></label>`, sel = (n, l, o, v = '', change = '') => `<label>${esc(l)}<select name="${esc(n)}" ${change}>${Object.entries(o).map(([k, x]) => `<option value="${esc(k)}" ${String(k) === String(v) ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></label>`, check = (n, l, v) => `<label><input style="width:auto" type="checkbox" name="${esc(n)}" value="1" ${v ? 'checked' : ''}> ${esc(l)}</label>`;
        function pane(id, html, cls = '') { return `<div class="form-pane form-grid ${cls}" data-pane="${id}">${html}</div>` } function setPane(id) { document.querySelectorAll('.form-pane').forEach(x => x.classList.toggle('on', x.dataset.pane === id)); document.querySelectorAll('.modal-tab').forEach(x => x.classList.toggle('on', x.dataset.pane === id)) } function tabs(def) { document.getElementById('modal-tabs').innerHTML = def.map((x, i) => `<button type="button" class="modal-tab ${i ? '' : 'on'}" data-pane="${x[0]}" onclick="setPane('${x[0]}')">${x[1]}</button>`).join('') }
        function updateAssetLogic() { const t = document.querySelector('[name=type]')?.value || ''; document.querySelectorAll('.asset-network').forEach(x => x.style.display = ['domain', 'website'].includes(t) ? 'none' : 'grid'); document.querySelectorAll('.asset-physical').forEach(x => x.style.display = ['vm', 'container', 'domain', 'website', 'ip'].includes(t) ? 'none' : 'grid') }
        function openAttachment(kind, id, label) { const f = document.querySelector('#attachment form'); f.kind.value = kind; f.item_id.value = id; f.return_view.value = kind; document.getElementById('attachment-title').textContent = 'Anhang: ' + label; document.getElementById('attachment').showModal() }
        function openEditor(kind, r) {
            const f = document.getElementById('editor-form'); f.kind.value = kind; f.id.value = r.id || ''; f.return_view.value = kind; let h = ''; const statuses = { active: 'Aktiv', inactive: 'Inaktiv', retired: 'Außer Betrieb', unknown: 'Unbekannt' };
            if (kind === 'assets') { tabs([['base', 'Basis'], ['network', 'Netzwerk'], ['physical', 'Physisch'], ['audit', 'Audit']]); h = pane('base', input('name', 'Name', r.name, 'text', 'required') + sel('type', 'Typ', { client: 'Client', laptop: 'Laptop / Notebook', desktop: 'Desktop', server: 'Server', vm: 'Virtuelle Maschine', container: 'Container', firewall: 'Firewall', router: 'Router', switch: 'Switch', access_point: 'Access Point', printer: 'Drucker', nas: 'NAS', camera: 'Kamera', phone: 'Telefon', domain: 'Domain', website: 'Website', ip: 'IP-Objekt', other: 'Sonstiges' }, r.type, 'onchange="updateAssetLogic()"') + input('hostname', 'Hostname', r.hostname) + sel('status', 'Status', statuses, r.status) + input('manufacturer', 'Hersteller', r.manufacturer) + input('model', 'Modell', r.model) + input('serial_number', 'Seriennummer', r.serial_number) + input('inventory_number', 'Inventarnummer', r.inventory_number) + area('notes', 'Notizen', r.notes), 'on') + pane('network', input('fqdn', 'FQDN', r.fqdn) + input('ipv4', 'IPv4, mit Komma getrennt', (r.ipv4 || []).join(', ')) + input('ipv6', 'IPv6, mit Komma getrennt', (r.ipv6 || []).join(', ')) + input('mac', 'MAC, mit Komma getrennt', (r.mac || []).join(', ')) + input('vlan', 'VLAN', r.vlan) + input('gateway', 'Gateway', r.gateway) + input('dns', 'DNS, mit Komma getrennt', (r.dns || []).join(', ')) + input('services', 'Dienste, z. B. HTTPS, SSH', (r.services || []).join(', ')) + input('web_url', 'Webinterface-URL', r.web_url, 'url'), 'asset-network') + pane('physical', sel('location_id', 'Standort', Object.fromEntries([['', 'Nicht zugeordnet'], ...locations.map(x => [x.id, x.name])]), r.location_id), 'asset-physical') + pane('audit', sel('criticality', 'Kritikalität', { low: 'Niedrig', normal: 'Normal', high: 'Hoch', critical: 'Kritisch' }, r.criticality) + sel('source', 'Quelle', { manual: 'Manuell', discovery: 'Discovery', import: 'Import', customer: 'Kundenangabe' }, r.source) + sel('verification', 'Prüfung', { unverified: 'Ungeprüft', observed: 'Beobachtet', verified: 'Verifiziert', conflicting: 'Widersprüchlich' }, r.verification) + input('os_version', 'Betriebssystem / Version', r.os_version) + input('firmware', 'Firmware', r.firmware) + input('support_end', 'Supportende', r.support_end, 'date') + check('backup', 'Backup vorhanden', r.backup) + check('monitoring', 'Monitoring vorhanden', r.monitoring) + check('documented', 'Dokumentiert', r.documented)); }
            else { tabs([]); if (kind === 'networks') h = pane('one', input('name', 'Name', r.name, 'text', 'required') + input('cidr', 'CIDR', r.cidr) + input('vlan', 'VLAN', r.vlan) + input('gateway', 'Gateway', r.gateway) + input('dns', 'DNS', (r.dns || []).join(', ')) + sel('status', 'Status', statuses, r.status) + area('purpose', 'Zweck', r.purpose) + area('notes', 'Notizen', r.notes), 'on'); if (kind === 'locations') h = pane('one', input('name', 'Name', r.name, 'text', 'required') + input('building', 'Gebäude', r.building) + input('room', 'Raum', r.room) + input('rack', 'Rack', r.rack) + input('rack_unit', 'Höheneinheit', r.rack_unit) + input('patch_panel', 'Patchfeld', r.patch_panel) + input('patch_port', 'Patchport', r.patch_port) + area('notes', 'Notizen', r.notes), 'on'); if (kind === 'connections') { const ao = Object.fromEntries(assets.map(x => [x.id, (x.name || x.id) + ' (' + (x.hostname || x.type || '') + ')'])); h = pane('one', sel('source_asset', 'Quelle', ao, r.source_asset) + sel('target_asset', 'Ziel', ao, r.target_asset) + sel('connection_type', 'Verbindung', { ethernet: 'Ethernet', fiber: 'Glasfaser', wifi: 'WLAN', vpn: 'VPN', virtual: 'Virtuell', logical: 'Logisch', unknown: 'Unbekannt' }, r.connection_type) + input('source_port', 'Quellport', r.source_port) + input('target_port', 'Zielport', r.target_port) + input('vlan', 'VLAN', r.vlan) + sel('status', 'Status', { confirmed: 'Bestätigt', observed: 'Beobachtet', assumed: 'Angenommen', inactive: 'Inaktiv' }, r.status) + area('notes', 'Notizen', r.notes), 'on') } if (kind === 'findings') { const ao = Object.fromEntries([['', 'Allgemein'], ...assets.map(x => [x.id, x.name || x.id])]); h = pane('one', sel('asset_id', 'Asset', ao, r.asset_id) + sel('severity', 'Schwere', { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Information' }, r.severity) + input('category', 'Kategorie', r.category) + input('title', 'Titel', r.title, 'text', 'required') + sel('status', 'Status', { open: 'Offen', accepted: 'Akzeptiert', in_progress: 'In Bearbeitung', resolved: 'Behoben', closed: 'Geschlossen' }, r.status) + area('description', 'Beschreibung', r.description) + area('recommendation', 'Empfehlung', r.recommendation), 'on') } if (kind === 'notes') h = pane('one', input('title', 'Titel', r.title, 'text', 'required') + sel('status', 'Status', { open: 'Offen', clarified: 'Geklärt', closed: 'Geschlossen' }, r.status) + area('body', 'Inhalt', r.body), 'on') }
            document.getElementById('editor-fields').innerHTML = h; document.getElementById('editor-title').textContent = r.id ? 'Eintrag bearbeiten' : 'Eintrag anlegen'; document.getElementById('editor').showModal(); if (kind === 'assets') { setPane('base'); updateAssetLogic() }
        }
    </script>
</body>

</html>
