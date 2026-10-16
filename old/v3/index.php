<?php
declare(strict_types=1);

/*
 * Network Documentation Audit Tool
 * Single-file, dependency-free PHP application.
 * Requires PHP 7.4+ with the normally available JSON and session functions. No optional PHP extensions are used.
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
function detect_upload_type(string $file): ?string
{
    $handle = @fopen($file, 'rb');
    if ($handle === false)
        return null;
    $head = fread($handle, 8192);
    fclose($handle);
    if ($head === false)
        return null;
    if (strncmp($head, "\xFF\xD8\xFF", 3) === 0)
        return 'jpg';
    if (strncmp($head, "\x89PNG\x0D\x0A\x1A\x0A", 8) === 0)
        return 'png';
    if (strncmp($head, '%PDF-', 5) === 0)
        return 'pdf';
    if (strpos($head, "\0") !== false)
        return null;
    if ($head !== '' && preg_match('//u', $head) !== 1)
        return null;
    $firstLine = strtok($head, "\r\n");
    if ($firstLine !== false && (strpos($firstLine, ',') !== false || strpos($firstLine, ';') !== false || strpos($firstLine, "\t") !== false))
        return 'csv';
    return 'txt';
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
            $extension = detect_upload_type($f['tmp_name']);
            if ($extension === null)
                throw new RuntimeException('Dateityp nicht erlaubt.');
            $name = date('Ymd_His') . '_' . bin2hex(random_bytes(5)) . '.' . $extension;
            $dest = tenant_path($tenant) . '/input/attachments/' . $name;
            if (!move_uploaded_file($f['tmp_name'], $dest))
                throw new RuntimeException('Datei konnte nicht gespeichert werden.');
            @chmod($dest, 0640);
            audit_log('attachment.upload', $tenant, $name);
            flash('ok', 'Anhang gespeichert: ' . $name);
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

$tenants = all_tenants();
$tenant = (string) ($_GET['tenant'] ?? array_key_first($tenants) ?? '');
$view = (string) ($_GET['view'] ?? 'overview');
$allowedViews = ['overview', 'assets', 'networks', 'locations', 'connections', 'findings', 'notes', 'map', 'report', 'settings'];
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
    <title><?= e(APP_NAME) ?></title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #090d12;
            --panel: #0f151d;
            --panel2: #131b25;
            --line: #263241;
            --text: #e5edf5;
            --muted: #8697aa;
            --accent: #4d9eff;
            --ok: #45c486;
            --warn: #e6b450;
            --bad: #ff6174
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
            grid-template-columns: 270px 1fr;
            min-height: 100vh
        }

        .side {
            border-right: 1px solid var(--line);
            background: #0c1219;
            padding: 16px;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow: auto
        }

        .brand {
            font-weight: 700;
            letter-spacing: .03em;
            padding: 5px 7px 18px
        }

        .tenant-tree a {
            display: block;
            color: var(--text);
            text-decoration: none;
            padding: 7px;
            border-radius: 4px
        }

        .tenant-tree a:hover,
        .tenant-tree a.on {
            background: var(--panel2)
        }

        .tree-child {
            margin-left: 14px;
            border-left: 1px solid var(--line);
            padding-left: 7px
        }

        .nav {
            display: block;
            text-decoration: none;
            color: var(--muted);
            padding: 8px 10px;
            margin: 2px 0;
            border-radius: 4px
        }

        .nav:hover,
        .nav.active {
            color: var(--text);
            background: var(--panel2)
        }

        .nav.active {
            box-shadow: inset 2px 0 var(--accent)
        }

        .main {
            padding: 22px;
            min-width: 0
        }

        .top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px
        }

        .top h1 {
            font-size: 20px;
            margin: 0
        }

        .muted {
            color: var(--muted)
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

        .btn.primary,
        button.primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #06111d;
            font-weight: 700
        }

        .btn.danger,
        button.danger {
            color: #ff8795
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px
        }

        .card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 14px
        }

        .metric {
            font-size: 26px;
            font-weight: 700
        }

        .section {
            margin-top: 14px
        }

        .section h2 {
            font-size: 14px;
            margin: 0 0 12px
        }

        .toolbar {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 12px
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
            color: var(--muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em
        }

        tr:hover td {
            background: #111a24
        }

        .pill {
            display: inline-block;
            border: 1px solid var(--line);
            padding: 2px 6px;
            border-radius: 10px;
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

        dialog {
            width: min(820px, 94vw);
            max-height: 90vh;
            overflow: auto;
            background: var(--panel);
            color: var(--text);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 20px
        }

        dialog::backdrop {
            background: #000a
        }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px
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
            background: #0b1118;
            border: 1px solid var(--line);
            color: var(--text);
            padding: 8px;
            border-radius: 4px
        }

        textarea {
            min-height: 85px;
            resize: vertical
        }

        .full {
            grid-column: 1/-1
        }

        .actions {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            margin-top: 14px
        }

        .flash {
            padding: 10px 12px;
            border: 1px solid var(--line);
            margin-bottom: 10px;
            background: var(--panel)
        }

        .flash.ok {
            border-color: #246b4b
        }

        .flash.error {
            border-color: #8c3340
        }

        .empty {
            padding: 25px;
            color: var(--muted);
            text-align: center;
            border: 1px dashed var(--line)
        }

        svg {
            width: 100%;
            background: var(--panel);
            border: 1px solid var(--line)
        }

        svg rect {
            fill: #162231;
            stroke: #3a4a5d
        }

        .link {
            stroke: #4d657d;
            stroke-width: 2
        }

        .node-title,
        .node-sub,
        .edge {
            fill: #e5edf5;
            text-anchor: middle;
            font-size: 12px
        }

        .node-sub,
        .edge {
            fill: #8697aa;
            font-size: 10px
        }

        .report {
            background: #fff;
            color: #17202b;
            padding: 28px;
            max-width: 1100px
        }

        .report .card {
            background: #fff;
            border-color: #ccd3db
        }

        .report table {
            background: #fff;
            border-color: #ccd3db
        }

        .report td,
        .report th {
            border-color: #ccd3db
        }

        .scope {
            margin-left: auto
        }

        .small {
            font-size: 11px
        }

        .logout {
            margin-top: 20px;
            width: 100%
        }

        @media(max-width:900px) {
            .shell {
                grid-template-columns: 1fr
            }

            .side {
                position: static;
                height: auto;
                border-right: 0;
                border-bottom: 1px solid var(--line)
            }

            .grid {
                grid-template-columns: repeat(2, 1fr)
            }

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
            <div class="brand">NETWORK AUDIT <span class="muted">v<?= e(APP_VERSION) ?></span></div>
            <div class="tenant-tree">
                <div class="muted small" style="padding:7px">TENANTS</div><?php
                function render_tree(array $all, ?string $parent, string $active, int $depth = 0): void
                {
                    foreach ($all as $id => $t)
                        if (($t['parent'] ?? null) === $parent) {
                            echo '<div class="' . ($depth ? 'tree-child' : '') . '"><a class="' . ($id === $active ? 'on' : '') . '" href="?tenant=' . e($id) . '">' . e($t['name']) . '</a>';
                            render_tree($all, $id, $active, $depth + 1);
                            echo '</div>';
                        }
                }
                render_tree($tenants, null, $tenant); ?>
            </div><button onclick="document.getElementById('tenant-new').showModal()" style="width:100%;margin:12px 0">+
                Tenant</button><?php if ($current): ?>
                <hr style="border:0;border-top:1px solid var(--line)">
                <?= nav_link($tenant, 'overview', 'Übersicht') ?>    <?= nav_link($tenant, 'assets', 'Assets') ?>    <?= nav_link($tenant, 'networks', 'Netzwerke') ?>    <?= nav_link($tenant, 'locations', 'Standorte / Racks') ?>    <?= nav_link($tenant, 'connections', 'Verbindungen') ?>    <?= nav_link($tenant, 'findings', 'Findings') ?>    <?= nav_link($tenant, 'notes', 'Notizen') ?>    <?= nav_link($tenant, 'map', 'Netzwerkkarte') ?>    <?= nav_link($tenant, 'report', 'Auditbericht') ?>    <?= nav_link($tenant, 'settings', 'Tenant-Einstellungen') ?><?php endif; ?>
            <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                    name="action" value="logout"><button class="logout">Abmelden</button></form>
        </aside>
        <main class="main">
            <?php foreach ($flashes as $f): ?>
                <div class="flash <?= e($f['type']) ?>"><?= e($f['message']) ?></div><?php endforeach; ?><?php if ($error): ?>
                <div class="flash error"><?= e($error) ?></div><?php endif; ?>
            <?php if (!$current): ?>
                <div class="top">
                    <h1>Kein Tenant ausgewählt</h1>
                </div>
                <div class="empty">Lege den ersten Kunden oder Mandanten an.</div><?php else: ?>
                <div class="top">
                    <div>
                        <h1><?= e($current['name']) ?></h1>
                        <div class="muted"><?= e($current['type']) ?> · <?= e($current['id']) ?></div>
                    </div>
                    <form method="get" class="toolbar"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input
                            type="hidden" name="view" value="<?= e($view) ?>"><select name="scope"
                            onchange="this.form.submit()">
                            <option value="own" <?= $includeChildren ? '' : 'selected' ?>>Nur dieser Tenant</option>
                            <option value="all" <?= $includeChildren ? 'selected' : '' ?>>Mit Sub-Tenants</option>
                        </select></form>
                </div>
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
                            <div class="muted">Dokumentationsgrad</div>
                        </div>
                    </div>
                    <section class="section card">
                        <h2>Asset-Typen</h2><?php foreach ($summary['types'] as $k => $v): ?><span class="pill"><?= e($k) ?>:
                                <?= e($v) ?></span> <?php endforeach; ?>
                    </section>
                    <section class="section card">
                        <h2>Risiken</h2><?php foreach ($summary['severity'] as $k => $v): ?><span
                                class="pill <?= e($k) ?>"><?= e($k) ?>: <?= e($v) ?></span> <?php endforeach; ?>
                    </section>
                    <section class="section card">
                        <h2>Ausgaben</h2>
                        <form method="post" class="toolbar"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                                type="hidden" name="action" value="generate"><input type="hidden" name="tenant"
                                value="<?= e($tenant) ?>"><input type="hidden" name="return_view" value="overview"><label
                                style="display:flex;gap:7px;align-items:center"><input style="width:auto;margin:0"
                                    type="checkbox" name="children" value="1" <?= $includeChildren ? 'checked' : '' ?>> Sub-Tenants
                                einschließen</label><button class="primary">JSON, CSV und HTML neu erzeugen</button></form>
                        <div class="muted small">Ablage: tenant/<?= e($tenant) ?>/output/</div>
                    </section>
                    <section class="section card">
                        <h2>Anhang hochladen</h2>
                        <form method="post" enctype="multipart/form-data" class="toolbar"><input type="hidden" name="csrf"
                                value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="upload"><input type="hidden"
                                name="tenant" value="<?= e($tenant) ?>"><input type="file" name="attachment"
                                required><button>Hochladen</button></form>
                        <div class="muted small">JPG, PNG, PDF, TXT oder CSV; maximal 20 MB.</div>
                    </section>
                <?php elseif (in_array($view, ['assets', 'networks', 'locations', 'connections', 'findings', 'notes'], true)): $rows = tenant_rows($tenant, $view, $includeChildren); ?>
                    <div class="toolbar"><button class="primary" onclick="openEditor('<?= e($view) ?>',{})">+
                            Eintrag</button><span class="muted"><?= count($rows) ?> Einträge</span></div>
                    <table>
                        <thead>
                            <tr><?php if ($includeChildren): ?>
                                    <th>Tenant</th><?php endif; ?>
                                <th>ID</th>
                                <th>Bezeichnung</th>
                                <th>Details</th>
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
                                    <td class="small"><?= e($r['id'] ?? '') ?></td>
                                    <td><?= e($label) ?></td>
                                    <td><?= e(text_cut((string) $details, 100)) ?></td>
                                    <td><span
                                            class="pill <?= e($r['severity'] ?? '') ?>"><?= e($r['status'] ?? $r['verification'] ?? '') ?></span>
                                    </td>
                                    <td><?php if (($r['_tenant'] ?? $tenant) === $tenant): ?><button
                                                onclick='openEditor(<?= json_encode($view) ?>,<?= json_encode($r, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button>
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
                <?php elseif ($view === 'map'): ?>
                    <div class="toolbar"><span class="muted">Aus Asset-Verbindungen erzeugt</span></div>
                    <?= svg_map($tenant, $includeChildren) ?>
                <?php elseif ($view === 'report'): ?>
                    <div class="report">
                        <h1>Netzwerk-Audit: <?= e($current['name']) ?></h1>
                        <p>Stand: <?= e(now()) ?></p>
                        <div class="grid">
                            <div class="card">
                                <div class="metric"><?= count($summary['assets']) ?></div>Assets
                            </div>
                            <div class="card">
                                <div class="metric"><?= count($summary['networks']) ?></div>Netze
                            </div>
                            <div class="card">
                                <div class="metric"><?= array_sum($summary['severity']) ?></div>Offene Findings
                            </div>
                            <div class="card">
                                <div class="metric"><?= e($summary['documentation_percent']) ?>%</div>Dokumentation
                            </div>
                        </div>
                        <h2>Offene Feststellungen</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Schwere</th>
                                    <th>Titel</th>
                                    <th>Kategorie</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody><?php foreach ($summary['findings'] as $f)
                                if (($f['status'] ?? 'open') !== 'closed'): ?>
                                        <tr>
                                            <td class="<?= e($f['severity'] ?? '') ?>"><?= e($f['severity'] ?? '') ?></td>
                                            <td><?= e($f['title'] ?? '') ?></td>
                                            <td><?= e($f['category'] ?? '') ?></td>
                                            <td><?= e($f['status'] ?? '') ?></td>
                                        </tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                <?php elseif ($view === 'settings'): ?>
                    <section class="card">
                        <h2>Tenant-Einstellungen</h2>
                        <form method="post" class="form-grid"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                                type="hidden" name="action" value="tenant_update"><input type="hidden" name="tenant"
                                value="<?= e($tenant) ?>"><?= field('name', 'Name', $current['name'] ?? '', 'text', 'required') ?><?= selectf('type', 'Typ', ['customer' => 'Kunde', 'subsidiary' => 'Tochtergesellschaft', 'branch' => 'Niederlassung', 'department' => 'Abteilung', 'business-unit' => 'Geschäftseinheit', 'external-customer' => 'Externer Kunde'], $current['type'] ?? 'customer') ?><?= selectf('parent', 'Übergeordneter Tenant', ['' => 'Keiner'] + array_map(fn($t) => $t['name'], $tenants), $current['parent'] ?? '') ?><?= selectf('status', 'Status', ['active' => 'Aktiv', 'inactive' => 'Inaktiv', 'archived' => 'Archiviert'], $current['status'] ?? 'active') ?>
                            <div class="actions full"><button class="primary">Speichern</button></div>
                        </form>
                    </section><?php endif; ?><?php endif; ?>
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
    <dialog id="editor">
        <h2 id="editor-title">Eintrag</h2>
        <form method="post" id="editor-form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                type="hidden" name="action" value="save_item"><input type="hidden" name="tenant"
                value="<?= e($tenant) ?>"><input type="hidden" name="kind"><input type="hidden" name="id"><input
                type="hidden" name="return_view">
            <div class="form-grid" id="editor-fields"></div>
            <div class="actions"><button type="button"
                    onclick="document.getElementById('editor').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
        </form>
    </dialog>
    <script>
        const assets = <?= json_encode($current ? items($tenant, 'assets') : [], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>;
        const locations = <?= json_encode($current ? items($tenant, 'locations') : [], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>;
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        const input = (n, l, v = '', type = 'text') => `<label>${esc(l)}<input type="${type}" name="${esc(n)}" value="${esc(v)}"></label>`;
        const area = (n, l, v = '') => `<label class="full">${esc(l)}<textarea name="${esc(n)}">${esc(v)}</textarea></label>`;
        const sel = (n, l, o, v = '') => `<label>${esc(l)}<select name="${esc(n)}">${Object.entries(o).map(([k, x]) => `<option value="${esc(k)}" ${String(k) === String(v) ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></label>`;
        const check = (n, l, v) => `<label><input style="width:auto" type="checkbox" name="${esc(n)}" value="1" ${v ? 'checked' : ''}> ${esc(l)}</label>`;
        function openEditor(kind, r) {
            const f = document.getElementById('editor-form'); f.kind.value = kind; f.id.value = r.id || ''; f.return_view.value = kind; let h = ''; const statuses = { active: 'Aktiv', inactive: 'Inaktiv', retired: 'Außer Betrieb', unknown: 'Unbekannt' };
            if (kind === 'assets') { h = input('name', 'Name', r.name) + sel('type', 'Typ', { client: 'Client', laptop: 'Laptop / Notebook', desktop: 'Desktop', server: 'Server', vm: 'Virtuelle Maschine', container: 'Container', firewall: 'Firewall', router: 'Router', switch: 'Switch', access_point: 'Access Point', printer: 'Drucker', nas: 'NAS', camera: 'Kamera', phone: 'Telefon', domain: 'Domain', website: 'Website', ip: 'IP-Objekt', other: 'Sonstiges' }, r.type) + input('hostname', 'Hostname', r.hostname) + input('fqdn', 'FQDN', r.fqdn) + input('manufacturer', 'Hersteller', r.manufacturer) + input('model', 'Modell', r.model) + input('serial_number', 'Seriennummer', r.serial_number) + input('inventory_number', 'Inventarnummer', r.inventory_number) + input('ipv4', 'IPv4, getrennt mit Komma', (r.ipv4 || []).join(', ')) + input('ipv6', 'IPv6, getrennt mit Komma', (r.ipv6 || []).join(', ')) + input('mac', 'MAC, getrennt mit Komma', (r.mac || []).join(', ')) + input('vlan', 'VLAN', r.vlan) + input('gateway', 'Gateway', r.gateway) + input('dns', 'DNS, getrennt mit Komma', (r.dns || []).join(', ')) + input('services', 'Dienste, z.B. HTTPS, SSH', (r.services || []).join(', ')) + input('web_url', 'Webinterface-URL', r.web_url, 'url') + sel('location_id', 'Standort', Object.fromEntries([['', 'Nicht zugeordnet'], ...locations.map(x => [x.id, x.name])]), r.location_id) + sel('criticality', 'Kritikalität', { low: 'Niedrig', normal: 'Normal', high: 'Hoch', critical: 'Kritisch' }, r.criticality) + sel('status', 'Status', statuses, r.status) + sel('source', 'Quelle', { manual: 'Manuell', discovery: 'Discovery', import: 'Import', customer: 'Kundenangabe' }, r.source) + sel('verification', 'Prüfung', { unverified: 'Ungeprüft', observed: 'Beobachtet', verified: 'Verifiziert', conflicting: 'Widersprüchlich' }, r.verification) + input('os_version', 'Betriebssystem / Version', r.os_version) + input('firmware', 'Firmware', r.firmware) + input('support_end', 'Supportende', r.support_end, 'date') + check('backup', 'Backup vorhanden', r.backup) + check('monitoring', 'Monitoring vorhanden', r.monitoring) + check('documented', 'Dokumentiert', r.documented) + area('notes', 'Notizen', r.notes) }
            if (kind === 'networks') h = input('name', 'Name', r.name) + input('cidr', 'CIDR, z.B. 192.168.10.0/24', r.cidr) + input('vlan', 'VLAN', r.vlan) + input('gateway', 'Gateway', r.gateway) + input('dns', 'DNS, getrennt mit Komma', (r.dns || []).join(', ')) + sel('status', 'Status', statuses, r.status) + area('purpose', 'Zweck', r.purpose) + area('notes', 'Notizen', r.notes);
            if (kind === 'locations') h = input('name', 'Name', r.name) + input('building', 'Gebäude', r.building) + input('room', 'Raum', r.room) + input('rack', 'Rack', r.rack) + input('rack_unit', 'Höheneinheit', r.rack_unit) + input('patch_panel', 'Patchfeld', r.patch_panel) + input('patch_port', 'Patchport', r.patch_port) + area('notes', 'Notizen', r.notes);
            if (kind === 'connections') { const ao = Object.fromEntries(assets.map(x => [x.id, (x.name || x.id) + ' (' + (x.hostname || x.type || '') + ')'])); h = sel('source_asset', 'Quelle', ao, r.source_asset) + sel('target_asset', 'Ziel', ao, r.target_asset) + sel('connection_type', 'Verbindung', { ethernet: 'Ethernet', fiber: 'Glasfaser', wifi: 'WLAN', vpn: 'VPN', virtual: 'Virtuell', logical: 'Logisch', unknown: 'Unbekannt' }, r.connection_type) + input('source_port', 'Quellport', r.source_port) + input('target_port', 'Zielport', r.target_port) + input('vlan', 'VLAN', r.vlan) + sel('status', 'Status', { confirmed: 'Bestätigt', observed: 'Beobachtet', assumed: 'Angenommen', inactive: 'Inaktiv' }, r.status) + area('notes', 'Notizen', r.notes) }
            if (kind === 'findings') { const ao = Object.fromEntries([['', 'Allgemein'], ...assets.map(x => [x.id, x.name || x.id])]); h = sel('asset_id', 'Asset', ao, r.asset_id) + sel('severity', 'Schwere', { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Information' }, r.severity) + input('category', 'Kategorie', r.category) + input('title', 'Titel', r.title) + sel('status', 'Status', { open: 'Offen', accepted: 'Akzeptiert', in_progress: 'In Bearbeitung', resolved: 'Behoben', closed: 'Geschlossen' }, r.status) + area('description', 'Beschreibung', r.description) + area('recommendation', 'Empfehlung', r.recommendation) }
            if (kind === 'notes') h = input('title', 'Titel', r.title) + sel('status', 'Status', { open: 'Offen', clarified: 'Geklärt', closed: 'Geschlossen' }, r.status) + area('body', 'Inhalt', r.body);
            document.getElementById('editor-fields').innerHTML = h; document.getElementById('editor-title').textContent = (r.id ? 'Eintrag bearbeiten' : 'Eintrag anlegen'); document.getElementById('editor').showModal();
        }
    </script>
</body>

</html>
