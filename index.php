<?php
declare(strict_types=1);

/*
 * Network Documentation Tool
 * Single-file, dependency-free PHP application.
 * Requires PHP 7.4+ with standard JSON and session support. No optional PHP extensions are used.
 */

const APP_NAME = 'NADA';
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
    $raw = json_read(USERS_FILE);
    $out = [];
    foreach ($raw as $u) {
        if (!is_array($u))
            continue;
        $name = clean_text((string) ($u['username'] ?? $u['user'] ?? ''), 40);
        $hash = (string) ($u['password_hash'] ?? $u['hash'] ?? '');
        if ($name === '' || $hash === '')
            continue;
        $legacyRole = (string) ($u['role'] ?? 'readonly');
        $legacyScope = ($u['scope'] ?? 'all') === 'selected' ? 'selected' : 'all';
        $legacyGlobal = array_key_exists('global_admin', $u) ? (bool) $u['global_admin'] : ($legacyRole === 'GlobalAdmin' || ($legacyRole === 'admin' && $legacyScope === 'all'));
        $manageUsers = array_key_exists('manage_users', $u) ? (bool) $u['manage_users'] : $legacyGlobal;
        $storedRights = array_map('strval', $u['write_rights'] ?? []);
        $legacyTenantEdit = in_array('tenant_edit', $storedRights, true) || in_array('tenant_icon', $storedRights, true);
        $legacyFindings = (bool) array_intersect(['findings', 'findings_create', 'findings_edit', 'findings_delete', 'findings_attach'], $storedRights);
        $manageTenants = array_key_exists('manage_tenants', $u) ? ((bool) $u['manage_tenants'] || $legacyTenantEdit) : ($legacyGlobal || $legacyTenantEdit);
        $readScope = ($u['read_scope'] ?? $legacyScope) === 'selected' ? 'selected' : 'all';
        $readTenants = array_values(array_filter(array_map('strval', $u['read_tenants'] ?? $u['tenants'] ?? [])));
        $writeMode = $u['write_mode'] ?? ($legacyRole === 'admin' ? 'full' : 'none');
        $legacyRights = [];
        if ($writeMode === 'findings')
            $legacyRights = ['findings'];
        if ($writeMode === 'full')
            $legacyRights = ['findings', 'reports_generate'];
        $allowedRights = ['findings', 'reports_generate'];
        $rightsSource = $u['write_rights'] ?? $legacyRights;
        if ($legacyFindings && !in_array('findings', $rightsSource, true))
            $rightsSource[] = 'findings';
        $rights = array_values(array_intersect($allowedRights, array_map('strval', $rightsSource)));
        $writeScope = ($u['write_scope'] ?? $legacyScope) === 'all' ? 'all' : 'selected';
        $writeTenants = array_values(array_filter(array_map('strval', $u['write_tenants'] ?? $u['tenants'] ?? [])));
        $record = ['username' => $name, 'password_hash' => $hash, 'manage_users' => $manageUsers, 'manage_tenants' => $manageTenants, 'read_scope' => $readScope, 'read_tenants' => $readScope === 'all' ? [] : $readTenants, 'write_scope' => $writeScope, 'write_tenants' => $writeScope === 'all' ? [] : $writeTenants, 'write_rights' => $rights, 'created_at' => $u['created_at'] ?? now()];

        $out[] = $record;
    }
    $hasManager = (bool) array_filter($out, fn($u) => !empty($u['manage_users']));
    if (!$hasManager && count($out) === 1) {
        $out[0]['manage_users'] = true;
        $out[0]['manage_tenants'] = true;
        $out[0]['read_scope'] = 'all';
        $out[0]['read_tenants'] = [];
        $out[0]['write_scope'] = 'all';
        $out[0]['write_tenants'] = [];
        $out[0]['write_rights'] = ['findings', 'reports_generate'];
    }
    if (!$hasManager && is_file(STORAGE_DIR . '/global-admin.txt')) {
        $owner = trim((string) file_get_contents(STORAGE_DIR . '/global-admin.txt'));
        foreach ($out as &$u)
            if ($u['username'] === $owner) {
                $u['manage_users'] = true;
                $u['manage_tenants'] = true;
                $u['read_scope'] = 'all';
                $u['read_tenants'] = [];
                $u['write_scope'] = 'all';
                $u['write_tenants'] = [];
                $u['write_rights'] = ['findings', 'reports_generate'];
            }
        unset($u);
    }
    return $out;
}
function save_users(array $users): void
{
    json_write(USERS_FILE, array_values($users));
}
function current_user(): array
{
    return is_array($_SESSION['user'] ?? null) ? $_SESSION['user'] : [];
}
function can_manage_users(): bool
{
    return !empty(current_user()['manage_users']);
}
function can_manage_tenants(): bool
{
    return !empty(current_user()['manage_tenants']);
}
function is_global_admin(): bool
{
    return can_manage_users() && can_manage_tenants();
}
function can_access_tenant(string $id): bool
{
    $u = current_user();
    return !empty($u) && (($u['read_scope'] ?? 'all') === 'all' || in_array($id, $u['read_tenants'] ?? [], true));
}
function write_scope_allows(string $id): bool
{
    $u = current_user();
    return !empty($u) && (($u['write_scope'] ?? 'selected') === 'all' || in_array($id, $u['write_tenants'] ?? [], true));
}
function has_write_right(string $right, string $id): bool
{
    $u = current_user();
    return write_scope_allows($id) && in_array($right, $u['write_rights'] ?? [], true);
}
function can_write_findings(string $id): bool
{
    return has_write_right('findings', $id);
}
function can_open_settings(string $id): bool
{
    return can_manage_tenants();
}
function require_write_right(string $right, string $tenant): void
{
    if (!has_write_right($right, $tenant))
        throw new RuntimeException('Das erforderliche Schreibrecht fehlt.');
}
function require_user_management(): void
{
    if (!can_manage_users())
        throw new RuntimeException('Keine Berechtigung zur Benutzerverwaltung.');
}
function require_tenant_management(): void
{
    if (!can_manage_tenants())
        throw new RuntimeException('Keine Berechtigung zur Tenantverwaltung.');
}
function require_global_admin(): void
{
    if (!is_global_admin())
        throw new RuntimeException('Benutzer- und Tenantverwaltung erforderlich.');
}
function delete_tree(string $path): void
{
    if (!is_dir($path))
        return;
    foreach (scandir($path) ?: [] as $n) {
        if ($n === '.' || $n === '..')
            continue;
        $f = $path . '/' . $n;
        is_dir($f) ? delete_tree($f) : @unlink($f);
    }
    @rmdir($path);
}
function logged_in(): bool
{
    return !empty(current_user());
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
    foreach ($ids as $tid) {
        if (!can_access_tenant($tid))
            continue;
        foreach (items($tid, $kind) as $r) {
            $r['_tenant'] = $tid;
            $rows[] = $r;
        }
    }
    return $rows;
}
function finding_title(array $r, array $assets): string
{
    $type = (string) ($r['finding_type'] ?? 'note');
    $host = clean_text((string) ($r['hostname'] ?? ''), 80);
    if ($type === 'asset')
        return ($host !== '' ? $host : clean_text((string) ($r['asset_type'] ?? 'Gerät'), 40)) . ' erfasst';
    if ($type === 'network')
        return 'Netzwerk ' . (clean_text((string) ($r['vlan'] ?? $r['cidr'] ?? ''), 80) ?: 'erfasst');
    if ($type === 'connection') {
        $asset = '';
        foreach ($assets as $a)
            if (($a['id'] ?? '') === ($r['source_asset'] ?? '')) {
                $asset = clean_text((string) ($a['hostname'] ?? $a['name'] ?? ''), 60);
                break;
            }
        $service = clean_text((string) ($r['service_name'] ?? ''), 60) ?: 'Dienst';
        $ip = clean_text((string) ($r['service_ip'] ?? ''), 60);
        return trim($service . ($ip !== '' ? ' auf ' . $ip : '') . ($asset !== '' ? ' · ' . $asset : ''));
    }
    if ($type === 'location')
        return 'Standort ' . (clean_text(trim((string) ($r['building'] ?? '') . ' ' . (string) ($r['room'] ?? '') . ' ' . (string) ($r['rack'] ?? '')), 80) ?: 'erfasst');
    if ($type === 'risk') {
        $category = clean_text((string) ($r['category'] ?? ''), 60);
        $description = clean_text((string) ($r['description'] ?? ''), 80);
        return $category !== '' ? $category : ($description !== '' ? text_cut($description, 80) : 'Audit / Risiko');
    }
    $description = clean_text((string) ($r['description'] ?? ''), 80);
    return $description !== '' ? text_cut($description, 80) : 'Beobachtung';
}
function context_asset_name(array $finding): string
{
    $hostname = clean_text((string) ($finding['hostname'] ?? ''), 150);
    if ($hostname !== '')
        return $hostname;
    $manufacturer = clean_text((string) ($finding['manufacturer'] ?? ''), 100);
    $model = clean_text((string) ($finding['model'] ?? ''), 100);
    $hardware = trim($manufacturer . ' ' . $model);
    if ($hardware !== '')
        return $hardware;
    $labels = ['client' => 'Client', 'laptop' => 'Laptop / Notebook', 'desktop' => 'Desktop', 'server' => 'Server', 'vm' => 'Virtuelle Maschine', 'container' => 'Container', 'firewall' => 'Firewall', 'router' => 'Router', 'switch' => 'Switch', 'access_point' => 'Access Point', 'printer' => 'Drucker', 'nas' => 'NAS', 'camera' => 'Kamera', 'phone' => 'Telefon', 'domain' => 'Domain', 'website' => 'Website', 'ip' => 'IP-Objekt', 'other' => 'Gerät'];
    $type = (string) ($finding['asset_type'] ?? 'other');
    return $labels[$type] ?? 'Gerät';
}
function derived_context(string $tenant, bool $children): array
{
    $findings = tenant_rows($tenant, 'findings', $children);
    $assets = tenant_rows($tenant, 'assets', $children);
    $networks = tenant_rows($tenant, 'networks', $children);
    $connections = tenant_rows($tenant, 'connections', $children);
    $locations = tenant_rows($tenant, 'locations', $children);
    foreach ($findings as $f) {
        $type = $f['finding_type'] ?? 'risk';
        if ($type === 'asset')
            $assets[] = ['id' => $f['id'], '_tenant' => $f['_tenant'] ?? $tenant, 'type' => $f['asset_type'] ?? 'other', 'name' => context_asset_name($f), 'hostname' => $f['hostname'] ?? '', 'manufacturer' => $f['manufacturer'] ?? '', 'model' => $f['model'] ?? '', 'serial_number' => $f['serial_number'] ?? '', 'ipv4' => $f['ipv4'] ?? [], 'ipv6' => $f['ipv6'] ?? [], 'dhcp' => (bool) ($f['dhcp'] ?? false), 'os_name' => $f['os_name'] ?? '', 'os_version' => $f['os_version'] ?? '', 'mac' => $f['mac'] ?? [], 'services' => [], 'location_id' => $f['location_id'] ?? '', 'status' => $f['status'] ?? 'observed', 'verification' => $f['verification'] ?? 'observed', 'service_name' => $f['service_name'] ?? '', 'service_protocol' => $f['service_protocol'] ?? '', 'service_port' => $f['service_port'] ?? '', 'service_ip' => $f['service_ip'] ?? '', 'notes' => $f['description'] ?? ''];
        elseif ($type === 'network')
            $networks[] = ['id' => $f['id'], '_tenant' => $f['_tenant'] ?? $tenant, 'name' => (($f['vlan'] ?? '') !== '' ? 'VLAN ' . $f['vlan'] : (($f['cidr'] ?? '') !== '' ? $f['cidr'] : 'Netzwerk')), 'cidr' => $f['cidr'] ?? '', 'vlan' => $f['vlan'] ?? '', 'gateway' => $f['gateway'] ?? '', 'status' => $f['status'] ?? 'observed', 'notes' => $f['description'] ?? ''];
        elseif ($type === 'connection')
            $connections[] = ['id' => $f['id'], '_tenant' => $f['_tenant'] ?? $tenant, 'source_asset' => $f['source_asset'] ?? '', 'target_asset' => $f['target_asset'] ?? '', 'connection_type' => $f['connection_type'] ?? 'unknown', 'source_port' => $f['source_port'] ?? '', 'target_port' => $f['target_port'] ?? '', 'vlan' => $f['vlan'] ?? '', 'status' => $f['verification'] ?? 'observed', 'notes' => $f['description'] ?? ''];
        elseif ($type === 'location')
            $locations[] = ['id' => $f['id'], '_tenant' => $f['_tenant'] ?? $tenant, 'name' => trim((string) ($f['building'] ?? '') . ' ' . (string) ($f['room'] ?? '') . ' ' . (string) ($f['rack'] ?? '')) ?: 'Standort', 'building' => $f['building'] ?? '', 'room' => $f['room'] ?? '', 'rack' => $f['rack'] ?? '', 'notes' => $f['description'] ?? ''];
    }
    return compact('findings', 'assets', 'networks', 'connections', 'locations');
}
function export_outputs(string $tenant, bool $children): void
{
    $all = all_tenants();
    $ids = $children ? tenant_descendants($tenant, $all) : [$tenant];
    $out = tenant_path($tenant) . '/output';
    ensure_dir($out . '/exports');
    $context = derived_context($tenant, $children);
    $bundle = ['generated_at' => now(), 'tenant' => $tenant, 'included_tenants' => $ids] + $context;
    json_write($out . '/network-audit.json', $bundle, $tenant, 'output');
    $csv = fopen('php://temp', 'r+');
    fputcsv($csv, ['Tenant', 'ID', 'Typ', 'Name', 'Hostname', 'IPv4', 'MAC', 'Hersteller', 'Modell', 'Status']);
    foreach ($context['assets'] as $a)
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
    $context = derived_context($tenant, $children);
    $assets = $context['assets'];
    $findings = $context['findings'];
    $networks = $context['networks'];
    $connections = $context['connections'];
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
    $context = derived_context($tenant, $children);
    $assets = $context['assets'];
    $connections = $context['connections'];
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
    echo '<!doctype html><html lang="de"><meta charset="utf-8"><title>Startfehler</title><style>body{margin:0;background:#090d12;color:#e5edf5;font:14px system-ui;padding:40px}main{max-width:760px;margin:auto;background:#0f151d;border:1px solid #263241;padding:24px}code{color:#7eb6ff}</style><main><h1>Network Asset Documentation konnte nicht starten</h1><p>' . $safe . '</p><p>Prüfe PHP-Version und Schreibrechte. Das Verzeichnis <code>' . htmlspecialchars(__DIR__, ENT_QUOTES, 'UTF-8') . '</code> muss für den PHP-Webserver beschreibbar sein.</p></main></html>';
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
            json_write(USERS_FILE, [['username' => $u, 'password_hash' => password_hash($p, PASSWORD_DEFAULT), 'manage_users' => true, 'manage_tenants' => true, 'read_scope' => 'all', 'read_tenants' => [], 'write_scope' => 'all', 'write_tenants' => [], 'write_rights' => ['findings', 'reports_generate'], 'created_at' => now()]]);
            audit_log('system.setup');
            flash('ok', 'Administrator wurde angelegt.');
            header('Location: ?');
            exit;
        }
        if ($action === 'login') {
            foreach (users() as $u)
                if (hash_equals((string) $u['username'], trim((string) ($_POST['username'] ?? ''))) && password_verify((string) ($_POST['password'] ?? ''), (string) $u['password_hash'])) {
                    session_regenerate_id(true);
                    $_SESSION['user'] = $u;
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
        if ($action === 'user_save') {
            require_user_management();
            $list = users();
            $name = clean_text((string) ($_POST['username'] ?? ''), 40);
            $password = (string) ($_POST['password'] ?? '');
            if (!preg_match('/^[a-zA-Z0-9._-]{3,40}$/', $name))
                throw new InvalidArgumentException('Ungültiger Benutzername.');
            $index = -1;
            foreach ($list as $i => $u)
                if ($u['username'] === $name)
                    $index = $i;
            if ($index < 0 && strlen($password) < 12)
                throw new InvalidArgumentException('Neue Passwörter müssen mindestens 12 Zeichen haben.');
            $manageUsers = isset($_POST['manage_users']) && $_POST['manage_users'] === '1';
            $manageTenants = isset($_POST['manage_tenants']) && $_POST['manage_tenants'] === '1';
            $readScope = ($_POST['read_scope'] ?? 'selected') === 'all' ? 'all' : 'selected';
            $readTenants = array_values(array_intersect(array_keys(all_tenants()), array_map('strval', $_POST['read_tenants'] ?? [])));
            $allowedRights = ['findings', 'reports_generate'];
            $writeRights = array_values(array_intersect($allowedRights, array_map('strval', $_POST['write_rights'] ?? [])));
            $writeScope = ($_POST['write_scope'] ?? 'selected') === 'all' ? 'all' : 'selected';
            $writeTenants = array_values(array_intersect(array_keys(all_tenants()), array_map('strval', $_POST['write_tenants'] ?? [])));
            if ($readScope === 'selected' && !$readTenants)
                throw new InvalidArgumentException('Mindestens einen Lese-Tenant auswählen.');
            if ($writeRights && $writeScope === 'selected' && !$writeTenants)
                throw new InvalidArgumentException('Mindestens einen Schreib-Tenant auswählen.');
            if ($writeRights && $readScope === 'selected')
                $readTenants = array_values(array_unique(array_merge($readTenants, $writeScope === 'all' ? array_keys(all_tenants()) : $writeTenants)));
            $record = ['username' => $name, 'password_hash' => $index >= 0 ? $list[$index]['password_hash'] : password_hash($password, PASSWORD_DEFAULT), 'manage_users' => $manageUsers, 'manage_tenants' => $manageTenants, 'read_scope' => $readScope, 'read_tenants' => $readScope === 'all' ? [] : $readTenants, 'write_scope' => $writeScope, 'write_tenants' => $writeScope === 'all' ? [] : $writeTenants, 'write_rights' => $writeRights, 'created_at' => $index >= 0 ? $list[$index]['created_at'] : now()];
            if ($password !== '')
                $record['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
            if ($index >= 0)
                $list[$index] = $record;
            else
                $list[] = $record;
            if (!array_filter($list, fn($u) => !empty($u['manage_users'])))
                throw new RuntimeException('Mindestens ein Benutzer muss Benutzerverwaltung besitzen.');
            save_users($list);
            audit_log('user.save', '', $name);
            flash('ok', 'Benutzer und Rechte gespeichert.');
            header('Location: ?view=users');
            exit;
        }
        if ($action === 'user_delete') {
            require_user_management();
            $name = clean_text((string) ($_POST['username'] ?? ''), 40);
            if ($name === (current_user()['username'] ?? ''))
                throw new RuntimeException('Der angemeldete Benutzer kann nicht gelöscht werden.');
            $list = array_values(array_filter(users(), fn($u) => $u['username'] !== $name));
            if (!array_filter($list, fn($u) => !empty($u['manage_users'])))
                throw new RuntimeException('Mindestens ein Benutzer mit Benutzerverwaltung muss bestehen bleiben.');
            save_users($list);
            audit_log('user.delete', '', $name);
            flash('ok', 'Benutzer gelöscht.');
            header('Location: ?view=users');
            exit;
        }
        if ($action === 'tenant_create') {
            require_tenant_management();
            $id = create_tenant($_POST);
            flash('ok', 'Tenant wurde erstellt.');
            header('Location: ?tenant=' . urlencode($id));
            exit;
        }
        $tenant = safe_id((string) ($_POST['tenant'] ?? ''));
        if (!can_access_tenant($tenant))
            throw new RuntimeException('Kein Zugriff auf diesen Tenant.');
        tenant_path($tenant);
        if ($action === 'tenant_delete') {
            require_tenant_management();
            foreach (all_tenants() as $child)
                if (($child['parent'] ?? null) === $tenant)
                    throw new RuntimeException('Tenant besitzt Sub-Tenants. Diese zuerst löschen.');
            delete_tree(tenant_path($tenant));
            audit_log('tenant.delete', $tenant, $tenant);
            flash('ok', 'Tenant gelöscht.');
            header('Location: ?');
            exit;
        }
        if ($action === 'tenant_update')
            require_tenant_management();
        if ($action === 'generate')
            require_write_right('reports_generate', $tenant);
        if (in_array($action, ['save_item', 'delete_item'], true)) {
            $kind = (string) ($_POST['kind'] ?? '');
            if ($kind !== 'findings')
                throw new RuntimeException('Direkte Eingaben sind nur als Finding zulässig.');
            require_write_right('findings', $tenant);
        }
        if ($action === 'upload') {
            $target = (string) ($_POST['upload_target'] ?? '');
            $kind = (string) ($_POST['kind'] ?? '');
            if ($target === 'tenant_icon')
                require_tenant_management();
            elseif ($target === 'item_attachment' && $kind === 'findings')
                require_write_right('findings', $tenant);
            else
                throw new RuntimeException('Upload-Ziel nicht erlaubt.');
        }
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
                $findingType = clean_text((string) ($_POST['finding_type'] ?? 'risk'), 30);
                $assetType = clean_text((string) ($_POST['asset_type'] ?? 'other'), 60);
                $ipv4 = trim((string) ($_POST['ipv4'] ?? ''));
                $ipv6 = trim((string) ($_POST['ipv6'] ?? ''));
                $serviceIp = trim((string) ($_POST['service_ip'] ?? ''));
                if ($ipv4 !== '' && filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false)
                    throw new InvalidArgumentException('IPv4-Adresse ist ungültig.');
                if ($ipv6 !== '' && filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false)
                    throw new InvalidArgumentException('IPv6-Adresse ist ungültig.');
                if ($serviceIp !== '' && filter_var($serviceIp, FILTER_VALIDATE_IP) === false)
                    throw new InvalidArgumentException('Dienst-IP ist ungültig.');
                $port = trim((string) ($_POST['service_port'] ?? ''));
                if ($port !== '' && (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535))
                    throw new InvalidArgumentException('Port muss zwischen 1 und 65535 liegen.');
                $isAudit = $findingType === 'risk';
                $status = $isAudit && in_array($_POST['status'] ?? 'open', ['observed', 'open', 'in_progress', 'closed'], true) ? $_POST['status'] : 'observed';
                $verification = $isAudit ? clean_text((string) ($_POST['verification'] ?? 'observed'), 30) : 'observed';
                $severity = $isAudit ? clean_text((string) ($_POST['severity'] ?? 'info'), 20) : 'info';
                $recommendation = $isAudit ? clean_text((string) ($_POST['recommendation'] ?? '')) : ' ';
                if (!$isAudit)
                    $recommendation = '';
                $row = array_merge($base, [
                    'finding_type' => $findingType,
                    'title' => '',
                    'status' => $status,
                    'verification' => $verification,
                    'severity' => $severity,
                    'category' => clean_text((string) ($_POST['category'] ?? ''), 80),
                    'description' => clean_text((string) ($_POST['description'] ?? '')),
                    'recommendation' => $recommendation,
                    'asset_type' => $assetType,
                    'hostname' => clean_text((string) ($_POST['hostname'] ?? ''), 150),
                    'manufacturer' => clean_text((string) ($_POST['manufacturer'] ?? ''), 100),
                    'model' => clean_text((string) ($_POST['model'] ?? ''), 100),
                    'serial_number' => clean_text((string) ($_POST['serial_number'] ?? ''), 100),
                    'ipv4' => $ipv4 === '' ? [] : [$ipv4],
                    'ipv6' => $ipv6 === '' ? [] : [$ipv6],
                    'dhcp' => isset($_POST['dhcp']) && $_POST['dhcp'] === '1',
                    'os_name' => clean_text((string) ($_POST['os_name'] ?? ''), 100),
                    'os_version' => clean_text((string) ($_POST['os_version'] ?? ''), 100),
                    'mac' => csv_list((string) ($_POST['mac'] ?? '')),
                    'location_id' => clean_text((string) ($_POST['location_id'] ?? ''), 100),
                    'cidr' => clean_text((string) ($_POST['cidr'] ?? ''), 100),
                    'vlan' => clean_text((string) ($_POST['vlan'] ?? ''), 50),
                    'gateway' => clean_text((string) ($_POST['gateway'] ?? ''), 100),
                    'source_asset' => clean_text((string) ($_POST['source_asset'] ?? ''), 100),
                    'target_asset' => clean_text((string) ($_POST['target_asset'] ?? ''), 100),
                    'connection_type' => clean_text((string) ($_POST['connection_type'] ?? 'unknown'), 50),
                    'source_port' => clean_text((string) ($_POST['source_port'] ?? ''), 100),
                    'target_port' => clean_text((string) ($_POST['target_port'] ?? ''), 100),
                    'service_name' => clean_text((string) ($_POST['service_name'] ?? ''), 100),
                    'service_protocol' => clean_text((string) ($_POST['service_protocol'] ?? 'tcp'), 20),
                    'service_port' => $port,
                    'service_ip' => $serviceIp,
                    'building' => clean_text((string) ($_POST['building'] ?? ''), 100),
                    'room' => clean_text((string) ($_POST['room'] ?? ''), 100),
                    'rack' => clean_text((string) ($_POST['rack'] ?? ''), 100)
                ]);
                $row['title'] = finding_title($row, derived_context($tenant, false)['assets']);
                if ($row['title'] === '')
                    $row['title'] = 'Finding';
                if ($findingType === 'connection' && $row['source_asset'] === '' && $serviceIp === '')
                    throw new InvalidArgumentException('Für Verbindung / Dienst ist ein Quell-Asset oder eine Dienst-IP erforderlich.');
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

$normalizedUsers = users();
if (isset($_SESSION['user']) && !is_array($_SESSION['user']))
    unset($_SESSION['user']);
if (!empty($_SESSION['user'])) {
    $fresh = null;
    foreach ($normalizedUsers as $u)
        if ($u['username'] === ($_SESSION['user']['username'] ?? '')) {
            $fresh = $u;
            break;
        }
    if ($fresh === null)
        unset($_SESSION['user']);
    else
        $_SESSION['user'] = $fresh;
}
$hasUsers = count($normalizedUsers) > 0;
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
        if (!can_access_tenant($downloadTenant))
            throw new RuntimeException('Kein Zugriff.');
        $mode = (string) $_GET['download'];
        if ($mode === 'report') {
            $reportScope = (($_GET['report_scope'] ?? 'own') === 'all') ? 'all' : 'own';
            if (has_write_right('reports_generate', $downloadTenant))
                export_outputs($downloadTenant, $reportScope === 'all');
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

$tenants = array_filter(all_tenants(), fn($t) => can_access_tenant($t['id']));
$tenant = (string) ($_GET['tenant'] ?? array_key_first($tenants) ?? '');
$view = (string) ($_GET['view'] ?? 'overview');
$allowedViews = ['overview', 'map', 'reports', 'assets', 'findings', 'settings', 'users'];
if (!in_array($view, $allowedViews, true))
    $view = 'overview';
if ($view === 'users' && !can_manage_users())
    $view = 'overview';
if ($view === 'settings' && $tenant !== '' && !can_open_settings($tenant))
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
if ($current && $view === 'reports' && has_write_right('reports_generate', $tenant)) {
    try {
        export_outputs($tenant, $includeChildren);
    } catch (Throwable $reportError) {
        $error = $reportError->getMessage();
    }
}
$flashes = $_SESSION['flash'] ?? [];
unset($_SESSION['flash']);
function nav_link(string $tenant, string $view, string $label): string
{
    $active = ($_GET['view'] ?? 'overview') === $view ? ' active' : '';
    return '<a class="nav' . $active . '" href="?tenant=' . urlencode($tenant) . '&view=' . $view . '&scope=' . urlencode((string) ($_GET['scope'] ?? 'own')) . '">' . e($label) . '</a>';
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
            overflow: hidden;
            display: grid;
            grid-template-rows: auto auto minmax(120px, 1fr) auto auto;
            gap: 10px
        }

        .tenant-tree {
            min-height: 0;
            overflow: auto;
            overscroll-behavior: contain;
            scrollbar-gutter: stable;
            padding-right: 5px;
            border-top: 1px solid var(--line);
            border-bottom: 1px solid var(--line)
        }

        .tenant-tree::-webkit-scrollbar {
            width: 9px
        }

        .tenant-tree::-webkit-scrollbar-thumb {
            background: #34475b;
            border-radius: 8px
        }

        .tenant-tree::-webkit-scrollbar-track {
            background: transparent
        }

        .tenant-branch {
            margin: 0;
            padding: 0
        }

        .tenant-branch>summary {
            display: flex;
            align-items: center;
            gap: 4px;
            list-style: none;
            cursor: pointer
        }

        .tenant-branch>summary::-webkit-details-marker {
            display: none
        }

        .tenant-branch>summary::before {
            content: '›';
            width: 12px;
            flex: 0 0 12px;
            color: var(--muted);
            transform: rotate(0deg);
            transition: transform .12s ease
        }

        .tenant-branch[open]>summary::before {
            transform: rotate(90deg)
        }

        .tenant-leaf {
            padding-left: 16px
        }

        .tenant-children {
            margin-left: 11px;
            padding-left: 7px;
            border-left: 1px solid var(--line)
        }

        .tenant-nav {
            min-height: 0;
            overflow: auto;
            padding-top: 2px
        }

        .tenant-actions {
            flex: 0 0 auto
        }

        .logout-form {
            margin: 0
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

        .permission-column {
            border: 1px solid var(--line);
            border-radius: 7px;
            padding: 14px
        }

        .permission-column h3 {
            margin: 0 0 12px
        }

        .tenant-checks {
            max-height: 230px;
            overflow: auto;
            margin: 10px 0;
            padding: 8px;
            border: 1px solid var(--line)
        }

        .tenant-permission-panel {
            margin-top: 10px;
            border: 1px solid var(--line);
            border-radius: 5px
        }

        .tenant-permission-panel>summary {
            cursor: pointer;
            padding: 9px;
            color: var(--text)
        }

        .rights-list {
            display: grid;
            gap: 6px;
            margin-top: 12px
        }

        .rights-list label {
            display: block
        }

        .rights-list input {
            width: auto;
            margin: 0 6px 0 0
        }

        .tenant-checks label {
            display: block;
            padding: 4px
        }

        .tenant-checks input {
            width: auto;
            margin: 0 6px 0 0
        }

        .nav-group {
            margin-bottom: 10px
        }

        .nav-parent {
            font-weight: 700;
            color: var(--text)
        }

        .nav-sub {
            padding-left: 28px !important;
            font-size: 12px
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

        .finding-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 11px
        }

        .finding-group {
            display: none;
            grid-column: 1/-1;
            grid-template-columns: 1fr 1fr;
            gap: 11px
        }

        .finding-group.on {
            display: grid
        }

        .audit-only {
            display: none;
            grid-column: 1/-1;
            grid-template-columns: 1fr 1fr;
            gap: 11px
        }

        .audit-only.on {
            display: grid
        }

        .finding-notes {
            grid-column: 1/-1;
            order: 100;
            padding-top: 4px
        }

        .finding-notes label {
            margin: 0
        }

        .finding-optional {
            grid-column: 1/-1;
            border: 1px solid var(--line);
            border-radius: 5px;
            padding: 9px
        }

        .finding-optional summary {
            cursor: pointer;
            color: var(--text);
            font-weight: 600
        }

        .finding-optional .form-grid {
            margin-top: 10px
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
                height: auto;
                max-height: none;
                overflow: visible;
                display: block
            }

            .tenant-tree {
                max-height: 320px;
                margin-bottom: 10px
            }

            .tenant-nav {
                overflow: visible;
                margin-bottom: 10px
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
            <div class="brand">Network Asset Documentation</div>
            <nav class="tenant-nav"><?php if ($current): ?>
                    <div class="nav-group"><a
                            class="nav nav-parent <?= in_array($view, ['overview', 'assets', 'map', 'reports'], true) ? 'active' : '' ?>"
                            href="?tenant=<?= e($tenant) ?>&view=overview&scope=<?= e($_GET['scope'] ?? 'own') ?>">Übersicht</a><a
                            class="nav nav-sub <?= ($view === 'assets' ? 'active' : '') ?>"
                            href="?tenant=<?= e($tenant) ?>&view=assets&scope=<?= e($_GET['scope'] ?? 'own') ?>">Assets</a><a
                            class="nav nav-sub <?= ($view === 'map' ? 'active' : '') ?>"
                            href="?tenant=<?= e($tenant) ?>&view=map&scope=<?= e($_GET['scope'] ?? 'own') ?>">Netzwerkkarte</a><a
                            class="nav nav-sub <?= ($view === 'reports' ? 'active' : '') ?>"
                            href="?tenant=<?= e($tenant) ?>&view=reports&scope=<?= e($_GET['scope'] ?? 'own') ?>">Reports</a>
                    </div>
                    <?= nav_link($tenant, 'findings', 'Findings') ?>     <?php if (can_open_settings($tenant)): ?>
                        <?= nav_link($tenant, 'settings', 'Einstellungen') ?>     <?php endif; ?>
                    <?php if (can_manage_users()): ?>         <?= nav_link($tenant, 'users', 'Benutzer') ?>
                    <?php endif; ?><?php endif; ?>
            </nav>
            <div class="tenant-tree"><?php
            function tenant_has_active(array $all, string $id, string $active): bool
            {
                if ($id === $active)
                    return true;
                foreach ($all as $childId => $child)
                    if (($child['parent'] ?? null) === $id && tenant_has_active($all, $childId, $active))
                        return true;
                return false;
            }
            function render_tree_v3(array $all, ?string $parent, string $active): void
            {
                foreach ($all as $id => $t) {
                    if (($t['parent'] ?? null) !== $parent)
                        continue;
                    $children = [];
                    foreach ($all as $childId => $child)
                        if (($child['parent'] ?? null) === $id)
                            $children[] = $childId;
                    $icon = tenant_icon_data($t);
                    $node = '<a class="tenant-node ' . ($id === $active ? 'on' : '') . '" href="?tenant=' . e($id) . '&view=' . urlencode((string) ($_GET['view'] ?? 'overview')) . '&scope=' . urlencode((string) ($_GET['scope'] ?? 'own')) . '">' .
                        ($icon ? '<img class="tenant-mini" src="' . e($icon) . '">' : '<span class="tenant-mini fallback">' . e(strtoupper(substr((string) $t['name'], 0, 1))) . '</span>') .
                        '<span>' . e($t['name']) . '</span></a>';
                    if ($children) {
                        echo '<details class="tenant-branch" ' . (tenant_has_active($all, $id, $active) ? 'open' : '') . '><summary>' . $node . '</summary><div class="tenant-children">';
                        render_tree_v3($all, $id, $active);
                        echo '</div></details>';
                    } else {
                        echo '<div class="tenant-leaf">' . $node . '</div>';
                    }
                }
            }
            render_tree_v3($tenants, null, $tenant); ?></div>
            <div class="tenant-actions"><?php if (can_manage_tenants()): ?><button style="width:100%"
                        onclick="document.getElementById('tenant-new').showModal()">+ Tenant</button><?php endif; ?></div>
            <form method="post" class="logout-form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                    type="hidden" name="action" value="logout"><button class="logout">Abmelden</button></form>
        </aside>
        <main class="main">
            <?php foreach ($flashes as $f): ?>
                <div class="flash <?= e($f['type']) ?>"><?= e($f['message']) ?></div>
            <?php endforeach; ?><?php if ($error): ?>
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
                            <div class="crumbs">
                                <?php foreach ($chain as $i => $c): ?>         <?= $i ? ' / ' : '' ?>         <?= e($c['name']) ?>
                                <?php endforeach; ?>
                                ·
                                <?= e($current['type']) ?>
                            </div>
                        </div>
                    </div>
                    <?php $hasSubTenants = false;
                    foreach ($tenants as $st)
                        if (($st['parent'] ?? null) === $tenant) {
                            $hasSubTenants = true;
                            break;
                        } ?>
                    <button type="button"
                        onclick="toggleScope()"><?= $includeChildren ? 'Mit Sub-Tenants' : 'Nur dieser Tenant' ?></button>
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
                            href="?tenant=<?= e($tenant) ?>&view=map"><strong>Netzwerkkarte</strong><span
                                class="muted">Topologie
                                aus bestätigten und beobachteten Verbindungen anzeigen.</span></a><a
                            href="?tenant=<?= e($tenant) ?>&view=reports"><strong>Reports</strong><span class="muted">Erzeugte
                                Audit-Ausgaben herunterladen.</span></a></section>
                    <section class="section card">
                        <h2>Offene Risiken</h2><?php foreach ($summary['severity'] as $k => $v): ?><span
                                class="pill <?= e($k) ?>"><?= e($k) ?>: <?= e($v) ?></span> <?php endforeach; ?>
                    </section>
                <?php elseif ($view === 'map'): ?>         <?= svg_map($tenant, $includeChildren) ?>
                <?php elseif ($view === 'reports'): ?>
                    <section class="card">
                        <h2>Reports</h2>
                        <?php $reportFiles = ['audit-report.html' => 'Auditbericht (HTML)', 'network-audit.json' => 'Gesamtdaten (JSON)', 'assets.csv' => 'Asset-Inventar (CSV)'];
                        foreach ($reportFiles as $rf => $label):
                            $path = tenant_path($tenant) . '/output/' . ($rf === 'assets.csv' ? 'exports/' : '') . $rf; ?>
                            <div class="report-file">
                                <div><strong><?= e($label) ?></strong>
                                    <div class="muted small">
                                        <?= is_file($path) ? 'Erzeugt ' . date('d.m.Y H:i', filemtime($path)) : 'Noch nicht erzeugt' ?>
                                    </div>
                                </div><?php if (is_file($path)): ?><button type="button" class="btn"
                                        onclick='openReportDownload(<?= json_encode($rf) ?>)'>Download</button><?php endif; ?>
                            </div><?php endforeach; ?>
                    </section>
                <?php elseif ($view === 'assets'): $context = derived_context($tenant, $includeChildren);
                    $rows = $context['assets']; ?>
                    <section class="card">
                        <h2>Assets aus Findings</h2>

                        <table>
                            <thead>
                                <tr><?php if ($includeChildren): ?>
                                        <th>Tenant</th><?php endif; ?>
                                    <th>Asset</th>
                                    <th>Typ</th>
                                    <th>Netzwerk</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody><?php foreach ($rows as $r): ?>
                                    <tr><?php if ($includeChildren): ?>
                                            <td><?= e($r['_tenant'] ?? '') ?></td><?php endif; ?>
                                        <td><strong><?= e($r['name'] ?? '') ?></strong><?php if (($r['hostname'] ?? '') !== '' && strcasecmp((string) ($r['hostname'] ?? ''), (string) ($r['name'] ?? '')) !== 0): ?>
                                                <div class="muted small"><?= e($r['hostname']) ?></div><?php endif; ?>
                                        </td>
                                        <td><?= e($r['type'] ?? '') ?></td>
                                        <td><?= e(implode(', ', $r['ipv4'] ?? [])) ?></td>
                                        <td><?= e($r['verification'] ?? $r['status'] ?? '') ?></td>
                                    </tr><?php endforeach; ?>
                            </tbody>
                        </table><?php if (!$rows): ?>
                            <div class="empty">Noch keine Asset-Findings erfasst.</div><?php endif; ?>
                    </section>
                <?php elseif ($view === 'findings'): $rows = tenant_rows($tenant, 'findings', $includeChildren); ?>
                    <div class="toolbar"><?php if (has_write_right('findings', $tenant)): ?><button class="primary"
                                onclick="openEditor('findings',{})">+ Finding</button><?php endif; ?><span
                            class="muted"><?= count($rows) ?> Findings</span></div>
                    <table>
                        <thead>
                            <tr><?php if ($includeChildren): ?>
                                    <th>Tenant</th><?php endif; ?>
                                <th>Finding</th>
                                <th>Art</th>
                                <th>Kontext</th>
                                <th>Status</th>
                                <th>Anhänge</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody><?php foreach ($rows as $r): ?>
                                <tr><?php if ($includeChildren): ?>
                                        <td><?= e($r['_tenant'] ?? '') ?></td><?php endif; ?>
                                    <td><strong><?= e($r['title'] ?? '') ?></strong></td>
                                    <td><?= e($r['finding_type'] ?? 'risk') ?></td>
                                    <td><?= e(text_cut((string) ($r['description'] ?? ''), 100)) ?></td>
                                    <td><span
                                            class="pill <?= e($r['severity'] ?? '') ?>"><?= e($r['verification'] ?? $r['status'] ?? '') ?></span>
                                    </td>
                                    <td><?= count($r['attachments'] ?? []) ?><?php foreach (($r['attachments'] ?? []) as $a): ?><br><a
                                                class="small"
                                                href="?tenant=<?= e($r['_tenant'] ?? $tenant) ?>&download=attachment&kind=findings&item=<?= e($r['id']) ?>&file=<?= e($a['file']) ?>"><?= e($a['original'] ?? $a['file']) ?></a><?php endforeach; ?>
                                    </td>
                                    <td><?php if (($r['_tenant'] ?? $tenant) === $tenant && (has_write_right('findings', $tenant) || has_write_right('findings', $tenant) || has_write_right('findings', $tenant))): ?><?php if (has_write_right('findings', $tenant)): ?><button
                                                    onclick='openEditor("findings",<?= json_encode($r, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button>
                                                <button
                                                    onclick='openAttachment("findings",<?= json_encode($r['id']) ?>,<?= json_encode($r['title'] ?? 'Finding') ?>)'>Anhang</button>
                                                <form method="post" style="display:inline"
                                                    onsubmit="return confirm('Finding wirklich löschen?')"><input type="hidden" name="csrf"
                                                        value="<?= e(csrf()) ?>"><input type="hidden" name="action"
                                                        value="delete_item"><input type="hidden" name="tenant"
                                                        value="<?= e($tenant) ?>"><input type="hidden" name="kind" value="findings"><input
                                                        type="hidden" name="id" value="<?= e($r['id']) ?>"><input type="hidden"
                                                        name="return_view" value="findings"><button class="danger">Löschen</button></form>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </td>
                                </tr><?php endforeach; ?>
                        </tbody>
                    </table><?php if (!$rows): ?>
                        <div class="empty">Noch keine Findings.</div><?php endif; ?>
                <?php elseif ($view === 'users' && can_manage_users()): ?>
                    <div class="toolbar"><button class="primary" onclick="openUser({})">+ Benutzer</button></div>
                    <table>
                        <thead>
                            <tr>
                                <th>Benutzer</th>
                                <th>Lesebereich</th>
                                <th>Schreibbereich</th>
                                <th>Verwaltung</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody><?php foreach (users() as $u): ?>
                                <tr>
                                    <td><?= e($u['username']) ?></td>
                                    <td><?= e($u['read_scope'] === 'all' ? 'Alle Tenants' : implode(', ', $u['read_tenants'])) ?>
                                    </td>
                                    <td><?= e(empty($u['write_rights']) ? 'Kein Zugriff' : implode(', ', array_map(fn($r) => ['findings' => 'Findings', 'reports_generate' => 'Reports erzeugen'][$r] ?? $r, $u['write_rights'])) . ' · ' . ($u['write_scope'] === 'all' ? 'alle Tenants' : implode(', ', $u['write_tenants']))) ?>
                                    </td>
                                    <td><?= e(implode(', ', array_filter([$u['manage_users'] ? 'Benutzerverwaltung' : '', $u['manage_tenants'] ? 'Tenantverwaltung' : '']))) ?>
                                    </td>
                                    <td><button
                                            onclick='openUser(<?= json_encode($u, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button><?php if ($u['username'] !== (current_user()['username'] ?? '')): ?>
                                            <form method="post" style="display:inline" onsubmit="return confirm('Benutzer löschen?')">
                                                <input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                                                    name="action" value="user_delete"><input type="hidden" name="username"
                                                    value="<?= e($u['username']) ?>"><button class="danger">Löschen</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr><?php endforeach; ?>
                        </tbody>
                    </table>
                <?php elseif ($view === 'settings'): ?>
                    <?php if (can_open_settings($tenant)): ?>
                        <div class="grid" style="grid-template-columns:2fr 1fr">
                            <?php if (can_manage_tenants()): ?>
                                <section class="card">
                                    <h2>Tenant</h2>
                                    <form method="post" class="form-grid"><input type="hidden" name="csrf"
                                            value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="tenant_update"><input
                                            type="hidden" name="tenant"
                                            value="<?= e($tenant) ?>"><?= field('name', 'Name', $current['name'] ?? '', 'text', 'required') ?><?= selectf('type', 'Typ', ['customer' => 'Kunde', 'subsidiary' => 'Tochtergesellschaft', 'branch' => 'Niederlassung', 'department' => 'Abteilung', 'business-unit' => 'Geschäftseinheit', 'external-customer' => 'Externer Kunde'], $current['type'] ?? 'customer') ?><?= selectf('parent', 'Übergeordneter Tenant', ['' => 'Keiner'] + array_map(fn($t) => $t['name'], $tenants), $current['parent'] ?? '') ?><?= selectf('status', 'Status', ['active' => 'Aktiv', 'inactive' => 'Inaktiv', 'archived' => 'Archiviert'], $current['status'] ?? 'active') ?>
                                        <div class="actions full"><button class="primary">Speichern</button></div>
                                    </form>
                                </section><?php endif; ?>
                            <?php if (can_manage_tenants()): ?>
                                <section class="card">
                                    <h2>Tenant-Icon</h2><?php if ($iconData): ?><img class="tenant-head-icon"
                                            src="<?= e($iconData) ?>"><?php endif; ?>
                                    <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf"
                                            value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="upload"><input
                                            type="hidden" name="upload_target" value="tenant_icon"><input type="hidden" name="tenant"
                                            value="<?= e($tenant) ?>"><input type="hidden" name="return_view"
                                            value="settings"><label>PNG
                                            oder JPG, maximal 2 MB<input type="file" name="attachment" accept="image/png,image/jpeg"
                                                required></label>
                                        <div class="actions"><button class="primary">Icon speichern</button></div>
                                    </form>
                                </section><?php endif; ?>
                        </div><?php endif; ?>
                    <?php if (can_manage_tenants()): ?>
                        <section class="card section">
                            <h2>Tenant löschen</h2>
                            <p class="muted">Nur möglich, wenn keine Sub-Tenants vorhanden sind.</p>
                            <form method="post" onsubmit="return confirm('Tenant und alle Daten endgültig löschen?')"><input
                                    type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden" name="action"
                                    value="tenant_delete"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><button
                                    class="danger">Tenant löschen</button></form>
                        </section><?php endif; ?>
                <?php endif; ?><?php endif; ?>
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
    <dialog id="report-download-dialog">
        <h2>Report herunterladen</h2>
        <p>Sollen nur die Daten des aktuellen Tenants oder zusätzlich alle lesbaren Sub-Tenants enthalten sein?</p>
        <div class="actions"><button type="button" onclick="downloadReport('own')">Nur dieser Tenant</button><button
                type="button" class="primary" onclick="downloadReport('all')">Mit Sub-Tenants</button></div>
    </dialog>
    <dialog id="attachment">
        <h2 id="attachment-title">Anhang hinzufügen</h2>
        <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf"
                value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="upload"><input type="hidden"
                name="upload_target" value="item_attachment"><input type="hidden" name="tenant"
                value="<?= e($tenant) ?>"><input type="hidden" name="kind"><input type="hidden" name="item_id"><input
                type="hidden" name="return_view"><label>Bild oder
                Dokument<input type="file" name="attachment"
                    accept="image/png,image/jpeg,application/pdf,text/plain,text/csv" required></label>
            <div class="actions"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button class="primary">Anhängen</button>
            </div>
        </form>
    </dialog>
    <dialog id="user-dialog">
        <h2>Benutzerrechte</h2>
        <form method="post" class="form-grid"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input
                type="hidden" name="action" value="user_save"><label>Benutzername<input name="username"
                    required></label><label>Passwort<input type="password" name="password"
                    placeholder="Leer lassen = unverändert"></label>
            <section class="permission-column">
                <h3>Lesebereich</h3><label>Bereich<select name="read_scope" onchange="toggleUserPermissions()">
                        <option value="selected">Bestimmte Tenants</option>
                        <option value="all">Alle Tenants</option>
                    </select></label>
                <details id="read-tenants-panel" class="tenant-permission-panel">
                    <summary>Tenants auswählen</summary>
                    <div class="tenant-checks"><?php foreach (all_tenants() as $ut): ?><label><input type="checkbox"
                                    name="read_tenants[]" value="<?= e($ut['id']) ?>">
                                <?= e($ut['name']) ?></label><?php endforeach; ?></div>
                </details>
            </section>
            <section class="permission-column">
                <h3>Schreibbereich</h3><label>Bereich<select name="write_scope" onchange="toggleUserPermissions()">
                        <option value="selected">Bestimmte Tenants</option>
                        <option value="all">Alle Tenants</option>
                    </select></label>
                <details id="write-tenants-panel" class="tenant-permission-panel">
                    <summary>Tenants auswählen</summary>
                    <div class="tenant-checks"><?php foreach (all_tenants() as $ut): ?><label><input type="checkbox"
                                    name="write_tenants[]" value="<?= e($ut['id']) ?>">
                                <?= e($ut['name']) ?></label><?php endforeach; ?></div>
                </details>
                <div class="rights-list"><strong>Zugriff</strong><label><input type="checkbox" name="write_rights[]"
                            value="findings"> Findings</label><label><input type="checkbox" name="write_rights[]"
                            value="reports_generate"> Reports erzeugen</label><label><input type="checkbox"
                            name="manage_users" value="1"> Benutzerverwaltung</label><label><input type="checkbox"
                            name="manage_tenants" value="1"> Tenantverwaltung</label></div>
            </section>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
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
        function applyScope(scope) { const u = new URL(window.location.href); u.searchParams.set('scope', scope); window.location.href = u.toString() }
        function toggleScope() { const current = new URL(window.location.href).searchParams.get('scope') || 'own'; applyScope(current === 'all' ? 'own' : 'all') }
        let pendingReportFile = '';
        function openReportDownload(file) { pendingReportFile = file; document.getElementById('report-download-dialog').showModal() }
        function downloadReport(reportScope) { if (!pendingReportFile) return; const u = new URL(window.location.href); u.searchParams.set('download', 'report'); u.searchParams.set('file', pendingReportFile); u.searchParams.set('report_scope', reportScope); document.getElementById('report-download-dialog').close(); window.location.href = u.toString() }
        <?php $editorContext = $current ? derived_context($tenant, false) : ['assets' => [], 'locations' => []]; ?>
        function openUser(r) { const d = document.getElementById('user-dialog'), f = d.querySelector('form'), u = r || {}; f.reset(); f.querySelector('[name=username]').value = u.username || ''; f.querySelector('[name=username]').readOnly = !!u.username; f.querySelector('[name=read_scope]').value = u.read_scope || 'selected'; f.querySelector('[name=write_scope]').value = u.write_scope || 'selected'; f.querySelector('[name=manage_users]').checked = !!u.manage_users; f.querySelector('[name=manage_tenants]').checked = !!u.manage_tenants; f.querySelectorAll('[name="read_tenants[]"]').forEach(x => x.checked = (u.read_tenants || []).includes(x.value)); f.querySelectorAll('[name="write_tenants[]"]').forEach(x => x.checked = (u.write_tenants || []).includes(x.value)); f.querySelectorAll('[name="write_rights[]"]').forEach(x => x.checked = (u.write_rights || []).includes(x.value)); toggleUserPermissions(); d.showModal() }
        function toggleUserPermissions() { const d = document.getElementById('user-dialog'); if (!d) return; const rp = document.getElementById('read-tenants-panel'), wp = document.getElementById('write-tenants-panel'); rp.style.display = d.querySelector('[name=read_scope]').value === 'selected' ? 'block' : 'none'; wp.style.display = d.querySelector('[name=write_scope]').value === 'selected' ? 'block' : 'none'; if (rp.style.display === 'none') rp.open = false; if (wp.style.display === 'none') wp.open = false }
        const assets = <?= json_encode($editorContext['assets'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>, locations = <?= json_encode($editorContext['locations'], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>;
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        const input = (n, l, v = '', type = 'text', x = '') => `<label>${esc(l)}<input type="${type}" name="${esc(n)}" value="${esc(v)}" ${x}></label>`, area = (n, l, v = '') => `<label class="full">${esc(l)}<textarea name="${esc(n)}">${esc(v)}</textarea></label>`, sel = (n, l, o, v = '', change = '') => `<label>${esc(l)}<select name="${esc(n)}" ${change}>${Object.entries(o).map(([k, x]) => `<option value="${esc(k)}" ${String(k) === String(v) ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></label>`, check = (n, l, v) => `<label><input style="width:auto" type="checkbox" name="${esc(n)}" value="1" ${v ? 'checked' : ''}> ${esc(l)}</label>`;
        function pane(id, html, cls = '') { return `<div class="form-pane form-grid ${cls}" data-pane="${id}">${html}</div>` } function setPane(id) { document.querySelectorAll('.form-pane').forEach(x => x.classList.toggle('on', x.dataset.pane === id)); document.querySelectorAll('.modal-tab').forEach(x => x.classList.toggle('on', x.dataset.pane === id)) } function tabs(def) { document.getElementById('modal-tabs').innerHTML = def.map((x, i) => `<button type="button" class="modal-tab ${i ? '' : 'on'}" data-pane="${x[0]}" onclick="setPane('${x[0]}')">${x[1]}</button>`).join('') }
        function updateAssetLogic() { const t = document.querySelector('[name=type]')?.value || ''; document.querySelectorAll('.asset-network').forEach(x => x.style.display = ['domain', 'website'].includes(t) ? 'none' : 'grid'); document.querySelectorAll('.asset-physical').forEach(x => x.style.display = ['vm', 'container', 'domain', 'website', 'ip'].includes(t) ? 'none' : 'grid') }
        function validIPv4(value) { if (!value) return true; const p = value.split('.'); return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255) }
        function cleanIPv4(el) { el.value = el.value.replace(/[^0-9.]/g, '').slice(0, 15); const p = el.value.split('.'); el.setCustomValidity(validIPv4(el.value) ? '' : 'IPv4 muss aus vier Zahlen von 0 bis 255 bestehen.') }
        function cleanIPv6(el) { el.value = el.value.replace(/[^0-9a-fA-F:]/g, '').slice(0, 39) }
        function updateFindingLogic() { const d = document.getElementById('editor'), t = d.querySelector('[name=finding_type]')?.value || 'asset', a = d.querySelector('[name=asset_type]')?.value || ''; d.querySelectorAll('.finding-group').forEach(x => x.classList.toggle('on', x.dataset.types.split(' ').includes(t))); d.querySelectorAll('.laptop-only').forEach(x => x.style.display = t === 'asset' && a === 'laptop' ? 'grid' : 'none'); d.querySelectorAll('.audit-only').forEach(x => x.classList.toggle('on', t === 'risk')) }
        function openAttachment(kind, id, label) { const f = document.querySelector('#attachment form'); f.kind.value = kind; f.item_id.value = id; f.return_view.value = kind; document.getElementById('attachment-title').textContent = 'Anhang: ' + label; document.getElementById('attachment').showModal() }
        function openEditor(kind, r) {
            if (kind !== 'findings') return; const f = document.getElementById('editor-form'); f.reset(); f.kind.value = 'findings'; f.id.value = r.id || ''; f.return_view.value = 'findings'; document.getElementById('modal-tabs').innerHTML = ''; const ao = Object.fromEntries([['', 'Nicht zugeordnet'], ...assets.map(x => [x.id, x.hostname || x.name || x.id])]); const types = { asset: 'Gerät', network: 'Netzwerk / VLAN', connection: 'Verbindung / Dienst', location: 'Standort / Rack', risk: 'Audit / Risiko', note: 'Allgemeine Beobachtung' }; let h = '<div class="finding-form">' + sel('finding_type', 'Art des Findings', types, r.finding_type || 'asset', 'onchange="updateFindingLogic()"') +
                '<div class="finding-group" data-types="asset">' + sel('asset_type', 'Gerätetyp', { client: 'Client', laptop: 'Laptop / Notebook', desktop: 'Desktop', server: 'Server', vm: 'Virtuelle Maschine', container: 'Container', firewall: 'Firewall', router: 'Router', switch: 'Switch', access_point: 'Access Point', printer: 'Drucker', nas: 'NAS', camera: 'Kamera', phone: 'Telefon', domain: 'Domain', website: 'Website', ip: 'IP-Objekt', other: 'Sonstiges' }, r.asset_type || 'client', 'onchange="updateFindingLogic()"') + input('manufacturer', 'Hersteller', r.manufacturer, 'text', 'maxlength="100"') + input('model', 'Modell', r.model, 'text', 'maxlength="100"') + input('serial_number', 'Seriennummer', r.serial_number, 'text', 'maxlength="100"') + '<div class="laptop-only full form-grid">' + input('os_name', 'Betriebssystem', r.os_name, 'text', 'maxlength="100"') + input('os_version', 'OS-Version', r.os_version, 'text', 'maxlength="100"') + '</div><details class="finding-optional"><summary>Netzwerkdaten hinzufügen</summary><div class="form-grid">' + input('hostname', 'Hostname', r.hostname, 'text', 'maxlength="150"') + input('ipv4', 'Aktuelle IPv4-Adresse', (r.ipv4 || [])[0] || '', 'text', 'inputmode="decimal" maxlength="15" placeholder="192.168.1.10" oninput="cleanIPv4(this)"') + input('ipv6', 'Aktuelle IPv6-Adresse', (r.ipv6 || [])[0] || '', 'text', 'maxlength="39" placeholder="2001:db8::10" oninput="cleanIPv6(this)"') + check('dhcp', 'DHCP / dynamische Adressierung', r.dhcp) + input('mac', 'MAC-Adresse', (r.mac || []).join(', '), 'text', 'maxlength="40"') + '</div></details></div>' +
                '<div class="finding-group" data-types="network">' + input('cidr', 'Netzwerk / CIDR', r.cidr, 'text', 'maxlength="43"') + input('vlan', 'VLAN-ID', r.vlan, 'number', 'min="1" max="4094"') + input('gateway', 'Gateway', r.gateway, 'text', 'maxlength="39"') + '</div>' +
                '<div class="finding-group" data-types="connection">' + sel('source_asset', 'Bekanntes Quell-Asset', ao, r.source_asset) + input('service_ip', 'IP-Adresse des Dienstes', r.service_ip, 'text', 'maxlength="39"') + input('service_name', 'Dienst / Zweck', r.service_name, 'text', 'maxlength="100"') + sel('service_protocol', 'Protokoll', { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', other: 'Sonstiges' }, r.service_protocol || 'tcp') + input('service_port', 'Port', r.service_port, 'number', 'min="1" max="65535"') + sel('target_asset', 'Gegenstelle, falls bekannt', ao, r.target_asset) + sel('connection_type', 'Verbindungsart', { ethernet: 'Ethernet', fiber: 'Glasfaser', wifi: 'WLAN', vpn: 'VPN', virtual: 'Virtuell', logical: 'Logisch', unknown: 'Unbekannt' }, r.connection_type || 'unknown') + '</div>' +
                '<div class="finding-group" data-types="location">' + input('building', 'Gebäude', r.building) + input('room', 'Raum', r.room) + input('rack', 'Rack', r.rack) + '</div>' + '<div class="audit-only">' + sel('verification', 'Erfassungsstand', { observed: 'Beobachtet', verified: 'Verifiziert', assumed: 'Angenommen', conflicting: 'Widersprüchlich' }, r.verification || 'observed') + sel('severity', 'Relevanz', { info: 'Dokumentation', low: 'Niedrig', medium: 'Mittel', high: 'Hoch', critical: 'Kritisch' }, r.severity || 'info') + sel('status', 'Status', { observed: 'Erfasst', open: 'Offen', in_progress: 'In Bearbeitung', closed: 'Abgeschlossen' }, r.status || 'open') + area('recommendation', 'Empfehlung / nächste Aktion', r.recommendation) + '</div>' + '<div class="finding-notes full">' + area('description', 'Notizen', r.description) + '</div></div>'; document.getElementById('editor-fields').innerHTML = h; document.getElementById('editor-title').textContent = r.id ? 'Finding bearbeiten' : 'Finding anlegen'; document.getElementById('editor').showModal(); updateFindingLogic()
        }
    </script>
</body>

</html>
