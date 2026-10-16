<?php
declare(strict_types=1);
const APP = 'Network Audit';
const ROOT = __DIR__;
const TENANTS = ROOT . '/tenant';
const STORE = ROOT . '/storage';
const MAX_UPLOAD = 20971520;
ini_set('display_errors', '0');
error_reporting(E_ALL);
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
session_name('network_audit');
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'path' => '/']);
session_start();
function dir_make(string $p): void
{
    if (!is_dir($p) && !mkdir($p, 0750, true) && !is_dir($p))
        throw new RuntimeException('Verzeichnis nicht beschreibbar: ' . $p);
}
function write_atomic(string $f, string $v): void
{
    dir_make(dirname($f));
    $l = fopen(STORE . '/' . hash('sha256', $f) . '.lock', 'c');
    if (!$l || !flock($l, LOCK_EX))
        throw new RuntimeException('Dateisperre fehlgeschlagen.');
    $t = tempnam(dirname($f), '.tmp');
    if ($t === false || file_put_contents($t, $v) === false || !rename($t, $f))
        throw new RuntimeException('Datei konnte nicht gespeichert werden.');
    flock($l, LOCK_UN);
    fclose($l);
}
function read_json(string $f, array $d = []): array
{
    if (!is_file($f))
        return $d;
    $x = json_decode((string) file_get_contents($f), true);
    return is_array($x) ? $x : $d;
}
function write_json(string $f, array $v, ?string $tenant = null, string $kind = ''): void
{
    if (is_file($f) && $tenant) {
        $r = STORE . '/revisions/' . $tenant . '/' . $kind;
        dir_make($r);
        @copy($f, $r . '/' . date('Ymd_His') . '_' . bin2hex(random_bytes(2)) . '.json');
    }
    $j = json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($j === false)
        throw new RuntimeException('JSON-Fehler.');
    write_atomic($f, $j . "\n");
}
function e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function cut(string $v, int $n): string
{
    if (preg_match_all('/./us', $v, $m) === false)
        return substr($v, 0, $n);
    return implode('', array_slice($m[0], 0, $n));
}
function clean($v, int $n = 5000): string
{
    return cut(trim((string) $v), $n);
}
function arr($v): array
{
    return array_values(array_filter(array_map('trim', preg_split('/[,;\n]+/', (string) $v) ?: []), fn($x) => $x !== ''));
}
function sid(string $v): string
{
    $v = strtolower(trim($v));
    if (!preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/', $v))
        throw new InvalidArgumentException('Ungültige Tenant-ID.');
    return $v;
}
function id(string $p): string
{
    return $p . '-' . date('YmdHis') . '-' . bin2hex(random_bytes(3));
}
function csrf(): string
{
    if (empty($_SESSION['csrf']))
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_check(): void
{
    if (!hash_equals($_SESSION['csrf'] ?? '', (string) ($_POST['csrf'] ?? '')))
        throw new RuntimeException('Ungültige Sitzung.');
}
function flash(string $m): void
{
    $_SESSION['flash'] = $m;
}
function tenant_dir(string $id): string
{
    $id = sid($id);
    $p = TENANTS . '/' . $id;
    if (!is_dir($p))
        throw new InvalidArgumentException('Tenant nicht gefunden.');
    $b = realpath(TENANTS);
    $r = realpath($p);
    if (!$b || !$r || strpos($r, $b . DIRECTORY_SEPARATOR) !== 0)
        throw new RuntimeException('Ungültiger Pfad.');
    return $r;
}
function meta(string $id): array
{
    return read_json(tenant_dir($id) . '/tenant.json');
}
function tenants(): array
{
    $o = [];
    foreach (glob(TENANTS . '/*/tenant.json') ?: [] as $f) {
        $t = read_json($f);
        if (!empty($t['id']))
            $o[$t['id']] = $t;
    }
    uasort($o, fn($a, $b) => strnatcasecmp($a['name'], $b['name']));
    return $o;
}
function data(string $t, string $k): array
{
    return read_json(tenant_dir($t) . '/input/' . $k . '.json');
}
function save(string $t, string $k, array $v): void
{
    write_json(tenant_dir($t) . '/input/' . $k . '.json', array_values($v), $t, $k);
}
function descendants(string $id, array $all): array
{
    $o = [$id];
    do {
        $n = count($o);
        foreach ($all as $k => $t)
            if (in_array($t['parent'] ?? null, $o, true) && !in_array($k, $o, true))
                $o[] = $k;
    } while (count($o) > $n);
    return $o;
}
function combined(string $t, string $k, bool $children): array
{
    $ids = $children ? descendants($t, tenants()) : [$t];
    $o = [];
    foreach ($ids as $x)
        foreach (data($x, $k) as $r) {
            $r['_tenant'] = $x;
            $o[] = $r;
        }
    return $o;
}
function find_i(array $a, string $id): int
{
    foreach ($a as $i => $r)
        if (($r['id'] ?? '') === $id)
            return $i;
    return -1;
}
function audit(string $a, string $t = '', string $o = ''): void
{
    file_put_contents(STORE . '/audit.jsonl', json_encode(['time' => date(DATE_ATOM), 'user' => $_SESSION['user'] ?? 'system', 'action' => $a, 'tenant' => $t, 'object' => $o], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
}
function icon(array $t): string
{
    $n = $t['icon'] ?? '';
    if (!preg_match('/^icon\.(png|jpg)$/', $n))
        return '';
    $f = tenant_dir($t['id']) . '/input/icon/' . $n;
    if (!is_file($f))
        return '';
    $raw = file_get_contents($f);
    return $raw === false ? '' : 'data:image/' . ($n === 'icon.png' ? 'png' : 'jpeg') . ';base64,' . base64_encode($raw);
}
function upload_ext(string $f, bool $icon = false): ?string
{
    $h = fopen($f, 'rb');
    if (!$h)
        return null;
    $x = fread($h, 8192);
    fclose($h);
    if (strncmp($x, "\xFF\xD8\xFF", 3) === 0)
        return 'jpg';
    if (strncmp($x, "\x89PNG\x0D\x0A\x1A\x0A", 8) === 0)
        return 'png';
    if ($icon)
        return null;
    if (strncmp($x, '%PDF-', 5) === 0)
        return 'pdf';
    if (strpos($x, "\0") !== false || ($x !== '' && preg_match('//u', $x) !== 1))
        return null;
    return (strpos((string) strtok($x, "\r\n"), ',') !== false || strpos((string) strtok($x, "\r\n"), ';') !== false) ? 'csv' : 'txt';
}
function asset_name(array $r): string
{
    return clean($r['hostname'] ?? '') ?: clean($r['name'] ?? '') ?: 'Unbenanntes Asset';
}
function finding_title(array $p, array $assets, array $networks): string
{
    $type = $p['finding_type'] ?? 'note';
    $asset = '';
    foreach ($assets as $a)
        if (($a['id'] ?? '') === ($p['asset_id'] ?? '')) {
            $asset = asset_name($a);
            break;
        }
    $network = '';
    foreach ($networks as $n)
        if (($n['id'] ?? '') === ($p['network_id'] ?? '')) {
            $network = $n['name'] ?? ($n['vlan'] ?? 'Netzwerk');
            break;
        }
    if ($type === 'asset_found')
        return asset_name($p) . ' gefunden';
    if ($type === 'asset_network')
        return ($asset ?: 'Gerät') . ' zu ' . ($network ?: ('VLAN ' . ($p['vlan'] ?? '?'))) . ' zugeordnet';
    if ($type === 'asset_os')
        return 'OS von ' . ($asset ?: 'Gerät') . ': ' . ($p['os_name'] ?? 'unbekannt');
    if ($type === 'asset_dhcp')
        return ($asset ?: 'Gerät') . ' nutzt ' . (($p['dhcp'] ?? 'yes') === 'yes' ? 'DHCP' : 'statische Adressierung');
    if ($type === 'connection')
        return ($asset ?: 'Gerät') . ' mit ' . ($p['target_name'] ?? 'Ziel') . ' verbunden';
    if ($type === 'network_found')
        return ($p['name'] ?? 'Netzwerk') . ' gefunden';
    if ($type === 'risk')
        return clean($p['manual_title'] ?? '') ?: 'Audit-Feststellung';
    return clean($p['manual_title'] ?? '') ?: 'Beobachtung';
}
function context(string $t, bool $c): array
{
    $assets = combined($t, 'assets', $c);
    $networks = combined($t, 'networks', $c);
    $findings = combined($t, 'findings', $c);
    $connections = [];
    foreach ($findings as $f) {
        if (($f['finding_type'] ?? '') === 'asset_network') {
            foreach ($assets as &$a)
                if (($a['id'] ?? '') === ($f['asset_id'] ?? '')) {
                    $a['network_id'] = $f['network_id'] ?? '';
                    $a['vlan'] = $f['vlan'] ?? '';
                    $a['dhcp'] = $f['dhcp'] ?? ($a['dhcp'] ?? 'unknown');
                }
            unset($a);
        } elseif (($f['finding_type'] ?? '') === 'asset_os') {
            foreach ($assets as &$a)
                if (($a['id'] ?? '') === ($f['asset_id'] ?? '')) {
                    $a['os_name'] = $f['os_name'] ?? '';
                    $a['os_version'] = $f['os_version'] ?? '';
                }
            unset($a);
        } elseif (($f['finding_type'] ?? '') === 'asset_dhcp') {
            foreach ($assets as &$a)
                if (($a['id'] ?? '') === ($f['asset_id'] ?? ''))
                    $a['dhcp'] = $f['dhcp'] ?? 'unknown';
            unset($a);
        } elseif (($f['finding_type'] ?? '') === 'connection')
            $connections[] = $f;
    }
    return compact('assets', 'networks', 'findings', 'connections');
}
function output(string $t, bool $c): void
{
    $x = context($t, $c);
    $o = tenant_dir($t) . '/output';
    dir_make($o);
    write_json($o . '/network-audit.json', ['generated_at' => date(DATE_ATOM)] + $x, $t, 'output');
    $h = '<!doctype html><meta charset="utf-8"><title>Report</title><style>body{font:14px system-ui;max-width:1100px;margin:40px auto}table{width:100%;border-collapse:collapse}td,th{border:1px solid #bbb;padding:7px;text-align:left}</style><h1>' . e(meta($t)['name']) . '</h1><p>Assets: ' . count($x['assets']) . ' · Findings: ' . count($x['findings']) . '</p><h2>Assets</h2><table><tr><th>Name</th><th>OS</th><th>IP</th><th>DHCP</th><th>VLAN / Segment</th></tr>';
    foreach ($x['assets'] as $a)
        $h .= '<tr><td>' . e(asset_name($a)) . '</td><td>' . e(trim(($a['os_name'] ?? '') . ' ' . ($a['os_version'] ?? ''))) . '</td><td>' . e(implode(', ', $a['ipv4'] ?? [])) . '</td><td>' . e($a['dhcp'] ?? 'unknown') . '</td><td>' . e($a['vlan'] ?? '') . '</td></tr>';
    $h .= '</table><h2>Findings</h2><table><tr><th>Bezeichnung</th><th>Typ</th><th>Status</th></tr>';
    foreach ($x['findings'] as $f)
        $h .= '<tr><td>' . e($f['title'] ?? '') . '</td><td>' . e($f['finding_type'] ?? '') . '</td><td>' . e($f['status'] ?? '') . '</td></tr>';
    write_atomic($o . '/report.html', $h . '</table>');
}
try {
    dir_make(TENANTS);
    dir_make(STORE);
    if (!is_file(STORE . '/users.json'))
        write_json(STORE . '/users.json', []);
} catch (Throwable $ex) {
    http_response_code(500);
    die(e($ex->getMessage()));
}
$error = '';
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        $a = $_POST['action'] ?? '';
        $users = read_json(STORE . '/users.json');
        if ($a === 'setup' && !$users) {
            $u = clean($_POST['username'] ?? '', 40);
            $p = (string) ($_POST['password'] ?? '');
            if (strlen($p) < 12)
                throw new InvalidArgumentException('Passwort mindestens 12 Zeichen.');
            write_json(STORE . '/users.json', [['user' => $u, 'hash' => password_hash($p, PASSWORD_DEFAULT)]]);
            header('Location: ?');
            exit;
        }
        if ($a === 'login') {
            foreach ($users as $u)
                if (hash_equals($u['user'], clean($_POST['username'] ?? '', 40)) && password_verify((string) $_POST['password'], $u['hash'])) {
                    session_regenerate_id(true);
                    $_SESSION['user'] = $u['user'];
                    header('Location: ?');
                    exit;
                }
            throw new RuntimeException('Anmeldung fehlgeschlagen.');
        }
        if ($a === 'logout') {
            session_destroy();
            header('Location: ?');
            exit;
        }
        if (empty($_SESSION['user']))
            throw new RuntimeException('Nicht angemeldet.');
        if ($a === 'tenant_new') {
            $id = sid($_POST['id'] ?? '');
            $p = TENANTS . '/' . $id;
            if (is_dir($p))
                throw new RuntimeException('Tenant existiert.');
            dir_make($p . '/input/icon');
            dir_make($p . '/input/attachments');
            dir_make($p . '/output');
            write_json($p . '/tenant.json', ['id' => $id, 'name' => clean($_POST['name'] ?? '', 150), 'parent' => clean($_POST['parent'] ?? '', 64) ?: null, 'type' => clean($_POST['type'] ?? 'customer', 30)]);
            foreach (['assets', 'networks', 'findings'] as $k)
                write_json($p . '/input/' . $k . '.json', []);
            header('Location: ?tenant=' . $id);
            exit;
        }
        $t = sid($_POST['tenant'] ?? '');
        tenant_dir($t);
        if ($a === 'asset_save') {
            $rows = data($t, 'assets');
            $i = find_i($rows, (string) ($_POST['id'] ?? ''));
            $r = $i >= 0 ? $rows[$i] : ['id' => id('asset'), 'created_at' => date(DATE_ATOM)];
            $r = array_merge($r, ['name' => clean($_POST['name'] ?? '', 150), 'type' => clean($_POST['type'] ?? 'client', 50), 'hostname' => clean($_POST['hostname'] ?? '', 150), 'manufacturer' => clean($_POST['manufacturer'] ?? '', 100), 'model' => clean($_POST['model'] ?? '', 100), 'serial' => clean($_POST['serial'] ?? '', 100), 'os_name' => clean($_POST['os_name'] ?? '', 100), 'os_version' => clean($_POST['os_version'] ?? '', 100), 'ipv4' => arr($_POST['ipv4'] ?? ''), 'ipv6' => arr($_POST['ipv6'] ?? ''), 'mac' => arr($_POST['mac'] ?? ''), 'dhcp' => clean($_POST['dhcp'] ?? 'unknown', 20), 'network_id' => clean($_POST['network_id'] ?? '', 100), 'vlan' => clean($_POST['vlan'] ?? '', 50), 'services' => arr($_POST['services'] ?? ''), 'status' => clean($_POST['status'] ?? 'active', 30), 'updated_at' => date(DATE_ATOM)]);
            if (asset_name($r) === 'Unbenanntes Asset')
                throw new RuntimeException('Name oder Hostname erforderlich.');
            if ($i >= 0)
                $rows[$i] = $r;
            else
                $rows[] = $r;
            save($t, 'assets', $rows);
            audit('asset.save', $t, $r['id']);
            flash('Hardware gespeichert.');
        } elseif ($a === 'network_save') {
            $rows = data($t, 'networks');
            $i = find_i($rows, (string) ($_POST['id'] ?? ''));
            $r = $i >= 0 ? $rows[$i] : ['id' => id('network'), 'created_at' => date(DATE_ATOM)];
            $r = array_merge($r, ['name' => clean($_POST['name'] ?? '', 150), 'cidr' => clean($_POST['cidr'] ?? '', 100), 'vlan' => clean($_POST['vlan'] ?? '', 50), 'gateway' => clean($_POST['gateway'] ?? '', 100), 'dhcp_server' => clean($_POST['dhcp_server'] ?? '', 100), 'notes' => clean($_POST['notes'] ?? '')]);
            if ($i >= 0)
                $rows[$i] = $r;
            else
                $rows[] = $r;
            save($t, 'networks', $rows);
            flash('Netzwerk gespeichert.');
        } elseif ($a === 'finding_save') {
            $assets = data($t, 'assets');
            $nets = data($t, 'networks');
            $rows = data($t, 'findings');
            $i = find_i($rows, (string) ($_POST['id'] ?? ''));
            $r = $i >= 0 ? $rows[$i] : ['id' => id('finding'), 'created_at' => date(DATE_ATOM)];
            $r = array_merge($r, ['finding_type' => clean($_POST['finding_type'] ?? 'note', 40), 'asset_type' => clean($_POST['asset_type'] ?? '', 50), 'hostname' => clean($_POST['hostname'] ?? '', 150), 'name' => clean($_POST['name'] ?? '', 150), 'ipv4' => arr($_POST['ipv4'] ?? ''), 'mac' => arr($_POST['mac'] ?? ''), 'asset_id' => clean($_POST['asset_id'] ?? '', 100), 'network_id' => clean($_POST['network_id'] ?? '', 100), 'vlan' => clean($_POST['vlan'] ?? '', 50), 'dhcp' => clean($_POST['dhcp'] ?? 'unknown', 20), 'os_name' => clean($_POST['os_name'] ?? '', 100), 'os_version' => clean($_POST['os_version'] ?? '', 100), 'target_name' => clean($_POST['target_name'] ?? '', 150), 'manual_title' => clean($_POST['manual_title'] ?? '', 200), 'description' => clean($_POST['description'] ?? ''), 'severity' => clean($_POST['severity'] ?? 'info', 20), 'status' => clean($_POST['status'] ?? 'observed', 30), 'updated_at' => date(DATE_ATOM)]);
            $r['title'] = finding_title($r, $assets, $nets);
            if ($i >= 0)
                $rows[$i] = $r;
            else
                $rows[] = $r;
            save($t, 'findings', $rows);
            flash('Finding gespeichert: ' . $r['title']);
        } elseif ($a === 'delete') {
            $k = in_array($_POST['kind'] ?? '', ['assets', 'networks', 'findings'], true) ? $_POST['kind'] : '';
            if (!$k)
                throw new RuntimeException('Ungültig.');
            $r = data($t, $k);
            $i = find_i($r, (string) $_POST['id']);
            if ($i >= 0)
                array_splice($r, $i, 1);
            save($t, $k, $r);
            flash('Gelöscht.');
        } elseif ($a === 'generate') {
            output($t, isset($_POST['children']));
            flash('Reports erzeugt.');
        } elseif ($a === 'icon') {
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK)
                throw new RuntimeException('Upload fehlgeschlagen.');
            $x = upload_ext($_FILES['file']['tmp_name'], true);
            if (!$x)
                throw new RuntimeException('Nur PNG oder JPG.');
            $d = tenant_dir($t) . '/input/icon';
            dir_make($d);
            foreach (glob($d . '/*') ?: [] as $f)
                @unlink($f);
            $n = 'icon.' . $x;
            move_uploaded_file($_FILES['file']['tmp_name'], $d . '/' . $n);
            $m = meta($t);
            $m['icon'] = $n;
            write_json(tenant_dir($t) . '/tenant.json', $m, $t, 'tenant');
            flash('Icon gespeichert.');
        }
        header('Location: ?tenant=' . $t . '&view=' . urlencode($_POST['return'] ?? 'overview'));
        exit;
    }
} catch (Throwable $ex) {
    $error = $ex->getMessage();
}
$users = read_json(STORE . '/users.json');
if (empty($_SESSION['user'])) { ?>    <!doctype html>
    <meta charset="utf-8">
    <title><?= e(APP) ?></title>
    <style>
        body {
            background: #090d12;
            color: #e7edf4;
            font: 14px system-ui;
            display: grid;
            place-items: center;
            height: 100vh
        }

        form {
            width: 360px;
            background: #111923;
            padding: 25px;
            border: 1px solid #283546
        }

        input,
        button {
            width: 100%;
            box-sizing: border-box;
            margin: 7px 0;
            padding: 10px;
            background: #0a1017;
            color: #fff;
            border: 1px solid #334256
        }
    </style>
    <form method="post">
        <h2><?= e(APP) ?></h2><?php if ($error): ?>
            <p><?= e($error) ?></p><?php endif; ?><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
            name="action" value="<?= $users ? 'login' : 'setup' ?>"><input name="username" placeholder="Benutzer" required><input
            type="password" name="password" placeholder="Passwort"
            required><button><?= $users ? 'Anmelden' : 'Administrator anlegen' ?></button>
    </form>
    <?php exit;
}
$all = tenants();
$tenant = sid($_GET['tenant'] ?? array_key_first($all) ?? 'aa');
$current = isset($all[$tenant]) ? $all[$tenant] : null;
$view = in_array($_GET['view'] ?? 'overview', ['overview', 'assets', 'map', 'reports', 'findings', 'settings'], true) ? $_GET['view'] : 'overview';
$children = ($_GET['scope'] ?? 'own') === 'all';
$ctx = $current ? context($tenant, $children) : ['assets' => [], 'networks' => [], 'findings' => [], 'connections' => []];
$ico = $current ? icon($current) : '';
$msg = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);
if (isset($_GET['download']) && $current) {
    $f = tenant_dir($tenant) . '/output/' . ($_GET['download'] === 'json' ? 'network-audit.json' : 'report.html');
    if (is_file($f)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($f) . '"');
        readfile($f);
        exit;
    }
}
function nav(string $t, string $v, string $l, string $cur): string
{
    return '<a class="nav ' . ($cur === $v ? 'on' : '') . '" href="?tenant=' . e($t) . '&view=' . $v . '">' . e($l) . '</a>';
}
?>
<!doctype html>
<html lang="de">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title><?= e($current ? ($current['name'] . ' · ' . APP) : APP) ?></title><?php if ($ico): ?>
        <link rel="icon" href="<?= e($ico) ?>"><?php endif; ?>
    <style>
        :root {
            color-scheme: dark;
            --bg: #080c11;
            --side: #0c1219;
            --panel: #111923;
            --line: #293747;
            --text: #e7edf4;
            --muted: #8c9bad;
            --accent: #56a5ff;
            --bad: #ff6677
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 13px system-ui
        }

        .app {
            display: grid;
            grid-template-columns: 270px 1fr;
            min-height: 100vh
        }

        .side {
            background: var(--side);
            border-right: 1px solid var(--line);
            padding: 16px
        }

        .brand {
            font-weight: 800;
            letter-spacing: .12em;
            margin: 4px 8px 18px
        }

        .tenant {
            display: flex;
            gap: 8px;
            align-items: center;
            color: var(--text);
            text-decoration: none;
            padding: 7px;
            border-radius: 5px
        }

        .tenant.on,
        .tenant:hover,
        .nav.on,
        .nav:hover {
            background: #16202c
        }

        .ti {
            width: 25px;
            height: 25px;
            border-radius: 5px;
            background: #1d2a38;
            display: grid;
            place-items: center;
            object-fit: cover
        }

        .child {
            margin-left: 15px;
            border-left: 1px solid var(--line);
            padding-left: 5px
        }

        .nav {
            display: block;
            color: var(--muted);
            text-decoration: none;
            padding: 9px;
            border-radius: 5px
        }

        .main {
            padding: 24px;
            min-width: 0
        }

        .head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px
        }

        .id {
            display: flex;
            gap: 12px;
            align-items: center
        }

        .id .ti {
            width: 42px;
            height: 42px
        }

        h1 {
            font-size: 20px;
            margin: 0
        }

        .muted {
            color: var(--muted)
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px
        }

        .card {
            background: var(--panel);
            border: 1px solid var(--line);
            padding: 15px;
            border-radius: 7px
        }

        .num {
            font-size: 26px;
            font-weight: 750
        }

        button,
        .btn,
        input,
        select,
        textarea {
            font: inherit
        }

        button,
        .btn {
            background: #192534;
            color: var(--text);
            border: 1px solid var(--line);
            padding: 8px 11px;
            border-radius: 5px;
            text-decoration: none;
            cursor: pointer
        }

        .primary {
            background: var(--accent);
            color: #07121e;
            font-weight: 700
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--panel)
        }

        td,
        th {
            padding: 9px;
            border: 1px solid var(--line);
            text-align: left
        }

        th {
            color: var(--muted);
            font-size: 10px;
            text-transform: uppercase
        }

        .toolbar {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap
        }

        .flash {
            padding: 10px;
            background: var(--panel);
            border: 1px solid var(--line);
            margin-bottom: 10px
        }

        dialog {
            width: min(820px, 94vw);
            background: var(--panel);
            color: var(--text);
            border: 1px solid var(--line);
            padding: 20px;
            border-radius: 8px
        }

        dialog::backdrop {
            background: #000b
        }

        .form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px
        }

        label {
            color: var(--muted)
        }

        input,
        select,
        textarea {
            width: 100%;
            margin-top: 5px;
            padding: 8px;
            background: #0a1017;
            color: var(--text);
            border: 1px solid var(--line)
        }

        textarea {
            min-height: 90px
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

        .hide {
            display: none
        }

        svg {
            width: 100%;
            background: var(--panel);
            border: 1px solid var(--line)
        }

        svg rect {
            fill: #182534;
            stroke: #3c5065
        }

        svg text {
            fill: #e7edf4;
            text-anchor: middle;
            font-size: 12px
        }

        svg line {
            stroke: #617990;
            stroke-width: 2
        }

        @media(max-width:850px) {
            .app {
                grid-template-columns: 1fr
            }

            .grid {
                grid-template-columns: 1fr 1fr
            }

            .form {
                grid-template-columns: 1fr
            }
        }
    </style>
</head>

<body>
    <div class="app">
        <aside class="side">
            <div class="brand">NETWORK AUDIT</div>
            <?php function tree(array $all, ?string $p, string $active): void
            {
                foreach ($all as $id => $t)
                    if (($t['parent'] ?? null) === $p) {
                        $i = icon($t);
                        echo '<div class="' . ($p ? 'child' : '') . '"><a class="tenant ' . ($id === $active ? 'on' : '') . '" href="?tenant=' . e($id) . '">' . ($i ? '<img class="ti" src="' . e($i) . '">' : '<span class="ti">' . e(strtoupper(substr($t['name'], 0, 1))) . '</span>') . e($t['name']) . '</a>';
                        tree($all, $id, $active);
                        echo '</div>';
                    }
            }
            tree($all, null, $tenant); ?><button
                style="width:100%;margin:12px 0" onclick="q('tenant').showModal()">+
                Tenant</button><?php if ($current): ?><?= nav($tenant, 'overview', 'Übersicht', $view) ?><?= nav($tenant, 'assets', 'Assets', $view) ?><?= nav($tenant, 'map', 'Netzwerkkarte', $view) ?><?= nav($tenant, 'reports', 'Reports', $view) ?><?= nav($tenant, 'findings', 'Findings', $view) ?><?= nav($tenant, 'settings', 'Einstellungen', $view) ?><?php endif; ?>
            <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                    name="action" value="logout"><button style="width:100%;margin-top:20px">Abmelden</button></form>
        </aside>
        <main class="main"><?php if ($msg): ?>
                <div class="flash"><?= e($msg) ?></div><?php endif; ?><?php if ($error): ?>
                <div class="flash"><?= e($error) ?></div><?php endif; ?><?php if (!$current): ?>
                <p>Tenant anlegen.</p><?php else: ?>
                <header class="head">
                    <div class="id">
                        <?= $ico ? '<img class="ti" src="' . e($ico) . '">' : '<span class="ti">' . e(strtoupper(substr($current['name'], 0, 1))) . '</span>' ?>
                        <div>
                            <h1><?= e($current['name']) ?></h1><span class="muted"><?= e($current['type']) ?> ·
                                <?= e($tenant) ?></span>
                        </div>
                    </div>
                    <form><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input type="hidden" name="view"
                            value="<?= e($view) ?>"><select name="scope" onchange="this.form.submit()">
                            <option value="own">Nur dieser Tenant</option>
                            <option value="all" <?= $children ? 'selected' : '' ?>>Mit Sub-Tenants</option>
                        </select></form>
                </header>
                <?php if ($view === 'overview'): ?>
                    <div class="grid">
                        <div class="card">
                            <div class="num"><?= count($ctx['assets']) ?></div><span class="muted">Assets</span>
                        </div>
                        <div class="card">
                            <div class="num"><?= count($ctx['networks']) ?></div><span class="muted">Netzwerke</span>
                        </div>
                        <div class="card">
                            <div class="num"><?= count($ctx['connections']) ?></div><span class="muted">Verbindungen</span>
                        </div>
                        <div class="card">
                            <div class="num"><?= count($ctx['findings']) ?></div><span class="muted">Findings</span>
                        </div>
                    </div>
                <?php elseif ($view === 'assets'): ?>
                    <div class="toolbar"><button class="primary" onclick="asset({})">+ Hardware</button><button
                            onclick="network({})">+ Netzwerksegment</button></div>
                    <table>
                        <tr>
                            <th>Asset</th>
                            <th>Hardware</th>
                            <th>OS</th>
                            <th>IP / DHCP</th>
                            <th>VLAN / Segment</th>
                            <th></th>
                        </tr><?php foreach ($ctx['assets'] as $a): ?>
                            <tr>
                                <td><strong><?= e(asset_name($a)) ?></strong><br><span class="muted"><?= e($a['type'] ?? '') ?></span>
                                </td>
                                <td><?= e(trim(($a['manufacturer'] ?? '') . ' ' . ($a['model'] ?? ''))) ?></td>
                                <td><?= e(trim(($a['os_name'] ?? '') . ' ' . ($a['os_version'] ?? ''))) ?></td>
                                <td><?= e(implode(', ', $a['ipv4'] ?? [])) ?><br><?= e($a['dhcp'] ?? 'unknown') ?></td>
                                <td><?= e($a['vlan'] ?? '') ?></td>
                                <td><?php if (($a['_tenant'] ?? $tenant) === $tenant): ?><button
                                            onclick='asset(<?= json_encode($a, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT) ?>)'>Bearbeiten</button><?php endif; ?>
                                </td>
                            </tr><?php endforeach; ?>
                    </table>
                    <h3>Netzwerksegmente</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>CIDR</th>
                            <th>VLAN</th>
                            <th>Gateway</th>
                            <th>DHCP-Server</th>
                            <th></th>
                        </tr><?php foreach ($ctx['networks'] as $n): ?>
                            <tr>
                                <td><?= e($n['name'] ?? '') ?></td>
                                <td><?= e($n['cidr'] ?? '') ?></td>
                                <td><?= e($n['vlan'] ?? '') ?></td>
                                <td><?= e($n['gateway'] ?? '') ?></td>
                                <td><?= e($n['dhcp_server'] ?? '') ?></td>
                                <td><button
                                        onclick='network(<?= json_encode($n, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button>
                                </td>
                            </tr><?php endforeach; ?>
                    </table>
                <?php elseif ($view === 'findings'): ?>
                    <div class="toolbar"><button class="primary" onclick="finding({})">+ Finding</button></div>
                    <table>
                        <tr>
                            <th>Bezeichnung</th>
                            <th>Art</th>
                            <th>Beschreibung</th>
                            <th>Relevanz</th>
                            <th></th>
                        </tr><?php foreach ($ctx['findings'] as $f): ?>
                            <tr>
                                <td><strong><?= e($f['title'] ?? '') ?></strong></td>
                                <td><?= e($f['finding_type'] ?? '') ?></td>
                                <td><?= e(cut($f['description'] ?? '', 100)) ?></td>
                                <td><?= e($f['severity'] ?? '') ?></td>
                                <td><?php if (($f['_tenant'] ?? $tenant) === $tenant): ?><button
                                            onclick='finding(<?= json_encode($f, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>)'>Bearbeiten</button><?php endif; ?>
                                </td>
                            </tr><?php endforeach; ?>
                    </table>
                <?php elseif ($view === 'map'): ?>        <?php $n = count($ctx['assets']);
                         if (!$n): ?>
                        <p class="muted">Keine Assets.</p><?php else: ?><svg
                            viewBox="0 0 1000 <?= max(420, ceil($n / 5) * 130) ?>"><?php $pos = [];
                            foreach ($ctx['assets'] as $i => $a) {
                                $x = 110 + ($i % 5) * 195;
                                $y = 80 + intdiv($i, 5) * 125;
                                $pos[$a['id']] = [$x, $y];
                            }
                            foreach ($ctx['connections'] as $c) {
                                $a = $pos[$c['asset_id']] ?? null;
                                if ($a) {
                                    $b = [900, 350]; ?>
                                    <line x1="<?= $a[0] ?>" y1="<?= $a[1] ?>" x2="<?= $b[0] ?>" y2="<?= $b[1] ?>" />
                                <?php }
                            }
                            foreach ($ctx['assets'] as $a) {
                                [$x, $y] = $pos[$a['id']]; ?>
                                <rect x="<?= $x - 75 ?>" y="<?= $y - 27 ?>" width="150" height="54" rx="6" /><text x="<?= $x ?>"
                                    y="<?= $y ?>"><?= e(cut(asset_name($a), 20)) ?></text><text x="<?= $x ?>"
                                    y="<?= $y + 17 ?>"><?= e($a['vlan'] ?? '') ?></text><?php } ?>
                        </svg><?php endif; ?>
                <?php elseif ($view === 'reports'): ?>
                    <div class="card">
                        <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                                name="action" value="generate"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input
                                type="hidden" name="return" value="reports"><label><input style="width:auto" type="checkbox"
                                    name="children"> Sub-Tenants einschließen</label> <button class="primary">Reports
                                erzeugen</button></form>
                        <p><a class="btn" href="?tenant=<?= e($tenant) ?>&download=html">HTML-Report</a> <a class="btn"
                                href="?tenant=<?= e($tenant) ?>&download=json">JSON-Daten</a></p>
                    </div>
                <?php elseif ($view === 'settings'): ?>
                    <div class="card">
                        <h3>Tenant-Icon</h3>
                        <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf"
                                value="<?= e(csrf()) ?>"><input type="hidden" name="action" value="icon"><input type="hidden"
                                name="tenant" value="<?= e($tenant) ?>"><input type="hidden" name="return" value="settings"><input
                                type="file" name="file" accept="image/png,image/jpeg" required><button>Speichern</button></form>
                    </div><?php endif; ?><?php endif; ?>
        </main>
    </div>
    <dialog id="tenant">
        <h3>Tenant anlegen</h3>
        <form method="post" class="form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                name="action" value="tenant_new"><label>ID<input name="id" required></label><label>Name<input
                    name="name" required></label><label>Typ<select name="type">
                    <option value="customer">Kunde</option>
                    <option value="subsidiary">Sub-Tenant</option>
                    <option value="branch">Standort</option>
                </select></label><label>Parent<select name="parent">
                    <option value="">Keiner</option><?php foreach ($all as $x): ?>
                        <option value="<?= e($x['id']) ?>"><?= e($x['name']) ?></option><?php endforeach; ?>
                </select></label>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button class="primary">Anlegen</button>
            </div>
        </form>
    </dialog>
    <dialog id="asset">
        <h3>Hardware / Asset</h3>
        <form method="post" class="form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                name="action" value="asset_save"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input
                type="hidden" name="return" value="assets"><input type="hidden" name="id"><label>Typ<select name="type">
                    <option value="client">Client</option>
                    <option value="laptop">Laptop</option>
                    <option value="server">Server</option>
                    <option value="switch">Switch</option>
                    <option value="router">Router</option>
                    <option value="firewall">Firewall</option>
                    <option value="access_point">Access Point</option>
                    <option value="printer">Drucker</option>
                    <option value="nas">NAS</option>
                    <option value="other">Sonstiges</option>
                </select></label><label>Hostname<input name="hostname"></label><label>Name<input
                    name="name"></label><label>Hersteller<input name="manufacturer"></label><label>Modell<input
                    name="model"></label><label>Seriennummer<input name="serial"></label><label>OS<input
                    name="os_name"></label><label>OS-Version<input name="os_version"></label><label>IPv4<input
                    name="ipv4"></label><label>IPv6<input name="ipv6"></label><label>MAC<input
                    name="mac"></label><label>Adressierung<select name="dhcp">
                    <option value="unknown">Unbekannt</option>
                    <option value="yes">DHCP</option>
                    <option value="no">Statisch</option>
                    <option value="reserved">DHCP-Reservierung</option>
                </select></label><label>Netzwerksegment<select name="network_id">
                    <option value="">Unbekannt</option><?php foreach ($ctx['networks'] as $n): ?>
                        <option value="<?= e($n['id']) ?>">
                            <?= e($n['name']) ?>    <?= !empty($n['vlan']) ? ' · VLAN ' . e($n['vlan']) : '' ?></option>
                    <?php endforeach; ?>
                </select></label><label>VLAN-ID<input name="vlan"></label><label>Dienste<input
                    name="services"></label><label>Status<select name="status">
                    <option value="active">Aktiv</option>
                    <option value="observed">Beobachtet</option>
                    <option value="inactive">Inaktiv</option>
                </select></label>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
        </form>
    </dialog>
    <dialog id="network">
        <h3>Netzwerksegment</h3>
        <form method="post" class="form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                name="action" value="network_save"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input
                type="hidden" name="return" value="assets"><input type="hidden" name="id"><label>Name<input name="name"
                    required></label><label>CIDR<input name="cidr"
                    placeholder="192.168.10.0/24"></label><label>VLAN-ID<input name="vlan"></label><label>Gateway<input
                    name="gateway"></label><label>DHCP-Server<input name="dhcp_server"></label><label
                class="full">Notizen<textarea name="notes"></textarea></label>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
        </form>
    </dialog>
    <dialog id="finding">
        <h3>Finding</h3>
        <form method="post" class="form"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>"><input type="hidden"
                name="action" value="finding_save"><input type="hidden" name="tenant" value="<?= e($tenant) ?>"><input
                type="hidden" name="return" value="findings"><input type="hidden" name="id"><label>Art<select
                    name="finding_type" onchange="findingFields()">
                    <option value="asset_found">Gerät gefunden</option>
                    <option value="asset_network">Gerät einem VLAN / Segment zuordnen</option>
                    <option value="asset_os">Betriebssystem festgestellt</option>
                    <option value="asset_dhcp">Adressierung festgestellt</option>
                    <option value="connection">Verbindung festgestellt</option>
                    <option value="network_found">Netzwerksegment gefunden</option>
                    <option value="risk">Audit-Feststellung</option>
                    <option value="note">Allgemeine Beobachtung</option>
                </select></label><label class="ff" data-for="asset_network asset_os asset_dhcp connection">Asset<select
                    name="asset_id">
                    <option value="">Auswählen</option><?php foreach ($ctx['assets'] as $a): ?>
                        <option value="<?= e($a['id']) ?>"><?= e(asset_name($a)) ?></option><?php endforeach; ?>
                </select></label>
            <div class="ff full form" data-for="asset_found"><label>Typ<select name="asset_type">
                        <option value="client">Client</option>
                        <option value="laptop">Laptop</option>
                        <option value="server">Server</option>
                        <option value="switch">Switch</option>
                        <option value="router">Router</option>
                        <option value="firewall">Firewall</option>
                        <option value="other">Sonstiges</option>
                    </select></label><label>Hostname<input name="hostname"></label><label>Name<input
                        name="name"></label><label>IPv4<input name="ipv4"></label><label>MAC<input name="mac"></label>
            </div><label class="ff" data-for="asset_network">Netzwerksegment<select name="network_id">
                    <option value="">Auswählen</option><?php foreach ($ctx['networks'] as $n): ?>
                        <option value="<?= e($n['id']) ?>"><?= e($n['name']) ?></option><?php endforeach; ?>
                </select></label><label class="ff" data-for="asset_network">VLAN-ID<input name="vlan"></label><label
                class="ff" data-for="asset_network asset_dhcp">Adressierung<select name="dhcp">
                    <option value="unknown">Unbekannt</option>
                    <option value="yes">DHCP</option>
                    <option value="no">Statisch</option>
                    <option value="reserved">DHCP-Reservierung</option>
                </select></label><label class="ff" data-for="asset_os">OS<input name="os_name"></label><label class="ff"
                data-for="asset_os">OS-Version<input name="os_version"></label><label class="ff"
                data-for="connection">Ziel / Gegenstelle<input name="target_name"></label><label class="ff"
                data-for="risk note network_found">Manuelle Bezeichnung<input
                    name="manual_title"></label><label>Relevanz<select name="severity">
                    <option value="info">Dokumentation</option>
                    <option value="low">Niedrig</option>
                    <option value="medium">Mittel</option>
                    <option value="high">Hoch</option>
                    <option value="critical">Kritisch</option>
                </select></label><label>Status<select name="status">
                    <option value="observed">Beobachtet</option>
                    <option value="verified">Verifiziert</option>
                    <option value="open">Offen</option>
                    <option value="resolved">Behoben</option>
                </select></label><label class="full">Beschreibung<textarea name="description"></textarea></label>
            <div class="actions full"><button type="button"
                    onclick="this.closest('dialog').close()">Abbrechen</button><button
                    class="primary">Speichern</button></div>
        </form>
    </dialog>
    <script>const q = id => document.getElementById(id); function fill(d, r) { Object.entries(r).forEach(([k, v]) => { const e = d.querySelector(`[name="${k}"]`); if (e) e.value = Array.isArray(v) ? v.join(', ') : v ?? '' }) } function asset(r) { const d = q('asset'); d.querySelector('form').reset(); fill(d, r); d.showModal() } function network(r) { const d = q('network'); d.querySelector('form').reset(); fill(d, r); d.showModal() } function finding(r) { const d = q('finding'); d.querySelector('form').reset(); fill(d, r); findingFields(); d.showModal() } function findingFields() { const d = q('finding'), t = d.querySelector('[name=finding_type]').value; d.querySelectorAll('.ff').forEach(x => x.style.display = x.dataset.for.split(' ').includes(t) ? 'grid' : 'none') }</script>
</body>

</html>
