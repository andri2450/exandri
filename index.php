<?php
/**
 * Diagnostic Checker untuk cPanel/Plesk Hosting
 * Cek DNS, Email (kirim/terima), dan akses Website
 * Upload file ini ke server kamu (cPanel/Plesk) lalu akses lewat browser.
 */

error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);

// ============== HELPER FUNCTIONS ==============

function get_records($domain, $type) {
    $records = @dns_get_record($domain, $type);
    return $records ?: [];
}

function check_port($host, $port, $timeout = 4) {
    $start = microtime(true);
    $conn = @fsockopen($host, $port, $errno, $errstr, $timeout);
    $ms = round((microtime(true) - $start) * 1000);
    if ($conn) {
        fclose($conn);
        return ['open' => true, 'ms' => $ms];
    }
    return ['open' => false, 'error' => $errstr ?: 'timeout/refused'];
}

function get_server_ip($domain) {
    $ip = @gethostbyname($domain);
    return ($ip && $ip !== $domain) ? $ip : null;
}

function get_ptr($ip) {
    if (!$ip) return null;
    $host = @gethostbyaddr($ip);
    return ($host && $host !== $ip) ? $host : null;
}

// ============== DIAGNOSTIC ENGINE ==============

function run_diagnosis($domain, $kendala) {
    $result = [
        'domain' => $domain,
        'kendala' => $kendala,
        'dns' => [],
        'findings' => [],
    ];

    // --- Kumpulkan data DNS dasar ---
    $a = get_records($domain, DNS_A);
    $ns = get_records($domain, DNS_NS);
    $mx = get_records($domain, DNS_MX);
    $txt = get_records($domain, DNS_TXT);
    $dmarc = get_records('_dmarc.' . $domain, DNS_TXT);

    $ip = get_server_ip($domain);
    $ptr = get_ptr($ip);

    $spf_record = null;
    foreach ($txt as $t) {
        if (isset($t['txt']) && stripos($t['txt'], 'v=spf1') === 0) {
            $spf_record = $t['txt'];
        }
    }
    $dmarc_record = null;
    foreach ($dmarc as $t) {
        if (isset($t['txt']) && stripos($t['txt'], 'v=dmarc1') === 0) {
            $dmarc_record = $t['txt'];
        }
    }

    // DKIM: coba selector umum (cPanel pakai "default", banyak provider pakai "default"/"selector1")
    $dkim_selectors = ['default', 'selector1', 'mail', 'k1'];
    $dkim_found = null;
    foreach ($dkim_selectors as $sel) {
        $rec = get_records($sel . '._domainkey.' . $domain, DNS_TXT);
        if (!empty($rec)) {
            $dkim_found = $sel;
            break;
        }
    }

    $result['dns'] = [
        'A' => $a,
        'NS' => $ns,
        'MX' => $mx,
        'IP' => $ip,
        'PTR' => $ptr,
        'SPF' => $spf_record,
        'DMARC' => $dmarc_record,
        'DKIM_selector' => $dkim_found,
    ];

    // --- Cek port berdasarkan jenis kendala ---
    $ports_to_check = [];
    if ($kendala === 'website' || $kendala === 'umum') {
        $ports_to_check['HTTP (80)'] = 80;
        $ports_to_check['HTTPS (443)'] = 443;
    }
    if ($kendala === 'kirim' || $kendala === 'umum') {
        $ports_to_check['SMTP (25)'] = 25;
        $ports_to_check['SMTP Submission (587)'] = 587;
        $ports_to_check['SMTPS (465)'] = 465;
    }
    if ($kendala === 'terima' || $kendala === 'umum') {
        $ports_to_check['IMAP (143)'] = 143;
        $ports_to_check['IMAPS (993)'] = 993;
        $ports_to_check['POP3 (110)'] = 110;
        $ports_to_check['POP3S (995)'] = 995;
    }

    $port_results = [];
    $target_host = $ip ?: $domain;
    foreach ($ports_to_check as $label => $port) {
        $port_results[$label] = check_port($target_host, $port);
    }
    $result['ports'] = $port_results;

    // --- ATURAN DIAGNOSIS ---

    if (empty($a) && empty($ns)) {
        $result['findings'][] = [
            'level' => 'error',
            'title' => 'Domain tidak resolve sama sekali',
            'detail' => 'Tidak ditemukan record A maupun NS untuk domain ini. Domain mungkin belum dikonfigurasi DNS-nya, salah ketik, atau belum delegasi ke nameserver.',
            'solusi' => 'Pastikan domain sudah diarahkan ke nameserver cPanel/Plesk kamu (cek di registrar domain), lalu buat zone DNS dan record A di WHM/cPanel atau Plesk DNS settings.',
        ];
    }

    if (empty($a) && !empty($ns)) {
        $result['findings'][] = [
            'level' => 'error',
            'title' => 'Tidak ada record A',
            'detail' => 'Nameserver ditemukan tapi tidak ada record A yang mengarah ke IP server. Ini sebabnya website tidak bisa diakses.',
            'solusi' => 'Tambahkan record A di zona DNS (cPanel: Zone Editor / Plesk: DNS Settings) mengarah ke IP server hosting kamu.',
        ];
    }

    if (($kendala === 'website' || $kendala === 'umum') && !empty($port_results)) {
        if (isset($port_results['HTTP (80)']) && !$port_results['HTTP (80)']['open']
            && isset($port_results['HTTPS (443)']) && !$port_results['HTTPS (443)']['open']) {
            $result['findings'][] = [
                'level' => 'error',
                'title' => 'Port 80 dan 443 tidak terbuka',
                'detail' => 'Web server (Apache/LiteSpeed/Nginx) di IP ' . ($ip ?: $domain) . ' tidak merespon di port 80 maupun 443.',
                'solusi' => 'Cek status web service di WHM/Plesk (restart Apache/LiteSpeed/Nginx), cek firewall (CSF/iptables) tidak memblokir port tersebut, dan pastikan akun hosting tidak suspend.',
            ];
        } elseif (isset($port_results['HTTPS (443)']) && !$port_results['HTTPS (443)']['open']) {
            $result['findings'][] = [
                'level' => 'warning',
                'title' => 'HTTPS (443) tidak terbuka',
                'detail' => 'Website mungkin masih bisa diakses lewat HTTP biasa, tapi HTTPS bermasalah.',
                'solusi' => 'Cek instalasi SSL di cPanel (AutoSSL) atau Plesk (Let\'s Encrypt), pastikan sertifikat belum expired dan service web mendengarkan di port 443.',
            ];
        }
    }

    if ($kendala === 'kirim' || $kendala === 'umum') {
        if (empty($spf_record)) {
            $result['findings'][] = [
                'level' => 'warning',
                'title' => 'Tidak ada SPF record',
                'detail' => 'Domain tidak memiliki SPF (TXT record v=spf1). Email yang dikirim berisiko ditandai spam atau ditolak oleh penerima.',
                'solusi' => 'Tambahkan TXT record di DNS: "v=spf1 a mx ip4:' . ($ip ?: 'IP_SERVER') . ' ~all" (sesuaikan dengan IP server mail kamu).',
            ];
        }
        if (empty($dkim_found)) {
            $result['findings'][] = [
                'level' => 'warning',
                'title' => 'DKIM tidak terdeteksi',
                'detail' => 'Tidak ditemukan record DKIM dengan selector umum (default/selector1/mail/k1). DKIM membantu memastikan email tidak dipalsukan dan meningkatkan reputasi pengiriman.',
                'solusi' => 'Aktifkan DKIM di cPanel (Email Deliverability tool) atau Plesk (Mail settings → DKIM signature) dan pastikan record TXT-nya sudah ditambahkan ke DNS.',
            ];
        }
        if (empty($dmarc_record)) {
            $result['findings'][] = [
                'level' => 'warning',
                'title' => 'Tidak ada DMARC record',
                'detail' => 'Tanpa DMARC, kebijakan terhadap email yang gagal SPF/DKIM tidak terdefinisi, ini menurunkan reputasi domain di mata Gmail/Outlook.',
                'solusi' => 'Tambahkan TXT record di "_dmarc.' . $domain . '": "v=DMARC1; p=none; rua=mailto:postmaster@' . $domain . '" sebagai langkah awal monitoring.',
            ];
        }
        if (isset($port_results['SMTP (25)']) && !$port_results['SMTP (25)']['open']) {
            $result['findings'][] = [
                'level' => 'error',
                'title' => 'Port 25 (SMTP) tertutup/diblokir',
                'detail' => 'Port 25 dari server ini tidak bisa diakses. Banyak provider/ISP memblokir port 25 untuk outbound mail, atau service Exim/Postfix sedang down.',
                'solusi' => 'Cek status mail service (Exim di WHM / Postfix di Plesk), cek apakah provider data center memblokir port 25 (umum di VPS/cloud, perlu request unblock atau pakai SMTP relay seperti port 587).',
            ];
        }
    }

    if ($kendala === 'terima' || $kendala === 'umum') {
        if (empty($mx)) {
            $result['findings'][] = [
                'level' => 'error',
                'title' => 'Tidak ada record MX',
                'detail' => 'Domain tidak punya MX record, sehingga email masuk tidak tahu harus dikirim ke server mana. Email yang dikirim ke domain ini akan bounce/gagal.',
                'solusi' => 'Tambahkan MX record di DNS zone (cPanel Zone Editor / Plesk DNS Settings) mengarah ke mail.' . $domain . ' atau server mail yang sesuai, dengan priority misal 0 atau 10.',
            ];
        }
        $imap_pop_open = false;
        foreach (['IMAP (143)', 'IMAPS (993)', 'POP3 (110)', 'POP3S (995)'] as $label) {
            if (isset($port_results[$label]) && $port_results[$label]['open']) {
                $imap_pop_open = true;
            }
        }
        if (!empty($mx) && !$imap_pop_open) {
            $result['findings'][] = [
                'level' => 'error',
                'title' => 'Service IMAP/POP3 tidak merespon',
                'detail' => 'MX record ada, tapi tidak ada port IMAP/POP3 yang terbuka di server ini. Email mungkin terkirim tapi user tidak bisa mengambilnya lewat client/webmail.',
                'solusi' => 'Cek status Dovecot (cPanel/Plesk mail service), restart service jika perlu, dan pastikan firewall tidak memblokir port 143/993/110/995.',
            ];
        }
    }

    if ($ip && $ptr === null && ($kendala === 'kirim' || $kendala === 'umum')) {
        $result['findings'][] = [
            'level' => 'info',
            'title' => 'PTR record (reverse DNS) tidak ditemukan',
            'detail' => 'IP server (' . $ip . ') tidak punya PTR record. Banyak penyedia email besar (Gmail, Outlook) menolak/spam-kan email dari IP tanpa PTR yang valid.',
            'solusi' => 'Minta provider hosting/data center kamu (bukan registrar domain) untuk mengatur reverse DNS IP ini agar mengarah ke mail.' . $domain . '.',
        ];
    }

    if (empty($result['findings'])) {
        $result['findings'][] = [
            'level' => 'ok',
            'title' => 'Tidak ditemukan masalah dari pengecekan dasar',
            'detail' => 'Semua record DNS dan port yang relevan terlihat normal dari pengecekan otomatis ini.',
            'solusi' => 'Jika kendala masih terjadi, cek log mendalam di server (mail log /var/log/exim_mainlog atau /var/log/maillog, error log Apache/Nginx) atau hubungi support hosting.',
        ];
    }

    return $result;
}

// ============== HANDLE REQUEST ==============

$result = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = trim($_POST['target'] ?? '');
    $kendala = $_POST['kendala'] ?? 'umum';

    if ($input === '') {
        $error = 'Masukkan nama domain atau alamat email.';
    } else {
        // Jika input berupa email, ambil bagian domain-nya
        if (strpos($input, '@') !== false) {
            $parts = explode('@', $input);
            $domain = end($parts);
        } else {
            $domain = preg_replace('#^https?://#', '', $input);
            $domain = rtrim(explode('/', $domain)[0], '.');
        }

        if (!preg_match('/^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/i', $domain)) {
            $error = 'Format domain/email tidak valid: ' . htmlspecialchars($domain);
        } else {
            $result = run_diagnosis($domain, $kendala);
        }
    }
}

function level_badge($level) {
    $map = [
        'error' => ['#fcebeb', '#791f1f', 'Bermasalah'],
        'warning' => ['#faeeda', '#633806', 'Perhatian'],
        'info' => ['#e6f1fb', '#0c447c', 'Info'],
        'ok' => ['#eaf3de', '#27500a', 'Normal'],
    ];
    [$bg, $fg, $label] = $map[$level] ?? $map['info'];
    return "<span style='background:$bg;color:$fg;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:600;'>$label</span>";
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Diagnostic Checker - DNS, Email & Website</title>
<style>
    * { box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
        background: #f4f5f7;
        margin: 0;
        padding: 24px;
        color: #1d2129;
    }
    .container { max-width: 760px; margin: 0 auto; }
    h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
    .subtitle { color: #65676b; font-size: 14px; margin-bottom: 24px; }
    .card {
        background: #fff;
        border: 1px solid #e4e6eb;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
    }
    label { display: block; font-size: 13px; color: #65676b; margin-bottom: 6px; margin-top: 14px; }
    input[type=text], select {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid #ccd0d5;
        border-radius: 8px;
        font-size: 14px;
    }
    button {
        margin-top: 18px;
        background: #1877f2;
        color: #fff;
        border: none;
        padding: 11px 22px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
    }
    button:hover { background: #166fe5; }
    .error-msg { background: #fcebeb; color: #791f1f; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
    .finding {
        border: 1px solid #e4e6eb;
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 12px;
    }
    .finding-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .finding-title strong { font-size: 14px; }
    .finding p { font-size: 13px; color: #4b4f56; margin: 4px 0; line-height: 1.5; }
    .finding .solusi { background: #f0f6ff; padding: 8px 10px; border-radius: 6px; margin-top: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
    table td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
    table td:first-child { color: #65676b; width: 35%; }
    .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
    .section-title { font-size: 14px; font-weight: 600; margin: 18px 0 8px; }
    .port-ok { color: #27500a; }
    .port-fail { color: #791f1f; }
</style>
</head>
<body>
<div class="container">
    <h1>Diagnostic Checker - Hosting cPanel / Plesk</h1>
    <p class="subtitle">Cek kendala DNS, pengiriman/penerimaan email, dan akses website pada domain kamu.</p>

    <div class="card">
        <form method="POST">
            <label for="target">Nama domain atau alamat email</label>
            <input type="text" id="target" name="target" placeholder="contoh.com atau user@contoh.com"
                   value="<?= htmlspecialchars($_POST['target'] ?? '') ?>" required>

            <label for="kendala">Kendala yang terjadi</label>
            <select id="kendala" name="kendala">
                <?php
                $opts = [
                    'umum' => 'Cek umum (semua aspek)',
                    'website' => 'Website tidak dapat diakses',
                    'kirim' => 'Email tidak terkirim',
                    'terima' => 'Email tidak diterima',
                ];
                $selected = $_POST['kendala'] ?? 'umum';
                foreach ($opts as $val => $label) {
                    $sel = $val === $selected ? 'selected' : '';
                    echo "<option value=\"$val\" $sel>$label</option>";
                }
                ?>
            </select>

            <button type="submit">Cek Sekarang</button>
        </form>
    </div>

    <?php if ($error): ?>
        <div class="error-msg"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($result): ?>
        <div class="card">
            <div class="section-title">Hasil diagnosis untuk <span class="mono"><?= htmlspecialchars($result['domain']) ?></span></div>
            <?php foreach ($result['findings'] as $f): ?>
                <div class="finding">
                    <div class="finding-title">
                        <strong><?= htmlspecialchars($f['title']) ?></strong>
                        <?= level_badge($f['level']) ?>
                    </div>
                    <p><?= htmlspecialchars($f['detail']) ?></p>
                    <p class="solusi"><strong>Solusi:</strong> <?= htmlspecialchars($f['solusi']) ?></p>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="card">
            <div class="section-title">Detail DNS</div>
            <table>
                <tr><td>IP server (A)</td><td class="mono"><?= htmlspecialchars($result['dns']['IP'] ?? '-') ?></td></tr>
                <tr><td>PTR (reverse DNS)</td><td class="mono"><?= htmlspecialchars($result['dns']['PTR'] ?? '-') ?></td></tr>
                <tr><td>Nameserver (NS)</td><td class="mono"><?= htmlspecialchars(implode(', ', array_column($result['dns']['NS'], 'target')) ?: '-') ?></td></tr>
                <tr><td>MX record</td><td class="mono"><?php
                    if (!empty($result['dns']['MX'])) {
                        foreach ($result['dns']['MX'] as $m) {
                            echo htmlspecialchars($m['target'] . ' (priority ' . $m['pri'] . ')') . '<br>';
                        }
                    } else { echo '-'; }
                ?></td></tr>
                <tr><td>SPF</td><td class="mono"><?= htmlspecialchars($result['dns']['SPF'] ?? 'tidak ditemukan') ?></td></tr>
                <tr><td>DKIM selector terdeteksi</td><td class="mono"><?= htmlspecialchars($result['dns']['DKIM_selector'] ?? 'tidak ditemukan') ?></td></tr>
                <tr><td>DMARC</td><td class="mono"><?= htmlspecialchars($result['dns']['DMARC'] ?? 'tidak ditemukan') ?></td></tr>
            </table>
        </div>

        <?php if (!empty($result['ports'])): ?>
        <div class="card">
            <div class="section-title">Status port</div>
            <table>
                <?php foreach ($result['ports'] as $label => $p): ?>
                    <tr>
                        <td><?= htmlspecialchars($label) ?></td>
                        <td>
                            <?php if ($p['open']): ?>
                                <span class="port-ok">Terbuka (<?= $p['ms'] ?>ms)</span>
                            <?php else: ?>
                                <span class="port-fail">Tertutup / tidak respon</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
        </div>
        <?php endif; ?>
    <?php endif; ?>

    <p style="font-size:12px;color:#8a8d91;text-align:center;margin-top:24px;">
        Pengecekan dilakukan dari server tempat file ini dijalankan. Hasil bersifat indikatif, bukan pengganti pengecekan log server secara langsung.
    </p>
</div>
</body>
</html>
