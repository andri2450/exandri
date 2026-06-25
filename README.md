# Diagnostic Checker - cPanel/Plesk Hosting

Aplikasi web single-file (PHP) untuk mengecek kendala DNS, email (kirim/terima), dan akses website pada suatu domain.

## Cara pakai
1. Upload `index.php` ke `public_html` (cPanel) atau `httpdocs` (Plesk) di server kamu — boleh di subfolder, misal `public_html/diagcheck/`.
2. Akses lewat browser, misal: `https://domainkamu.com/diagcheck/`
3. Masukkan nama domain atau alamat email yang ingin dicek, pilih jenis kendala, klik "Cek Sekarang".

## Yang dicek otomatis
- **DNS dasar**: record A, NS, MX
- **Email**: SPF, DKIM (selector umum: default, selector1, mail, k1), DMARC, PTR/reverse DNS
- **Port**: 80/443 (web), 25/587/465 (SMTP kirim), 143/993/110/995 (IMAP/POP3 terima)
- Diagnosis otomatis + saran solusi untuk tiap temuan yang bermasalah

## Keterbatasan & catatan penting
- **Cek port dilakukan dari server tempat file ini diupload.** Karena itu sebaiknya file ini diupload ke server hosting yang sama dengan domain yang bermasalah (atau server lain yang punya akses jaringan keluar tanpa firewall ketat), supaya hasil port check akurat.
- Beberapa hosting/firewall membatasi `fsockopen()` keluar — jika semua port selalu muncul "tertutup", cek apakah `fsockopen` diizinkan oleh provider hosting (kadang dibatasi di shared hosting murah).
- Deteksi DKIM hanya mencoba selector yang umum dipakai. Jika provider kamu pakai selector custom, tambahkan manual di array `$dkim_selectors` pada kode.
- Ini adalah pengecekan **dari luar/sisi server**, bukan pengganti cek log mendalam (`/var/log/exim_mainlog`, `/var/log/maillog`, error log Apache/Nginx) untuk kasus yang lebih rumit.

## Pengembangan lanjutan yang bisa ditambahkan
- Simpan riwayat pengecekan ke database (MySQL) supaya bisa dilihat tren masalah per domain
- Tambah pengecekan blacklist IP (RBL) untuk domain yang emailnya sering masuk spam
- Tambah autentikasi login supaya tidak semua orang bisa mengecek domain sembarangan
- Jadwalkan cron job untuk pengecekan berkala otomatis + notifikasi email/Telegram jika ada error

## Keamanan
Sebelum dipakai di production:
- Tambahkan rate-limiting (mencegah orang spam cek domain berkali-kali)
- Pertimbangkan autentikasi sederhana (htpasswd atau login) supaya tool ini tidak diakses publik
- Validasi input domain sudah ada, tapi tetap perlu diaudit jika ingin menambah fitur baru
