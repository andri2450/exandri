# Diagnostic Checker - DNS, Email & Website (versi GitHub Pages)

Versi statis (HTML + JavaScript, tanpa backend) dari diagnostic checker, dirancang agar bisa dijalankan langsung di **GitHub Pages**.

## Cara deploy di GitHub Pages
1. Buat repository baru di GitHub (atau pakai yang sudah ada).
2. Upload file `index.html` ke root repository (atau folder `/docs` kalau kamu set Pages source ke `/docs`).
3. Buka **Settings → Pages** di repository tersebut.
4. Pilih source: branch `main`, folder `/ (root)` (atau `/docs` sesuai lokasi file).
5. Tunggu beberapa menit, lalu akses lewat URL yang diberikan GitHub, contoh:
   `https://username.github.io/nama-repo/`

## Apa yang dicek
- **DNS**: A, NS, MX — lewat DNS-over-HTTPS API publik dari Google (`https://dns.google/resolve`), yang mendukung akses langsung dari browser (CORS).
- **Email**: SPF, DKIM (selector umum: default, selector1, mail, k1), DMARC
- **Website**: tes koneksi HTTP/HTTPS langsung dari browser (mode no-cors, jadi hanya bisa deteksi "berhasil connect atau tidak", bukan baca status code/isi halaman)

## Keterbatasan penting (dibanding versi PHP)
Karena ini berjalan murni di browser pengguna:

- **Tidak bisa cek port SMTP/IMAP/POP3** (25, 587, 465, 143, 993, 110, 995). Browser tidak mengizinkan koneksi TCP mentah ke port sembarang — ini batasan keamanan semua browser modern, tidak bisa diakali dari JavaScript murni.
- Tes "website reachable" hanya menunjukkan berhasil/tidaknya koneksi jaringan, **bukan** isi response atau status HTTP (karena `mode: 'no-cors'`).
- Bergantung pada API publik `dns.google` — jika domain ini di-block oleh jaringan pengguna (misal di beberapa negara/ISP), fitur DNS check tidak akan berfungsi. Bisa diganti ke `https://cloudflare-dns.com/dns-query` sebagai alternatif kalau perlu (lihat variabel `DOH_ENDPOINT` di kode).

## Kalau butuh cek port (SMTP/IMAP/POP3) yang akurat
Itu wajib dijalankan dari server, tidak bisa dari browser. Opsinya:
1. Pakai versi PHP yang sebelumnya sudah dibuat — upload ke hosting cPanel/Plesk kamu langsung (bukan GitHub Pages).
2. Atau buat backend kecil (Node/PHP) yang di-deploy ke platform yang support server-side code (Render, Railway, fly.io, dll), lalu versi GitHub Pages ini panggil API ke backend itu untuk hasil port check-nya.

## Pengembangan lanjutan
- Tambahkan cek blacklist IP (RBL) untuk domain yang emailnya sering masuk spam
- Simpan riwayat pengecekan (perlu backend/database, tidak bisa pure static)
- Ganti DoH endpoint ke Cloudflare sebagai fallback jika Google diblokir
