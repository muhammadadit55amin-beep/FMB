# LegacyOS — Edisi Server (backend sungguhan)

Backend Node.js untuk LegacyOS: **SQLite** sebagai database, **autentikasi bcrypt** dengan
sesi cookie httpOnly, **peran server-side**, **audit trail**, dan **proxy pindai AI**
(kunci API tersimpan di server, bukan di browser). Front-end di `public/index.html`
bersifat dwimode: dibuka sebagai file statis ia memakai localStorage; disajikan oleh
server ini ia otomatis beralih ke mode server.

## Menjalankan

1. Pasang Node.js 20+.
2. Di folder ini: `npm install` lalu `npm start` (default `http://localhost:8787`,
   ubah dengan env `PORT`).
3. Buka di browser — layar pertama adalah **pembuatan akun admin** (email, sandi min. 8
   karakter, nama keluarga). Setelah itu layar masuk memakai email + sandi sungguhan.
4. Opsional: salin `.env.example` menjadi `.env` (atau set env langsung) dan isi
   `ANTHROPIC_API_KEY` agar fitur *Pindai Dokumen — AI* berjalan lewat server;
   tanpa ini pindai memakai ekstraksi lokal sederhana.

## Peran

`admin` mengelola pengguna (Pengaturan → *Kelola pengguna*) dan seluruh data;
`editor` mengubah data; `viewer` hanya membaca. Penegakan dilakukan **di server**
(viewer yang memaksa PUT tetap ditolak 403), bukan sekadar disembunyikan di tampilan.

## Data, versi & backup

Seluruh data keluarga tersimpan sebagai dokumen berversi di tabel `state`
(`data/legacyos.db`). Setiap simpanan menaikkan versi; bila dua orang mengedit
bersamaan, penyimpan kedua menerima **409** dan tampilannya dimuat ulang dengan data
terbaru — tidak ada yang tertimpa diam-diam. Audit (masuk, simpan, kelola pengguna,
pindai) tersedia di `GET /api/audit`. Backup: salin berkas `data/legacyos.db`
(hentikan server sejenak atau gunakan `sqlite3 ".backup"`), atau gunakan
**Ekspor JSON** dari dalam aplikasi.

## Produksi

Jalankan di balik reverse proxy ber-HTTPS dan set `NODE_ENV=production`
(cookie menjadi `Secure`). Contoh Caddy:

    keluarga.example.com {
        reverse_proxy 127.0.0.1:8787
    }

Cocok pula untuk Railway/Render/Fly/VPS kecil; pastikan folder `data/` persisten.

## Batasan jujur

Satu workspace per server (satu keluarga). Sinkron memakai dokumen utuh dengan deteksi
konflik — memadai untuk tim kecil, bukan penyuntingan kolaboratif per-sel. Belum ada
2FA/e-sign; kolom sandi login lama ("YubiKey") kini murni kosmetik digantikan sandi
sungguhan.
