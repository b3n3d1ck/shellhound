<div align="center">

# shellhound

Memburu webshell, backdoor, dan uploader PHP dengan membaca **filesystem** server — bukan menebak dari luar.

<img src="docs/demo.png" alt="contoh shellhound berjalan" width="760">

</div>

## Kenapa baca filesystem, bukan scan dari luar

Webshell yang berhasil ditanam orang di server biasanya namanya acak, misalnya `x7g9.php` atau menyamar jadi `avatar.jpg`. Dia nggak akan muncul di listing direktori dan nggak akan ketebak wordlist, berapa pun panjangnya. Jadi scanner yang menembak nama file dari luar lewat HTTP itu lemah untuk tujuan ini: dia cuma nemu yang namanya kebetulan ada di daftar.

shellhound kerja dari sisi dalam. Dia dijalankan di server yang kamu kelola, lalu membaca tiap file di web root langsung dari disk. Nama file nggak penting lagi; yang diperiksa adalah **isinya**. File `avatar.jpg` yang ternyata berisi `<?php system(...)` ketahuan, karena yang dilihat kode di dalamnya, bukan ekstensinya.

Tool ini read-only. Dia membaca, menilai, dan melapor. Nggak ada file yang diubah, dipindah, atau dihapus.

## Apa yang dideteksi

Tiap file PHP dicocokkan dengan beberapa kelompok indikator, lalu diberi skor:

- **Signature keluarga webshell** — penanda khas dari tool yang sudah dikenal: c99, r57, b374k, WSO/FilesMan, Alfa, IndoXploit, dan lainnya.
- **Fungsi eksekusi berbahaya** — `eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `preg_replace` dengan modifier `/e`, dan sejenisnya.
- **Obfuscation** — pola khas shell yang dikemas, seperti `eval(gzinflate(base64_decode(...)))`, rantai decode berlapis, blob base64 panjang, deretan `chr()` atau escape heksa.
- **Kemampuan upload** — `move_uploaded_file`, penulisan file dari input user: ini yang sering jadi pintu masuk shell.
- **Ekstensi menyamar** — file berisi kode PHP tapi ekstensinya `.jpg`, `.ico`, `.txt`, dan semacamnya.

Kalau indikator berbahaya muncul bareng input user (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`), skornya naik, karena kombinasi itulah yang bikin sebuah file benar-benar bisa dipakai menjalankan perintah dari jarak jauh.

Hasilnya dikelompokkan jadi tiga tingkat: **KEMUNGKINAN BESAR WEBSHELL**, **MENCURIGAKAN**, dan **PERLU DITINJAU**. Tiap temuan disertai potongan kode pemicunya (nomor baris), dan nilai yang mirip password atau base64 payload **disensor** di laporan supaya tidak ikut tersebar.

## Instalasi

**Unduh binary jadi** dari halaman [Releases](https://github.com/b3n3d1ck/shellhound/releases) — tersedia untuk Linux, Windows, dan macOS. Ekstrak, taruh di server, jalankan.

**Lewat Go** (butuh Go 1.21+):

```bash
go install github.com/b3n3d1ck/shellhound@latest
```

**Build dari sumber:**

```bash
git clone https://github.com/b3n3d1ck/shellhound.git
cd shellhound
go build -o shellhound .
```

## Pemakaian

```bash
shellhound /var/www/html                                  # scan satu web root
shellhound -base https://situsku.com /var/www/html        # sekalian petakan ke link publik
shellhound -all-ext -min 20 /var/www/html                 # periksa semua file, lebih sensitif
shellhound -json -o lapor.json /var/www/html              # simpan laporan JSON
```

Opsi `-base` berguna karena laporannya langsung memberi URL yang bisa diklik untuk tiap temuan, jadi gampang dicocokkan dengan log akses. Keluaran JSON cocok buat disimpan sebagai arsip atau dilempar ke sistem lain.

| Opsi | Arti | Default |
|---|---|---|
| `-ext` | daftar ekstensi yang diperiksa | `php,php3,php4,php5,php7,phtml,pht,phar,inc` |
| `-all-ext` | periksa semua file teks, bukan cuma PHP | off |
| `-min` | skor minimum untuk dilaporkan | 25 |
| `-base` | URL dasar untuk memetakan path file ke link | — |
| `-max-size` | lewati file lebih besar dari sekian MB | 3 |
| `-skip` | folder yang dilewati | `.git,node_modules,.svn,.hg` |
| `-c` | jumlah worker paralel (0 = otomatis) | 0 |
| `-json` / `-o` | keluaran JSON ke layar / ke file | — |

Kalau ada temuan, exit code-nya 1. Jadi bisa langsung dipasang di cron atau CI untuk alarm otomatis.

## Pasang sebagai scan harian

Taruh di crontab, kirim email kalau ada yang ketangkap:

```cron
0 3 * * * /usr/local/bin/shellhound /var/www/html || mail -s "shellhound: temuan di web root" admin@situsku.com < /dev/null
```

## Kalau ada yang ketangkap

Laporannya sudah memandu, tapi ringkasnya: jangan buka file-nya lewat browser (sama saja menjalankan shell-nya), pindahkan dulu ke luar web root biar bukti aman, cek `access.log` untuk tahu kapan dan dari IP mana dia dipanggil, cari file lain yang dimodifikasi di waktu sama, lalu ganti semua kredensial di server. Untuk nutup celahnya: matikan eksekusi PHP di folder upload, batasi `disable_functions` di php.ini, dan perbarui CMS beserta plugin/tema-nya — itu pintu masuk paling umum.

## Batasan

Deteksinya berbasis signature dan heuristik, jadi dua hal perlu diingat. Shell yang ditulis dengan teknik baru atau diobfuscate dengan cara yang belum dikenal bisa lolos; skor bersih bukan jaminan mutlak. Sebaliknya, kode sah yang kebetulan memakai `exec` atau `base64_decode` untuk alasan wajar bisa muncul sebagai "perlu ditinjau" — makanya tiap temuan selalu disertai potongan kodenya, supaya kamu bisa menilai sendiri, bukan percaya buta ke skornya. Alat ini mempercepat pemeriksaan, bukan menggantikan mata manusia.

## Izin & hukum

shellhound membaca filesystem, jadi secara alami dia dipakai di server yang **kamu punya aksesnya sendiri**. Tetap: jalankan hanya pada sistem yang kamu miliki atau yang kamu diberi izin tertulis untuk diperiksa.

## Kontribusi

Yang paling berguna: signature webshell baru dan pola obfuscation yang belum tertangkap. Tambahkan di `signatures.go`, lengkapi tesnya (`go test ./...` harus lolos), kirim pull request. Alat ini sengaja dijaga sebagai scanner defensif — ia melapor, tidak mengeksploitasi.

## Lisensi

[MIT](LICENSE) © 2025 Mas Bram
