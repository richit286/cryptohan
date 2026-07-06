# Build Windows `.exe`

```bash
pip install -e ".[transport,build]"
pyinstaller packaging/cryptohan.spec --noconfirm --clean
```

Hasil: `dist/cryptohan/cryptohan.exe` (mode onedir — start lebih cepat & lebih mudah
didiagnosis dibanding onefile bila ada modul yang tidak terbawa).

Build selalu menyertakan extra `transport` supaya fitur kirim/terima P2P ikut terbungkus —
pengguna `.exe` tidak bisa menambah dependency setelah dibangun.

## Checklist smoke-test manual setelah build

Jalankan `dist/cryptohan/cryptohan.exe` (dobel-klik untuk GUI, atau lewat terminal untuk CLI) dan pastikan:

- [ ] GUI terbuka tanpa error.
- [ ] Enkripsi & dekripsi AES-256-GCM berhasil (roundtrip).
- [ ] Buat kunci RSA, enkripsi & dekripsi RSA-2048 Hybrid berhasil.
- [ ] Tombol Fingerprint menampilkan kartu kata/hex/angka.
- [ ] Kirim & terima file antar dua salinan `cryptohan.exe` di localhost (port berbeda) berhasil,
      termasuk verifikasi fingerprint.
- [ ] `cryptohan.exe --help` menampilkan semua subcommand CLI dari terminal.
