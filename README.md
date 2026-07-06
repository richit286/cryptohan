# CryptoHan

Aplikasi enkripsi file & transfer P2P aman, dengan GUI (Tkinter) dan CLI.

## Fitur

- **Enkripsi file streaming** (chunked AEAD, tidak memuat seluruh file ke RAM):
  - `AES-256-GCM` berbasis password (PBKDF2-HMAC-SHA256, 600.000 iterasi).
  - `RSA-2048 Hybrid` berbasis kunci publik/privat (kunci AES dibungkus RSA-OAEP).
- **Transfer P2P terenkripsi** lewat `Noise_XX_25519_ChaChaPoly_SHA256` (forward secrecy, mutual auth), dengan:
  - Verifikasi **fingerprint** (kata/hex/angka) untuk mencegah man-in-the-middle.
  - **Anti-replay** (UUID + timestamp) dan verifikasi **checksum SHA-256** setelah transfer.
  - Registry **kontak** (IP/port/fingerprint) yang diproteksi HMAC dari tamper.
- **GUI** (Tkinter) dan **CLI** (`cryptohan ...`) berbagi logika inti yang sama persis.
- Logging ke `~/.cryptohan/cryptohan.log` (tidak pernah mencatat password/kunci).

## Instalasi

### Dari source (pip, cross-platform)

```bash
pip install -e ".[transport]"       # + fitur transfer P2P
# atau, cukup enkripsi/dekripsi file tanpa transfer:
pip install -e .
```

Untuk development (test, lint):

```bash
pip install -e ".[transport,dev]"
```

### Linux

1. Install Tkinter sistem dulu — satu-satunya bagian yang tidak otomatis lewat pip di Linux
   (beda dari Windows/Mac yang biasanya sudah bundel Tk). Bisa dilewati kalau cuma pakai CLI
   tanpa GUI sama sekali (`gui.py` baru di-import saat subcommand `gui` benar-benar dipanggil):

   ```bash
   sudo apt install python3-tk        # Debian/Ubuntu
   sudo dnf install python3-tkinter   # Fedora/RHEL
   sudo pacman -S tk                  # Arch
   ```

2. Buat venv & install package:

   ```bash
   git clone <repo-ini> cryptohan && cd cryptohan
   python3 -m venv .venv
   source .venv/bin/activate
      
   ```

3. Jalankan:

   ```bash
   cryptohan              # atau: python -m cryptohan  -> buka GUI
   cryptohan encrypt data.txt --algo aes --password "rahasia"
   cryptohan receive --port 50777 --out-dir ./diterima
   ```

Bonus: `secure_chmod()`/`ensure_identity_dir()` (chmod `0600`/`0700` ke `~/.cryptohan`) benar-benar
berfungsi penuh di Linux — berbeda dari Windows, tempat `os.chmod` praktis tidak berpengaruh — jadi
kunci privat & identitas transport memang terlindungi permission OS secara nyata.

Kalau mau binary standalone (versi Linux dari `.exe`): PyInstaller tidak cross-compile, jadi spec
yang sama (`packaging/cryptohan.spec`) harus dijalankan ulang **di mesin Linux**-nya:

```bash
pip install -e ".[transport,build]"
pyinstaller packaging/cryptohan.spec --noconfirm --clean
```

Hasilnya `dist/cryptohan/cryptohan` (ELF, bukan `.exe`).

### Windows `.exe`

Lihat [packaging/README.md](packaging/README.md) untuk cara build `dist/cryptohan/cryptohan.exe` dengan PyInstaller.

## Pemakaian

### GUI

```bash
cryptohan                 # atau: cryptohan gui
python -m cryptohan
```

### CLI

```bash
cryptohan encrypt data.txt --algo aes --password "rahasia"
cryptohan decrypt data.txt.enc --password "rahasia"

cryptohan keygen --kind rsa --priv k.priv.pem --pub k.pub.pem
cryptohan encrypt data.txt --algo rsa --pubkey k.pub.pem
cryptohan decrypt data.txt.enc --privkey k.priv.pem

cryptohan fingerprint k.pub.pem

cryptohan receive --port 50777 --out-dir ./diterima --auto-decrypt --password "rahasia"
cryptohan send data.txt.enc --host 192.168.1.10 --port 50777

cryptohan contacts add alice 192.168.1.10 50777 --fingerprint <hex>
cryptohan contacts list
```

Jalankan `cryptohan <subcommand> --help` untuk opsi lengkap tiap perintah.

## Arsitektur

Kode inti ada di `src/cryptohan/`, dipecah per tanggung jawab (tanpa duplikasi logika antara GUI dan CLI):

| Modul | Tanggung jawab |
|---|---|
| `config.py` | Konstanta, exception, direktori identitas (`~/.cryptohan`) |
| `crypto.py` | Enkripsi/dekripsi file streaming (AES-GCM & RSA-Hybrid) |
| `keys.py` | Pembuatan & pemuatan kunci RSA dan identitas transport X25519 |
| `fingerprint.py` | Fingerprint kunci publik (kata/hex/angka) untuk verifikasi anti-MITM |
| `contacts.py` | Registry kontak (IP/port/fingerprint), diproteksi HMAC |
| `transport.py` | Transport Noise_XX (kirim/terima file), anti-replay, checksum |
| `logging_setup.py` | Logging berotasi ke `~/.cryptohan/cryptohan.log` |
| `gui.py` | Antarmuka grafis Tkinter |
| `cli.py` | Antarmuka command-line (argparse) |

`legacy/` berisi dua versi awal aplikasi ini (`cryptohan.py`, `cryptohan2.py`) yang sudah sepenuhnya digantikan oleh `src/cryptohan/` — dipertahankan hanya untuk referensi historis.

Penjelasan detail cara kerja verifikasi fingerprint dan protokol transport (Noise_XX): lihat [docs/fingerprint-dan-transport.md](docs/fingerprint-dan-transport.md).

## Testing

```bash
pip install -e ".[transport,dev]"
pytest -q
```

## Keamanan

- Direktori `~/.cryptohan` menyimpan kunci privat, identitas transport, dan registry kontak. Permission file diset ke `0600`/`0700` secara best-effort (`os.chmod` bukan jaminan penuh di Windows — untuk kontrol akses yang kuat di lingkungan perusahaan, batasi lewat ACL folder profil pengguna).
- Selalu verifikasi **fingerprint** lawan bicara lewat jalur di luar aplikasi ini (telepon/tatap muka) sebelum mengandalkan proteksi anti-MITM.
