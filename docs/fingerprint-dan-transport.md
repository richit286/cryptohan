# Fingerprint & Transport di CryptoHan

Dokumen ini menjelaskan dua lapisan keamanan inti yang dipakai CryptoHan saat transfer file P2P: **fingerprint** (verifikasi identitas) dan **transport** (kanal terenkripsi, Noise Protocol). Disusun dari dasar masalahnya, konsep pondasi, sampai detail implementasi di kode.

## Daftar isi

1. [Masalah yang diselesaikan](#1-masalah-yang-diselesaikan)
2. [Konsep pondasi](#2-konsep-pondasi)
3. [Lapisan Fingerprint](#3-lapisan-fingerprint)
4. [Lapisan Transport (Noise Protocol)](#4-lapisan-transport-noise-protocol)
5. [Hubungan kedua lapisan](#5-hubungan-kedua-lapisan)

---

## 1. Masalah yang diselesaikan

Bayangkan Alice mau kirim file ke Bob lewat internet, langsung dari komputernya ke komputer Bob (P2P, tanpa server perantara). Ada dua ancaman berbeda yang **harus dua-duanya ditangani**:

1. **Penyadapan (eavesdropping)** — orang di tengah jalan (mis. di jaringan WiFi yang sama) membaca isi file saat lewat. → butuh **enkripsi kanal**.
2. **Peniruan (impersonation/MITM)** — orang di tengah jalan berpura-pura jadi "Bob" (menyisipkan diri di antara Alice dan Bob), lalu diam-diam meneruskan/mengubah data. Kanalnya **tetap terenkripsi**, tapi Alice sebenarnya sedang bicara dengan penyerang, bukan Bob. → butuh **autentikasi identitas**.

Poin krusial yang sering disalahpahami: **enkripsi saja TIDAK mencegah MITM**. Penyerang bisa saja punya kunci sendiri yang valid dan menyelesaikan proses "jabat tangan kriptografis" dengan sempurna — hasilnya kanal itu **memang terenkripsi**, cuma terenkripsi antara Alice dan si penyerang, bukan Alice dan Bob. Ini sebabnya CryptoHan butuh dua lapisan terpisah: **Transport** (bikin kanal terenkripsi) dan **Fingerprint** (pastikan ujung kanal itu benar Bob, bukan penyerang).

## 2. Konsep pondasi

Dua alat matematis yang jadi dasar semuanya:

**a) Hash satu-arah (SHA-256)** — fungsi yang mengubah data apa pun jadi "sidik jari" 32-byte. Sifatnya: (1) sekali dihitung, tidak bisa dibalik ke data aslinya, (2) perubahan sekecil apa pun di input menghasilkan hash yang benar-benar berbeda. Ini yang membuat hash cocok jadi "fingerprint" — representasi pendek yang mewakili kunci publik yang jauh lebih panjang.

**b) Diffie-Hellman (DH) key exchange** — trik matematis yang memungkinkan dua pihak sepakat soal satu rahasia bersama **tanpa pernah mengirim rahasia itu lewat jaringan** — bahkan kalau ada penyadap yang merekam SEMUA lalu lintas, dia tidak bisa menghitung rahasia yang sama. Ini fondasi dari hampir semua protokol modern (TLS, SSH, Signal, WireGuard) — termasuk Noise Protocol yang dipakai CryptoHan.

Yang perlu diingat: DH sendiri **anonim** — dua pihak bisa sepakat soal rahasia bersama walau salah satunya penyerang yang menyamar. DH menyelesaikan masalah #1 (penyadapan), bukan #2 (peniruan). Masalah #2 baru selesai kalau kita menambahkan **kunci statis jangka panjang** ke dalam campuran DH-nya, lalu **memverifikasi kunci statis itu** lewat cara lain di luar protokol — di situlah fingerprint masuk.

## 3. Lapisan Fingerprint

### 3.1 Apa yang sebenarnya di-hash

Lihat `fingerprint.py`:

```python
def fp_digest(pb): return hashlib.sha256(pb).digest()
def fp_hex_full(pb): return fp_digest(pb).hex()
def fp_words(pb, n=8): return " ".join(WORDS[b] for b in fp_digest(pb)[:n])
```

`pb` (public bytes) datang dari `canonical_public_bytes()` di `keys.py` — encoding standar **DER SubjectPublicKeyInfo** dari kunci publik (RSA atau X25519). Alurnya:

```
kunci publik (objek Python) → encode ke bytes standar (DER) → SHA-256 → 32 byte fingerprint
```

### 3.2 Kenapa ditampilkan 3 cara berbeda

32 byte hash itu tidak enak dibaca manusia lewat telepon. Maka dibuat 3 representasi (`fingerprint.py`):

- **Kata** (`fp_words`) — 8 kata dari daftar 256 kata unik, tiap byte hash dipetakan ke satu kata. Paling gampang dibacakan lisan dan dihafal sekilas ("junk golf fade join...").
- **Hex** (`fp_hex`) — dikelompokkan 2-byte, cocok buat dicocokkan visual di layar/dicatat.
- **Numerik** (`fp_numeric`) — buat orang yang lebih terbiasa baca angka daripada huruf.

Ketiganya **mewakili hash yang sama persis** — cuma "bahasa" tampilan yang beda, seperti menulis angka `255` vs `0xFF` vs "dua ratus lima puluh lima".

### 3.3 Dua identitas terpisah yang di-fingerprint

Ada **dua** pasangan kunci berbeda di aplikasi ini, dengan fingerprint masing-masing:

| Identitas | Algoritma | Fungsi | Lokasi |
|---|---|---|---|
| **RSA keypair** | RSA-2048 | Enkripsi file mode Hybrid (`encrypt --algo rsa`) | dibuat manual, dimana saja, sebanyak apa pun |
| **Transport identity** | X25519 | Autentikasi P2P saat transfer file (anti-MITM) | auto-dibuat sekali di `~/.cryptohan/transport.priv.pem` |

Fingerprint yang dibahas untuk "verifikasi lawan bicara saat kirim file" adalah fingerprint **Transport identity**, bukan RSA.

### 3.4 Model kepercayaan: TOFU + pin manual (bukan CA)

Tidak ada otoritas pusat yang "menjamin" fingerprint itu benar milik Bob. Kepercayaannya datang dari **manusia**:

```
Alice & Bob telepon-teleponan → saling bacakan fingerprint → cocok? → Alice simpan fingerprint Bob
                                                                       di contacts.json
```

Ini dilindungi HMAC lokal (`contacts.py`) — bukan supaya orang lain tidak bisa membaca, tapi supaya proses lain di komputer yang sama tidak bisa diam-diam mengganti fingerprint yang tersimpan tanpa ketahuan.

Begitu fingerprint sudah tersimpan (`expected_fp`), tiap kali transfer, aplikasi **membandingkan** fingerprint yang benar-benar diterima saat handshake dengan yang tersimpan — pakai `hmac.compare_digest()` (bukan `==` biasa, supaya waktu perbandingannya konstan dan tidak bisa dipakai menebak isi hash lewat serangan timing).

## 4. Lapisan Transport (Noise Protocol)

### 4.1 Kenapa bukan TLS biasa

TLS didesain untuk dunia yang punya CA (certificate authority). CryptoHan tidak punya itu — jadi dipilih **Noise Protocol Framework**, kerangka handshake yang lebih ringan, dipakai juga oleh WireGuard dan WhatsApp, yang secara eksplisit mendukung mode "raw key + verifikasi manual" tanpa perlu sertifikat sama sekali. Konfigurasinya di `config.py`:

```python
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
```

Dibaca begini: pola handshake **XX**, kurva eliptik **25519** (X25519), cipher **ChaChaPoly** (ChaCha20-Poly1305, buat enkripsi+autentikasi tiap pesan), hash **SHA256**.

### 4.2 Kenapa polanya "XX"

Nama pola di Noise selalu 2 huruf: huruf pertama = apa yang initiator (pengirim) kirim soal kunci statisnya, huruf kedua = apa yang responder (penerima) kirim soal kunci statisnya. **X** artinya "kunci statis dikirim tersembunyi di tengah handshake" (bukan diketahui sejak awal). Jadi **XX** = kedua pihak **saling** mengungkap kunci statis mereka selama proses — cocok untuk P2P yang sifatnya dua arah setara, beda dengan TLS server-klien yang biasanya cuma satu arah wajib (server) dan satu arah opsional (mTLS).

### 4.3 Tiga pesan handshake, langkah demi langkah

Lihat `transport.py` (fungsi `send_file` untuk sisi pengirim, `Receiver._handle` untuk sisi penerima):

```
Pengirim (initiator)                          Penerima (responder)
────────────────────                          ────────────────────
1. kirim kunci sesaat (ephemeral) miliknya  →
                                             ←  2. kirim kunci sesaat + kunci statis (permanen)
                                                   miliknya, dienkripsi pakai rahasia dari DH
                                                   sesaat↔sesaat + sesaat↔statis
3. kirim kunci statis miliknya, dienkripsi  →
   pakai rahasia gabungan sejauh ini
```

Setelah pesan ke-3, **kedua pihak** sudah:

- Sepakat soal satu rahasia bersama (lewat 3 kombinasi DH berbeda: sesaat-sesaat, sesaat-statis, statis-sesaat — makin banyak kombinasi = makin kuat jaminan autentikasinya).
- Tahu kunci publik statis (permanen) lawan bicaranya — **inilah** yang di-hash jadi fingerprint dan dibandingkan dengan yang di-pin.

Fungsi kecil yang mengambil kunci statis lawan dari objek handshake (`transport.py`):

```python
def _rs_public_raw(hs):
    rs = getattr(hs, "rs", None)          # "remote static" — kunci statis lawan bicara
    v = getattr(rs, "public_bytes", None) if rs is not None else None
    return bytes(v) if isinstance(v, (bytes, bytearray)) else None
```

### 4.4 Titik krusial: verifikasi terjadi SETELAH handshake, SEBELUM data

Ini titik penghubung Bagian 3 dan Bagian 4. Handshake Noise di atas **akan selesai dengan sukses** bahkan kalau lawan bicaranya penyerang (karena DH tidak peduli siapa lawannya, cuma peduli matematikanya konsisten). Makanya, tepat setelah handshake selesai, ditambahkan gerbang aplikasi-level:

```
handshake selesai (3 pesan)
        ↓
peer_fp = SHA256(kunci statis lawan yang baru diterima)
        ↓
peer_fp == expected_fp (yang dipin di contacts.json)?
   ├─ cocok / belum pernah dipin  → kirim frame "ACCEPT", lanjut kirim file
   └─ tidak cocok                → kirim frame "REJECT:fingerprint", batalkan (FingerprintMismatchError)
```

Bagian ini ada di `transport.py`, sisi pengirim (`send_file`) dan sisi penerima (`Receiver._handle`) — dirancang supaya kedua sisi **eksplisit saling memberi tahu** hasil verifikasi lewat frame terenkripsi, bukan cuma diam-diam menutup koneksi.

### 4.5 Urutan pesan lengkap end-to-end

Menggabungkan semuanya, satu sesi kirim file terlihat begini:

```
┌─ HANDSHAKE (Noise_XX, 3 pesan) ─────────────────┐
│ 1. e            (pengirim → penerima)            │
│ 2. e, ee, s, es (penerima → pengirim)            │
│ 3. s, se        (pengirim → penerima)            │
└───────────────────────────────────────────────────┘
        kedua sisi hitung peer_fp dari kunci statis lawan
┌─ GERBANG FINGERPRINT ────────────────────────────┐
│ penerima → pengirim: ACCEPT  atau  REJECT:fingerprint │
└───────────────────────────────────────────────────┘
        (kalau REJECT → berhenti di sini, tidak ada data mengalir)
┌─ TRANSFER DATA (semua terenkripsi Noise) ────────┐
│ pengirim → penerima: header (nama, ukuran, sha256,│
│                       uuid, timestamp)             │
│ pengirim → penerima: potongan file (berulang)      │
│ penerima → pengirim: OK  atau  ERR:size/replay/    │
│                       checksum                     │
└───────────────────────────────────────────────────┘
```

### 4.6 Lapisan pengaman tambahan di atas transport

Selain fingerprint, ada 3 pengaman lain yang jalan bersamaan di level data (`transport.py`):

- **Anti-replay** — tiap transfer punya `uuid` unik + `timestamp`; penerima menyimpan uuid yang sudah pernah dilihat dan menolak kalau uuid yang sama diputar ulang, atau timestamp-nya sudah lewat `REPLAY_WINDOW_SEC` (5 menit).
- **Checksum SHA-256 seluruh file** — dihitung pengirim sebelum kirim, dicocokkan penerima setelah selesai terima; kalau beda (file rusak/di-tamper di tengah jalan), file yang sudah ditulis langsung dihapus.
- **Sanitasi nama file** (`_safe_name`) — mencegah nama file berisi path traversal (`../../etc/passwd`) atau null byte menimpa file di luar folder tujuan.

## 5. Hubungan kedua lapisan

| | Tugasnya | Menjawab pertanyaan |
|---|---|---|
| **Transport (Noise_XX)** | Bikin kanal terenkripsi + memungkinkan kedua pihak saling menunjukkan kunci statis mereka | "Apakah data ini aman dari penyadapan selama di jalan?" |
| **Fingerprint** | Memutuskan apakah kunci statis yang ditunjukkan itu **benar milik orang yang dimaksud** | "Apakah aku benar sedang bicara dengan Bob, bukan penyerang?" |

Keduanya **wajib jalan bersama** — Transport tanpa Fingerprint rentan MITM (kanal aman tapi ke orang yang salah); Fingerprint tanpa Transport tidak ada gunanya (tidak ada kanal aman untuk diverifikasi sama sekali).
