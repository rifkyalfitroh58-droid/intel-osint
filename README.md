# 🔍 INTEL-OSINT Dashboard v2.1

Dashboard analisis intelijen sumber terbuka berbasis Python + Streamlit.
Pantau pemberitaan publik, analisis sentimen, peta entitas, dan skor risiko secara otomatis.

---

## 📋 Persyaratan

- **Python 3.9 atau lebih baru**
- Koneksi internet (untuk mengambil berita dari NewsAPI)
- API key gratis dari [newsapi.org](https://newsapi.org/register)

---

## 🚀 Cara Install & Jalankan

### Langkah 1 — Download & Ekstrak
Ekstrak file zip ke folder yang kamu inginkan, contoh:
```
C:\Users\NamaKamu\intel-osint\     ← Windows
/Users/NamaKamu/intel-osint/       ← Mac
/home/NamaKamu/intel-osint/        ← Linux
```

### Langkah 2 — Install Python
Jika belum punya Python:
- **Windows/Mac**: Download dari https://python.org/downloads → centang "Add to PATH"
- **Linux**: `sudo apt install python3 python3-pip`

Cek versi: `python --version` (harus 3.9+)

### Langkah 3 — Install dependencies
Buka terminal/command prompt, masuk ke folder `intel-osint`:
```bash
cd intel-osint

# Buat virtual environment (direkomendasikan)
python -m venv venv

# Aktifkan virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install semua library
pip install -r requirements.txt
```

### Langkah 4 — Daftarkan API Key (WAJIB untuk ambil berita baru)
1. Buka https://newsapi.org/register → daftar gratis
2. Salin API key kamu
3. Buka file `app/config.py` dengan Notepad/TextEdit
4. Ganti baris ini:
   ```python
   NEWS_API_KEY = os.getenv("NEWS_API_KEY", "isi_api_key_kamu_di_sini")
   ```
   menjadi:
   ```python
   NEWS_API_KEY = os.getenv("NEWS_API_KEY", "abc123xxxAPIkeyKamu")
   ```

   **Alternatif (lebih aman):** salin `.env.example` menjadi `.env`, lalu isi:
   ```
   NEWS_API_KEY=abc123xxxAPIkeyKamu
   ```

### Langkah 5 — Jalankan Dashboard
```bash
streamlit run app/dashboard.py
```

Browser akan terbuka otomatis di `http://localhost:8501`

---

## 📱 Akses dari HP (di jaringan WiFi yang sama)

1. Jalankan dashboard di laptop dengan perintah:
   ```bash
   streamlit run app/dashboard.py --server.address 0.0.0.0
   ```
2. Lihat IP laptop kamu:
   - Windows: `ipconfig` → cari "IPv4 Address"
   - Mac/Linux: `ifconfig` atau `ip addr`
3. Buka di HP: `http://[IP-LAPTOP]:8501`
   Contoh: `http://192.168.1.5:8501`

---

## 🌐 NLP Opsional (ekstraksi entitas lebih akurat)

Dashboard sudah punya NLP bawaan (rule-based). Untuk akurasi lebih tinggi,
install spaCy:
```bash
pip install spacy
python -m spacy download en_core_web_sm
```

Untuk teks Bahasa Indonesia, install TextBlob:
```bash
pip install textblob
```

---

## 📁 Struktur Folder

```
intel-osint/
├── app/
│   ├── dashboard.py     ← File utama dashboard
│   └── config.py        ← Konfigurasi (API key, path, dll)
├── data/
│   └── osint_intel.db   ← Database SQLite (dibuat otomatis)
├── reports/             ← Folder laporan (dibuat otomatis)
├── requirements.txt     ← Daftar library
├── .env.example         ← Template API key
└── README.md            ← Panduan ini
```

---

## ❓ Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `streamlit: command not found` | Aktifkan venv dulu: `source venv/bin/activate` |
| `ModuleNotFoundError` | Jalankan ulang `pip install -r requirements.txt` |
| Berita tidak muncul | Cek API key di `config.py`, pastikan sudah diisi |
| Port 8501 tidak bisa dibuka | Coba: `streamlit run app/dashboard.py --server.port 8502` |
| Error saat pertama buka | Tambah target baru dulu lewat sidebar |

---

## 🔑 API Key Gratis

NewsAPI gratis untuk penggunaan pribadi (100 request/hari):
1. Buka https://newsapi.org/register
2. Daftar dengan email
3. Salin API key yang diberikan
4. Tempel di `config.py` atau file `.env`

---

Dibuat dengan Python, Streamlit, Plotly, NetworkX, dan SQLite.
