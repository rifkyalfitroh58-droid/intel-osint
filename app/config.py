import os

# Coba baca .env jika python-dotenv tersedia
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass  # Tidak masalah, bisa juga set manual di bawah

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR    = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH     = os.path.join(DATA_DIR, "osint_intel.db")

# ── NewsAPI Key ───────────────────────────────────────────────────────────────
# Cara 1: Isi langsung di sini (ganti teks di bawah)
# Cara 2: Buat file .env di folder intel-osint/ lalu isi: NEWS_API_KEY=xxx
# Cara 3: Set environment variable di terminal: export NEWS_API_KEY=xxx
NEWS_API_KEY = os.getenv("NEWS_API_KEY", "isi_api_key_kamu_di_sini")

# ── Risk level thresholds ─────────────────────────────────────────────────────
RISK_LEVELS = {
    "HIGH"  : (70, 100, "🔴 TINGGI",  "#E74C3C"),
    "MEDIUM": (40,  69, "🟡 SEDANG",  "#F39C12"),
    "LOW"   : ( 0,  39, "🟢 RENDAH",  "#2ECC71"),
}

# ── Entity colors untuk network graph ────────────────────────────────────────
ENTITY_COLORS = {
    "PERSON" : "#E74C3C",
    "ORG"    : "#3498DB",
    "GPE"    : "#2ECC71",
    "MONEY"  : "#F39C12",
    "EVENT"  : "#9B59B6",
    "PRODUCT": "#1ABC9C",
}

# ── Label tipe entitas ────────────────────────────────────────────────────────
ENTITY_LABELS = {
    "PERSON" : "Individu",
    "ORG"    : "Organisasi",
    "GPE"    : "Lokasi/Negara",
    "MONEY"  : "Finansial",
    "EVENT"  : "Kejadian",
    "PRODUCT": "Produk",
}
