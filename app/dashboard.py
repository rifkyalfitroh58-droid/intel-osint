"""
INTEL-OSINT Dashboard v2.0
Sistem Analisis Intelijen Sumber Terbuka — Fully Dynamic
"""

import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import os, sys, re, json, math
from datetime import datetime, timezone
from collections import Counter
import warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DB_PATH, REPORTS_DIR, ENTITY_COLORS, ENTITY_LABELS, RISK_LEVELS, NEWS_API_KEY

# ── Opsional: spaCy & TextBlob (graceful fallback jika tidak tersedia) ────────
try:
    import spacy
    _nlp = spacy.load("en_core_web_sm")
    NLP_AVAILABLE = True
except Exception:
    NLP_AVAILABLE = False

try:
    from textblob import TextBlob
    TEXTBLOB_AVAILABLE = True
except Exception:
    TEXTBLOB_AVAILABLE = False

# ── Rule-based NLP fallback (selalu aktif, tidak butuh spaCy) ─────────────────
# Daftar entitas yang dikenal — bisa diperluas sesuai kebutuhan
_KNOWN_PERSONS = {
    "Elon Musk","Sam Altman","Jeff Bezos","Sundar Pichai","Tim Cook",
    "Mark Zuckerberg","Satya Nadella","Larry Page","Sergey Brin",
    "Shivon Zilis","Greg Brockman","Jared Birchall","Grok","Grimes",
    "Prabowo Subianto","Prabowo","Joko Widodo","Jokowi","Gibran",
    "Sri Mulyani","Anies Baswedan","Megawati","Airlangga","Luhut",
    "Nadiem Makarim","Basuki Tjahaja","Ahok","Yusril","Mahfud",
    "Donald Trump","Joe Biden","Kamala Harris","Barack Obama",
    "Keir Starmer","Emmanuel Macron","Vladimir Putin","Xi Jinping",
    "Volodymyr Zelensky","Benjamin Netanyahu","Narendra Modi",
    "Sarah Smith","Pete Hegseth","Marco Rubio","Robert F Kennedy",
    "Ursula von der Leyen","Olaf Scholz","Giorgia Meloni",
}
_KNOWN_ORGS = {
    "Tesla","SpaceX","X Corp","X Money","OpenAI","xAI","Neuralink","Boring Company",
    "Google","Apple","Microsoft","Amazon","Meta","NVIDIA","AMD","Intel",
    "DOGE","SEC","NASA","CIA","FBI","NSA","FTC","DOJ","FEC",
    "UN","WHO","NATO","EU","IMF","World Bank","BRICS","WTO","OPEC",
    "Pertamina","PLN","Telkom","BRI","BNI","Mandiri","Bulog","Garuda",
    "TNI","Polri","KPK","DPR","MPR","MK","MA","BI","OJK","BPS",
    "Republican Party","Democrat","GOP","White House","Pentagon",
    "Congress","Senate","Supreme Court","Federal Reserve","IRS",
    "BBC","CNN","Reuters","Bloomberg","New York Times","Fox News",
    "Americast","Guardian","Washington Post","Associated Press",
    "Hamas","Hezbollah","ISIS","Al-Qaeda","Taliban",
}
_KNOWN_LOCS = {
    "United States","US","USA","America","Russia","China","Ukraine",
    "Iran","Israel","Europe","UK","Britain","England","Germany","France",
    "Japan","India","Indonesia","Jakarta","Bali","Surabaya","Bandung",
    "Papua","Aceh","Kalimantan","Sulawesi","Sumatra","Yogyakarta",
    "Washington","New York","California","Texas","Florida","Chicago",
    "London","Brussels","Paris","Berlin","Rome","Vienna",
    "Beijing","Moscow","Tehran","Gaza","West Bank","Tel Aviv",
    "Taiwan","Australia","Singapore","Malaysia","Thailand",
    "Philippines","Vietnam","South Korea","North Korea","Canada",
    "Middle East","Southeast Asia","Eastern Europe","Central Asia",
    "Saudi Arabia","UAE","Qatar","Turkey","Egypt","Libya","Sudan",
}
_FALSE_POSITIVES = {
    "former google","education ministry","the indonesian","hajj village",
    "the white","the court","this week","he said","she said",
    "the senate","the department","in west","the youtefa",
}

def extract_entities_rule_based(text: str) -> list:
    """
    Ekstrak entitas tanpa spaCy menggunakan:
    1. Pencocokan daftar entitas yang dikenal (PERSON / ORG / GPE)
    2. Pola regex proper noun 2+ kata sebagai fallback PERSON
    Return: list of (text, label)
    """
    if not text:
        return []
    results, seen = [], set()

    def _add(ent, label):
        key = ent.lower().strip()
        if key and key not in seen and key not in _FALSE_POSITIVES:
            seen.add(key)
            results.append((ent, label))

    for ent in _KNOWN_PERSONS:
        if re.search(r'\b' + re.escape(ent) + r'\b', text, re.IGNORECASE):
            _add(ent, "PERSON")
    for ent in _KNOWN_ORGS:
        if re.search(r'\b' + re.escape(ent) + r'\b', text, re.IGNORECASE):
            _add(ent, "ORG")
    for ent in _KNOWN_LOCS:
        if re.search(r'\b' + re.escape(ent) + r'\b', text, re.IGNORECASE):
            _add(ent, "GPE")

    # Fallback: tangkap proper noun 2+ kata yang belum ada di daftar
    caps = re.findall(r'\b([A-Z][a-z]{1,}(?:\s+[A-Z][a-z]{1,}){1,3})\b', text)
    for cap in caps:
        if len(cap) > 5:
            _add(cap, "PERSON")

    return results


def backfill_entities(target_id: int) -> tuple:
    """
    Isi ulang entitas & relasi untuk target yang belum punya data entitas.
    Menggunakan rule-based NLP (atau spaCy jika tersedia).
    Return: (n_entities, n_relations)
    """
    try:
        conn = get_conn()
        arts = conn.execute(
            "SELECT title, description FROM articles WHERE target_id=?", (target_id,)
        ).fetchall()
        if not arts:
            conn.close()
            return 0, 0

        entity_counter: Counter = Counter()
        co_occur:       Counter = Counter()

        for title, desc in arts:
            text = (desc or "").strip() or (title or "").strip()
            if not text:
                continue

            ents_in_doc = []
            if NLP_AVAILABLE:
                try:
                    doc = _nlp(text[:500])
                    for ent in doc.ents:
                        if ent.label_ in ENTITY_COLORS and len(ent.text.strip()) > 1:
                            entity_counter[(ent.text.strip(), ent.label_)] += 1
                            ents_in_doc.append(ent.text.strip())
                except Exception:
                    pass
            # Selalu jalankan rule-based juga (melengkapi spaCy)
            for ent_text, ent_label in extract_entities_rule_based(text):
                entity_counter[(ent_text, ent_label)] += 1
                ents_in_doc.append(ent_text)

            # Co-occurrence pairs
            unique_ents = list(dict.fromkeys(ents_in_doc))  # preserve order, deduplicate
            for i, ea in enumerate(unique_ents):
                for eb in unique_ents[i+1:]:
                    if ea != eb:
                        co_occur[tuple(sorted([ea, eb]))] += 1

        cur = conn.cursor()
        # Hapus entitas & relasi lama dulu (hindari duplikat jika di-backfill ulang)
        cur.execute("DELETE FROM entities WHERE target_id=?",  (target_id,))
        cur.execute("DELETE FROM relations WHERE target_id=?", (target_id,))

        n_ent = 0
        for (text_e, label_e), count_e in entity_counter.most_common(100):
            cur.execute(
                "INSERT INTO entities (target_id, text, label, count) VALUES (?,?,?,?)",
                (target_id, text_e, label_e, count_e)
            )
            n_ent += 1

        n_rel = 0
        for (ea, eb), weight in co_occur.most_common(50):
            if ea != eb:
                cur.execute(
                    "INSERT INTO relations (target_id, entity_a, entity_b, weight) VALUES (?,?,?,?)",
                    (target_id, ea, eb, weight)
                )
                n_rel += 1

        conn.commit()
        conn.close()
        clear_cache()
        return n_ent, n_rel

    except Exception as e:
        return 0, 0


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="INTEL-OSINT Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;700&family=DM+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
#MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 1.2rem; padding-bottom: 1rem; }

.intel-header {
    background: linear-gradient(135deg, #0A0F1E 0%, #0D1B2A 50%, #1A2744 100%);
    border: 1px solid #1E3A5F;
    border-radius: 12px;
    padding: 1.4rem 2rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
}
.intel-header::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(30,90,120,0.03) 2px, rgba(30,90,120,0.03) 4px
    );
}
.intel-title {
    font-family: 'DM Mono', monospace; font-size: 1.5rem;
    font-weight: 500; color: #4FC3F7; letter-spacing: 0.08em; margin: 0;
}
.intel-sub {
    font-family: 'DM Mono', monospace; font-size: 0.72rem;
    color: rgba(79,195,247,0.5); letter-spacing: 0.12em;
    margin-top: 4px; text-transform: uppercase;
}
.intel-badge {
    display: inline-block; font-family: 'DM Mono', monospace; font-size: 0.65rem;
    background: rgba(79,195,247,0.1); border: 1px solid rgba(79,195,247,0.3);
    color: #4FC3F7; border-radius: 4px; padding: 2px 8px;
    margin-right: 6px; margin-top: 8px; letter-spacing: 0.06em;
}
.intel-badge.red   { background: rgba(231,76,60,0.1); border-color: rgba(231,76,60,0.3); color: #E74C3C; }
.intel-badge.green { background: rgba(46,204,113,0.1); border-color: rgba(46,204,113,0.3); color: #2ECC71; }

.metric-card {
    background: #0D1B2A; border: 1px solid #1E3A5F;
    border-radius: 10px; padding: 1rem 1.2rem;
    text-align: center; position: relative; overflow: hidden;
}
.metric-card::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px; }
.metric-card.blue::after   { background: #4FC3F7; }
.metric-card.red::after    { background: #E74C3C; }
.metric-card.green::after  { background: #2ECC71; }
.metric-card.yellow::after { background: #F39C12; }
.metric-card.purple::after { background: #9B59B6; }
.metric-num   { font-family:'DM Mono',monospace; font-size:1.9rem; font-weight:500; color:#4FC3F7; line-height:1.1; }
.metric-num.red    { color:#E74C3C; }
.metric-num.green  { color:#2ECC71; }
.metric-num.yellow { color:#F39C12; }
.metric-label { font-size:0.72rem; color:rgba(255,255,255,0.4); margin-top:4px; letter-spacing:0.06em; text-transform:uppercase; }

.section-title {
    font-family: 'DM Mono', monospace; font-size: 0.8rem; font-weight: 500;
    color: #4FC3F7; letter-spacing: 0.12em; text-transform: uppercase;
    padding-bottom: 6px; border-bottom: 1px solid #1E3A5F;
    margin: 1.2rem 0 0.8rem; display: flex; align-items: center; gap: 8px;
}
.intel-box {
    background: #0A0F1E; border: 1px solid #1E3A5F; border-radius: 8px;
    padding: 0.9rem 1.1rem; margin-bottom: 0.6rem;
    font-size: 0.84rem; color: rgba(255,255,255,0.8); line-height: 1.6;
}
.intel-box.alert   { border-color: rgba(231,76,60,0.4); background: rgba(231,76,60,0.05); color: #E98E82; }
.intel-box.success { border-color: rgba(46,204,113,0.4); background: rgba(46,204,113,0.05); color: #82E8A8; }
.intel-box.warning { border-color: rgba(243,156,18,0.4); background: rgba(243,156,18,0.05); color: #F5C261; }

.entity-tag {
    display: inline-block; font-family: 'DM Mono', monospace; font-size: 0.68rem;
    padding: 2px 8px; border-radius: 3px; margin: 2px; border: 1px solid;
}
.article-card {
    background: #0D1B2A; border: 1px solid #1E3A5F; border-radius: 8px;
    padding: 0.8rem 1rem; margin-bottom: 8px; font-size: 0.82rem;
}
.article-title { color: white; font-weight: 500; margin-bottom: 4px; }
.article-meta  { color: rgba(255,255,255,0.35); font-size: 0.72rem; font-family: 'DM Mono', monospace; }
.article-sent-pos { color: #2ECC71; font-weight: 700; }
.article-sent-neg { color: #E74C3C; font-weight: 700; }
.article-sent-neu { color: #888; font-weight: 700; }

.report-box {
    background: #0A0F1E; border: 1px solid #1E3A5F; border-radius: 8px;
    padding: 1.2rem; font-family: 'DM Mono', monospace; font-size: 0.75rem;
    color: rgba(255,255,255,0.75); line-height: 1.8; white-space: pre-wrap;
    max-height: 500px; overflow-y: auto;
}
.divider { border: none; border-top: 1px solid #1E3A5F; margin: 0.8rem 0; }

section[data-testid="stSidebar"] { background: #050A14; }
section[data-testid="stSidebar"] * { color: rgba(255,255,255,0.8) !important; }
section[data-testid="stSidebar"] hr { border-color: #1E3A5F !important; }

.stTabs [data-baseweb="tab-list"] {
    background: transparent; border-bottom: 1px solid #1E3A5F; gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'DM Mono', monospace; font-size: 0.75rem; letter-spacing: 0.08em;
    padding: 8px 16px; border-radius: 6px 6px 0 0;
    color: rgba(255,255,255,0.4) !important; background: transparent; border: none;
}
.stTabs [aria-selected="true"] {
    background: rgba(79,195,247,0.1) !important;
    color: #4FC3F7 !important; border-bottom: 2px solid #4FC3F7 !important;
}
div[data-testid="stButton"] button {
    background: rgba(79,195,247,0.1) !important; color: #4FC3F7 !important;
    border: 1px solid rgba(79,195,247,0.3) !important; border-radius: 6px !important;
    font-family: 'DM Mono', monospace !important; font-size: 0.78rem !important;
    letter-spacing: 0.06em !important;
}
div[data-testid="stButton"] button:hover { background: rgba(79,195,247,0.2) !important; }
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #0A0F1E; }
::-webkit-scrollbar-thumb { background: #1E3A5F; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# ── Plotly dark theme ─────────────────────────────────────────────────────────
PLOT = dict(
    plot_bgcolor="#0A0F1E", paper_bgcolor="#0D1B2A",
    font=dict(family="DM Sans", color="rgba(255,255,255,0.7)", size=11),
    margin=dict(l=10, r=10, t=36, b=10),
    xaxis=dict(showgrid=True, gridcolor="#1E3A5F", showline=False,
               tickfont=dict(color="rgba(255,255,255,0.4)")),
    yaxis=dict(showgrid=True, gridcolor="#1E3A5F", showline=False,
               tickfont=dict(color="rgba(255,255,255,0.4)")),
)

TOPIC_COLORS = ["#E74C3C","#3498DB","#F39C12","#9B59B6","#2ECC71","#1ABC9C","#E67E22"]


# ── Database helpers ──────────────────────────────────────────────────────────
def get_conn():
    return sqlite3.connect(DB_PATH)


def ensure_db():
    """Buat tabel jika belum ada."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_conn()
    cur  = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            created_at TEXT NOT NULL,
            total_news INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            summary TEXT
        );
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            title TEXT, description TEXT, content TEXT,
            source TEXT, author TEXT, url TEXT,
            published_at TEXT, sentiment REAL DEFAULT 0.0,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            text TEXT, label TEXT, count INTEGER DEFAULT 1,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            entity_a TEXT, entity_b TEXT, weight INTEGER DEFAULT 1,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );
    """)
    conn.commit()
    conn.close()


ensure_db()


@st.cache_data(ttl=30)
def load_targets() -> pd.DataFrame:
    try:
        conn = get_conn()
        df   = pd.read_sql("SELECT * FROM targets ORDER BY created_at DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_articles(target_id: int) -> pd.DataFrame:
    try:
        conn = get_conn()
        df   = pd.read_sql(
            "SELECT * FROM articles WHERE target_id=? ORDER BY published_at DESC",
            conn, params=(target_id,))
        conn.close()
        df["published_at"] = pd.to_datetime(df["published_at"], errors="coerce")
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_entities(target_id: int) -> pd.DataFrame:
    try:
        conn = get_conn()
        df   = pd.read_sql(
            "SELECT * FROM entities WHERE target_id=? ORDER BY count DESC",
            conn, params=(target_id,))
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_relations(target_id: int) -> pd.DataFrame:
    try:
        conn = get_conn()
        df   = pd.read_sql(
            "SELECT * FROM relations WHERE target_id=? ORDER BY weight DESC LIMIT 60",
            conn, params=(target_id,))
        conn.close()
        # Hapus self-relation
        df = df[df["entity_a"] != df["entity_b"]]
        return df
    except Exception:
        return pd.DataFrame()


def clear_cache():
    load_targets.clear()
    load_articles.clear()
    load_entities.clear()
    load_relations.clear()


# ── Helpers UI ────────────────────────────────────────────────────────────────
def get_risk_color(score: float) -> str:
    if score >= 70: return "#E74C3C"
    if score >= 40: return "#F39C12"
    return "#2ECC71"


def get_risk_label(score: float) -> str:
    if score >= 70: return "🔴 TINGGI"
    if score >= 40: return "🟡 SEDANG"
    return "🟢 RENDAH"


def hex_rgb(h: str) -> str:
    h = h.lstrip("#")
    return ",".join(str(int(h[i:i+2], 16)) for i in (0, 2, 4))


# ── Kalkulasi Risk Score DINAMIS ──────────────────────────────────────────────
def compute_risk_score(df_art: pd.DataFrame, df_ent: pd.DataFrame) -> dict:
    """
    Hitung risk score 0-100 dari data aktual:
    Volume (25) + Sentimen negatif (30) + Keragaman sumber (20) + Keyword sensitif (25)
    """
    if df_art.empty:
        return {"total": 0.0, "volume": 0.0, "sentimen": 0.0, "keragaman": 0.0, "sensitif": 0.0}

    n = len(df_art)

    # Volume — log scale; 200 artikel = 25pt
    vol_raw  = min(math.log1p(n) / math.log1p(200) * 25, 25)

    # Sentimen negatif
    neg_ratio = (df_art["sentiment"] < -0.05).sum() / max(n, 1)
    sent_raw  = round(neg_ratio * 30, 2)

    # Keragaman sumber
    n_src    = df_art["source"].nunique()
    div_raw  = min(n_src / 10 * 20, 20)

    # Keyword sensitif dalam judul
    SENSITIVE = [
        "arrest","crime","fraud","corruption","scandal","lawsuit","investigation",
        "accused","convicted","illegal","bribery","penipuan","korupsi","ditangkap",
        "tersangka","pidana","kriminal","skandal","manipulasi",
    ]
    titles_lower = df_art["title"].str.lower().fillna("")
    sens_hits    = titles_lower.apply(lambda t: any(k in t for k in SENSITIVE)).sum()
    sens_raw     = min(sens_hits / max(n, 1) * 25 * 3, 25)

    total = vol_raw + sent_raw + div_raw + sens_raw
    return {
        "total":     round(min(total, 100), 1),
        "volume":    round(vol_raw, 1),
        "sentimen":  round(sent_raw, 1),
        "keragaman": round(div_raw, 1),
        "sensitif":  round(sens_raw, 1),
    }


# ── Ekstrak Topik DINAMIS dari artikel ───────────────────────────────────────
def extract_topics_dynamic(df_art: pd.DataFrame, n_topics: int = 5) -> list:
    """
    Ekstrak topik dari frekuensi kata di judul + deskripsi.
    Setiap topik = seed word + kata yang sering co-occur bersamanya.
    """
    STOPWORDS = {
        "the","a","an","in","of","to","and","or","for","on","at","by","is",
        "are","was","were","with","this","that","it","as","be","has","have",
        "had","will","would","can","could","from","into","its","he","she",
        "we","they","but","not","so","up","if","do","did","about","after",
        "over","under","new","more","than","all","just","also","been","said",
        "says","what","how","who","which","when","their","other","such","no",
        "yang","di","ke","dan","dari","dengan","ini","itu","tidak","untuk",
        "ada","bisa","pada","juga","akan","sudah","karena","agar","saat",
        "via","amid","after","before","while","since","through","without",
    }
    if df_art.empty:
        return []

    texts    = (df_art["title"].fillna("") + " " + df_art["description"].fillna("")).str.lower()
    all_w    = re.findall(r'[a-zA-Z]{3,}', " ".join(texts))
    filtered = [w for w in all_w if w not in STOPWORDS]
    word_freq = Counter(filtered)

    top_words = [w for w, _ in word_freq.most_common(n_topics * 8)]

    topics, used = [], set()
    for seed in top_words:
        if seed in used or len(topics) >= n_topics:
            continue
        mask_seed     = texts.str.contains(r'\b' + re.escape(seed) + r'\b', regex=True, na=False)
        related_texts = texts[mask_seed]
        if len(related_texts) < 2:
            continue
        co_w   = re.findall(r'[a-zA-Z]{3,}', " ".join(related_texts))
        co_w   = [w for w in co_w if w not in STOPWORDS and w != seed]
        co_top = [w for w, _ in Counter(co_w).most_common(8) if w not in used][:5]
        used.update([seed] + co_top[:2])
        topics.append({
            "id":       len(topics) + 1,
            "label":    seed.title(),
            "keywords": [seed] + co_top,
            "color":    TOPIC_COLORS[len(topics) % len(TOPIC_COLORS)],
        })
    return topics


# ── NewsAPI fetch & simpan ke DB ──────────────────────────────────────────────
def fetch_and_store(query: str, page_size: int = 50) -> tuple:
    """Ambil berita dari NewsAPI, proses NLP, simpan ke DB. Return (target_id, n, err)."""
    import requests

    if not NEWS_API_KEY or NEWS_API_KEY == "isi_api_key_kamu":
        return None, 0, "NEWS_API_KEY belum diisi di config.py"

    try:
        resp = requests.get(
            "https://newsapi.org/v2/everything",
            params={"q": query, "pageSize": page_size,
                    "sortBy": "publishedAt", "language": "en", "apiKey": NEWS_API_KEY},
            timeout=15,
        )
        data = resp.json()
    except Exception as e:
        return None, 0, f"Koneksi gagal: {e}"

    if data.get("status") != "ok":
        return None, 0, f"NewsAPI error: {data.get('message','unknown')}"

    articles = [a for a in data.get("articles", []) if a.get("title")]
    if not articles:
        return None, 0, "Tidak ada artikel ditemukan."

    conn = get_conn()
    cur  = conn.cursor()
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO targets (query,created_at,total_news) VALUES (?,?,?)",
                (query, now, data.get("totalResults", len(articles))))
    target_id = cur.lastrowid

    entity_counter: Counter = Counter()
    co_occur:       Counter = Counter()

    for art in articles:
        title       = art.get("title", "")   or ""
        description = art.get("description","") or ""
        content     = art.get("content", "") or ""
        source      = (art.get("source") or {}).get("name","Unknown")
        author      = art.get("author","")   or ""
        url         = art.get("url","")      or ""
        published   = art.get("publishedAt","") or ""

        text_nlp = description if description.strip() else title
        sentiment = 0.0
        if TEXTBLOB_AVAILABLE and text_nlp.strip():
            try:
                sentiment = round(TextBlob(text_nlp).sentiment.polarity, 4)
            except Exception:
                pass

        cur.execute(
            "INSERT INTO articles (target_id,title,description,content,source,author,url,published_at,sentiment)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (target_id, title, description, content, source, author, url, published, sentiment)
        )

        if text_nlp.strip():
            ents_in_doc = []
            if NLP_AVAILABLE:
                try:
                    doc = _nlp(text_nlp[:500])
                    for ent in doc.ents:
                        if ent.label_ in ENTITY_COLORS and len(ent.text.strip()) > 1:
                            entity_counter[(ent.text.strip(), ent.label_)] += 1
                            ents_in_doc.append(ent.text.strip())
                except Exception:
                    pass
            # Rule-based selalu dijalankan sebagai fallback / pelengkap spaCy
            for ent_text, ent_label in extract_entities_rule_based(text_nlp):
                entity_counter[(ent_text, ent_label)] += 1
                ents_in_doc.append(ent_text)
            unique_ents = list(dict.fromkeys(ents_in_doc))
            for i, ea in enumerate(unique_ents):
                for eb in unique_ents[i+1:]:
                    if ea != eb:
                        co_occur[tuple(sorted([ea, eb]))] += 1

    for (text, label), count in entity_counter.most_common(100):
        cur.execute("INSERT INTO entities (target_id,text,label,count) VALUES (?,?,?,?)",
                    (target_id, text, label, count))

    for (ea, eb), weight in co_occur.most_common(50):
        if ea != eb:
            cur.execute("INSERT INTO relations (target_id,entity_a,entity_b,weight) VALUES (?,?,?,?)",
                        (target_id, ea, eb, weight))

    # Hitung & simpan risk score
    df_tmp = pd.DataFrame([{
        "sentiment": a.get("sentiment", 0.0),
        "title":     a.get("title",""),
        "source":    (a.get("source") or {}).get("name",""),
    } for a in articles])
    rs_val = compute_risk_score(df_tmp, pd.DataFrame())["total"]
    cur.execute("UPDATE targets SET risk_score=? WHERE id=?", (rs_val, target_id))

    conn.commit()
    conn.close()
    clear_cache()
    return target_id, len(articles), None


# ═════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="padding:.8rem 0 .4rem">
        <div style="font-family:'DM Mono',monospace;font-size:1rem;font-weight:500;color:#4FC3F7;letter-spacing:.1em">
            ◈ INTEL-OSINT
        </div>
        <div style="font-family:'DM Mono',monospace;font-size:.65rem;color:rgba(79,195,247,.4);
                    letter-spacing:.12em;text-transform:uppercase;margin-top:2px">
            Open Source Intelligence System v2.0
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    # ── Form input target baru ─────────────────────────────────────────────
    st.markdown(
        '<div style="font-family:DM Mono;font-size:.65rem;color:rgba(79,195,247,.5);'
        'letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px">◈ TARGET BARU</div>',
        unsafe_allow_html=True,
    )
    new_query = st.text_input(
        "nama atau entitas",
        placeholder="mis. Elon Musk, Pertamina, AI Act...",
        label_visibility="collapsed",
        key="new_query_input",
    )
    col_fetch, col_n = st.columns([2, 1])
    with col_fetch:
        fetch_btn = st.button("⬇ Ambil Berita", use_container_width=True)
    with col_n:
        n_art_opt = st.selectbox("", [20, 50, 100], label_visibility="collapsed")

    if fetch_btn:
        if not new_query.strip():
            st.warning("Masukkan nama atau entitas terlebih dahulu.")
        else:
            with st.spinner(f"Mengambil berita untuk: {new_query}..."):
                tid, n_fetched, err = fetch_and_store(new_query.strip(), n_art_opt)
            if err:
                st.error(f"❌ {err}")
            else:
                st.success(f"✅ {n_fetched} artikel berhasil diambil!")
                st.rerun()

    st.divider()

    # ── Pilih target yang ada ──────────────────────────────────────────────
    df_targets = load_targets()

    if df_targets.empty:
        st.info("Belum ada data. Tambah target di atas atau upload `osint_intel.db` ke folder `data/`.")
        target_id   = None
        target_name = None
    else:
        st.markdown(
            '<div style="font-family:DM Mono;font-size:.65rem;color:rgba(79,195,247,.5);'
            'letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">TARGET AKTIF</div>',
            unsafe_allow_html=True,
        )
        target_options = {f"{r['query']} (#{r['id']})": r['id'] for _, r in df_targets.iterrows()}
        selected_label = st.selectbox("Target", list(target_options.keys()), label_visibility="collapsed")
        target_id      = target_options[selected_label]
        target_name    = selected_label.split(" (#")[0]

        col_del, col_fill = st.columns(2)
        with col_del:
            if st.button("🗑 Hapus", use_container_width=True):
                try:
                    conn = get_conn()
                    cur  = conn.cursor()
                    for tbl in ["relations","entities","articles"]:
                        cur.execute(f"DELETE FROM {tbl} WHERE target_id=?", (target_id,))
                    cur.execute("DELETE FROM targets WHERE id=?", (target_id,))
                    conn.commit()
                    conn.close()
                    clear_cache()
                    st.success("Target dihapus.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Gagal hapus: {e}")
        with col_fill:
            _n_ent_chk = get_conn().execute(
                "SELECT COUNT(*) FROM entities WHERE target_id=?", (target_id,)
            ).fetchone()[0]
            _btn_lbl = "🔄 Refresh" if _n_ent_chk > 0 else "⚡ Isi Entitas"
            if st.button(_btn_lbl, use_container_width=True):
                with st.spinner("Mengekstrak entitas..."):
                    n_e, n_r = backfill_entities(target_id)
                if n_e > 0:
                    st.success(f"✅ {n_e} entitas, {n_r} relasi")
                    st.rerun()
                else:
                    st.warning("Tidak ada entitas ditemukan.")

    st.divider()

    # ── Quick stats sidebar ────────────────────────────────────────────────
    if target_id:
        df_art_sb = load_articles(target_id)
        df_tgt_sb = df_targets[df_targets["id"] == target_id].iloc[0]
        rs_sb     = compute_risk_score(df_art_sb, load_entities(target_id))
        rc_sb     = get_risk_color(rs_sb["total"])
        rl_sb     = get_risk_label(rs_sb["total"])
        n_src_sb  = df_art_sb["source"].nunique() if not df_art_sb.empty else 0

        st.markdown(f"""
        <div style="font-family:'DM Mono',monospace;font-size:.65rem;color:rgba(79,195,247,.5);
                    letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px">QUICK STATS</div>
        <div style="background:#0A0F1E;border:1px solid #1E3A5F;border-radius:8px;padding:.8rem">
            <div style="color:rgba(255,255,255,.5);font-size:.7rem;margin-bottom:2px">Risk Score</div>
            <div style="font-family:'DM Mono',monospace;font-size:1.6rem;color:{rc_sb};font-weight:500">
                {rs_sb['total']:.1f}<span style="font-size:.9rem">/100</span>
            </div>
            <div style="font-size:.75rem;color:{rc_sb};margin-top:2px">{rl_sb}</div>
        </div>
        <div style="margin-top:8px;font-family:'DM Mono',monospace;font-size:.7rem;
                    color:rgba(255,255,255,.4);line-height:2">
            ARTICLES &nbsp;&nbsp;: {len(df_art_sb)}<br>
            SOURCES &nbsp;&nbsp;&nbsp;: {n_src_sb}<br>
            CREATED &nbsp;&nbsp;&nbsp;: {str(df_tgt_sb.get('created_at',''))[:10]}
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div style="font-family:'DM Mono',monospace;font-size:.65rem;
                color:rgba(79,195,247,.25);line-height:2;letter-spacing:.06em">
        INTEL-OSINT v2.0<br>
        DATA: NewsAPI (Public)<br>
        NLP: spaCy + TextBlob<br>
        CLASSIFICATION: OPEN
    </div>
    """, unsafe_allow_html=True)


# ── HEADER ────────────────────────────────────────────────────────────────────
now_str = datetime.now().strftime("%d %b %Y %H:%M")
st.markdown(f"""
<div class="intel-header">
    <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div>
            <div class="intel-title">◈ INTEL-OSINT DASHBOARD</div>
            <div class="intel-sub">Open Source Intelligence Analysis System — v2.0</div>
            <div style="margin-top:8px">
                <span class="intel-badge">UNCLASSIFIED</span>
                <span class="intel-badge green">OSINT</span>
                <span class="intel-badge">PUBLIC DATA ONLY</span>
            </div>
        </div>
        <div style="font-family:'DM Mono',monospace;font-size:.72rem;
                    color:rgba(79,195,247,.5);text-align:right">
            {now_str}<br>
            <span style="color:rgba(79,195,247,.25)">SYSTEM: ONLINE</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

if not target_id:
    st.info("👆 Tambahkan target baru di sidebar untuk memulai analisis.")
    st.stop()

# ── Load data utama ───────────────────────────────────────────────────────────
df_art = load_articles(target_id)
df_ent = load_entities(target_id)
df_rel = load_relations(target_id)
df_tgt = df_targets[df_targets["id"] == target_id].iloc[0]

if df_art.empty:
    st.warning(f"Tidak ada artikel untuk target **{target_name}**. Coba ambil berita baru.")
    st.stop()

# Kalkulasi dinamis dari data aktual
rs      = compute_risk_score(df_art, df_ent)
risk_sc = rs["total"]

# ── TABS ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "◈ OVERVIEW", "◈ SENTIMEN", "◈ ENTITAS & JARINGAN", "◈ TOPIK", "◈ LAPORAN",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    n     = len(df_art)
    pos_n = int((df_art["sentiment"] > 0.05).sum())
    neg_n = int((df_art["sentiment"] < -0.05).sum())
    n_src = int(df_art["source"].nunique())
    n_ent = len(df_ent)
    avg_s = float(df_art["sentiment"].mean())

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, val, lbl, nc, cc in [
        (c1, str(n),        "TOTAL ARTIKEL", "blue",   "blue"),
        (c2, str(n_src),    "SUMBER UNIK",   "blue",   "blue"),
        (c3, str(n_ent),    "ENTITAS",        "purple", "blue"),
        (c4, f"{risk_sc:.0f}", "RISK SCORE",
             "red" if risk_sc>=70 else "yellow" if risk_sc>=40 else "green",
             "red" if risk_sc>=70 else "yellow" if risk_sc>=40 else "green"),
        (c5, f"{avg_s:.3f}", "AVG SENTIMEN",
             "green" if avg_s > 0 else "red", "blue"),
    ]:
        with col:
            st.markdown(f"""
            <div class="metric-card {cc}">
                <div class="metric-num {nc}">{val}</div>
                <div class="metric-label">{lbl}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown('<hr class="divider">', unsafe_allow_html=True)

    col_risk, col_time = st.columns([1, 2])
    with col_risk:
        st.markdown('<div class="section-title">⬡ RISK ASSESSMENT</div>', unsafe_allow_html=True)
        rc = get_risk_color(risk_sc)
        rl = get_risk_label(risk_sc)

        fig_g = go.Figure(go.Indicator(
            mode="gauge+number", value=risk_sc,
            gauge=dict(
                axis=dict(range=[0,100], tickfont=dict(color="rgba(255,255,255,0.3)", size=9)),
                bar=dict(color=rc, thickness=0.3),
                bgcolor="#0A0F1E", bordercolor="#1E3A5F",
                steps=[
                    dict(range=[0,40],   color="rgba(46,204,113,0.08)"),
                    dict(range=[40,70],  color="rgba(243,156,18,0.08)"),
                    dict(range=[70,100], color="rgba(231,76,60,0.08)"),
                ],
                threshold=dict(line=dict(color=rc, width=2), thickness=0.75, value=risk_sc),
            ),
            number=dict(font=dict(color=rc, size=36, family="DM Mono"), suffix="/100"),
            title=dict(text=rl, font=dict(color=rc, size=13, family="DM Mono")),
        ))
        fig_g.update_layout(**{k:v for k,v in PLOT.items() if k not in ["xaxis","yaxis"]}, height=220)
        st.plotly_chart(fig_g, use_container_width=True)

        # Breakdown DINAMIS — dari compute_risk_score
        for lbl2, score2, mx2 in [
            ("Volume",    rs["volume"],    25),
            ("Sentimen-", rs["sentimen"],  30),
            ("Keragaman", rs["keragaman"], 20),
            ("Sensitif",  rs["sensitif"],  25),
        ]:
            pct = score2 / mx2 * 100 if mx2 > 0 else 0
            st.markdown(f"""
            <div style="font-family:'DM Mono',monospace;font-size:.68rem;
                        color:rgba(255,255,255,.5);margin-bottom:6px">
                {lbl2:<12} {score2:5.1f}/{mx2}
                <div style="background:#1E3A5F;border-radius:3px;height:4px;margin-top:2px">
                    <div style="background:{rc};height:4px;border-radius:3px;width:{pct:.1f}%"></div>
                </div>
            </div>""", unsafe_allow_html=True)

    with col_time:
        st.markdown('<div class="section-title">⬡ TIMELINE PEMBERITAAN</div>', unsafe_allow_html=True)
        df_ts = df_art.dropna(subset=["published_at"]).copy()
        if not df_ts.empty:
            df_ts["date"] = df_ts["published_at"].dt.date
            tl = df_ts.groupby("date").agg(count=("id","count"), avg_sent=("sentiment","mean")).reset_index()
            fig_tl = make_subplots(specs=[[{"secondary_y": True}]])
            fig_tl.add_trace(go.Bar(x=tl["date"], y=tl["count"], name="Artikel",
                                    marker_color="#4FC3F7", marker_opacity=0.7,
                                    hovertemplate="%{x}<br>Artikel: %{y}<extra></extra>"), secondary_y=False)
            fig_tl.add_trace(go.Scatter(x=tl["date"], y=tl["avg_sent"], name="Avg Sentimen",
                                        line=dict(color="#2ECC71", width=2), mode="lines+markers",
                                        marker=dict(size=6),
                                        hovertemplate="%{x}<br>Sentimen: %{y:.3f}<extra></extra>"), secondary_y=True)
            fig_tl.update_layout(**PLOT, height=260,
                title=dict(text="Volume Artikel & Sentimen per Hari",
                           font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0),
                legend=dict(orientation="h", y=-0.2, font=dict(color="rgba(255,255,255,0.5)", size=10)),
                hovermode="x unified",
            )
            fig_tl.update_yaxes(title_text="Artikel", secondary_y=False, title_font=dict(color="rgba(255,255,255,0.3)"))
            fig_tl.update_yaxes(title_text="Sentimen", secondary_y=True, title_font=dict(color="rgba(255,255,255,0.3)"))
            st.plotly_chart(fig_tl, use_container_width=True)
        else:
            st.info("Tidak ada data waktu yang valid.")

    st.markdown('<div class="section-title">⬡ ARTIKEL TERBARU</div>', unsafe_allow_html=True)
    for _, row in df_art.head(6).iterrows():
        sent = row["sentiment"]
        if sent > 0.05:
            ss = f'<span class="article-sent-pos">▲ {sent:.3f}</span>'
        elif sent < -0.05:
            ss = f'<span class="article-sent-neg">▼ {sent:.3f}</span>'
        else:
            ss = f'<span class="article-sent-neu">● {sent:.3f}</span>'
        pub = row["published_at"].strftime("%d %b %Y") if pd.notna(row["published_at"]) else "N/A"
        ttl = str(row["title"])[:100] + ("..." if len(str(row["title"])) > 100 else "")
        url = row.get("url", "#") or "#"
        st.markdown(f"""
        <div class="article-card">
            <div class="article-title">{ttl}</div>
            <div class="article-meta">
                [{row['source']}] &nbsp;·&nbsp; {pub} &nbsp;·&nbsp; SENT: {ss}
                &nbsp;·&nbsp; <a href="{url}" target="_blank"
                style="color:rgba(79,195,247,0.5);text-decoration:none">↗ SOURCE</a>
            </div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — SENTIMEN
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-title">⬡ ANALISIS SENTIMEN PUBLIK</div>', unsafe_allow_html=True)

    pos = int((df_art["sentiment"] > 0.05).sum())
    neg = int((df_art["sentiment"] < -0.05).sum())
    neu = len(df_art) - pos - neg

    c1, c2 = st.columns(2)
    with c1:
        fig_pie = go.Figure(go.Pie(
            labels=["Positif","Negatif","Netral"], values=[pos,neg,neu],
            marker_colors=["#2ECC71","#E74C3C","#4FC3F7"], hole=0.55,
            textfont=dict(size=11, family="DM Mono"),
            hovertemplate="%{label}: %{value} artikel (%{percent})<extra></extra>",
        ))
        fig_pie.update_layout(**{k:v for k,v in PLOT.items() if k not in ["xaxis","yaxis"]},
            height=260,
            title=dict(text="Distribusi Sentimen", font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0),
            showlegend=True, legend=dict(font=dict(color="rgba(255,255,255,0.5)", size=10), orientation="h", y=-0.1),
            annotations=[dict(text=f"<b>{len(df_art)}</b><br>Artikel", x=0.5, y=0.5,
                              font_size=14, font_color="#4FC3F7", showarrow=False)],
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        cols_bar = ["#2ECC71" if s>0.05 else "#E74C3C" if s<-0.05 else "#4FC3F7"
                    for s in df_art["sentiment"]]
        fig_bar = go.Figure(go.Bar(
            x=list(range(len(df_art))), y=df_art["sentiment"],
            marker_color=cols_bar, marker_opacity=0.8,
            hovertemplate="Artikel %{x}<br>Sentimen: %{y:.3f}<extra></extra>",
        ))
        mean_s = float(df_art["sentiment"].mean())
        fig_bar.add_hline(y=0, line_color="rgba(255,255,255,0.2)", line_dash="dash", line_width=1)
        fig_bar.add_hline(y=mean_s, line_color="#F39C12", line_dash="dot", line_width=1.5,
                          annotation_text=f"Mean: {mean_s:.3f}",
                          annotation_font_color="#F39C12", annotation_font_size=10)
        fig_bar.update_layout(**PLOT, height=260,
            title=dict(text="Sentiment Score per Artikel", font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0))
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown('<div class="section-title">⬡ SENTIMEN PER SUMBER BERITA</div>', unsafe_allow_html=True)
    src_sent = df_art.groupby("source").agg(avg_sent=("sentiment","mean"), count=("id","count")).sort_values("avg_sent").reset_index()
    if not src_sent.empty:
        cols_s = ["#E74C3C" if s<-0.05 else "#2ECC71" if s>0.05 else "#4FC3F7" for s in src_sent["avg_sent"]]
        fig_src = go.Figure(go.Bar(
            x=src_sent["avg_sent"], y=src_sent["source"], orientation="h",
            marker_color=cols_s, marker_opacity=0.8,
            text=[f"{v:.3f} ({c} art)" for v,c in zip(src_sent["avg_sent"], src_sent["count"])],
            textfont=dict(size=10, color="rgba(255,255,255,0.6)"), textposition="outside",
            hovertemplate="%{y}<br>Sentimen: %{x:.3f}<extra></extra>",
        ))
        fig_src.add_vline(x=0, line_color="rgba(255,255,255,0.2)", line_dash="dash", line_width=1)
        fig_src.update_layout(**PLOT, height=max(250, len(src_sent)*45),
            title=dict(text="Rata-rata Sentimen per Sumber", font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0))
        st.plotly_chart(fig_src, use_container_width=True)

    st.markdown('<div class="section-title">⬡ ARTIKEL PALING NEGATIF</div>', unsafe_allow_html=True)
    neg_arts = df_art[df_art["sentiment"] < -0.05].nsmallest(5, "sentiment")
    if neg_arts.empty:
        st.markdown('<div class="intel-box warning">Tidak ada artikel dengan sentimen negatif signifikan.</div>',
                    unsafe_allow_html=True)
    else:
        for _, row in neg_arts.iterrows():
            pub = row["published_at"].strftime("%d %b %Y") if pd.notna(row["published_at"]) else ""
            st.markdown(f"""
            <div class="intel-box alert">
                <b>{row['title']}</b><br>
                <span style="font-family:'DM Mono',monospace;font-size:.7rem">
                [{row['source']}] · {pub} · SENT: {row['sentiment']:.3f}
                </span>
            </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ENTITAS & JARINGAN
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    if df_ent.empty:
        st.markdown(
            '<div class="intel-box warning">⚠️ Belum ada data entitas untuk target ini. '
            'Data entitas tersedia jika spaCy terinstal saat pengambilan berita.</div>',
            unsafe_allow_html=True,
        )
    else:
        c_ent, c_net = st.columns([1, 2])

        with c_ent:
            st.markdown('<div class="section-title">⬡ TOP ENTITAS</div>', unsafe_allow_html=True)
            for lk, ln in ENTITY_LABELS.items():
                ents = df_ent[df_ent["label"] == lk].head(6)
                if ents.empty:
                    continue
                color = ENTITY_COLORS.get(lk, "#888")
                rgb   = hex_rgb(color)
                st.markdown(f'<div style="font-family:\'DM Mono\',monospace;font-size:.65rem;'
                            f'color:rgba(255,255,255,.35);letter-spacing:.1em;text-transform:uppercase;margin:8px 0 4px">{ln}</div>',
                            unsafe_allow_html=True)
                tags = "".join([
                    f'<span class="entity-tag" style="background:rgba({rgb},0.12);'
                    f'border-color:rgba({rgb},0.3);color:{color};font-family:DM Mono,monospace">'
                    f'{r["text"]} <span style="opacity:.5">×{r["count"]}</span></span>'
                    for _, r in ents.iterrows()
                ])
                st.markdown(f'<div style="margin-bottom:6px">{tags}</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-title">⬡ DISTRIBUSI ENTITAS</div>', unsafe_allow_html=True)
            try:
                fig_tree = px.treemap(df_ent.head(30).copy(), path=["label","text"],
                                      values="count", color="label", color_discrete_map=ENTITY_COLORS)
                fig_tree.update_layout(**{k:v for k,v in PLOT.items() if k not in ["xaxis","yaxis"]},
                    height=280,
                    title=dict(text="Treemap Entitas", font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0))
                fig_tree.update_traces(textfont=dict(size=11, family="DM Mono"))
                st.plotly_chart(fig_tree, use_container_width=True)
            except Exception as e:
                st.warning(f"Treemap tidak dapat ditampilkan: {e}")

        with c_net:
            st.markdown('<div class="section-title">⬡ ENTITY RELATIONSHIP NETWORK</div>', unsafe_allow_html=True)
            if df_rel.empty:
                st.info("Belum ada data relasi antar entitas.")
            else:
                try:
                    G = nx.Graph()
                    ent_dict = {r["text"]: (r["label"], r["count"]) for _, r in df_ent.iterrows()}
                    for _, r in df_rel.iterrows():
                        G.add_edge(r["entity_a"], r["entity_b"], weight=r["weight"])

                    if len(G.nodes()) > 0:
                        pos_g = nx.spring_layout(G, k=1.8, seed=42)
                        edge_tr = []
                        for e in G.edges(data=True):
                            x0,y0 = pos_g[e[0]]; x1,y1 = pos_g[e[1]]
                            edge_tr.append(go.Scatter(
                                x=[x0,x1,None], y=[y0,y1,None], mode="lines",
                                line=dict(width=min(e[2].get("weight",1)*0.5+0.5,4), color="rgba(79,195,247,0.2)"),
                                hoverinfo="none", showlegend=False,
                            ))
                        nx_c, ny_c, nc_c, ns_c, nt_c = [], [], [], [], []
                        for nd in G.nodes():
                            lb, ct = ent_dict.get(nd, ("ORG",1))
                            nx_c.append(pos_g[nd][0]); ny_c.append(pos_g[nd][1])
                            nc_c.append(ENTITY_COLORS.get(lb,"#888"))
                            ns_c.append(min(10+ct*3,50))
                            nt_c.append(f"<b>{nd}</b><br>{lb} · ×{ct}")
                        node_tr = go.Scatter(
                            x=nx_c, y=ny_c, mode="markers+text",
                            text=[nd if len(nd)<20 else nd[:18]+"…" for nd in G.nodes()],
                            textposition="top center",
                            textfont=dict(size=9, color="rgba(255,255,255,0.7)", family="DM Mono"),
                            hovertext=nt_c, hoverinfo="text",
                            marker=dict(color=nc_c, size=ns_c, line=dict(color="rgba(255,255,255,0.2)", width=1)),
                            showlegend=False,
                        )
                        fig_net = go.Figure(data=edge_tr+[node_tr])
                        fig_net.update_layout(**{k:v for k,v in PLOT.items() if k not in ["xaxis","yaxis"]},
                            height=480,
                            title=dict(text=f"Entity Network — {target_name}",
                                       font=dict(size=12, color="rgba(255,255,255,0.6)"), x=0),
                            xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                            yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                            hovermode="closest",
                        )
                        st.plotly_chart(fig_net, use_container_width=True)
                        leg = "".join([
                            f'<span style="font-family:DM Mono,monospace;font-size:.68rem;margin-right:12px">'
                            f'<span style="background:{c};border-radius:50%;display:inline-block;'
                            f'width:8px;height:8px;margin-right:4px"></span>{k}</span>'
                            for k,c in ENTITY_COLORS.items()
                        ])
                        st.markdown(f'<div style="text-align:center;padding:4px 0">{leg}</div>', unsafe_allow_html=True)
                    else:
                        st.info("Tidak ada node dalam graph.")
                except Exception as e:
                    st.warning(f"Network graph error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — TOPIK (DINAMIS)
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-title">⬡ TOPIC INTELLIGENCE</div>', unsafe_allow_html=True)

    # Ekstrak topik dari data artikel aktif — sepenuhnya dinamis
    topic_data = extract_topics_dynamic(df_art, n_topics=5)

    if not topic_data:
        st.markdown('<div class="intel-box warning">Tidak cukup data untuk mengekstrak topik.</div>',
                    unsafe_allow_html=True)
    else:
        for i in range(0, len(topic_data), 2):
            cols = st.columns(2)
            for j, col in enumerate(cols):
                if i+j >= len(topic_data): break
                t   = topic_data[i+j]
                rgb = hex_rgb(t["color"])
                kws = " &nbsp; ".join([
                    f'<span style="font-family:DM Mono,monospace;font-size:.68rem;'
                    f'background:rgba({rgb},0.12);border:1px solid rgba({rgb},0.3);'
                    f'color:{t["color"]};padding:1px 7px;border-radius:3px">{kw}</span>'
                    for kw in t["keywords"]
                ])
                with col:
                    st.markdown(f"""
                    <div class="intel-box" style="border-color:rgba({rgb},0.3)">
                        <div style="font-family:'DM Mono',monospace;font-size:.7rem;
                                    color:rgba(255,255,255,.35);letter-spacing:.1em;margin-bottom:4px">
                            TOPIK {t['id']:02d}
                        </div>
                        <div style="font-size:.9rem;font-weight:500;color:{t['color']};margin-bottom:8px">
                            {t['label']}
                        </div>
                        <div>{kws}</div>
                    </div>""", unsafe_allow_html=True)

        st.markdown('<div class="section-title">⬡ ARTIKEL PER TOPIK</div>', unsafe_allow_html=True)
        selected_topic = st.selectbox("Pilih Topik",
                                      [f"Topik {t['id']} — {t['label']}" for t in topic_data],
                                      label_visibility="collapsed")
        t_idx = int(selected_topic.split(" ")[1]) - 1
        t_sel = topic_data[t_idx]
        kws_lw = [k.lower() for k in t_sel["keywords"][:4]]

        mask = (
            df_art["title"].str.lower().apply(lambda x: any(k in str(x) for k in kws_lw)) |
            df_art["description"].str.lower().apply(lambda x: any(k in str(x) for k in kws_lw))
        )
        df_ta = df_art[mask].head(8)

        if df_ta.empty:
            st.markdown('<div class="intel-box warning">Tidak ada artikel yang cocok dengan topik ini.</div>',
                        unsafe_allow_html=True)
        else:
            for _, row in df_ta.iterrows():
                sent = row["sentiment"]
                sc   = "#2ECC71" if sent>0.05 else "#E74C3C" if sent<-0.05 else "#4FC3F7"
                pub  = row["published_at"].strftime("%d %b %Y") if pd.notna(row["published_at"]) else ""
                st.markdown(f"""
                <div class="article-card" style="border-left:3px solid {t_sel['color']}">
                    <div class="article-title">{row['title']}</div>
                    <div class="article-meta">[{row['source']}] · {pub} ·
                        <span style="color:{sc}">SENT: {sent:.3f}</span>
                    </div>
                </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — LAPORAN
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown('<div class="section-title">⬡ INTELLIGENCE REPORT</div>', unsafe_allow_html=True)

    now_rpt  = datetime.now().strftime("%d %B %Y %H:%M")
    n_total  = len(df_art)
    pos_r    = int((df_art["sentiment"] > 0.05).sum())
    neg_r    = int((df_art["sentiment"] < -0.05).sum())
    neu_r    = n_total - pos_r - neg_r
    avg_sent = float(df_art["sentiment"].mean())

    persons = df_ent[df_ent["label"]=="PERSON"]["text"].head(5).tolist() if not df_ent.empty else []
    orgs    = df_ent[df_ent["label"]=="ORG"]["text"].head(5).tolist()    if not df_ent.empty else []
    locs    = df_ent[df_ent["label"]=="GPE"]["text"].head(5).tolist()    if not df_ent.empty else []
    top_src = df_art["source"].value_counts().head(5)
    neg_r3  = df_art[df_art["sentiment"]<-0.05].nsmallest(3,"sentiment")
    pos_r3  = df_art[df_art["sentiment"]>0.05].nlargest(3,"sentiment")

    report_text = f"""
╔══════════════════════════════════════════════════════════════════╗
║          LAPORAN INTELIJEN SUMBER TERBUKA (OSINT)               ║
║                   CONFIDENTIAL - FOR OFFICIAL USE                ║
╚══════════════════════════════════════════════════════════════════╝

NOMOR LAPORAN  : OSINT-{target_id:04d}-{datetime.now().strftime('%Y%m%d')}
TANGGAL        : {now_rpt}
ANALIS         : INTEL-OSINT Dashboard v2.0
KLASIFIKASI    : TERBUKA (Sumber Publik)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. IDENTITAS TARGET
   Nama/Query    : {target_name}
   Total Artikel : {n_total} artikel dari {df_art['source'].nunique()} sumber

2. PENILAIAN RISIKO (Kalkulasi Dinamis)
   Risk Level    : {get_risk_label(risk_sc)}
   Total Score   : {risk_sc:.1f}/100
   — Volume      : {rs['volume']:.1f}/25
   — Sentimen-   : {rs['sentimen']:.1f}/30
   — Keragaman   : {rs['keragaman']:.1f}/20
   — Sensitif    : {rs['sensitif']:.1f}/25

3. ANALISIS SENTIMEN
   Positif  : {pos_r} artikel ({pos_r/n_total*100:.1f}%)
   Negatif  : {neg_r} artikel ({neg_r/n_total*100:.1f}%)
   Netral   : {neu_r} artikel ({neu_r/n_total*100:.1f}%)
   Rata-rata: {avg_sent:.4f}

4. JARINGAN ENTITAS
   Individu  : {' | '.join(persons) if persons else 'Tidak ada data'}
   Organisasi: {' | '.join(orgs)    if orgs    else 'Tidak ada data'}
   Lokasi    : {' | '.join(locs)    if locs    else 'Tidak ada data'}

5. SUMBER PEMBERITAAN UTAMA
{chr(10).join(f"   {i+1}. {src} ({cnt} artikel)" for i,(src,cnt) in enumerate(top_src.items()))}

6. ARTIKEL PALING SIGNIFIKAN

   PALING NEGATIF:
{chr(10).join(f"   [{r['source']}] {str(r['title'])[:70]}..." for _,r in neg_r3.iterrows()) if len(neg_r3) else "   Tidak ada"}

   PALING POSITIF:
{chr(10).join(f"   [{r['source']}] {str(r['title'])[:70]}..." for _,r in pos_r3.iterrows()) if len(pos_r3) else "   Tidak ada"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AKHIR LAPORAN] — INTEL-OSINT System v2.0
Sumber: Data publik (NewsAPI) — Bukan untuk distribusi luar
"""

    st.markdown(f'<div class="report-box">{report_text}</div>', unsafe_allow_html=True)

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        st.download_button(
            label="⬇ DOWNLOAD LAPORAN (.txt)",
            data=report_text,
            file_name=f"intel_report_{target_name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.txt",
            mime="text/plain",
        )
    with col_d2:
        csv_data = df_art[["title","source","published_at","sentiment","url"]].to_csv(index=False)
        st.download_button(
            label="⬇ EXPORT ARTIKEL (.csv)",
            data=csv_data,
            file_name=f"articles_{target_name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )
