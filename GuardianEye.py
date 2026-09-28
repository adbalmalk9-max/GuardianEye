import base64
import datetime as dt
import hashlib
import html
import io
import json
import math
import re
import time
import uuid
import wave
from collections import Counter, defaultdict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except Exception:
    st_autorefresh = None


# ================================================================
# GuardianEye — Global Security Operations Center
# ================================================================

APP_NAME = "GuardianEye"
APP_VERSION = "10.0"
HEALTHY_THRESHOLD_MS = 1500
AGENT_OFFLINE_SECONDS = 90
INCIDENT_OPEN_WINDOW_MINUTES = 15
SECURITY_ALERT_WINDOW_MINUTES = 10
HEALTH_CHECK_INTERVAL_SECONDS = 30
UI_REFRESH_INTERVAL_MS = 10000
MAX_SECURITY_EVENTS = 1000
MAX_INCIDENTS = 500
MAX_OPERATIONAL_EVENTS = 1000


# ================================================================
# Page configuration
# ================================================================

st.set_page_config(
    page_title="GuardianEye — Security Operations",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ================================================================
# Global visual system
# ================================================================

st.markdown(
    """
<style>
:root{
  --bg:#05080d;
  --bg2:#081019;
  --panel:#0b121b;
  --panel2:#0e1722;
  --panel3:#111d2a;
  --line:rgba(145,166,190,.16);
  --line2:rgba(145,166,190,.26);
  --text:#f2f6fb;
  --muted:#8493a5;
  --muted2:#607185;
  --blue:#46b5ff;
  --blue2:#8ed7ff;
  --green:#38e0a0;
  --yellow:#f3c76b;
  --red:#ff5f73;
  --purple:#9a7cff;
}
html,body,[class*="css"]{
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
body{background:var(--bg);color:var(--text);}
[data-testid="stAppViewContainer"]{background:
  radial-gradient(circle at 78% 7%, rgba(42,114,165,.10), transparent 27%),
  radial-gradient(circle at 15% 0%, rgba(55,83,125,.08), transparent 30%),
  var(--bg);
}
[data-testid="stHeader"]{background:transparent!important;}
[data-testid="stToolbar"],#MainMenu,footer,[data-testid="stDecoration"]{
  display:none!important;visibility:hidden!important;
}
.block-container{max-width:1550px;padding:1.25rem 1.6rem 4rem;}
[data-testid="stSidebar"]{
  background:linear-gradient(180deg,#070d14,#060a10);
  border-right:1px solid var(--line);
}
[data-testid="stSidebarCollapsedControl"]{display:none!important;}
.stButton>button{
  min-height:40px;
  border-radius:10px;
  border:1px solid var(--line2);
  background:linear-gradient(180deg,#101a26,#0b131d);
  color:var(--text);
  font-weight:760;
  transition:all .16s ease;
}
.stButton>button:hover{
  border-color:rgba(70,181,255,.62);
  background:#122131;
  transform:translateY(-1px);
}
.stDownloadButton>button{
  min-height:40px;border-radius:10px;font-weight:760;
}
.stTextInput>div>div,.stTextInput input,
.stSelectbox>div>div,.stMultiSelect>div>div,
.stNumberInput>div>div,.stTextArea>div>div{
  background:#0b141f!important;
  border:1px solid var(--line)!important;
  border-radius:10px!important;
  color:var(--text)!important;
}
.stTextInput input{height:46px;}
.stTextInput input:focus{
  border-color:rgba(70,181,255,.65)!important;
  box-shadow:0 0 0 1px rgba(70,181,255,.18)!important;
}
[data-baseweb="select"] *{color:var(--text)!important;}
[data-testid="stDataFrame"]{
  border:1px solid var(--line);
  border-radius:14px;
  overflow:hidden;
}
hr{border-color:var(--line)!important;}

/* Brand */
.brand-row{display:flex;align-items:center;gap:.75rem;margin-bottom:1.2rem;}
.brand-mark{
  width:44px;height:44px;border-radius:13px;
  display:flex;align-items:center;justify-content:center;
  border:1px solid rgba(70,181,255,.40);
  background:linear-gradient(145deg,#10283b,#09111a);
  box-shadow:0 0 25px rgba(70,181,255,.10) inset;
  color:#83d5ff;font-size:1.15rem;font-weight:900;
}
.brand-name{font-size:1rem;font-weight:900;letter-spacing:.14em;}
.brand-sub{font-size:.69rem;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;margin-top:.15rem;}
.eyebrow{font-size:.68rem;letter-spacing:.24em;text-transform:uppercase;color:#61baff;font-weight:900;}
.page-title{font-size:2.55rem;font-weight:920;letter-spacing:-.05em;line-height:1.02;margin:.35rem 0 .45rem;}
.page-subtitle{color:#8c9bae;max-width:970px;line-height:1.75;font-size:.94rem;margin-bottom:1rem;}

/* Login */
.login-shell{padding-top:.3rem;}
.login-hero{
  min-height:470px;padding:2.4rem 2.2rem 2.2rem;
  border:1px solid var(--line);border-radius:24px;
  background:linear-gradient(145deg,rgba(12,22,33,.94),rgba(6,10,15,.98));
  position:relative;overflow:hidden;
}
.login-hero:before{content:"";position:absolute;inset:-25% -15% auto auto;width:520px;height:520px;background:radial-gradient(circle,rgba(57,161,225,.15),transparent 64%);pointer-events:none;}
.login-hero:after{content:"";position:absolute;left:-160px;bottom:-210px;width:500px;height:500px;background:radial-gradient(circle,rgba(101,83,201,.06),transparent 63%);pointer-events:none;}
.hero-title{font-size:4rem;font-weight:950;line-height:.96;letter-spacing:-.065em;max-width:820px;margin:1rem 0 1.15rem;position:relative;z-index:1;}
.hero-rule{height:2px;width:120px;background:linear-gradient(90deg,var(--blue),transparent);margin:1.15rem 0;}
.hero-copy{color:#99a8ba;max-width:720px;font-size:1rem;line-height:1.9;position:relative;z-index:1;}
.hero-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:.7rem;margin-top:2rem;position:relative;z-index:1;}
.hero-mini{border:1px solid var(--line);border-radius:13px;background:rgba(8,15,23,.68);padding:.75rem .85rem;}
.hero-mini .label{font-size:.67rem;color:var(--muted2);text-transform:uppercase;letter-spacing:.10em;}
.hero-mini .value{font-size:1rem;font-weight:850;margin-top:.2rem;}
.login-panel{
  min-height:470px;padding:1.5rem 1.55rem;
  border:1px solid rgba(70,181,255,.20);border-radius:24px;
  background:linear-gradient(180deg,#0c151f,#070c13);
  box-shadow:0 20px 60px rgba(0,0,0,.24);
}
.login-panel-top{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1rem;}
.secure-badge{display:inline-flex;align-items:center;gap:.45rem;padding:.37rem .62rem;border:1px solid rgba(56,224,160,.25);background:rgba(56,224,160,.05);border-radius:999px;color:#72edbb;font-size:.69rem;font-weight:900;letter-spacing:.08em;text-transform:uppercase;}
.secure-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(56,224,160,.7);}
.login-title{font-size:2rem;font-weight:920;letter-spacing:-.035em;margin:.7rem 0 .35rem;}
.login-note{color:var(--muted);font-size:.8rem;line-height:1.7;margin-bottom:1.2rem;}

/* Navigation */
.command-nav{
  border:1px solid var(--line);border-radius:15px;
  background:linear-gradient(180deg,#0a1119,#080e15);
  padding:.5rem;margin-bottom:1rem;
  box-shadow:0 12px 35px rgba(0,0,0,.15);
}
.nav-meta{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.3rem .5rem .55rem;}
.nav-meta .left{display:flex;align-items:center;gap:.55rem;}
.nav-meta .title{font-size:.69rem;letter-spacing:.13em;text-transform:uppercase;color:#65778c;font-weight:900;}
.nav-live{display:inline-flex;align-items:center;gap:.4rem;color:#7df0bd;font-size:.68rem;font-weight:900;letter-spacing:.06em;text-transform:uppercase;}
.nav-live:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(56,224,160,.6);}

/* Panels */
.panel{border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,rgba(12,19,29,.98),rgba(7,12,18,.99));padding:1rem 1.05rem;margin-bottom:1rem;}
.panel-header{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;margin-bottom:.8rem;}
.panel-title{font-size:1rem;font-weight:870;}
.panel-note{font-size:.71rem;color:var(--muted2);}

/* KPI */
.kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:1rem;}
.kpi{
  position:relative;overflow:hidden;
  min-height:126px;padding:1rem 1.05rem;
  border:1px solid var(--line);border-radius:16px;
  background:linear-gradient(180deg,#101a25,#0a1119);
}
.kpi:before{content:"";position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,var(--blue),transparent);}
.kpi.red:before{background:linear-gradient(90deg,var(--red),transparent);}
.kpi.green:before{background:linear-gradient(90deg,var(--green),transparent);}
.kpi.yellow:before{background:linear-gradient(90deg,var(--yellow),transparent);}
.kpi .label{font-size:.68rem;color:#8392a4;text-transform:uppercase;letter-spacing:.10em;}
.kpi .value{font-size:2.1rem;font-weight:930;letter-spacing:-.04em;margin:.35rem 0 .1rem;}
.kpi .note{font-size:.68rem;color:#617284;}

/* Global posture */
.posture{
  position:relative;overflow:hidden;
  border:1px solid var(--line);border-radius:18px;padding:1.05rem 1.15rem;
  background:linear-gradient(135deg,#101c29,#091019);
  margin-bottom:1rem;
}
.posture.danger{border-color:rgba(255,95,115,.42);box-shadow:0 0 35px rgba(255,95,115,.05) inset;}
.posture.ok{border-color:rgba(56,224,160,.22);}
.posture .top{display:flex;justify-content:space-between;align-items:center;gap:1rem;}
.posture-title{font-size:.68rem;text-transform:uppercase;letter-spacing:.17em;color:#6d8298;font-weight:900;}
.posture-value{font-size:1.35rem;font-weight:920;margin-top:.3rem;}
.posture-text{color:#8293a6;font-size:.78rem;line-height:1.65;margin-top:.35rem;}
.signal-pill{display:inline-flex;align-items:center;gap:.45rem;padding:.36rem .62rem;border-radius:999px;font-size:.67rem;font-weight:900;letter-spacing:.08em;text-transform:uppercase;}
.signal-pill.safe{background:rgba(56,224,160,.06);border:1px solid rgba(56,224,160,.22);color:#75efba;}
.signal-pill.danger{background:rgba(255,95,115,.08);border:1px solid rgba(255,95,115,.34);color:#ff9aa8;animation:dangerPulse 1.9s ease-in-out infinite;}
.signal-pill .orb{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 13px currentColor;}
@keyframes dangerPulse{50%{box-shadow:0 0 0 6px rgba(255,95,115,.05);}}

/* System cards */
.system-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:.8rem;}
.system-card{border:1px solid var(--line);border-radius:16px;background:#0b131d;padding:1rem;position:relative;overflow:hidden;}
.system-card.attack{border-color:rgba(255,95,115,.52);box-shadow:0 0 0 1px rgba(255,95,115,.08) inset,0 0 25px rgba(255,95,115,.05);}
.system-card.healthy{border-color:rgba(56,224,160,.19);}
.system-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;}
.system-name{font-size:1rem;font-weight:880;}
.system-id{font-size:.66rem;color:#637487;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:.24rem;}
.system-alert{display:inline-flex;align-items:center;gap:.38rem;padding:.3rem .5rem;border-radius:999px;background:rgba(255,95,115,.08);border:1px solid rgba(255,95,115,.34);color:#ff9ca8;font-size:.64rem;font-weight:950;letter-spacing:.08em;text-transform:uppercase;}
.system-alert:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--red);box-shadow:0 0 12px rgba(255,95,115,.7);}
.status-pill{display:inline-flex;align-items:center;gap:.36rem;padding:.28rem .52rem;border-radius:999px;border:1px solid var(--line);font-size:.65rem;font-weight:850;white-space:nowrap;}
.status-pill.good{background:rgba(56,224,160,.05);color:#79eebd;border-color:rgba(56,224,160,.18);}
.status-pill.warn{background:rgba(243,199,107,.05);color:#f4d589;border-color:rgba(243,199,107,.20);}
.status-pill.bad{background:rgba(255,95,115,.06);color:#ff9aa8;border-color:rgba(255,95,115,.25);}
.status-pill.neutral{background:rgba(131,147,164,.05);color:#9cadbd;}
.status-pill.info{background:rgba(70,181,255,.05);color:#8fd2ff;border-color:rgba(70,181,255,.20);}
.system-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:.55rem;margin-top:.85rem;}
.mini-metric{border:1px solid var(--line);border-radius:11px;background:#0d1620;padding:.52rem .58rem;}
.mini-metric .value{font-weight:870;font-size:.86rem;}
.mini-metric .label{font-size:.61rem;color:#647589;margin-top:.1rem;}
.system-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;margin-top:.8rem;}

/* Feeds / timeline */
.feed-row{display:grid;grid-template-columns:9px 1fr auto;gap:.65rem;align-items:start;padding:.7rem .72rem;border:1px solid var(--line);border-radius:12px;background:#0a121b;margin-bottom:.5rem;}
.feed-dot{width:8px;height:8px;border-radius:50%;margin-top:.32rem;background:var(--blue);box-shadow:0 0 11px rgba(70,181,255,.4);}
.feed-dot.danger{background:var(--red);box-shadow:0 0 13px rgba(255,95,115,.5);}
.feed-dot.warn{background:var(--yellow);box-shadow:0 0 13px rgba(243,199,107,.35);}
.feed-title{font-size:.78rem;font-weight:840;}
.feed-meta{font-size:.64rem;color:#67788c;margin-top:.15rem;}
.feed-evidence{font-size:.69rem;color:#8e9cae;line-height:1.55;margin-top:.3rem;}

/* Detail */
.detail-hero{border:1px solid var(--line);border-radius:17px;background:linear-gradient(135deg,#101d2b,#091019);padding:1.1rem 1.15rem;margin-bottom:1rem;}
.detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.65rem;margin-top:.8rem;}
.detail-tile{border:1px solid var(--line);border-radius:11px;background:#0b141e;padding:.65rem .7rem;}
.detail-tile .label{font-size:.62rem;color:#617286;text-transform:uppercase;letter-spacing:.08em;}
.detail-tile .value{font-size:.88rem;font-weight:840;margin-top:.18rem;}

/* Incident */
.incident-card{border:1px solid var(--line);border-radius:16px;background:#0b131c;padding:1rem;margin-bottom:.65rem;}
.incident-card.critical,.incident-card.high{border-color:rgba(255,95,115,.38);}
.incident-card.medium{border-color:rgba(243,199,107,.24);}
.incident-header{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;}
.incident-title{font-size:.98rem;font-weight:880;}
.incident-sub{font-size:.68rem;color:#6d7f92;margin-top:.22rem;}
.timeline-line{position:relative;padding-left:1.05rem;margin-left:.2rem;}
.timeline-line:before{content:"";position:absolute;left:.18rem;top:.25rem;bottom:.25rem;width:1px;background:var(--line2);}
.timeline-event{position:relative;padding:.55rem 0 .7rem;}
.timeline-event:before{content:"";position:absolute;left:-.07rem;top:.62rem;width:7px;height:7px;border-radius:50%;background:var(--blue);box-shadow:0 0 11px rgba(70,181,255,.35);}
.timeline-event.danger:before{background:var(--red);box-shadow:0 0 12px rgba(255,95,115,.45);}
.timeline-time{font-size:.62rem;color:#607184;}
.timeline-text{font-size:.72rem;color:#96a4b5;margin-top:.12rem;line-height:1.55;}

/* Tables / tags */
.tag-row{display:flex;gap:.4rem;flex-wrap:wrap;}
.tag{border:1px solid var(--line);background:#0b141e;color:#8fa1b3;border-radius:999px;padding:.27rem .5rem;font-size:.61rem;font-weight:800;}
.search-hint{font-size:.63rem;color:#65778b;margin-top:.35rem;}

/* Section headings */
.section-head{display:flex;justify-content:space-between;align-items:end;gap:1rem;margin:.85rem 0 .65rem;}
.section-head .title{font-size:1rem;font-weight:880;}
.section-head .note{font-size:.66rem;color:#647588;}

/* Utility buttons */
.action-row{display:flex;gap:.55rem;flex-wrap:wrap;margin:.8rem 0;}
.return-link{font-size:.72rem;color:#83cfff;font-weight:760;}

@media(max-width:1050px){
  .kpi-grid{grid-template-columns:repeat(2,1fr);}
  .system-grid{grid-template-columns:1fr;}
  .hero-title{font-size:3rem;}
  .hero-metrics{grid-template-columns:1fr;}
  .detail-grid{grid-template-columns:repeat(2,1fr);}
}
@media(max-width:700px){
  .block-container{padding:1rem .8rem 3rem;}
  .hero-title{font-size:2.5rem;}
  .kpi-grid{grid-template-columns:1fr;}
  .system-metrics{grid-template-columns:repeat(2,1fr);}
  .detail-grid{grid-template-columns:1fr;}
}
</style>
""",
    unsafe_allow_html=True,
)

if st_autorefresh is not None:
    try:
        st_autorefresh(interval=UI_REFRESH_INTERVAL_MS, limit=None, key="guardianeye_global_refresh")
    except Exception:
        pass


# ================================================================
# Secrets / clients
# ================================================================

def required_secret(name):
    value = str(st.secrets.get(name, "")).strip()
    if not value:
        raise RuntimeError(name)
    return value


try:
    ADMIN_USER = required_secret("GUARDIAN_ADMIN_USER")
    ADMIN_PASSWORD = required_secret("GUARDIAN_ADMIN_PASSWORD")
    SUPABASE_URL = required_secret("SUPABASE_URL").rstrip("/")
    SUPABASE_SERVICE_ROLE_KEY = required_secret("SUPABASE_SERVICE_ROLE_KEY")
    GUARDIAN_ENCRYPTION_KEY = required_secret("GUARDIAN_ENCRYPTION_KEY")
    SECRET_BOOTSTRAP_ERROR = ""
except RuntimeError as exc:
    ADMIN_USER = ""
    ADMIN_PASSWORD = ""
    SUPABASE_URL = ""
    SUPABASE_SERVICE_ROLE_KEY = ""
    GUARDIAN_ENCRYPTION_KEY = ""
    SECRET_BOOTSTRAP_ERROR = str(exc)


@st.cache_resource(show_spinner=False)
def get_supabase():
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


@st.cache_resource(show_spinner=False)
def get_fernet():
    from cryptography.fernet import Fernet
    return Fernet(GUARDIAN_ENCRYPTION_KEY.encode("utf-8"))


# ================================================================
# Generic helpers
# ================================================================

def safe_text(value):
    return html.escape(str(value)) if value is not None else ""


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def iso_now():
    return utc_now().isoformat()


def short_id(value):
    return str(value)[:8] if value else "—"


def response_ms_text(value):
    if value is None:
        return "—"
    try:
        return f"{float(value):.0f} ms"
    except (TypeError, ValueError):
        return "—"


def parse_dt(value):
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        stamp = dt.datetime.fromisoformat(text)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=dt.timezone.utc)
        return stamp
    except (TypeError, ValueError):
        return None


def minutes_since(value):
    stamp = parse_dt(value)
    if not stamp:
        return None
    return max(0.0, (utc_now() - stamp).total_seconds() / 60.0)


def age_text(value):
    minutes = minutes_since(value)
    if minutes is None:
        return "—"
    if minutes < 1:
        return "الآن"
    if minutes < 60:
        return f"منذ {minutes:.0f} د"
    hours = minutes / 60
    if hours < 24:
        return f"منذ {hours:.1f} س"
    return f"منذ {hours/24:.1f} يوم"


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def database_error(exc):
    text = str(exc).strip()
    return text[:800] if text else "خطأ غير معروف في قاعدة البيانات."


def encrypt_secret(value):
    if not value:
        return ""
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value):
    if not value:
        return ""
    try:
        return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


def hash_ingest_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def status_badge(status):
    mapping = {
        "Healthy": ("good", "● Healthy"),
        "Slow": ("warn", "● Slow"),
        "Down": ("bad", "● Down"),
        "Auth Error": ("bad", "● Auth Error"),
        "Not Checked": ("neutral", "● Not Checked"),
        "Online": ("good", "● Online"),
        "Offline": ("bad", "● Offline"),
        "Enabled": ("good", "● Enabled"),
        "Disabled": ("neutral", "● Disabled"),
    }
    css, label = mapping.get(status, ("neutral", f"● {status}"))
    return f'<span class="status-pill {css}">{safe_text(label)}</span>'


def severity_badge(severity):
    css = {
        "Critical": "bad",
        "High": "bad",
        "Medium": "warn",
        "Low": "info",
        "Info": "neutral",
    }.get(severity, "neutral")
    return f'<span class="status-pill {css}">{safe_text(severity or "Unknown")}</span>'


def page_header(eyebrow, title, subtitle=None):
    st.markdown(f'<div class="eyebrow">{safe_text(eyebrow)}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="page-title">{safe_text(title)}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="page-subtitle">{safe_text(subtitle)}</div>', unsafe_allow_html=True)


def panel_header(title, note=None):
    note_html = f'<div class="panel-note">{safe_text(note)}</div>' if note else ""
    st.markdown(
        f'<div class="panel-header"><div class="panel-title">{safe_text(title)}</div>{note_html}</div>',
        unsafe_allow_html=True,
    )


def navigation_button(label, page_key, current_page):
    active = current_page == page_key
    prefix = "● " if active else ""
    return st.button(prefix + label, key=f"nav_{page_key}", use_container_width=True)


def set_page(page_key):
    st.session_state.page = page_key
    st.session_state.pop("selected_system_id", None)
    st.session_state.pop("selected_incident_id", None)
    st.rerun()


def back_to_overview_button():
    if st.button("← العودة إلى مركز المراقبة", key=f"back_{st.session_state.get('page','unknown')}"):
        set_page("Overview")


def data_url_csv(df):
    return df.to_csv(index=False).encode("utf-8-sig")


def generate_alarm_wav():
    buffer = io.BytesIO()
    rate = 44100
    duration = 0.32
    samples = int(rate * duration)
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        for i in range(samples):
            t = i / rate
            envelope = min(1.0, i / 900, (samples - i) / 900)
            freq = 740 if t < duration / 2 else 520
            value = int(12000 * envelope * math.sin(2 * math.pi * freq * t))
            wav.writeframes(value.to_bytes(2, byteorder="little", signed=True))
    return buffer.getvalue()


ALARM_WAV = generate_alarm_wav()


def render_alarm_panel(active_count):
    if active_count <= 0:
        return
    st.markdown(
        f'''<div class="posture danger">
          <div class="top">
            <div>
              <div class="posture-title">SECURITY ALERT</div>
              <div class="posture-value">تم رصد نشاط هجومي على {active_count} منظومة</div>
              <div class="posture-text">GuardianEye يراقب جميع المنظومات المسجلة في هذه اللحظة. راجع Security Feed وIncidents لمعرفة المصدر والأدلة.</div>
            </div>
            <span class="signal-pill danger"><span class="orb"></span>ATTACK DETECTED</span>
          </div>
        </div>''',
        unsafe_allow_html=True,
    )
    with st.expander("تشغيل إشارة الإنذار الصوتية", expanded=False):
        st.caption("المتصفح قد يتطلب تفاعلًا من المستخدم قبل تشغيل الصوت.")
        st.audio(ALARM_WAV, format="audio/wav", autoplay=False)


# ================================================================
# Safe data access
# ================================================================

def safe_db_call(label, fn, default):
    try:
        return fn(), ""
    except Exception as exc:
        return default, f"{label}: {database_error(exc)}"


def load_systems():
    return get_supabase().table("systems").select(
        "id,company,url,api_url,api_key_enc,status,http_status,response_ms,"
        "last_message,last_checked,created_at,ingest_token_hash,agent_enabled,agent_last_seen"
    ).order("created_at", desc=False).execute().data or []


def load_events(limit=MAX_OPERATIONAL_EVENTS):
    return get_supabase().table("events").select(
        "id,time,system_id,company,old_status,new_status,message"
    ).order("time", desc=True).limit(limit).execute().data or []


def load_security_events(limit=MAX_SECURITY_EVENTS):
    return get_supabase().table("security_events").select(
        "id,system_id,event_time,event_type,attack_type,severity,confidence,"
        "source_ip,source_port,dest_port,protocol,evidence,status,detected_by,raw_data"
    ).order("event_time", desc=True).limit(limit).execute().data or []


def load_incidents(limit=MAX_INCIDENTS):
    return get_supabase().table("incidents").select(
        "id,system_id,title,attack_type,severity,source_ip,first_seen,last_seen,"
        "event_count,status,evidence_summary,resolved_at,created_at"
    ).order("last_seen", desc=True).limit(limit).execute().data or []


def load_heartbeats(limit=500):
    return get_supabase().table("agent_heartbeats").select(
        "id,system_id,seen_at,hostname,os_name,agent_version,cpu_percent,"
        "memory_percent,open_connections,monitored_logs"
    ).order("seen_at", desc=True).limit(limit).execute().data or []


# ================================================================
# Database mutations
# ================================================================

def create_system(company, url, api_url, api_key):
    system_id = str(uuid.uuid4())
    ingest_token = uuid.uuid4().hex + uuid.uuid4().hex
    row = {
        "id": system_id,
        "company": company.strip(),
        "url": url.strip(),
        "api_url": api_url.strip(),
        "api_key_enc": encrypt_secret(api_key.strip()),
        "status": "Not Checked",
        "http_status": None,
        "response_ms": None,
        "last_message": "Waiting for first check.",
        "ingest_token_hash": hash_ingest_token(ingest_token),
        "agent_enabled": True,
        "agent_last_seen": None,
    }
    get_supabase().table("systems").insert(row).execute()
    return system_id, ingest_token


def update_system(system):
    payload = {
        "status": system.get("status"),
        "http_status": system.get("http_status"),
        "response_ms": system.get("response_ms"),
        "last_message": system.get("last_message"),
        "last_checked": system.get("last_checked"),
    }
    get_supabase().table("systems").update(payload).eq("id", system["id"]).execute()


def create_event(system, old_status, new_status, message):
    row = {
        "id": str(uuid.uuid4()),
        "system_id": system["id"],
        "company": system["company"],
        "old_status": old_status,
        "new_status": new_status,
        "message": message,
    }
    get_supabase().table("events").insert(row).execute()


def permanently_delete_system(system_id):
    get_supabase().table("events").delete().eq("system_id", system_id).execute()
    get_supabase().table("security_events").delete().eq("system_id", system_id).execute()
    get_supabase().table("incidents").delete().eq("system_id", system_id).execute()
    get_supabase().table("agent_heartbeats").delete().eq("system_id", system_id).execute()
    get_supabase().table("systems").delete().eq("id", system_id).execute()


def insert_demo_security_event(system):
    source_ip = "192.0.2.50"
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()),
        "system_id": system["id"],
        "event_time": now,
        "event_type": "demo_detection",
        "attack_type": "Brute Force",
        "severity": "High",
        "confidence": 0.98,
        "source_ip": source_ip,
        "source_port": 51514,
        "dest_port": 22,
        "protocol": "TCP",
        "evidence": "Demo: 184 failed authentication attempts from one source within 60 seconds.",
        "status": "Open",
        "detected_by": "GuardianEye Demo Detector",
        "raw_data": {"demo": True, "attempts": 184},
    }
    get_supabase().table("security_events").insert(event).execute()
    create_or_update_incident_from_event(event)


def create_or_update_incident_from_event(event):
    system_id = event["system_id"]
    attack_type = event.get("attack_type") or "Suspicious Activity"
    source_ip = event.get("source_ip")
    now = event.get("event_time") or iso_now()
    cutoff = (utc_now() - dt.timedelta(minutes=INCIDENT_OPEN_WINDOW_MINUTES)).isoformat()

    rows = get_supabase().table("incidents").select(
        "id,event_count,evidence_summary"
    ).eq("system_id", system_id).eq("attack_type", attack_type).eq(
        "status", "Open"
    ).gte("last_seen", cutoff).limit(1).execute().data or []

    if rows:
        inc = rows[0]
        summary = str(inc.get("evidence_summary") or "")
        evidence = str(event.get("evidence") or "")
        combined = (summary + " | " + evidence).strip(" |")[-1200:]
        get_supabase().table("incidents").update({
            "last_seen": now,
            "event_count": safe_int(inc.get("event_count")) + 1,
            "evidence_summary": combined,
            "source_ip": source_ip or None,
            "severity": event.get("severity") or "Medium",
        }).eq("id", inc["id"]).execute()
        return inc["id"]

    system_rows = get_supabase().table("systems").select("company").eq(
        "id", system_id
    ).limit(1).execute().data or []
    company = system_rows[0].get("company") if system_rows else "Unknown"
    title = f"{attack_type} detected on {company}"
    inserted = get_supabase().table("incidents").insert({
        "id": str(uuid.uuid4()),
        "system_id": system_id,
        "title": title,
        "attack_type": attack_type,
        "severity": event.get("severity") or "Medium",
        "source_ip": source_ip or None,
        "first_seen": now,
        "last_seen": now,
        "event_count": 1,
        "status": "Open",
        "evidence_summary": str(event.get("evidence") or "")[:1200],
    }).execute()
    return inserted.data[0]["id"] if inserted.data else None


def resolve_incident(incident_id):
    get_supabase().table("incidents").update({
        "status": "Resolved",
        "resolved_at": iso_now(),
    }).eq("id", incident_id).execute()


# ================================================================
# Monitoring engine
# ================================================================

def check_system(system):
    target = (system.get("api_url") or system.get("url") or "").strip()
    api_key = decrypt_secret(system.get("api_key_enc", ""))
    if not target:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": "No monitoring URL configured.",
        }

    headers = {
        "User-Agent": f"GuardianEye-Monitor/{APP_VERSION}",
        "Accept": "application/json, text/plain, */*",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.perf_counter()
    try:
        response = requests.get(
            target,
            headers=headers,
            timeout=8,
            allow_redirects=True,
        )
        elapsed = (time.perf_counter() - started) * 1000
        code = response.status_code
        if code in (401, 403):
            status = "Auth Error"
            message = f"Endpoint returned HTTP {code}."
        elif 200 <= code < 400:
            status = "Slow" if elapsed >= HEALTHY_THRESHOLD_MS else "Healthy"
            message = f"HTTP {code} · {elapsed:.0f} ms"
        else:
            status = "Down"
            message = f"Endpoint returned HTTP {code}."
        return {
            "status": status,
            "http_status": code,
            "response_ms": elapsed,
            "message": message,
        }
    except requests.exceptions.Timeout:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": "Request timed out after 8 seconds.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": f"Connection error: {str(exc)[:180]}",
        }


def run_health_monitoring(force=False):
    now = time.time()
    last = safe_float(st.session_state.get("last_health_run", 0.0))
    if not force and now - last < HEALTH_CHECK_INTERVAL_SECONDS:
        return

    st.session_state.last_health_run = now
    systems, err = safe_db_call("تحميل المنظومات", load_systems, [])
    if err:
        st.session_state.monitor_error = err
        return

    for system in systems:
        result = check_system(system)
        old_status = system.get("status", "Not Checked")
        system.update({
            "status": result["status"],
            "http_status": result["http_status"],
            "response_ms": result["response_ms"],
            "last_message": result["message"],
            "last_checked": iso_now(),
        })
        if old_status != "Not Checked" and old_status != result["status"]:
            try:
                create_event(system, old_status, result["status"], result["message"])
            except Exception:
                pass
        try:
            update_system(system)
        except Exception:
            pass


def agent_is_online(system):
    if not system.get("agent_enabled", True):
        return False
    stamp = parse_dt(system.get("agent_last_seen"))
    if not stamp:
        return False
    return (utc_now() - stamp).total_seconds() <= AGENT_OFFLINE_SECONDS


def is_attack_event(event):
    return (event.get("severity") or "").lower() in {"critical", "high"}


def attack_system_ids(events):
    cutoff = utc_now() - dt.timedelta(minutes=SECURITY_ALERT_WINDOW_MINUTES)
    ids = set()
    for event in events:
        stamp = parse_dt(event.get("event_time"))
        if stamp and stamp >= cutoff and is_attack_event(event):
            if event.get("system_id"):
                ids.add(event.get("system_id"))
    return ids


def correlate_sources(events):
    mapping = defaultdict(set)
    for event in events:
        source = event.get("source_ip")
        system = event.get("system_id")
        if source and system:
            mapping[source].add(system)
    return sorted(
        ((source, systems) for source, systems in mapping.items() if len(systems) >= 2),
        key=lambda item: (-len(item[1]), item[0]),
    )


# ================================================================
# Authentication
# ================================================================

def login():
    if SECRET_BOOTSTRAP_ERROR:
        st.error("GuardianEye غير جاهز بعد: يوجد Secret مفقود في Streamlit.")
        st.code(f"Missing Streamlit Secret: {SECRET_BOOTSTRAP_ERROR}")
        st.stop()

    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    left, right = st.columns([1.08, .92], gap="large")

    with left:
        st.markdown(
            '''<div class="login-hero">
              <div class="brand-row">
                <div class="brand-mark">◉</div>
                <div><div class="brand-name">GUARDIANEYE</div><div class="brand-sub">Security Operations Platform</div></div>
              </div>
              <div class="eyebrow">Security Operations / Control Plane</div>
              <div class="hero-title">مركز القيادة<br>للمراقبة الأمنية.</div>
              <div class="hero-rule"></div>
              <div class="hero-copy">رؤية مركزية للمنظومات المصرح بمراقبتها: صحة الخدمات، إشارات الحساس، الأحداث الأمنية، الحوادث، والتحليلات — في مساحة تشغيل واحدة.</div>
              <div class="hero-metrics">
                <div class="hero-mini"><div class="label">Architecture</div><div class="value">Agent + Control Plane</div></div>
                <div class="hero-mini"><div class="label">Monitoring</div><div class="value">Fleet-wide visibility</div></div>
                <div class="hero-mini"><div class="label">Security</div><div class="value">Events → Incidents</div></div>
              </div>
            </div>''',
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="login-panel">', unsafe_allow_html=True)
        st.markdown(
            '<div class="login-panel-top"><div class="eyebrow">Identity Gateway</div><span class="secure-badge"><span class="secure-dot"></span>Secure channel</span></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="login-title">تسجيل الدخول</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-note">الوصول مخصص للمستخدمين المخولين. بعد الدخول يتم فتح مركز القيادة ومراقبة جميع المنظومات المسجلة.</div>', unsafe_allow_html=True)
        username = st.text_input("اسم المستخدم", placeholder="أدخل اسم المستخدم", key="login_username")
        password = st.text_input("كلمة المرور", type="password", placeholder="أدخل كلمة المرور", key="login_password")
        if st.button("دخول إلى مركز القيادة", use_container_width=True, key="login_submit"):
            if username == ADMIN_USER and password == ADMIN_PASSWORD:
                st.session_state.logged_in = True
                st.session_state.page = "Overview"
                st.session_state.pop("login_password", None)
                st.rerun()
            else:
                st.error("بيانات الدخول غير صحيحة.")
        st.caption("AUTHORIZED ACCESS ONLY · GuardianEye Control Plane")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


def logout():
    st.session_state.logged_in = False
    st.session_state.pop("login_password", None)
    st.rerun()


# ================================================================
# Main navigation
# ================================================================

def render_nav():
    pages = [
        ("Overview", "مركز المراقبة"),
        ("Fleet", "المنظومات"),
        ("Add System", "إضافة منظومة"),
        ("Security", "الأمن"),
        ("Incidents", "الحوادث"),
        ("Analytics", "التحليلات"),
        ("Events", "الأحداث"),
        ("Agents", "الحساسات"),
        ("Agent Setup", "إعداد الحساس"),
    ]
    current = st.session_state.get("page", "Overview")
    st.markdown('<div class="command-nav">', unsafe_allow_html=True)
    st.markdown(
        '<div class="nav-meta"><div class="left"><div class="title">GUARDIANEYE COMMAND CENTER</div><span class="nav-live">Live monitoring</span></div><div class="panel-note">Refresh 10s · Global fleet view</div></div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(len(pages))
    for col, (key, label) in zip(cols, pages):
        with col:
            if navigation_button(label, key, current):
                set_page(key)
    st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Overview page — global fleet visibility
# ================================================================

def overview_page():
    run_health_monitoring()

    systems, systems_err = safe_db_call("تحميل المنظومات", load_systems, [])
    security, security_err = safe_db_call("تحميل الأحداث الأمنية", lambda: load_security_events(500), [])
    incidents, incidents_err = safe_db_call("تحميل الحوادث", lambda: load_incidents(200), [])
    heartbeats, _ = safe_db_call("تحميل heartbeat", lambda: load_heartbeats(300), [])

    latest_hb = {}
    for hb in heartbeats:
        sid = hb.get("system_id")
        if sid and sid not in latest_hb:
            latest_hb[sid] = hb

    systems_by_id = {s["id"]: s for s in systems if s.get("id")}
    online_agents = sum(agent_is_online(s) for s in systems)
    healthy = sum(s.get("status") == "Healthy" for s in systems)
    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    critical_incidents = sum(i.get("severity") == "Critical" for i in open_incidents)
    attacks = attack_system_ids(security)
    attack_system_count = len(attacks)

    page_header(
        "COMMAND CENTER",
        "مركز المراقبة",
        "رؤية تشغيلية وأمنية موحدة لجميع المنظومات المسجلة في الوقت الحالي.",
    )

    kpis = [
        ("المنظومات", len(systems), "مسجلة مركزيًا", ""),
        ("Healthy", healthy, "الخدمات المستجيبة", "green"),
        ("الحساسات النشطة", online_agents, "آخر 90 ثانية", "green"),
        ("الحوادث المفتوحة", len(open_incidents), "تحتاج متابعة", "red" if open_incidents else ""),
        ("High / Critical", critical_incidents + attack_system_count, "إشارات تحتاج انتباهًا", "red" if (critical_incidents + attack_system_count) else ""),
    ]
    st.markdown('<div class="kpi-grid">', unsafe_allow_html=True)
    for label, value, note, tone in kpis:
        st.markdown(
            f'<div class="kpi {tone}"><div class="label">{safe_text(label)}</div><div class="value">{safe_text(value)}</div><div class="note">{safe_text(note)}</div></div>',
            unsafe_allow_html=True,
        )
    st.markdown('</div>', unsafe_allow_html=True)

    if attack_system_count:
        render_alarm_panel(attack_system_count)
    else:
        st.markdown(
            '<div class="posture ok"><div class="top"><div><div class="posture-title">SECURITY POSTURE</div><div class="posture-value">المراقبة مستقرة</div><div class="posture-text">لا توجد حوادث High/Critical ضمن نافذة التنبيه الحالية. تستمر المراقبة لجميع المنظومات والحساسات.</div></div><span class="signal-pill safe"><span class="orb"></span>MONITORING</span></div></div>',
            unsafe_allow_html=True,
        )

    left, right = st.columns([1.25, .75], gap="large")

    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("حالة جميع المنظومات", "Fleet-wide visibility")
        if systems:
            search = st.text_input("بحث في المنظومات", placeholder="اسم الشركة أو System ID...", key="overview_system_search")
            query = search.strip().lower()
            visible = [s for s in systems if not query or query in str(s.get("company", "")).lower() or query in str(s.get("id", "")).lower()]
            st.markdown('<div class="system-grid">', unsafe_allow_html=True)
            for system in visible:
                sid = system.get("id")
                online = agent_is_online(system)
                attacked = sid in attacks
                status = system.get("status", "Not Checked")
                card_class = "attack" if attacked else ("healthy" if status == "Healthy" else "")
                alert = '<span class="system-alert">Attack detected</span>' if attacked else status_badge(status)
                hb = latest_hb.get(sid, {})
                last_event = next((e for e in security if e.get("system_id") == sid), None)
                event_label = (last_event.get("attack_type") if last_event else "—")
                event_sev = (last_event.get("severity") if last_event else "—")
                st.markdown(
                    f'''<div class="system-card {card_class}">
                      <div class="system-head"><div><div class="system-name">{safe_text(system.get("company", "Unknown"))}</div><div class="system-id">{safe_text(short_id(sid))}</div></div>{alert}</div>
                      <div style="margin-top:.65rem">{status_badge("Online" if online else "Offline")}</div>
                      <div class="system-metrics">
                        <div class="mini-metric"><div class="value">{safe_text(status)}</div><div class="label">Service</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(response_ms_text(system.get("response_ms")))}</div><div class="label">Latency</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(event_label)}</div><div class="label">Last security</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(event_sev)}</div><div class="label">Severity</div></div>
                      </div>
                      <div class="system-metrics" style="margin-top:.55rem">
                        <div class="mini-metric"><div class="value">{safe_text(hb.get("os_name", "—"))}</div><div class="label">OS</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(str(hb.get("cpu_percent", "—")) + "%" if hb.get("cpu_percent") is not None else "—")}</div><div class="label">CPU</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(str(hb.get("memory_percent", "—")) + "%" if hb.get("memory_percent") is not None else "—")}</div><div class="label">Memory</div></div>
                        <div class="mini-metric"><div class="value">{safe_text(age_text(system.get("agent_last_seen")))}</div><div class="label">Agent seen</div></div>
                      </div>
                    </div>''',
                    unsafe_allow_html=True,
                )
                a, b, c = st.columns(3)
                with a:
                    if st.button("فتح المنظومة", key=f"ov_open_{sid}", use_container_width=True):
                        st.session_state.selected_system_id = sid
                        set_page("Fleet")
                with b:
                    if st.button("الأمن", key=f"ov_security_{sid}", use_container_width=True):
                        st.session_state.security_system_filter = sid
                        set_page("Security")
                with c:
                    if st.button("الحساس", key=f"ov_agent_{sid}", use_container_width=True):
                        st.session_state.agent_system_filter = sid
                        set_page("Agents")
            st.markdown('</div>', unsafe_allow_html=True)
            if not visible:
                st.info("لا توجد منظومات مطابقة للبحث.")
        else:
            st.info("لا توجد منظومات مسجلة بعد. استخدم «إضافة منظومة»." )
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("أحدث الإشارات الأمنية", "آخر 10 أحداث")
        if security:
            for event in security[:10]:
                sev = (event.get("severity") or "Info").lower()
                dot = "danger" if sev in {"critical", "high"} else ("warn" if sev == "medium" else "")
                company = systems_by_id.get(event.get("system_id"), {}).get("company", short_id(event.get("system_id")))
                st.markdown(
                    f'''<div class="feed-row"><span class="feed-dot {dot}"></span><div><div class="feed-title">{safe_text(event.get("attack_type") or event.get("event_type") or "Security Event")}</div><div class="feed-meta">{safe_text(company)} · {safe_text(event.get("source_ip") or "Unknown")} · {safe_text(age_text(event.get("event_time")))}</div><div class="feed-evidence">{safe_text(event.get("evidence") or "")}</div></div>{severity_badge(event.get("severity") or "Info")}</div>''',
                    unsafe_allow_html=True,
                )
        else:
            st.info("لا توجد أحداث أمنية بعد.")
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("ارتباطات متعددة المنظومات", "نفس المصدر ظهر على أكثر من منظومة")
        correlations = correlate_sources(security)
        if correlations:
            for source, system_ids in correlations[:8]:
                names = [systems_by_id.get(sid, {}).get("company", short_id(sid)) for sid in system_ids]
                st.markdown(
                    f'<div class="incident-card"><div class="incident-title">Source {safe_text(source)}</div><div class="incident-sub">ظهر على {len(names)} منظومات</div><div class="tag-row" style="margin-top:.5rem">' + ''.join(f'<span class="tag">{safe_text(name)}</span>' for name in names) + '</div></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("لا توجد ارتباطات متعددة المنظومات ضمن البيانات الحالية.")
        st.markdown('</div>', unsafe_allow_html=True)

    if systems_err or security_err or incidents_err:
        st.caption("بعض البيانات لم تُحمّل في هذه الدورة، لكن بقية مركز المراقبة يستمر بالعمل.")


# ================================================================
# Fleet page
# ================================================================

def fleet_page():
    page_header("FLEET OPERATIONS", "المنظومات", "إدارة ومراقبة جميع المنظومات في واجهة تشغيل موحدة.")
    back_to_overview_button()

    systems, err = safe_db_call("تحميل المنظومات", load_systems, [])
    security, _ = safe_db_call("تحميل الأحداث الأمنية", lambda: load_security_events(800), [])
    incidents, _ = safe_db_call("تحميل الحوادث", lambda: load_incidents(300), [])
    heartbeat_rows, _ = safe_db_call("تحميل heartbeat", lambda: load_heartbeats(500), [])
    heartbeats = {}
    for hb in heartbeat_rows:
        if hb.get("system_id") and hb.get("system_id") not in heartbeats:
            heartbeats[hb.get("system_id")] = hb

    if err:
        st.warning("تعذر تحميل قائمة المنظومات في هذه اللحظة.")
        return

    if not systems:
        st.info("لا توجد منظومات. انتقل إلى «إضافة منظومة».")
        return

    options = [(s.get("id"), s.get("company", "Unknown")) for s in systems]
    selected_id = st.session_state.get("selected_system_id")
    selected_id = selected_id if selected_id in [o[0] for o in options] else None

    if selected_id:
        selected = next(s for s in systems if s.get("id") == selected_id)
        render_system_detail(selected, systems, security, incidents, heartbeats)
        return

    q = st.text_input("بحث", placeholder="اسم الشركة، الحالة، System ID...", key="fleet_search")
    ql = q.strip().lower()
    filtered = [s for s in systems if not ql or ql in str(s.get("company", "")).lower() or ql in str(s.get("status", "")).lower() or ql in str(s.get("id", "")).lower()]

    status_filter = st.multiselect("فلترة الحالة", ["Healthy", "Slow", "Down", "Auth Error", "Not Checked"], default=[], key="fleet_status_filter")
    if status_filter:
        filtered = [s for s in filtered if s.get("status") in status_filter]

    attack_ids = attack_system_ids(security)
    st.markdown(f'<div class="panel-note" style="margin:.55rem 0 .8rem">عرض {len(filtered)} من {len(systems)} منظومة · {len(attack_ids)} ضمن نافذة التنبيه</div>', unsafe_allow_html=True)

    st.markdown('<div class="system-grid">', unsafe_allow_html=True)
    for system in filtered:
        sid = system.get("id")
        hb = heartbeats.get(sid, {})
        sys_incidents = [i for i in incidents if i.get("system_id") == sid and i.get("status") == "Open"]
        sys_security = [e for e in security if e.get("system_id") == sid]
        attacked = sid in attack_ids
        card_class = "attack" if attacked else ("healthy" if system.get("status") == "Healthy" else "")
        alert = '<span class="system-alert">Attack detected</span>' if attacked else status_badge(system.get("status", "Not Checked"))
        st.markdown(
            f'''<div class="system-card {card_class}">
              <div class="system-head"><div><div class="system-name">{safe_text(system.get("company", "Unknown"))}</div><div class="system-id">{safe_text(sid)}</div></div>{alert}</div>
              <div style="margin-top:.55rem">{status_badge("Online" if agent_is_online(system) else "Offline")} {status_badge("Enabled" if system.get("agent_enabled", True) else "Disabled")}</div>
              <div class="system-metrics">
                <div class="mini-metric"><div class="value">{safe_text(response_ms_text(system.get("response_ms")))}</div><div class="label">Latency</div></div>
                <div class="mini-metric"><div class="value">{safe_text(len(sys_incidents))}</div><div class="label">Open incidents</div></div>
                <div class="mini-metric"><div class="value">{safe_text(len(sys_security))}</div><div class="label">Security events</div></div>
                <div class="mini-metric"><div class="value">{safe_text(age_text(system.get("agent_last_seen")))}</div><div class="label">Agent heartbeat</div></div>
              </div>
            </div>''',
            unsafe_allow_html=True,
        )
        cols = st.columns(3)
        with cols[0]:
            if st.button("تفاصيل", key=f"fleet_detail_{sid}", use_container_width=True):
                st.session_state.selected_system_id = sid
                st.rerun()
        with cols[1]:
            if st.button("فحص الآن", key=f"fleet_check_{sid}", use_container_width=True):
                result = check_system(system)
                old = system.get("status", "Not Checked")
                system.update({
                    "status": result["status"],
                    "http_status": result["http_status"],
                    "response_ms": result["response_ms"],
                    "last_message": result["message"],
                    "last_checked": iso_now(),
                })
                try:
                    if old != "Not Checked" and old != result["status"]:
                        create_event(system, old, result["status"], result["message"])
                    update_system(system)
                    st.success("تم تحديث حالة المنظومة.")
                    st.rerun()
                except Exception as exc:
                    st.error("فشل حفظ نتيجة الفحص.")
                    st.code(database_error(exc))
        with cols[2]:
            if st.button("حذف نهائي", key=f"fleet_delete_{sid}", use_container_width=True):
                st.session_state[f"confirm_delete_{sid}"] = True
                st.rerun()
        if st.session_state.get(f"confirm_delete_{sid}"):
            st.warning("سيتم حذف المنظومة وجميع الأحداث والحوادث وبيانات الحساس المرتبطة بها نهائيًا.")
            yes, no = st.columns(2)
            with yes:
                if st.button("تأكيد الحذف", key=f"fleet_yes_{sid}", use_container_width=True):
                    try:
                        permanently_delete_system(sid)
                        st.session_state.pop(f"confirm_delete_{sid}", None)
                        st.session_state.pop("selected_system_id", None)
                        st.success("تم الحذف النهائي.")
                        st.rerun()
                    except Exception as exc:
                        st.error("فشل الحذف النهائي.")
                        st.code(database_error(exc))
            with no:
                if st.button("إلغاء", key=f"fleet_no_{sid}", use_container_width=True):
                    st.session_state.pop(f"confirm_delete_{sid}", None)
                    st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


def render_system_detail(system, systems, security, incidents, heartbeats):
    sid = system.get("id")
    hb = heartbeats.get(sid, {})
    related_security = [e for e in security if e.get("system_id") == sid]
    related_incidents = [i for i in incidents if i.get("system_id") == sid]
    attacked = sid in attack_system_ids(security)

    st.markdown('<div class="detail-hero">', unsafe_allow_html=True)
    st.markdown(f'<div class="eyebrow">SYSTEM DETAIL</div><div class="page-title" style="font-size:2rem">{safe_text(system.get("company", "Unknown"))}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="small-muted">{safe_text(sid)}</div>', unsafe_allow_html=True)
    if attacked:
        st.markdown('<div style="margin-top:.6rem"><span class="signal-pill danger"><span class="orb"></span>ATTACK DETECTED</span></div>', unsafe_allow_html=True)
    st.markdown(
        f'''<div class="detail-grid">
          <div class="detail-tile"><div class="label">Service</div><div class="value">{safe_text(system.get("status", "Not Checked"))}</div></div>
          <div class="detail-tile"><div class="label">HTTP</div><div class="value">{safe_text(system.get("http_status") or "—")}</div></div>
          <div class="detail-tile"><div class="label">Latency</div><div class="value">{safe_text(response_ms_text(system.get("response_ms")))}</div></div>
          <div class="detail-tile"><div class="label">Agent</div><div class="value">{"Online" if agent_is_online(system) else "Offline"}</div></div>
          <div class="detail-tile"><div class="label">OS</div><div class="value">{safe_text(hb.get("os_name", "—"))}</div></div>
          <div class="detail-tile"><div class="label">Agent version</div><div class="value">{safe_text(hb.get("agent_version", "—"))}</div></div>
          <div class="detail-tile"><div class="label">CPU</div><div class="value">{safe_text(str(hb.get("cpu_percent", "—")) + "%" if hb.get("cpu_percent") is not None else "—")}</div></div>
          <div class="detail-tile"><div class="label">Memory</div><div class="value">{safe_text(str(hb.get("memory_percent", "—")) + "%" if hb.get("memory_percent") is not None else "—")}</div></div>
        </div>''',
        unsafe_allow_html=True,
    )
    st.markdown('</div>', unsafe_allow_html=True)

    if st.button("← العودة إلى قائمة المنظومات", key="back_fleet_list"):
        st.session_state.pop("selected_system_id", None)
        st.rerun()

    a, b, c = st.columns(3)
    with a:
        if st.button("فحص الخدمة الآن", use_container_width=True, key="detail_check"):
            result = check_system(system)
            old = system.get("status", "Not Checked")
            system.update({
                "status": result["status"],
                "http_status": result["http_status"],
                "response_ms": result["response_ms"],
                "last_message": result["message"],
                "last_checked": iso_now(),
            })
            try:
                if old != "Not Checked" and old != result["status"]:
                    create_event(system, old, result["status"], result["message"])
                update_system(system)
                st.success("تم تحديث الحالة.")
                st.rerun()
            except Exception as exc:
                st.error("تعذر حفظ النتيجة.")
                st.code(database_error(exc))
    with b:
        if st.button("عرض الأمن لهذه المنظومة", use_container_width=True, key="detail_security"):
            st.session_state.security_system_filter = sid
            set_page("Security")
    with c:
        if st.button("عرض الحساس", use_container_width=True, key="detail_agent"):
            st.session_state.agent_system_filter = sid
            set_page("Agents")

    left, right = st.columns([1.1, .9], gap="large")
    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("Security timeline", f"{len(related_security)} events")
        if related_security:
            st.markdown('<div class="timeline-line">', unsafe_allow_html=True)
            for event in related_security[:30]:
                cls = "danger" if is_attack_event(event) else ""
                st.markdown(
                    f'<div class="timeline-event {cls}"><div class="timeline-time">{safe_text(event.get("event_time"))} · {safe_text(event.get("protocol") or "—")}</div><div class="timeline-text"><strong>{safe_text(event.get("attack_type") or event.get("event_type") or "Event")}</strong> · {safe_text(event.get("source_ip") or "Unknown")} · {safe_text(event.get("severity") or "Info")}<br>{safe_text(event.get("evidence") or "")}</div></div>',
                    unsafe_allow_html=True,
                )
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("لا توجد أحداث أمنية لهذه المنظومة.")
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("Incidents", f"{len(related_incidents)} total")
        if related_incidents:
            for incident in related_incidents[:12]:
                sev = incident.get("severity") or "Medium"
                st.markdown(
                    f'''<div class="incident-card {str(sev).lower()}"><div class="incident-header"><div><div class="incident-title">{safe_text(incident.get("title"))}</div><div class="incident-sub">{safe_text(incident.get("source_ip") or "Unknown")} · {safe_text(age_text(incident.get("last_seen")))}</div></div><div>{severity_badge(sev)}</div></div></div>''',
                    unsafe_allow_html=True,
                )
        else:
            st.info("لا توجد حوادث مسجلة لهذه المنظومة.")
        st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Add System page
# ================================================================

def add_system_page():
    page_header("SYSTEM ONBOARDING", "إضافة منظومة", "تسجيل منظومة جديدة وإصدار هوية خاصة للحساس.")
    back_to_overview_button()

    if "new_agent_credentials" not in st.session_state:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("Onboarding wizard", "4 خطوات عملية")
        company = st.text_input("اسم الشركة / المؤسسة", placeholder="Example Company", key="add_company")
        url = st.text_input("الرابط الرئيسي", placeholder="https://example.com", key="add_url")
        api_url = st.text_input("واجهة الصحة / الفحص", placeholder="https://example.com/health", key="add_api_url")
        api_key = st.text_input("مفتاح API الخاص بالمنظومة", type="password", key="add_api_key")
        st.markdown('<div class="search-hint">الرابط الرئيسي مطلوب مع واجهة الفحص اختيارية. مفتاح API اختياري ويستخدم فقط عندما تحتاج المنظومة إلى مصادقة.</div>', unsafe_allow_html=True)
        if st.button("تسجيل المنظومة وإصدار رمز الحساس", use_container_width=True, key="add_system_submit"):
            if not company.strip() or not (url.strip() or api_url.strip()):
                st.error("اسم الشركة ورابط رئيسي أو واجهة فحص مطلوبان.")
            else:
                try:
                    system_id, token = create_system(company, url, api_url, api_key)
                    st.session_state.new_agent_credentials = {
                        "system_id": system_id,
                        "ingest_token": token,
                        "company": company.strip(),
                    }
                    st.success("تم تسجيل المنظومة وإنشاء هوية الحساس.")
                    st.rerun()
                except Exception as exc:
                    st.error("فشل تسجيل المنظومة.")
                    st.code(database_error(exc))
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        creds = st.session_state.new_agent_credentials
        st.markdown('<div class="posture ok"><div class="top"><div><div class="posture-title">ONBOARDING COMPLETE</div><div class="posture-value">تم إنشاء هوية الحساس</div><div class="posture-text">يتم تخزين بصمة الـIngest Token في قاعدة البيانات، لذلك احفظ القيمة المعروضة الآن ولا تعتمد على استرجاعها لاحقًا.</div></div><span class="signal-pill safe"><span class="orb"></span>READY</span></div></div>', unsafe_allow_html=True)
        st.code(json.dumps(creds, ensure_ascii=False, indent=2), language="json")
        st.download_button(
            "تنزيل بيانات الهوية بصيغة JSON",
            data=json.dumps(creds, ensure_ascii=False, indent=2).encode("utf-8"),
            file_name=f"GuardianEye_{short_id(creds.get('system_id'))}_credentials.json",
            mime="application/json",
            use_container_width=True,
        )
        if st.button("إخفاء رمز الحساس", use_container_width=True, key="hide_creds"):
            st.session_state.pop("new_agent_credentials", None)
            st.rerun()

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    panel_header("ما الذي يحدث بعد التسجيل؟", "Control flow")
    st.markdown(
        '''<div class="tag-row">
          <span class="tag">System ID</span><span class="tag">Ingest Token</span><span class="tag">Agent</span><span class="tag">Heartbeat</span><span class="tag">Security Events</span><span class="tag">Incidents</span>
        </div>''',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="panel-note" style="margin-top:.7rem">بعد تشغيل الحساس داخل البيئة المصرح بها، يبدأ GuardianEye باستقبال heartbeat والأحداث الأمنية وربطها بالمنظومة الصحيحة.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Security page — global feed, no system selection required
# ================================================================

def security_page():
    page_header("GLOBAL SECURITY", "المراقبة الأمنية", "Global Security Feed لجميع المنظومات، مع تنبيهات وارتباطات متعددة المنظومات.")
    back_to_overview_button()

    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    events, _ = safe_db_call("تحميل الأحداث الأمنية", lambda: load_security_events(MAX_SECURITY_EVENTS), [])
    incidents, _ = safe_db_call("تحميل الحوادث", lambda: load_incidents(MAX_INCIDENTS), [])
    systems_by_id = {s.get("id"): s for s in systems}

    attack_ids = attack_system_ids(events)
    render_alarm_panel(len(attack_ids))

    critical = sum((e.get("severity") == "Critical") for e in events)
    high = sum((e.get("severity") == "High") for e in events)
    medium = sum((e.get("severity") == "Medium") for e in events)
    open_count = sum((e.get("status") or "Open") == "Open" for e in events)

    cols = st.columns(4)
    metrics = [("Critical", critical, "أعلى مستوى"), ("High", high, "تنبيه مرتفع"), ("Medium", medium, "مؤشرات متوسطة"), ("Open", open_count, "أحداث مفتوحة")]
    for col, (label, value, note) in zip(cols, metrics):
        with col:
            tone = "red" if label in {"Critical", "High", "Open"} and value else ""
            st.markdown(f'<div class="kpi {tone}"><div class="label">{label}</div><div class="value">{value}</div><div class="note">{note}</div></div>', unsafe_allow_html=True)

    filter_cols = st.columns([1,1,1,2])
    with filter_cols[0]:
        severities = st.multiselect("الخطورة", ["Critical", "High", "Medium", "Low", "Info"], default=[], key="sec_severity")
    with filter_cols[1]:
        system_filter = st.session_state.get("security_system_filter")
        system_names = [s.get("company", "Unknown") for s in systems]
        selected_name = st.selectbox("المنظومة", ["كل المنظومات"] + system_names, key="sec_system")
        if selected_name != "كل المنظومات":
            matched = next((s.get("id") for s in systems if s.get("company") == selected_name), None)
            system_filter = matched
    with filter_cols[2]:
        search = st.text_input("بحث", placeholder="attack / IP / evidence", key="sec_search")
    with filter_cols[3]:
        st.markdown('<div class="panel-note" style="padding-top:1.8rem">المراقبة هنا تجمع كل المنظومات تلقائيًا ولا تتطلب تحديد منظومة واحدة.</div>', unsafe_allow_html=True)

    visible = []
    q = search.strip().lower()
    for event in events:
        if severities and event.get("severity") not in severities:
            continue
        if system_filter and event.get("system_id") != system_filter:
            continue
        if q:
            blob = " ".join(str(event.get(k, "")) for k in ["attack_type", "event_type", "source_ip", "evidence", "protocol"]).lower()
            if q not in blob:
                continue
        visible.append(event)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    panel_header("Global Security Feed", f"{len(visible)} matching events")
    if visible:
        rows = []
        for event in visible:
            system_name = systems_by_id.get(event.get("system_id"), {}).get("company", short_id(event.get("system_id")))
            rows.append({
                "الوقت": event.get("event_time"),
                "المنظومة": system_name,
                "النوع": event.get("attack_type") or event.get("event_type"),
                "الخطورة": event.get("severity"),
                "المصدر": event.get("source_ip") or "Unknown",
                "البروتوكول": event.get("protocol") or "—",
                "الثقة": f"{safe_float(event.get('confidence'))*100:.0f}%",
                "الحالة": event.get("status") or "Open",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("تصدير Security Feed", data=data_url_csv(df), file_name="GuardianEye_Security_Feed.csv", mime="text/csv", use_container_width=True)

        st.markdown('<div class="section-head"><div class="title">تفاصيل أحدث الأحداث</div><div class="note">دليل الحدث والمصدر</div></div>', unsafe_allow_html=True)
        for event in visible[:8]:
            company = systems_by_id.get(event.get("system_id"), {}).get("company", short_id(event.get("system_id")))
            sev = event.get("severity") or "Info"
            dot = "danger" if sev in {"Critical", "High"} else ("warn" if sev == "Medium" else "")
            st.markdown(
                f'<div class="feed-row"><span class="feed-dot {dot}"></span><div><div class="feed-title">{safe_text(event.get("attack_type") or event.get("event_type"))} · {safe_text(company)}</div><div class="feed-meta">{safe_text(event.get("event_time"))} · source={safe_text(event.get("source_ip") or "Unknown")}</div><div class="feed-evidence">{safe_text(event.get("evidence") or "No evidence text")}</div></div>{severity_badge(sev)}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("لا توجد أحداث مطابقة للفلاتر الحالية.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    panel_header("Multi-system correlation", "مصادر ظهرت عبر أكثر من منظومة")
    correlations = correlate_sources(events)
    if correlations:
        for source, system_ids in correlations[:12]:
            names = [systems_by_id.get(sid, {}).get("company", short_id(sid)) for sid in system_ids]
            st.markdown(
                f'<div class="incident-card"><div class="incident-title">{safe_text(source)}</div><div class="incident-sub">{len(names)} منظومات متأثرة</div><div class="tag-row" style="margin-top:.45rem">' + ''.join(f'<span class="tag">{safe_text(name)}</span>' for name in names) + '</div></div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("لا توجد علاقة متعددة المنظومات ضمن الأحداث الحالية.")
    st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Incidents page
# ================================================================

def incidents_page():
    page_header("INCIDENT RESPONSE", "الحوادث الأمنية", "تحويل الأحداث إلى حوادث قابلة للتحليل والمتابعة والإغلاق والتصدير.")
    back_to_overview_button()

    incidents, _ = safe_db_call("تحميل الحوادث", lambda: load_incidents(MAX_INCIDENTS), [])
    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    events, _ = safe_db_call("تحميل الأحداث", lambda: load_security_events(MAX_SECURITY_EVENTS), [])
    systems_by_id = {s.get("id"): s for s in systems}

    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    critical = sum(i.get("severity") == "Critical" for i in open_incidents)
    high = sum(i.get("severity") == "High" for i in open_incidents)

    cols = st.columns(4)
    for col, label, value, note, tone in [
        (cols[0], "Open", len(open_incidents), "مفتوحة الآن", "red" if open_incidents else ""),
        (cols[1], "Critical", critical, "تحتاج أولوية عالية", "red" if critical else ""),
        (cols[2], "High", high, "تنبيهات مرتفعة", "red" if high else ""),
        (cols[3], "Total", len(incidents), "ضمن السجل الحالي", ""),
    ]:
        with col:
            st.markdown(f'<div class="kpi {tone}"><div class="label">{label}</div><div class="value">{value}</div><div class="note">{note}</div></div>', unsafe_allow_html=True)

    search = st.text_input("بحث في الحوادث", placeholder="عنوان الحادث أو المصدر أو المنظومة...", key="incident_search")
    sev_filter = st.multiselect("الخطورة", ["Critical", "High", "Medium", "Low"], key="incident_sev")
    status_filter = st.multiselect("الحالة", ["Open", "Resolved"], default=["Open"], key="incident_status")

    q = search.strip().lower()
    visible = []
    for incident in incidents:
        if sev_filter and incident.get("severity") not in sev_filter:
            continue
        if status_filter and incident.get("status") not in status_filter:
            continue
        if q:
            blob = " ".join(str(incident.get(k, "")) for k in ["title", "attack_type", "source_ip", "evidence_summary"]).lower()
            company = systems_by_id.get(incident.get("system_id"), {}).get("company", "").lower()
            if q not in blob and q not in company:
                continue
        visible.append(incident)

    selected_id = st.session_state.get("selected_incident_id")
    if selected_id:
        incident = next((i for i in incidents if i.get("id") == selected_id), None)
        if incident:
            render_incident_detail(incident, systems_by_id, events)
            return

    if not visible:
        st.info("لا توجد حوادث مطابقة للفلاتر.")
        return

    for incident in visible[:100]:
        sev = incident.get("severity") or "Medium"
        company = systems_by_id.get(incident.get("system_id"), {}).get("company", short_id(incident.get("system_id")))
        st.markdown(
            f'''<div class="incident-card {str(sev).lower()}">
              <div class="incident-header"><div><div class="incident-title">{safe_text(incident.get("title"))}</div><div class="incident-sub">{safe_text(company)} · {safe_text(incident.get("source_ip") or "Unknown")} · {safe_text(age_text(incident.get("last_seen")))}</div></div><div>{severity_badge(sev)} {status_badge("Enabled" if incident.get("status") == "Open" else "Disabled")}</div></div>
              <div class="feed-evidence">{safe_text(incident.get("evidence_summary") or "No summary")}</div>
            </div>''',
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns([1, 5])
        with c1:
            if st.button("فتح", key=f"inc_open_{incident.get('id')}", use_container_width=True):
                st.session_state.selected_incident_id = incident.get("id")
                st.rerun()


def render_incident_detail(incident, systems_by_id, events):
    system = systems_by_id.get(incident.get("system_id"), {})
    related = [e for e in events if e.get("system_id") == incident.get("system_id") and e.get("attack_type") == incident.get("attack_type")]
    if incident.get("source_ip"):
        related = [e for e in related if not e.get("source_ip") or e.get("source_ip") == incident.get("source_ip")]

    if st.button("← العودة إلى قائمة الحوادث", key="incident_back"):
        st.session_state.pop("selected_incident_id", None)
        st.rerun()

    sev = incident.get("severity") or "Medium"
    st.markdown(
        f'''<div class="detail-hero"><div class="eyebrow">INCIDENT WORKSPACE</div><div class="page-title" style="font-size:2rem">{safe_text(incident.get("title"))}</div><div class="tag-row" style="margin-top:.45rem">{severity_badge(sev)} {status_badge("Enabled" if incident.get("status") == "Open" else "Disabled")}<span class="tag">{safe_text(system.get("company", "Unknown"))}</span><span class="tag">{safe_text(incident.get("source_ip") or "Unknown")}</span></div></div>''',
        unsafe_allow_html=True,
    )

    cols = st.columns(4)
    facts = [
        ("Attack Type", incident.get("attack_type") or "Unknown"),
        ("Source", incident.get("source_ip") or "Unknown"),
        ("Events", incident.get("event_count", 0)),
        ("Last Seen", age_text(incident.get("last_seen"))),
    ]
    for col, (label, value) in zip(cols, facts):
        with col:
            st.markdown(f'<div class="kpi"><div class="label">{safe_text(label)}</div><div class="value" style="font-size:1.1rem">{safe_text(value)}</div><div class="note">Incident context</div></div>', unsafe_allow_html=True)

    left, right = st.columns([1.15, .85], gap="large")
    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("Evidence & timeline", f"{len(related)} related events")
        st.markdown(f'<div class="feed-evidence">{safe_text(incident.get("evidence_summary") or "No evidence summary")}</div>', unsafe_allow_html=True)
        st.markdown('<div class="timeline-line" style="margin-top:.7rem">', unsafe_allow_html=True)
        for event in related[:100]:
            cls = "danger" if is_attack_event(event) else ""
            st.markdown(
                f'<div class="timeline-event {cls}"><div class="timeline-time">{safe_text(event.get("event_time"))}</div><div class="timeline-text"><strong>{safe_text(event.get("attack_type") or event.get("event_type"))}</strong> · {safe_text(event.get("source_ip") or "Unknown")}<br>{safe_text(event.get("evidence") or "")}</div></div>',
                unsafe_allow_html=True,
            )
        st.markdown('</div></div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("Response actions", "Control")
        if incident.get("status") == "Open":
            if st.button("وضع الحادث كمحلول", use_container_width=True, key="resolve_incident"):
                try:
                    resolve_incident(incident["id"])
                    st.success("تم حل الحادث.")
                    st.session_state.pop("selected_incident_id", None)
                    st.rerun()
                except Exception as exc:
                    st.error("تعذر تحديث الحادث.")
                    st.code(database_error(exc))
        else:
            st.success("الحادث مغلق.")

        report = build_incident_report(incident, system, related)
        st.download_button(
            "تصدير تقرير الحادث",
            data=report,
            file_name=f"GuardianEye_Incident_{short_id(incident.get('id'))}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        st.markdown('</div>', unsafe_allow_html=True)


def build_incident_report(incident, system, events):
    lines = [
        "# GuardianEye Security Incident Report",
        "",
        f"Incident ID: {incident.get('id')}",
        f"System: {system.get('company', 'Unknown')}",
        f"Attack Type: {incident.get('attack_type', 'Unknown')}",
        f"Severity: {incident.get('severity', 'Unknown')}",
        f"Source IP: {incident.get('source_ip') or 'Unknown'}",
        f"Status: {incident.get('status') or 'Open'}",
        f"First Seen: {incident.get('first_seen') or 'Unknown'}",
        f"Last Seen: {incident.get('last_seen') or 'Unknown'}",
        f"Event Count: {incident.get('event_count', 0)}",
        "",
        "## Evidence Summary",
        incident.get("evidence_summary") or "No summary provided.",
        "",
        "## Related Events",
    ]
    for event in events[:200]:
        lines.append(
            f"- {event.get('event_time')} | {event.get('attack_type') or event.get('event_type')} | {event.get('severity')} | source={event.get('source_ip') or 'Unknown'} | {event.get('evidence') or ''}"
        )
    lines.extend(["", "Generated by GuardianEye."])
    return "\n".join(lines)


# ================================================================
# Analytics page
# ================================================================

def analytics_page():
    page_header("SECURITY ANALYTICS", "التحليلات", "لوحة تحليلية تربط صحة الخدمات بالحوادث والأحداث ومصادرها.")
    back_to_overview_button()

    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    events, _ = safe_db_call("تحميل الأحداث", lambda: load_security_events(MAX_SECURITY_EVENTS), [])
    incidents, _ = safe_db_call("تحميل الحوادث", lambda: load_incidents(MAX_INCIDENTS), [])

    if systems:
        health_df = pd.DataFrame([{
            "company": s.get("company", "Unknown"),
            "response_ms": safe_float(s.get("response_ms"), None),
            "status": s.get("status", "Not Checked"),
        } for s in systems]).dropna(subset=["response_ms"])
        if not health_df.empty:
            st.markdown('<div class="panel">', unsafe_allow_html=True)
            panel_header("زمن الاستجابة الحالي", "Operational health")
            fig = px.bar(health_df, x="company", y="response_ms", color="status", title="Response latency by system")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10,r=10,t=50,b=10), font=dict(color="#cbd5e1"))
            st.plotly_chart(fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

    left, right = st.columns(2, gap="large")
    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("توزيع أنواع الأحداث", "Attack taxonomy")
        if events:
            df = pd.DataFrame(events)
            counts = df["attack_type"].fillna(df["event_type"]).fillna("Unknown").value_counts().reset_index()
            counts.columns = ["attack_type", "count"]
            fig = px.pie(counts, names="attack_type", values="count", hole=.58, title="Security events")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"), margin=dict(l=10,r=10,t=50,b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("لا توجد أحداث أمنية لعرضها.")
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("مصادر متكررة", "Top source IPs")
        if events:
            df = pd.DataFrame(events)
            ips = df["source_ip"].fillna("Unknown").value_counts().head(10).reset_index()
            ips.columns = ["source_ip", "count"]
            fig = px.bar(ips, x="source_ip", y="count", title="Source frequency")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"), margin=dict(l=10,r=10,t=50,b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("لا توجد عناوين مصدر.")
        st.markdown('</div>', unsafe_allow_html=True)

    if events:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("الخطورة بمرور الوقت", "Event intensity")
        df = pd.DataFrame(events)
        df["event_time_dt"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
        df = df.dropna(subset=["event_time_dt"])
        if not df.empty:
            by_hour = df.groupby(df["event_time_dt"].dt.floor("h")).size().reset_index(name="count")
            fig = px.line(by_hour, x="event_time_dt", y="count", markers=True, title="Events per hour")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"), margin=dict(l=10,r=10,t=50,b=10))
            st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if incidents:
        sev = Counter(i.get("severity") or "Unknown" for i in incidents)
        table = pd.DataFrame([{"الخطورة": k, "العدد": v} for k, v in sev.items()])
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        panel_header("ملخص الحوادث", "Incident distribution")
        st.dataframe(table, use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Events page
# ================================================================

def events_page():
    page_header("EVENT EXPLORER", "سجل الأحداث", "استكشاف تشغيلي وأمني مع تصفية وتصدير.")
    back_to_overview_button()

    operational, _ = safe_db_call("تحميل الأحداث التشغيلية", lambda: load_events(MAX_OPERATIONAL_EVENTS), [])
    security, _ = safe_db_call("تحميل الأحداث الأمنية", lambda: load_security_events(MAX_SECURITY_EVENTS), [])
    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    systems_by_id = {s.get("id"): s for s in systems}

    tab1, tab2 = st.tabs(["Operational events", "Security events"])

    with tab1:
        if operational:
            rows = []
            for event in operational:
                rows.append({
                    "الوقت": event.get("time"),
                    "المنظومة": event.get("company") or systems_by_id.get(event.get("system_id"), {}).get("company", short_id(event.get("system_id"))),
                    "من": event.get("old_status"),
                    "إلى": event.get("new_status"),
                    "الرسالة": event.get("message"),
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("تصدير الأحداث التشغيلية", data=data_url_csv(df), file_name="GuardianEye_Operational_Events.csv", mime="text/csv", use_container_width=True)
        else:
            st.info("لا توجد أحداث تشغيلية.")

    with tab2:
        if security:
            search = st.text_input("بحث في الأحداث الأمنية", placeholder="IP / attack / evidence", key="events_security_search")
            q = search.strip().lower()
            visible = []
            for event in security:
                blob = " ".join(str(event.get(k, "")) for k in ["attack_type", "event_type", "source_ip", "evidence"]).lower()
                if q and q not in blob:
                    continue
                visible.append(event)
            rows = []
            for event in visible:
                rows.append({
                    "الوقت": event.get("event_time"),
                    "المنظومة": systems_by_id.get(event.get("system_id"), {}).get("company", short_id(event.get("system_id"))),
                    "النوع": event.get("attack_type") or event.get("event_type"),
                    "الخطورة": event.get("severity"),
                    "المصدر": event.get("source_ip") or "Unknown",
                    "الحالة": event.get("status") or "Open",
                    "الثقة": f"{safe_float(event.get('confidence'))*100:.0f}%",
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("تصدير Security Events", data=data_url_csv(df), file_name="GuardianEye_Security_Events.csv", mime="text/csv", use_container_width=True)
        else:
            st.info("لا توجد أحداث أمنية.")


# ================================================================
# Agents page
# ================================================================

def agents_page():
    page_header("AGENT FLEET", "الحساسات", "حالة أسطول GuardianEye Agent، heartbeat، إصدار البرنامج، وقياسات التشغيل.")
    back_to_overview_button()

    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    heartbeats_list, _ = safe_db_call("تحميل heartbeat", lambda: load_heartbeats(500), [])
    heartbeats = {}
    for hb in heartbeats_list:
        sid = hb.get("system_id")
        if sid and sid not in heartbeats:
            heartbeats[sid] = hb

    filter_id = st.session_state.get("agent_system_filter")
    if filter_id:
        systems = [s for s in systems if s.get("id") == filter_id]
        if st.button("مسح فلتر المنظومة", key="clear_agent_filter"):
            st.session_state.pop("agent_system_filter", None)
            st.rerun()

    online = [s for s in systems if agent_is_online(s)]
    offline = [s for s in systems if not agent_is_online(s)]
    cols = st.columns(3)
    for col, label, value, note, tone in [
        (cols[0], "Online", len(online), "آخر 90 ثانية", "green"),
        (cols[1], "Offline", len(offline), "لا يوجد heartbeat حديث", "red" if offline else ""),
        (cols[2], "Fleet", len(systems), "الحساسات المسجلة", ""),
    ]:
        with col:
            st.markdown(f'<div class="kpi {tone}"><div class="label">{label}</div><div class="value">{value}</div><div class="note">{note}</div></div>', unsafe_allow_html=True)

    if not systems:
        st.info("لا توجد منظومات لعرض الحساسات.")
        return

    for system in systems:
        sid = system.get("id")
        hb = heartbeats.get(sid, {})
        is_online = agent_is_online(system)
        status = "Online" if is_online else "Offline"
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown(
            f'<div class="section-head"><div><div class="title">{safe_text(system.get("company", "Unknown"))}</div><div class="note">System ID: {safe_text(sid)}</div></div><div>{status_badge(status)}</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'''<div class="detail-grid">
              <div class="detail-tile"><div class="label">Hostname</div><div class="value">{safe_text(hb.get("hostname", "—"))}</div></div>
              <div class="detail-tile"><div class="label">OS</div><div class="value">{safe_text(hb.get("os_name", "—"))}</div></div>
              <div class="detail-tile"><div class="label">Version</div><div class="value">{safe_text(hb.get("agent_version", "—"))}</div></div>
              <div class="detail-tile"><div class="label">Last heartbeat</div><div class="value">{safe_text(age_text(system.get("agent_last_seen")))}</div></div>
              <div class="detail-tile"><div class="label">CPU</div><div class="value">{safe_text(str(hb.get("cpu_percent", "—")) + "%" if hb.get("cpu_percent") is not None else "—")}</div></div>
              <div class="detail-tile"><div class="label">Memory</div><div class="value">{safe_text(str(hb.get("memory_percent", "—")) + "%" if hb.get("memory_percent") is not None else "—")}</div></div>
              <div class="detail-tile"><div class="label">Connections</div><div class="value">{safe_text(hb.get("open_connections", "—"))}</div></div>
              <div class="detail-tile"><div class="label">Monitored logs</div><div class="value">{safe_text(len(hb.get("monitored_logs") or []))}</div></div>
            </div>''',
            unsafe_allow_html=True,
        )
        if hb.get("monitored_logs"):
            st.markdown('<div class="tag-row" style="margin-top:.7rem">' + ''.join(f'<span class="tag">{safe_text(p)}</span>' for p in (hb.get("monitored_logs") or [])[:12]) + '</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Agent Setup page — controlled onboarding view
# ================================================================

def agent_setup_page():
    page_header("AGENT CONTROL", "إعداد الحساس", "متابعة حالة الحساسات وتعليمات الربط لكل منظومة.")
    back_to_overview_button()

    systems, _ = safe_db_call("تحميل المنظومات", load_systems, [])
    heartbeat_rows, _ = safe_db_call("تحميل heartbeat", lambda: load_heartbeats(500), [])
    heartbeat_map = {}
    for hb in heartbeat_rows:
        sid = hb.get("system_id")
        if sid and sid not in heartbeat_map:
            heartbeat_map[sid] = hb

    online_count = sum(agent_is_online(s) for s in systems)
    offline_count = max(0, len(systems) - online_count)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="kpi green"><div class="label">AGENTS ONLINE</div><div class="value">{online_count}</div><div class="note">Heartbeat خلال 90 ثانية</div></div>', unsafe_allow_html=True)
    with c2:
        tone = "red" if offline_count else ""
        st.markdown(f'<div class="kpi {tone}"><div class="label">AGENTS OFFLINE</div><div class="value">{offline_count}</div><div class="note">لا يوجد heartbeat حديث</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="kpi"><div class="label">REGISTERED SYSTEMS</div><div class="value">{len(systems)}</div><div class="note">منظومات مرتبطة بالمركز</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    panel_header("حالة الحساسات", "Agent fleet")
    if not systems:
        st.info("لا توجد منظومات مسجلة بعد.")
    else:
        for system in systems:
            sid = system.get("id")
            hb = heartbeat_map.get(sid, {})
            status = "Online" if agent_is_online(system) else "Offline"
            st.markdown(
                f'<div class="section-head"><div><div class="title">{safe_text(system.get("company", "Unknown"))}</div><div class="note">System ID: {safe_text(sid)}</div></div><div>{status_badge(status)}</div></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""<div class="detail-grid">
                  <div class="detail-tile"><div class="label">Hostname</div><div class="value">{safe_text(hb.get("hostname", "—"))}</div></div>
                  <div class="detail-tile"><div class="label">OS</div><div class="value">{safe_text(hb.get("os_name", "—"))}</div></div>
                  <div class="detail-tile"><div class="label">Agent Version</div><div class="value">{safe_text(hb.get("agent_version", "—"))}</div></div>
                  <div class="detail-tile"><div class="label">Last heartbeat</div><div class="value">{safe_text(age_text(system.get("agent_last_seen")))}</div></div>
                </div>""",
                unsafe_allow_html=True,
            )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    panel_header("Agent package", "Client deployment")
    st.markdown(
        """<div class="tag-row">
          <span class="tag">guardianeye_agent.py</span>
          <span class="tag">agent_config.json</span>
          <span class="tag">Windows</span>
          <span class="tag">Linux</span>
          <span class="tag">Heartbeat</span>
          <span class="tag">Security Events</span>
        </div>""",
        unsafe_allow_html=True,
    )
    st.caption("لكل منظومة System ID وIngest Token مستقلان. لا يتم عرض Token قديم لأن قاعدة البيانات تحتفظ ببصمته فقط.")
    st.markdown('</div>', unsafe_allow_html=True)


# ================================================================
# Compatibility helpers kept from the previous GuardianEye API
# ================================================================

def metric_card(label, value, note):
    return (
        f'<div class="kpi"><div class="label">{safe_text(label)}</div>'
        f'<div class="value">{safe_text(value)}</div>'
        f'<div class="note">{safe_text(note)}</div></div>'
    )


def systems_page():
    # Backward-compatible entry point for the previous page name.
    return fleet_page()

# ================================================================
# Session state and dispatch
# ================================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "page" not in st.session_state:
    st.session_state.page = "Overview"
if "last_health_run" not in st.session_state:
    st.session_state.last_health_run = 0.0
if "monitor_error" not in st.session_state:
    st.session_state.monitor_error = ""


if not st.session_state.logged_in:
    login()
    st.stop()

# Run the global health engine for all systems. It is internally throttled.
run_health_monitoring()

with st.sidebar:
    st.markdown(
        '<div class="brand-row"><div class="brand-mark">◉</div><div><div class="brand-name">GUARDIANEYE</div><div class="brand-sub">Security Operations Platform</div></div></div>',
        unsafe_allow_html=True,
    )
    st.divider()
    st.markdown('<div class="panel-note">CONTROL CENTER</div>', unsafe_allow_html=True)
    current = st.session_state.get("page", "Overview")
    sidebar_pages = [
        ("Overview", "مركز المراقبة"),
        ("Fleet", "المنظومات"),
        ("Add System", "إضافة منظومة"),
        ("Security", "الأمن"),
        ("Incidents", "الحوادث"),
        ("Analytics", "التحليلات"),
        ("Events", "الأحداث"),
        ("Agents", "الحساسات"),
        ("Agent Setup", "إعداد الحساس"),
    ]
    for key, label in sidebar_pages:
        if st.button(("● " if current == key else "○ ") + label, key=f"side_{key}", use_container_width=True):
            set_page(key)
    st.divider()
    st.markdown(f'<div class="small-muted">Signed in as<br><strong>{safe_text(ADMIN_USER)}</strong></div>', unsafe_allow_html=True)
    if st.button("تسجيل الخروج", use_container_width=True, key="logout_button"):
        logout()

render_nav()

try:
    page = st.session_state.page
    if page == "Overview":
        overview_page()
    elif page == "Fleet":
        fleet_page()
    elif page == "Add System":
        add_system_page()
    elif page == "Security":
        security_page()
    elif page == "Incidents":
        incidents_page()
    elif page == "Analytics":
        analytics_page()
    elif page == "Events":
        events_page()
    elif page == "Agents":
        agents_page()
    elif page == "Agent Setup":
        agent_setup_page()
    else:
        st.session_state.page = "Overview"
        st.rerun()
except Exception as exc:
    # Keep the control center alive without dumping raw Python errors to the user.
    st.error("حدث خطأ غير متوقع أثناء تحميل هذه الوحدة.")
    st.code(database_error(exc))
    st.caption("إذا استمر الخطأ، راجع سجل التطبيق على Streamlit Cloud. الوحدات الأخرى يمكن الوصول إليها من شريط التنقل العلوي.")