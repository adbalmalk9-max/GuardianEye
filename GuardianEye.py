import datetime as dt
import base64
import io
import math
import struct
import wave
import hashlib
import html
import json
import re
import time
import uuid
from collections import Counter
from textwrap import dedent

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh


APP_NAME = "GuardianEye"
APP_VERSION = "8.1"
HEALTHY_THRESHOLD_MS = 1500
AGENT_OFFLINE_SECONDS = 90
INCIDENT_OPEN_WINDOW_MINUTES = 15

st.set_page_config(
    page_title="GuardianEye",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
:root{
  --bg:#070a0f;
  --surface:#0d131b;
  --surface2:#111923;
  --border:rgba(148,163,184,.14);
  --border2:rgba(148,163,184,.23);
  --text:#eef3f8;
  --muted:#8996a6;
  --good:#42d392;
  --warn:#f2bd62;
  --bad:#f06a78;
  --blue:#4aa8ff;
}
html,body,[class*="css"]{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}
body{background:var(--bg);color:var(--text);}
.block-container{max-width:1500px;padding-top:1.2rem;padding-bottom:3rem;}
div[data-testid="stSidebar"]{background:#090e15;border-right:1px solid var(--border);}
.small-muted{color:var(--muted);font-size:.82rem;}
.brand{font-size:1.55rem;font-weight:800;letter-spacing:-.02em;}
.brand-sub{color:var(--muted);font-size:.78rem;margin-top:.15rem;}
.page-title{font-size:2rem;font-weight:800;letter-spacing:-.035em;margin-bottom:.15rem;}
.page-subtitle{color:var(--muted);margin-bottom:1.2rem;}
.metric-card{background:linear-gradient(180deg,rgba(17,25,35,.96),rgba(13,19,27,.96));border:1px solid var(--border);border-radius:16px;padding:1rem 1.05rem;min-height:118px;}
.metric-label{color:var(--muted);font-size:.78rem;letter-spacing:.04em;text-transform:uppercase;}
.metric-value{font-size:2rem;font-weight:800;margin-top:.25rem;}
.metric-note{color:var(--muted);font-size:.75rem;margin-top:.15rem;}
.status-pill{display:inline-block;padding:.23rem .62rem;border-radius:999px;border:1px solid var(--border);font-size:.72rem;font-weight:750;}
.good{background:rgba(66,211,146,.09);color:#7ae9b0;}
.warn{background:rgba(242,189,98,.09);color:#f6d18b;}
.bad{background:rgba(240,106,120,.09);color:#ff9ba5;}
.neutral{background:rgba(148,163,184,.07);color:#c5cfda;}
.info{background:rgba(74,168,255,.09);color:#9bcfff;}
.incident-card{background:#0d141d;border:1px solid var(--border);border-radius:15px;padding:1rem 1.05rem;margin-bottom:.75rem;}
.incident-critical{border-color:rgba(240,106,120,.32);}
.incident-high{border-color:rgba(240,106,120,.22);}
.incident-medium{border-color:rgba(242,189,98,.20);}
.source-ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;}
.mini{font-size:.75rem;color:var(--muted);}
.alert-banner{border:1px solid rgba(240,106,120,.35);background:linear-gradient(180deg,rgba(71,18,27,.44),rgba(39,15,21,.38));padding:1rem 1.05rem;border-radius:15px;margin-bottom:1rem;}
.timeline-row{padding:.75rem 0;border-bottom:1px solid var(--border);}
.stButton>button{border-radius:10px;font-weight:700;background:#111a25;border:1px solid var(--border2);}
.stButton>button:hover{border-color:rgba(74,168,255,.55);background:#152130;}
[data-testid="stDataFrame"]{border:1px solid var(--border);border-radius:12px;overflow:hidden;}


/* =========================================================
   GuardianEye v7 Command Center layer
   ========================================================= */
:root{
  --g-accent:#4aa8ff;
  --g-cyan:#5de1ff;
  --g-green:#38e6a5;
  --g-red:#ff4f6d;
  --g-yellow:#f4c86a;
}
[data-testid="stSidebar"]{display:none !important;}
[data-testid="collapsedControl"]{display:none !important;}
[data-testid="stToolbar"]{display:none !important;}
#MainMenu{display:none !important;}
footer{display:none !important;}
[data-testid="stDecoration"]{display:none !important;}
.top-command-nav{display:flex;gap:.45rem;align-items:center;justify-content:space-between;padding:.55rem .65rem;border:1px solid rgba(148,163,184,.16);border-radius:14px;background:rgba(8,13,19,.88);backdrop-filter:blur(10px);margin:0 0 1rem 0;}
.nav-kicker{font-size:.68rem;letter-spacing:.17em;text-transform:uppercase;color:#71859d;font-weight:800;white-space:nowrap;}
.section-chip{display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .58rem;border:1px solid rgba(148,163,184,.12);border-radius:999px;background:#0b1118;color:#9eafc2;font-size:.72rem;}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--g-green);box-shadow:0 0 0 5px rgba(56,230,165,.08),0 0 18px rgba(56,230,165,.55);display:inline-block;}
.live-dot.alert{background:var(--g-red);box-shadow:0 0 0 5px rgba(255,79,109,.09),0 0 20px rgba(255,79,109,.6);animation:guardianPulse 1.15s infinite;}
@keyframes guardianPulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.35);opacity:.72}}
.fleet-alert{border:1px solid rgba(255,79,109,.48);background:linear-gradient(110deg,rgba(70,13,26,.72),rgba(28,12,19,.62));box-shadow:0 0 0 1px rgba(255,79,109,.08),0 10px 34px rgba(255,79,109,.08);padding:1rem 1.05rem;border-radius:16px;margin:0 0 1rem 0;display:flex;align-items:center;justify-content:space-between;gap:1rem;}
.fleet-alert-title{font-size:1rem;font-weight:850;color:#fff;}
.fleet-alert-sub{font-size:.76rem;color:#d7a9b3;margin-top:.2rem;}
.system-grid-card{background:linear-gradient(160deg,#0d1620,#091018);border:1px solid rgba(148,163,184,.16);border-radius:18px;padding:1rem;min-height:205px;position:relative;overflow:hidden;margin-bottom:1rem;}
.system-grid-card::after{content:"";position:absolute;inset:auto -15% -45% auto;width:160px;height:160px;border-radius:50%;background:radial-gradient(circle,rgba(74,168,255,.09),transparent 68%);pointer-events:none;}
.system-grid-card.attack{border-color:rgba(255,79,109,.55);box-shadow:0 0 0 1px rgba(255,79,109,.12),0 12px 35px rgba(255,79,109,.09);}
.system-grid-card.warn{border-color:rgba(244,200,106,.38);}
.system-grid-head{display:flex;justify-content:space-between;align-items:flex-start;gap:.75rem;}
.system-name{font-size:1.06rem;font-weight:850;color:#f2f6fb;}
.system-meta{font-size:.72rem;color:#7890aa;margin-top:.2rem;}
.system-signal{display:flex;align-items:center;gap:.45rem;font-size:.68rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase;}
.system-signal.attack{color:#ff96a8;}.system-signal.good{color:#75e5bb;}.system-signal.warn{color:#f3d28d;}.system-signal.off{color:#9aa8b7;}
.system-stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;margin-top:1rem;}
.system-stat{padding:.62rem .65rem;border:1px solid rgba(148,163,184,.11);border-radius:11px;background:rgba(255,255,255,.018);}
.system-stat-label{font-size:.65rem;color:#71869c;text-transform:uppercase;letter-spacing:.06em;}.system-stat-value{font-weight:850;font-size:1rem;margin-top:.2rem;color:#eef3f8;}
.system-event{margin-top:.75rem;padding:.6rem .7rem;border-left:2px solid rgba(74,168,255,.45);background:rgba(74,168,255,.04);border-radius:0 9px 9px 0;font-size:.72rem;color:#a8bacb;line-height:1.5;}
.system-event.attack{border-left-color:var(--g-red);background:rgba(255,79,109,.045);color:#efc5cc;}
.posture-panel{background:linear-gradient(125deg,rgba(17,31,44,.95),rgba(11,18,26,.96));border:1px solid rgba(148,163,184,.15);border-radius:18px;padding:1rem 1.1rem;margin:1rem 0;}
.posture-label{font-size:.66rem;letter-spacing:.17em;text-transform:uppercase;color:#6d849e;font-weight:850;}.posture-title{font-size:1.15rem;font-weight:850;margin-top:.28rem;}.posture-copy{color:#9eb0c1;font-size:.78rem;line-height:1.65;margin-top:.35rem;}
.correlation-card{border:1px solid rgba(255,79,109,.3);background:rgba(255,79,109,.04);border-radius:14px;padding:.8rem .9rem;margin-top:.7rem;}
.correlation-title{font-weight:850;color:#f0d4d9;font-size:.82rem;}.correlation-meta{color:#b3979e;font-size:.7rem;margin-top:.15rem;}
.quick-action{height:100%;background:#0c141d;border:1px solid rgba(148,163,184,.13);border-radius:14px;padding:.82rem .9rem;}
.quick-action .qa-title{font-weight:800;font-size:.82rem;}.quick-action .qa-copy{font-size:.69rem;color:#7e93a8;margin-top:.2rem;}
.alarm-state{display:inline-flex;align-items:center;gap:.45rem;font-size:.71rem;color:#9fb0c1;}

</style>
""",
    unsafe_allow_html=True,
)

# Refresh UI; database monitoring is separately protected against excessive checks.
st_autorefresh(interval=10000, limit=None, key="guardianeye_refresh")


def required_secret(name):
    value = str(st.secrets.get(name, "")).strip()
    if not value:
        raise RuntimeError(f"Missing Streamlit Secret: {name}")
    return value


try:
    ADMIN_USER = required_secret("GUARDIAN_ADMIN_USER")
    ADMIN_PASSWORD = required_secret("GUARDIAN_ADMIN_PASSWORD")
    SUPABASE_URL = required_secret("SUPABASE_URL").rstrip("/")
    SUPABASE_SERVICE_ROLE_KEY = required_secret("SUPABASE_SERVICE_ROLE_KEY")
    GUARDIAN_ENCRYPTION_KEY = required_secret("GUARDIAN_ENCRYPTION_KEY")
except RuntimeError as exc:
    st.error("GuardianEye يحتاج إلى إعداد الأسرار في Streamlit.")
    st.code(str(exc))
    st.stop()


@st.cache_resource(show_spinner=False)
def get_supabase():
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


@st.cache_resource(show_spinner=False)
def get_fernet():
    from cryptography.fernet import Fernet
    return Fernet(GUARDIAN_ENCRYPTION_KEY.encode("utf-8"))


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


def safe_text(value):
    return html.escape(str(value)) if value is not None else ""


def status_badge(status):
    mapping = {
        "Healthy": ("good", "● Healthy"),
        "Slow": ("warn", "● Slow"),
        "Down": ("bad", "● Down"),
        "Auth Error": ("bad", "● Auth Error"),
        "Not Checked": ("neutral", "● Not Checked"),
        "Online": ("good", "● Online"),
        "Offline": ("bad", "● Offline"),
    }
    css, label = mapping.get(status, ("neutral", f"● {status}"))
    return f'<span class="status-pill {css}">{safe_text(label)}</span>'


def severity_badge(severity):
    mapping = {"Critical": "bad", "High": "bad", "Medium": "warn", "Low": "info", "Info": "neutral"}
    css = mapping.get(severity, "neutral")
    return f'<span class="status-pill {css}">{safe_text(severity)}</span>'


def database_error(exc):
    text = str(exc).strip()
    return text[:600] if text else "Unknown database error."


def load_systems():
    result = (
        get_supabase().table("systems")
        .select(
            "id,company,url,api_url,api_key_enc,status,http_status,response_ms,"
            "last_message,last_checked,created_at,ingest_token_hash,agent_enabled,agent_last_seen"
        )
        .order("created_at", desc=False)
        .execute()
    )
    return result.data or []


def load_events(limit=500):
    result = (
        get_supabase().table("events")
        .select("id,time,system_id,company,old_status,new_status,message")
        .order("time", desc=True).limit(limit).execute()
    )
    return result.data or []


def load_security_events(limit=500):
    result = (
        get_supabase().table("security_events")
        .select(
            "id,system_id,event_time,event_type,attack_type,severity,confidence,"
            "source_ip,source_port,dest_port,protocol,evidence,status,detected_by,raw_data"
        )
        .order("event_time", desc=True).limit(limit).execute()
    )
    return result.data or []


def load_incidents(limit=300):
    result = (
        get_supabase().table("incidents")
        .select(
            "id,system_id,title,attack_type,severity,source_ip,first_seen,last_seen,"
            "event_count,status,evidence_summary,resolved_at,created_at"
        )
        .order("last_seen", desc=True).limit(limit).execute()
    )
    return result.data or []


def load_heartbeats(limit=300):
    result = (
        get_supabase().table("agent_heartbeats")
        .select(
            "id,system_id,seen_at,hostname,os_name,agent_version,cpu_percent,"
            "memory_percent,open_connections,monitored_logs"
        )
        .order("seen_at", desc=True).limit(limit).execute()
    )
    return result.data or []


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

    query = (
        get_supabase().table("incidents")
        .select("id,event_count,evidence_summary")
        .eq("system_id", system_id)
        .eq("attack_type", attack_type)
        .eq("status", "Open")
        .gte("last_seen", cutoff)
        .limit(1)
        .execute()
    )
    rows = query.data or []

    if rows:
        inc = rows[0]
        summary = str(inc.get("evidence_summary") or "")
        evidence = str(event.get("evidence") or "")
        combined = (summary + " | " + evidence).strip(" |")[-1200:]
        get_supabase().table("incidents").update({
            "last_seen": now,
            "event_count": int(inc.get("event_count") or 0) + 1,
            "evidence_summary": combined,
            "source_ip": source_ip or None,
            "severity": event.get("severity") or "Medium",
        }).eq("id", inc["id"]).execute()
        return inc["id"]

    system_row = get_supabase().table("systems").select("company").eq("id", system_id).limit(1).execute().data
    company = (system_row[0].get("company") if system_row else "Unknown")
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
    return (inserted.data[0]["id"] if inserted.data else None)


def resolve_incident(incident_id):
    get_supabase().table("incidents").update({
        "status": "Resolved",
        "resolved_at": iso_now(),
    }).eq("id", incident_id).execute()


def check_system(system):
    target = (system.get("api_url") or system.get("url") or "").strip()
    api_key = decrypt_secret(system.get("api_key_enc", ""))
    if not target:
        return {"status": "Down", "http_status": None, "response_ms": None, "message": "No monitoring URL configured."}

    headers = {
        "User-Agent": f"GuardianEye-Monitor/{APP_VERSION}",
        "Accept": "application/json, text/plain, */*",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.perf_counter()
    try:
        response = requests.get(target, headers=headers, timeout=8, allow_redirects=True)
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
        return {"status": status, "http_status": code, "response_ms": elapsed, "message": message}
    except requests.exceptions.Timeout:
        return {"status": "Down", "http_status": None, "response_ms": None, "message": "Request timed out after 8 seconds."}
    except requests.exceptions.RequestException as exc:
        return {"status": "Down", "http_status": None, "response_ms": None, "message": f"Connection error: {str(exc)[:140]}"}




def _to_dt(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def make_alarm_wav_data_uri():
    """Generate a tiny two-tone alarm entirely in memory (no extra file)."""
    sample_rate = 22050
    duration = 0.32
    frames = int(sample_rate * duration)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        for i in range(frames):
            t = i / sample_rate
            freq = 880 if int(t * 6) % 2 == 0 else 660
            envelope = max(0.0, 1.0 - (t / duration) * 0.15)
            value = int(14000 * envelope * math.sin(2 * math.pi * freq * t))
            wf.writeframes(struct.pack("<h", value))
    return "data:audio/wav;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


ALARM_AUDIO_URI = make_alarm_wav_data_uri()


def render_alarm_sound(should_play):
    if not should_play or not st.session_state.get("alarm_armed", False):
        return
    st.markdown(
        f'<audio autoplay playsinline style="display:none"><source src="{ALARM_AUDIO_URI}" type="audio/wav"></audio>',
        unsafe_allow_html=True,
    )


def render_app_nav(active_page):
    """Persistent in-app navigation; independent from the Streamlit sidebar."""
    pages = [
        ("Overview", "مركز المراقبة"),
        ("Systems", "المنظومات"),
        ("Add System", "إضافة منظومة"),
        ("Security", "المراقبة الأمنية"),
        ("Incidents", "الحوادث"),
        ("Analytics", "التحليلات"),
        ("Events", "سجل الأحداث"),
        ("Agent Setup", "إعداد الحساس"),
    ]
    st.markdown('<div class="top-command-nav"><span class="nav-kicker">GuardianEye Command Layer</span><span class="section-chip"><span class="live-dot"></span> live</span></div>', unsafe_allow_html=True)
    cols = st.columns(len(pages), gap="small")
    for col, (key, label) in zip(cols, pages):
        with col:
            if st.button(label, key=f"nav_{key}", use_container_width=True, type="primary" if key == active_page else "secondary"):
                st.session_state.page = key
                st.rerun()


def render_back_to_overview():
    if st.button("← العودة إلى مركز المراقبة", key=f"back_{st.session_state.get('page','page')}"):
        st.session_state.page = "Overview"
        st.rerun()


def summarize_fleet(systems, incidents, security_events):
    now = utc_now()
    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    recent_events = []
    for e in security_events:
        stamp = _to_dt(e.get("event_time"))
        if stamp and (now - stamp).total_seconds() <= 300:
            recent_events.append(e)
    active_attack_systems = set()
    for inc in open_incidents:
        active_attack_systems.add(str(inc.get("system_id")))
    for e in recent_events:
        if str(e.get("severity") or "").lower() in {"high", "critical"}:
            active_attack_systems.add(str(e.get("system_id")))
    return open_incidents, recent_events, active_attack_systems


def multi_system_correlations(security_events):
    cutoff = utc_now() - dt.timedelta(minutes=5)
    grouped = defaultdict(set)
    for e in security_events:
        stamp = _to_dt(e.get("event_time"))
        if not stamp or stamp < cutoff:
            continue
        source = e.get("source_ip")
        sid = e.get("system_id")
        if source and sid and source not in {"Unknown", "unknown"}:
            grouped[str(source)].add(str(sid))
    return {source: systems for source, systems in grouped.items() if len(systems) > 1}


def run_health_monitoring():
    now = time.time()
    last = st.session_state.get("last_health_run", 0.0)
    if now - last < 30:
        return
    st.session_state.last_health_run = now
    try:
        systems = load_systems()
    except Exception:
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
    last_seen = system.get("agent_last_seen")
    if not last_seen:
        return False
    try:
        stamp = dt.datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        return (utc_now() - stamp).total_seconds() <= AGENT_OFFLINE_SECONDS
    except ValueError:
        return False


def login():
    st.markdown(
        """
        <style>
        /* =====================================================
           GuardianEye v8.1 — Clean Executive Access Gate
           ===================================================== */
        .login-wrap{
            min-height:76vh;
            padding:2rem 0 2.5rem;
            position:relative;
        }
        .login-wrap::before{
            content:"";
            position:absolute;
            inset:-6% -5% auto -5%;
            height:500px;
            background:
              radial-gradient(circle at 18% 30%, rgba(74,168,255,.12), transparent 27%),
              radial-gradient(circle at 84% 18%, rgba(56,230,165,.07), transparent 24%);
            pointer-events:none;
            z-index:0;
        }
        .login-brand{
            display:flex;
            align-items:center;
            gap:.8rem;
            margin-bottom:3.1rem;
        }
        .brand-mark{
            width:44px;height:44px;border-radius:13px;
            display:grid;place-items:center;
            border:1px solid rgba(93,225,255,.28);
            background:linear-gradient(145deg,#0e1d2b,#09111a);
            box-shadow:0 0 34px rgba(74,168,255,.08);
            color:#76dcff;font-size:1rem;font-weight:900;
        }
        .brand-name{
            font-size:1.04rem;font-weight:900;letter-spacing:.15em;
            color:#eef4f8;text-transform:uppercase;
        }
        .brand-meta{
            color:#71869d;font-size:.66rem;letter-spacing:.18em;
            text-transform:uppercase;margin-top:.16rem;
        }
        .login-eyebrow{
            color:#61b0ea;font-size:.67rem;font-weight:900;
            letter-spacing:.22em;text-transform:uppercase;
        }
        .login-title{
            margin:.7rem 0 .6rem;
            font-size:3.65rem;font-weight:900;letter-spacing:-.055em;
            color:#f6f9fc;line-height:1.02;
        }
        .login-rule{
            width:118px;height:2px;margin:1.5rem 0 1.35rem;
            background:linear-gradient(90deg,#4aa8ff,rgba(74,168,255,0));
        }
        .login-copy{
            max-width:620px;color:#91a5b9;font-size:.92rem;line-height:1.9;
        }
        .login-copy strong{color:#e3ebf2;}
        .login-brief{
            display:flex;gap:1rem;align-items:center;margin-top:2rem;
            color:#6d8398;font-size:.67rem;letter-spacing:.06em;text-transform:uppercase;
        }
        .brief-dot{
            width:7px;height:7px;border-radius:50%;background:#38e6a5;
            box-shadow:0 0 13px rgba(56,230,165,.5);flex:0 0 auto;
        }
        .brief-line{height:1px;width:76px;background:rgba(148,163,184,.15);}

        .access-panel{
            margin-top:4.5rem;
            position:relative;
            border:1px solid rgba(148,163,184,.2);
            background:linear-gradient(160deg,rgba(14,22,31,.98),rgba(8,13,19,.99));
            border-radius:22px;
            padding:1.5rem 1.5rem 1.2rem;
            box-shadow:0 30px 90px rgba(0,0,0,.38),0 0 0 1px rgba(74,168,255,.028) inset;
            overflow:hidden;
        }
        .access-panel::before{
            content:"";position:absolute;left:0;right:0;top:0;height:2px;
            background:linear-gradient(90deg,#4aa8ff,rgba(74,168,255,.08),rgba(56,230,165,.5));
        }
        .access-topline{
            display:flex;justify-content:space-between;align-items:center;
            padding-bottom:1rem;margin-bottom:1.05rem;
            border-bottom:1px solid rgba(148,163,184,.1);
        }
        .access-kicker{font-size:.63rem;letter-spacing:.18em;text-transform:uppercase;color:#68819b;font-weight:900;}
        .access-status{display:inline-flex;align-items:center;gap:.4rem;color:#75dfb4;font-size:.61rem;font-weight:800;}
        .access-status-dot{width:7px;height:7px;border-radius:50%;background:#38e6a5;box-shadow:0 0 12px rgba(56,230,165,.5);}
        .access-icon{
            width:46px;height:46px;border-radius:14px;margin-bottom:1rem;
            display:grid;place-items:center;
            border:1px solid rgba(74,168,255,.18);
            background:rgba(74,168,255,.05);color:#68c7ff;font-size:1rem;
        }
        .access-title{font-size:1.8rem;font-weight:900;letter-spacing:-.03em;color:#f3f7fa;margin-bottom:.35rem;}
        .access-copy{color:#8195a9;font-size:.73rem;line-height:1.75;margin-bottom:1.2rem;}
        .access-panel [data-testid="stFormSubmitButton"] button,
        .access-panel .stButton>button{
            min-height:50px;border-radius:13px;font-weight:850;
            border:1px solid rgba(74,168,255,.26);
            background:linear-gradient(180deg,#142334,#101b28);
            color:#eef7ff;
            transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease,background .18s ease;
        }
        .access-panel [data-testid="stFormSubmitButton"] button:hover,
        .access-panel .stButton>button:hover{
            transform:translateY(-1px);
            border-color:rgba(93,225,255,.58);
            box-shadow:0 14px 30px rgba(74,168,255,.11);
            background:linear-gradient(180deg,#182b40,#122132);
        }
        .access-panel input{
            border-radius:12px !important;
            border:1px solid rgba(148,163,184,.14) !important;
            background:#0a1017 !important;
            min-height:48px !important;
        }
        .access-panel input:focus{
            border-color:rgba(74,168,255,.55) !important;
            box-shadow:0 0 0 1px rgba(74,168,255,.17),0 0 24px rgba(74,168,255,.07) !important;
        }
        .access-panel [data-testid="stTextInput"] label{font-size:.68rem;font-weight:800;color:#b8c8d7;}
        .access-panel .stAlert{border-radius:12px;margin-top:.85rem;}
        .trust-row{
            display:grid;grid-template-columns:repeat(3,1fr);gap:.4rem;
            margin-top:1rem;
        }
        .trust-chip{
            padding:.55rem .55rem;border:1px solid rgba(148,163,184,.1);
            background:rgba(255,255,255,.014);border-radius:10px;
            text-align:center;color:#70869c;font-size:.61rem;letter-spacing:.05em;text-transform:uppercase;
        }
        .access-notice{
            margin-top:.85rem;padding-top:.75rem;border-top:1px solid rgba(148,163,184,.1);
            color:#70859a;font-size:.64rem;line-height:1.7;text-align:center;
        }
        @media (max-width: 900px){
            .login-wrap{min-height:auto;}
            .login-title{font-size:2.6rem;}
            .access-panel{margin-top:1.2rem;}
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="login-wrap"></div>', unsafe_allow_html=True)
    left, right = st.columns([1.08, .92], gap="large")

    with left:
        st.markdown(
            '<div class="login-brand">'
            '<div class="brand-mark">◉</div>'
            '<div><div class="brand-name">GuardianEye</div><div class="brand-meta">Security Operations Platform</div></div>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="login-eyebrow">SECURITY OPERATIONS / CONTROL PLANE</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-title">مركز القيادة<br>للمراقبة الأمنية.</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-rule"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="login-copy">'
            'رؤية مركزية للمنظومات المصرح بمراقبتها، تجمع <strong>الصحة التشغيلية</strong> و<strong>البيانات الأمنية</strong> والحوادث في مساحة واحدة قابلة للمتابعة.'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="login-brief"><span class="brief-dot"></span><span>Operator access gateway</span><span class="brief-line"></span><span>Protected environment</span></div>',
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="access-panel">', unsafe_allow_html=True)
        st.markdown(
            '<div class="access-topline">'
            '<span class="access-kicker">Identity Gateway</span>'
            '<span class="access-status"><span class="access-status-dot"></span>Secure channel</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="access-icon">◈</div>', unsafe_allow_html=True)
        st.markdown('<div class="access-title">تسجيل الدخول</div>', unsafe_allow_html=True)
        st.markdown('<div class="access-copy">الوصول إلى مركز المراقبة مخصص للمستخدمين المصرح لهم فقط.</div>', unsafe_allow_html=True)

        with st.form("guardianeye_login_form", clear_on_submit=False):
            username = st.text_input("اسم المستخدم", placeholder="أدخل معرف المشغل", key="login_username")
            password = st.text_input("كلمة المرور", type="password", placeholder="أدخل كلمة المرور", key="login_password")
            submitted = st.form_submit_button("فتح مركز القيادة  →", use_container_width=True)

        if submitted:
            if username == ADMIN_USER and password == ADMIN_PASSWORD:
                st.session_state.logged_in = True
                st.session_state.pop("login_password", None)
                st.rerun()
            else:
                st.error("بيانات الدخول غير صحيحة.")

        st.markdown(
            '<div class="trust-row">'
            '<div class="trust-chip">Identity</div>'
            '<div class="trust-chip">Encrypted</div>'
            '<div class="trust-chip">Authorized</div>'
            '</div>'
            '<div class="access-notice">لا تشارك بيانات الدخول. سجلات المراقبة والبيانات التشغيلية متاحة داخل مركز القيادة للمستخدم المصرح له فقط.</div>',
            unsafe_allow_html=True,
        )
        st.markdown('</div>', unsafe_allow_html=True)


def logout():
    st.session_state.logged_in = False
    st.session_state.pop("login_password", None)
    st.rerun()


def metric_card(label, value, note):
    return f'<div class="metric-card"><div class="metric-label">{safe_text(label)}</div><div class="metric-value">{safe_text(value)}</div><div class="metric-note">{safe_text(note)}</div></div>'


def overview_page():
    run_health_monitoring()
    systems = load_systems()
    incidents = load_incidents(200)
    security_events = load_security_events(500)
    open_incidents, recent_events, active_attack_systems = summarize_fleet(systems, incidents, security_events)

    if "alarm_armed" not in st.session_state:
        st.session_state.alarm_armed = False
    if "alarm_initialized" not in st.session_state:
        st.session_state.alarm_initialized = False
    if "alarm_seen" not in st.session_state:
        st.session_state.alarm_seen = set()

    high_recent = [
        e for e in recent_events
        if str(e.get("severity") or "").lower() in {"high", "critical"}
    ]
    current_high_ids = {str(e.get("id")) for e in high_recent if e.get("id") is not None}
    should_sound = False
    if not st.session_state.alarm_initialized:
        st.session_state.alarm_seen = current_high_ids.copy()
        st.session_state.alarm_initialized = True
    else:
        new_ids = current_high_ids - set(st.session_state.alarm_seen)
        should_sound = bool(new_ids)
        st.session_state.alarm_seen.update(new_ids)

    render_app_nav("Overview")
    st.markdown('<div class="page-kicker">COMMAND CENTER</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-title">مركز المراقبة</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">رؤية موحّدة لكل المنظومات والحساسات والأحداث الأمنية في الوقت الحالي</div>', unsafe_allow_html=True)

    if active_attack_systems:
        st.markdown(
            f'<div class="fleet-alert"><div><div class="fleet-alert-title">⚠ تنبيه أمني نشط على {len(active_attack_systems)} منظومة</div>'
            f'<div class="fleet-alert-sub">GuardianEye رصد أحداثًا أمنية عالية الخطورة أو حوادث مفتوحة وتعرضها لكل منظومة بشكل مستقل.</div></div>'
            f'<span class="system-signal attack"><span class="live-dot alert"></span> ATTACK SIGNAL</span></div>',
            unsafe_allow_html=True,
        )

    armed = st.session_state.alarm_armed
    arm_label = "🔊 تعطيل صوت الإنذار" if armed else "🔊 تسليح صوت الإنذار"
    if st.button(arm_label, key="arm_alarm", type="secondary"):
        st.session_state.alarm_armed = not st.session_state.alarm_armed
        st.rerun()
    st.markdown(
        f'<div class="alarm-state">حالة الإنذار الصوتي: <strong>{"مسلّح" if st.session_state.alarm_armed else "غير مسلّح"}</strong> · الصوت يعمل عند رصد حدث High/Critical جديد، وقد تمنعه سياسات المتصفح قبل تفاعل المستخدم.</div>',
        unsafe_allow_html=True,
    )
    render_alarm_sound(should_sound)

    healthy = sum(1 for s in systems if s.get("status") == "Healthy")
    online_agents = sum(1 for s in systems if agent_is_online(s))
    critical = sum(1 for i in open_incidents if str(i.get("severity") or "").lower() == "critical")
    high = sum(1 for i in open_incidents if str(i.get("severity") or "").lower() == "high")

    cols = st.columns(5)
    metrics = [
        ("المنظومات", len(systems), "مراقبة مركزية"),
        ("Healthy", healthy, "استجابة تشغيلية"),
        ("الحساسات", online_agents, "Online خلال 90 ثانية"),
        ("الحوادث", len(open_incidents), "مفتوحة الآن"),
        ("High / Critical", high + critical, "تحتاج متابعة"),
    ]
    for col, data in zip(cols, metrics):
        with col:
            st.markdown(metric_card(*data), unsafe_allow_html=True)

    st.markdown('<div class="posture-panel"><div class="posture-label">SECURITY POSTURE</div>'
                f'<div class="posture-title">{"يتطلب انتباهًا فوريًا" if active_attack_systems else "الوضع التشغيلي مستقر حاليًا"}</div>'
                f'<div class="posture-copy">تمت مراقبة {len(systems)} منظومة في دورة واحدة. {len(recent_events)} حدثًا ظهر خلال آخر خمس دقائق، بينما توجد {len(open_incidents)} حوادث مفتوحة.</div></div>',
                unsafe_allow_html=True)

    correlations = multi_system_correlations(security_events)
    if correlations:
        st.markdown("### ارتباطات متعددة المنظومات")
        for source, system_ids in sorted(correlations.items(), key=lambda kv: len(kv[1]), reverse=True)[:6]:
            names = [next((s.get("company") for s in systems if str(s.get("id")) == sid), sid[:8]) for sid in system_ids]
            st.markdown(
                f'<div class="correlation-card"><div class="correlation-title">مصدر واحد ظهر عبر {len(system_ids)} منظومات</div>'
                f'<div class="correlation-meta">Source: <strong>{safe_text(source)}</strong> · {safe_text("، ".join(names))}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("### جميع المنظومات — مراقبة متزامنة")
    if not systems:
        st.info("لا توجد منظومات مسجلة بعد.")
    else:
        system_cols = st.columns(2, gap="large")
        for idx, system in enumerate(systems):
            sid = str(system.get("id"))
            online = agent_is_online(system)
            sys_incidents = [i for i in open_incidents if str(i.get("system_id")) == sid]
            sys_events = [e for e in recent_events if str(e.get("system_id")) == sid]
            sys_high = [e for e in sys_events if str(e.get("severity") or "").lower() in {"high", "critical"}]
            attacked = sid in active_attack_systems or bool(sys_incidents) or bool(sys_high)
            status_cls = "attack" if attacked else ("good" if system.get("status") == "Healthy" and online else "warn")
            signal_label = "ATTACK DETECTED" if attacked else ("MONITORING" if online else "AGENT OFFLINE")
            signal_class = "attack" if attacked else ("good" if online else "off")
            latest_event = sorted(sys_events, key=lambda e: str(e.get("event_time") or ""), reverse=True)
            latest_text = "لا توجد أحداث أمنية خلال آخر 5 دقائق."
            if latest_event:
                ev = latest_event[0]
                latest_text = f'{safe_text(ev.get("attack_type") or ev.get("event_type") or "Security Event")} · {safe_text(ev.get("severity") or "Info")} · {safe_text(ev.get("source_ip") or "Unknown")}'
            with system_cols[idx % 2]:
                st.markdown(
                    f'<div class="system-grid-card {status_cls}">'
                    f'<div class="system-grid-head"><div><div class="system-name">{safe_text(system.get("company") or "Unnamed System")}</div>'
                    f'<div class="system-meta">{safe_text(system.get("url") or "No primary URL")} · ID {safe_text(short_id(sid))}</div></div>'
                    f'<div class="system-signal {signal_class}"><span class="live-dot {"alert" if attacked else ""}"></span>{signal_label}</div></div>'
                    f'<div class="system-stat-row">'
                    f'<div class="system-stat"><div class="system-stat-label">Health</div><div class="system-stat-value">{safe_text(system.get("status") or "Not Checked")}</div></div>'
                    f'<div class="system-stat"><div class="system-stat-label">Agent</div><div class="system-stat-value">{"Online" if online else "Offline"}</div></div>'
                    f'<div class="system-stat"><div class="system-stat-label">Open incidents</div><div class="system-stat-value">{len(sys_incidents)}</div></div>'
                    f'</div>'
                    f'<div class="system-event {"attack" if attacked else ""}">{latest_text}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    st.markdown("### Quick Actions")
    qa_cols = st.columns(4)
    quick = [
        ("Systems", "إدارة حالة المنظومات"),
        ("Security", "الأحداث الأمنية الحية"),
        ("Incidents", "الحوادث والأدلة"),
        ("Agent Setup", "حالة الحساسات والربط"),
    ]
    for col, (key, label) in zip(qa_cols, quick):
        with col:
            st.markdown(f'<div class="quick-action"><div class="qa-title">{label}</div><div class="qa-copy">GuardianEye module</div></div>', unsafe_allow_html=True)
            if st.button(f"فتح {label}", key=f"qa_{key}", use_container_width=True):
                st.session_state.page = key
                st.rerun()

    if open_incidents:
        st.markdown("### آخر الحوادث النشطة")
        for inc in sorted(open_incidents, key=lambda i: str(i.get("last_seen") or ""), reverse=True)[:6]:
            st.markdown(
                f'<div class="incident-card incident-{str(inc.get("severity") or "Medium").lower()}">'
                f'<strong>{safe_text(inc.get("title") or inc.get("attack_type") or "Incident")}</strong> '
                f'{severity_badge(inc.get("severity") or "Medium")} · {safe_text(inc.get("source_ip") or "Unknown")}<br>'
                f'<span class="small-muted">آخر ظهور: {safe_text(inc.get("last_seen") or "—")} · أحداث: {safe_text(inc.get("event_count") or 0)}</span></div>',
                unsafe_allow_html=True,
            )


def systems_page():
    render_app_nav("Systems")
    render_back_to_overview()
    run_health_monitoring()
    systems = load_systems()
    st.markdown('<div class="page-title">المنظومات</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">الصحة التشغيلية وحالة الحساس الأمني لكل منظومة</div>', unsafe_allow_html=True)
    if not systems:
        st.info("لا توجد منظومات. استخدم صفحة «إضافة منظومة». )")
        return

    for system in systems:
        system_id = system["id"]
        company = system.get("company", "Unknown")
        status = system.get("status", "Not Checked")
        online = agent_is_online(system)
        with st.container(border=True):
            top_left, top_right = st.columns([3, 1])
            with top_left:
                st.markdown(f"### {safe_text(company)}", unsafe_allow_html=True)
                st.caption(f"ID: {short_id(system_id)}")
            with top_right:
                st.markdown(status_badge(status), unsafe_allow_html=True)
                st.markdown(status_badge("Online" if online else "Offline"), unsafe_allow_html=True)
            a, b, c = st.columns(3)
            with a:
                st.write(f"**الرابط:** {system.get('url') or '—'}")
                st.write(f"**واجهة الفحص:** {system.get('api_url') or '—'}")
            with b:
                st.write(f"**HTTP:** {system.get('http_status') or '—'}")
                st.write(f"**الاستجابة:** {response_ms_text(system.get('response_ms'))}")
            with c:
                st.write(f"**آخر فحص:** {system.get('last_checked') or '—'}")
                st.write(f"**آخر إرسال للحساس:** {system.get('agent_last_seen') or '—'}")
            check_col, delete_col = st.columns(2)
            with check_col:
                if st.button("فحص الآن", key=f"check_{system_id}", use_container_width=True):
                    result = check_system(system)
                    old = system.get("status", "Not Checked")
                    system.update({
                        "status": result["status"], "http_status": result["http_status"],
                        "response_ms": result["response_ms"], "last_message": result["message"],
                        "last_checked": iso_now(),
                    })
                    if old != "Not Checked" and old != result["status"]:
                        try:
                            create_event(system, old, result["status"], result["message"])
                        except Exception:
                            pass
                    update_system(system)
                    st.success("تم الفحص وتحديث النتيجة.")
                    st.rerun()
            with delete_col:
                key = f"confirm_delete_{system_id}"
                if not st.session_state.get(key):
                    if st.button("حذف نهائي", key=f"delete_{system_id}", use_container_width=True):
                        st.session_state[key] = True
                        st.rerun()
                else:
                    st.warning("هذا سيحذف المنظومة والأحداث الأمنية والحوادث وسجلات الحساس نهائيًا.")
                    y, n = st.columns(2)
                    with y:
                        if st.button("تأكيد الحذف", key=f"confirm_yes_{system_id}", use_container_width=True):
                            permanently_delete_system(system_id)
                            st.session_state.pop(key, None)
                            st.success("تم الحذف النهائي.")
                            st.rerun()
                    with n:
                        if st.button("إلغاء", key=f"confirm_no_{system_id}", use_container_width=True):
                            st.session_state.pop(key, None)
                            st.rerun()


def add_system_page():
    render_app_nav("Add System")
    render_back_to_overview()
    st.markdown('<div class="page-title">إضافة منظومة</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">تسجيل منظومة ثم إصدار رمز خاص للحساس الموجود داخلها</div>', unsafe_allow_html=True)

    with st.form("add_system_form", clear_on_submit=True):
        company = st.text_input("اسم الشركة / المؤسسة", placeholder="Example Company")
        url = st.text_input("الرابط الرئيسي", placeholder="https://example.com")
        api_url = st.text_input("واجهة الصحة / الفحص", placeholder="https://example.com/health")
        api_key = st.text_input("مفتاح API الخاص بالمنظومة", type="password")
        submitted = st.form_submit_button("تسجيل المنظومة وإصدار رمز الحساس", use_container_width=True)

    if submitted:
        if not company.strip() or not (url.strip() or api_url.strip()):
            st.error("اسم المنظومة ورابط صالح واحد على الأقل مطلوبان.")
            return
        try:
            system_id, token = create_system(company, url, api_url, api_key)
        except Exception as exc:
            st.error("فشل تسجيل المنظومة.")
            st.code(database_error(exc))
            return
        st.session_state.new_agent_credentials = {
            "system_id": system_id,
            "ingest_token": token,
            "company": company.strip(),
        }
        st.success("تم تسجيل المنظومة بنجاح.")
        st.rerun()

    creds = st.session_state.get("new_agent_credentials")
    if creds:
        st.markdown("### رمز الحساس")
        st.warning("احفظ هذا الرمز الآن. قاعدة البيانات تخزن بصمة الرمز وليس الرمز نفسه، لذلك لن يمكن استرجاعه لاحقًا من الموقع.")
        st.code(json.dumps(creds, ensure_ascii=False, indent=2))
        st.info("استخدم هذه القيم في ملف إعداد الحساس داخل المنظومة.")
        if st.button("إخفاء الرمز", use_container_width=True):
            st.session_state.pop("new_agent_credentials", None)
            st.rerun()


def security_page():
    render_app_nav("Security")
    render_back_to_overview()
    events = load_security_events(800)
    incidents = load_incidents(300)
    systems = {s["id"]: s for s in load_systems()}
    now = utc_now()
    recent = [e for e in events if (_to_dt(e.get("event_time")) and (now - _to_dt(e.get("event_time"))).total_seconds() <= 300)]
    active = [e for e in recent if str(e.get("severity") or "").lower() in {"high", "critical"}]

    st.markdown('<div class="page-title">المراقبة الأمنية</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">عرض متزامن لجميع المنظومات — لا توجد منظومة مستثناة من المراقبة.</div>', unsafe_allow_html=True)

    if active:
        st.markdown(
            f'<div class="fleet-alert"><div><div class="fleet-alert-title">⚠ {len(active)} إشارات أمنية عالية الخطورة خلال آخر 5 دقائق</div>'
            f'<div class="fleet-alert-sub">اللون الأحمر على كل بطاقة يحدد المنظومة المتأثرة مباشرة.</div></div>'
            f'<span class="system-signal attack"><span class="live-dot alert"></span> ACTIVE</span></div>',
            unsafe_allow_html=True,
        )

    a, b, c, d = st.columns(4)
    with a: st.markdown(metric_card("أحداث أمنية", len(events), "السجل المتاح"), unsafe_allow_html=True)
    with b: st.markdown(metric_card("High / Critical", len(active), "آخر 5 دقائق"), unsafe_allow_html=True)
    with c: st.markdown(metric_card("حوادث مفتوحة", sum(i.get("status") == "Open" for i in incidents), "تحتاج متابعة"), unsafe_allow_html=True)
    with d: st.markdown(metric_card("مصادر فريدة", len({e.get("source_ip") for e in events if e.get("source_ip")}), "عناوين ظاهرة"), unsafe_allow_html=True)

    st.markdown("### اختبار إنذار شامل")
    st.caption("ينشئ بيانات تجريبية فقط داخل قاعدة البيانات لإظهار كيفية انعكاس حادث واحد على عدة منظومات، دون تنفيذ هجوم حقيقي.")
    if systems and st.button("إنشاء إنذار تجريبي متعدد المنظومات", use_container_width=True, type="primary"):
        demo_source = "198.51.100.77"
        for system in systems.values():
            event = {
                "id": str(uuid.uuid4()),
                "system_id": system["id"],
                "event_time": iso_now(),
                "event_type": "demo_multi_system_detection",
                "attack_type": "Brute Force",
                "severity": "High",
                "confidence": 0.98,
                "source_ip": demo_source,
                "source_port": 51514,
                "dest_port": 22,
                "protocol": "TCP",
                "evidence": "Demo: coordinated failed authentication attempts observed across multiple monitored systems.",
                "status": "Open",
                "detected_by": "GuardianEye Fleet Demo",
                "raw_data": {"demo": True, "fleet_demo": True},
            }
            get_supabase().table("security_events").insert(event).execute()
            create_or_update_incident_from_event(event)
        st.success("تم إنشاء إنذار تجريبي متعدد المنظومات.")
        st.rerun()

    st.markdown("### الحالة الأمنية لكل منظومة")
    system_list = list(systems.values())
    cols = st.columns(2, gap="large")
    for idx, system in enumerate(system_list):
        sid = system["id"]
        sys_events = [e for e in recent if e.get("system_id") == sid]
        sys_incidents = [i for i in incidents if i.get("system_id") == sid and i.get("status") == "Open"]
        high_events = [e for e in sys_events if str(e.get("severity") or "").lower() in {"high", "critical"}]
        attacked = bool(sys_incidents or high_events)
        latest = sorted(sys_events, key=lambda e: str(e.get("event_time") or ""), reverse=True)
        signal_label = "ATTACK DETECTED" if attacked else "NO ACTIVE HIGH ALERT"
        with cols[idx % 2]:
            st.markdown(
                f'<div class="system-grid-card {"attack" if attacked else ""}">'
                f'<div class="system-grid-head"><div><div class="system-name">{safe_text(system.get("company") or "Unnamed")}</div>'
                f'<div class="system-meta">{safe_text(system.get("url") or "—")}</div></div>'
                f'<div class="system-signal {"attack" if attacked else "good"}"><span class="live-dot {"alert" if attacked else ""}"></span>{signal_label}</div></div>'
                f'<div class="system-stat-row"><div class="system-stat"><div class="system-stat-label">Security Events</div><div class="system-stat-value">{len(sys_events)}</div></div>'
                f'<div class="system-stat"><div class="system-stat-label">High/Critical</div><div class="system-stat-value">{len(high_events)}</div></div>'
                f'<div class="system-stat"><div class="system-stat-label">Incidents</div><div class="system-stat-value">{len(sys_incidents)}</div></div></div>'
                f'<div class="system-event {"attack" if attacked else ""}">{safe_text((latest[0].get("attack_type") or latest[0].get("event_type") or "لا توجد أحداث حديثة") if latest else "لا توجد أحداث حديثة")}</div>'
                f'</div>', unsafe_allow_html=True)

    st.markdown("### آخر الأحداث الأمنية")
    if not events:
        st.info("لا توجد أحداث أمنية بعد.")
        return
    rows = []
    for e in events[:120]:
        rows.append({
            "الوقت": e.get("event_time"),
            "المنظومة": systems.get(e.get("system_id"), {}).get("company", short_id(e.get("system_id"))),
            "نوع الحادث": e.get("attack_type") or e.get("event_type"),
            "الخطورة": e.get("severity"),
            "عنوان المصدر": e.get("source_ip") or "—",
            "الثقة": f"{float(e.get('confidence') or 0)*100:.0f}%",
            "الحالة": e.get("status") or "Open",
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def incidents_page():
    render_app_nav("Incidents")
    render_back_to_overview()
    incidents = load_incidents(300)
    systems = {s["id"]: s for s in load_systems()}
    events = load_security_events(1000)

    st.markdown('<div class="page-title">الحوادث الأمنية</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">كل حادث يجمع نوع الهجوم، المصدر، التوقيت، الأدلة، والأحداث المرتبطة</div>', unsafe_allow_html=True)

    if not incidents:
        st.info("لا توجد حوادث بعد. يمكنك استخدام «إنشاء تنبيه تجريبي» في صفحة المراقبة الأمنية.")
        return

    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    if open_incidents:
        st.markdown('<div class="alert-banner"><strong>تنبيه:</strong> توجد حوادث مفتوحة تحتاج مراجعة.</div>', unsafe_allow_html=True)

    selected_id = st.selectbox(
        "اختر حادثًا",
        [i["id"] for i in incidents],
        format_func=lambda iid: next((f"{i.get('title')} · {i.get('severity')} · {short_id(iid)}" for i in incidents if i["id"] == iid), short_id(iid)),
    )
    incident = next(i for i in incidents if i["id"] == selected_id)
    system = systems.get(incident.get("system_id"), {})
    related = [e for e in events if e.get("system_id") == incident.get("system_id") and e.get("attack_type") == incident.get("attack_type")]
    related = [e for e in related if (not incident.get("source_ip") or e.get("source_ip") == incident.get("source_ip"))][:100]

    sev = incident.get("severity") or "Medium"
    card_class = f"incident-card incident-{sev.lower()}"
    st.markdown(
        f'<div class="{card_class}"><div style="font-size:1.25rem;font-weight:800">{safe_text(incident.get("title"))}</div>'
        f'{severity_badge(sev)} <span class="small-muted"> · {safe_text(incident.get("status"))}</span></div>',
        unsafe_allow_html=True,
    )

    a, b, c, d = st.columns(4)
    with a: st.markdown(metric_card("نوع الحادث", incident.get("attack_type") or "Suspicious Activity", "تصنيف الحساس"), unsafe_allow_html=True)
    with b: st.markdown(metric_card("عنوان المصدر", incident.get("source_ip") or "Unknown", "المصدر المرصود"), unsafe_allow_html=True)
    with c: st.markdown(metric_card("الأحداث", incident.get("event_count", 0), "مرتبطة بهذا الحادث"), unsafe_allow_html=True)
    with d: st.markdown(metric_card("الحالة", incident.get("status", "Open"), "المتابعة الحالية"), unsafe_allow_html=True)

    st.markdown("### تفاصيل الحادث")
    st.write(f"**المنظومة:** {system.get('company', 'Unknown')}")
    st.write(f"**أول ظهور:** {incident.get('first_seen') or '—'}")
    st.write(f"**آخر ظهور:** {incident.get('last_seen') or '—'}")
    st.write(f"**الملخص:** {incident.get('evidence_summary') or '—'}")

    st.markdown("### الأدلة والأحداث المرتبطة")
    if not related:
        st.info("لا توجد أحداث مرتبطة متاحة.")
    else:
        for e in related:
            st.markdown(
                f'<div class="timeline-row"><strong>{safe_text(e.get("event_time"))}</strong> · '
                f'{severity_badge(e.get("severity") or "Medium")} · '
                f'<span class="source-ip">{safe_text(e.get("source_ip") or "Unknown")}</span><br>'
                f'{safe_text(e.get("evidence") or "No evidence text")}</div>',
                unsafe_allow_html=True,
            )

    r1, r2 = st.columns(2)
    with r1:
        if incident.get("status") == "Open":
            if st.button("وضع الحادث كمحلول", use_container_width=True):
                resolve_incident(incident["id"])
                st.success("تم تحديث حالة الحادث.")
                st.rerun()
    with r2:
        report = build_incident_report(incident, system, related)
        st.download_button(
            "تصدير تقرير للمختصين",
            data=report,
            file_name=f"GuardianEye_Incident_{short_id(incident['id'])}.md",
            mime="text/markdown",
            use_container_width=True,
        )


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
    for e in events[:100]:
        lines.append(
            f"- {e.get('event_time')} | {e.get('attack_type') or e.get('event_type')} | "
            f"{e.get('severity')} | source={e.get('source_ip') or 'Unknown'} | "
            f"{e.get('evidence') or ''}"
        )
    lines.extend(["", "Generated by GuardianEye."])
    return "\n".join(lines)


def analytics_page():
    render_app_nav("Analytics")
    render_back_to_overview()
    incidents = load_incidents(500)
    events = load_security_events(1000)
    systems = load_systems()
    st.markdown('<div class="page-title">التحليلات</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">مؤشرات الصحة والأحداث الأمنية واتجاهات الحوادث</div>', unsafe_allow_html=True)
    if systems:
        health_df = pd.DataFrame([{
            "company": s.get("company", "Unknown"),
            "response_ms": s.get("response_ms"),
            "status": s.get("status", "Not Checked"),
        } for s in systems]).dropna(subset=["response_ms"])
        if not health_df.empty:
            fig = px.bar(health_df, x="company", y="response_ms", title="زمن الاستجابة الحالي")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)
    with left:
        if events:
            counts = pd.DataFrame(events)["attack_type"].fillna("Unknown").value_counts().reset_index()
            counts.columns = ["attack_type", "count"]
            fig = px.pie(counts, names="attack_type", values="count", hole=.58, title="أنواع الحوادث")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("لا توجد أحداث أمنية لعرضها.")
    with right:
        if events:
            ips = pd.DataFrame(events)["source_ip"].fillna("Unknown").value_counts().head(10).reset_index()
            ips.columns = ["source_ip", "count"]
            fig = px.bar(ips, x="source_ip", y="count", title="أكثر عناوين المصدر ظهورًا")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("لا توجد عناوين مصدر لعرضها.")

    if incidents:
        sev = Counter(i.get("severity") for i in incidents)
        st.markdown("### ملخص الخطورة")
        st.dataframe(pd.DataFrame([{"الخطورة": k, "العدد": v} for k, v in sev.items()]), use_container_width=True, hide_index=True)


def events_page():
    render_app_nav("Events")
    render_back_to_overview()
    events = load_events(500)
    security = load_security_events(500)
    st.markdown('<div class="page-title">سجل الأحداث</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">التغيّرات التشغيلية والأحداث الأمنية المسجلة</div>', unsafe_allow_html=True)

    st.markdown("### أحداث تشغيلية")
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
    else:
        st.info("لا توجد أحداث تشغيلية.")

    st.markdown("### أحداث أمنية")
    if security:
        rows = [{
            "الوقت": e.get("event_time"),
            "النوع": e.get("attack_type") or e.get("event_type"),
            "الخطورة": e.get("severity"),
            "عنوان المصدر": e.get("source_ip"),
            "البروتوكول": e.get("protocol"),
            "الحالة": e.get("status"),
            "اكتشف بواسطة": e.get("detected_by"),
        } for e in security]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("لا توجد أحداث أمنية.")


def agent_setup_page():
    render_app_nav("Agent Setup")
    render_back_to_overview()
    systems = load_systems()
    st.markdown('<div class="page-title">إعداد الحساس</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">الحساس يعمل داخل منظومة العميل ويرسل الأحداث إلى GuardianEye عبر قناة مصرح بها</div>', unsafe_allow_html=True)
    st.info("الحساس هو الجزء الذي يجمع المعلومات من داخل المنظومة. الموقع وحده لا يرى كل ما يحدث داخل الخادم.")
    st.markdown("### لكل منظومة")
    for s in systems:
        online = agent_is_online(s)
        st.markdown(
            f'<div class="incident-card"><strong>{safe_text(s.get("company"))}</strong> '
            f'{status_badge("Online" if online else "Offline")}<br>'
            f'<span class="small-muted">System ID: {safe_text(s.get("id"))}</span><br>'
            f'آخر إرسال: {safe_text(s.get("agent_last_seen") or "—")}</div>',
            unsafe_allow_html=True,
        )
    st.markdown("### شكل الإعداد")
    st.code(
        '{\n'
        '  "supabase_url": "YOUR_PROJECT_URL",\n'
        '  "supabase_anon_key": "YOUR_PUBLISHABLE_OR_ANON_KEY",\n'
        '  "system_id": "SYSTEM_UUID",\n'
        '  "ingest_token": "ONE_TIME_AGENT_TOKEN",\n'
        '  "log_paths": ["/var/log/auth.log", "/var/log/nginx/access.log"]\n'
        '}',
        language="json",
    )
    st.caption("لا تضع مفتاح service_role داخل الحساس. استخدم مفتاح Supabase العام/النشر مع رمز الحساس الخاص بالمنظومة.")


if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "last_health_run" not in st.session_state:
    st.session_state.last_health_run = 0.0
if "page" not in st.session_state:
    st.session_state.page = "Overview"

if not st.session_state.logged_in:
    login()
    st.stop()

# Sidebar is intentionally not used as the primary navigation.
# The in-app command bar remains available even when the browser is fullscreen.

try:
    page = st.session_state.page
    if page == "Overview":
        overview_page()
    elif page == "Systems":
        systems_page()
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
    elif page == "Agent Setup":
        agent_setup_page()
except Exception as exc:
    st.error("حدث خطأ أثناء تشغيل الصفحة.")
    st.code(database_error(exc))