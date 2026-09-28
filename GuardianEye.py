import datetime as dt
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
APP_VERSION = "5.2"
HEALTHY_THRESHOLD_MS = 1500
AGENT_OFFLINE_SECONDS = 90
INCIDENT_OPEN_WINDOW_MINUTES = 15

st.set_page_config(
    page_title="GuardianEye",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
:root{
  --bg:#070a0f;
  --surface:#0b1119;
  --surface-2:#0f1722;
  --surface-3:#131d2a;
  --line:rgba(148,163,184,.14);
  --line-strong:rgba(148,163,184,.24);
  --text:#f4f7fb;
  --muted:#8e9aaa;
  --good:#46d89a;
  --warn:#f2bd62;
  --bad:#f06a78;
  --blue:#62b5ff;
}
html,body,[class*="css"]{
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
body{background:var(--bg);color:var(--text);}
.block-container{max-width:1520px;padding:1.15rem 2rem 3.5rem;}

/* Streamlit chrome - best effort for the app surface */
#MainMenu{visibility:hidden;}
footer{visibility:hidden;display:none!important;}
[data-testid="stToolbar"]{visibility:hidden;display:none!important;}
[data-testid="stDecoration"]{display:none!important;}
[data-testid="stStatusWidget"]{display:none!important;}

div[data-testid="stSidebar"]{
  background:linear-gradient(180deg,#090e15 0%,#080c12 100%);
  border-right:1px solid var(--line);
}
div[data-testid="stSidebarContent"]{padding:1.15rem .9rem 1.4rem;}
div[data-testid="stSidebarNav"]{display:none;}

/* Sidebar radio navigation */
div[role="radiogroup"]{gap:.28rem!important;}
div[role="radiogroup"] > label{
  background:transparent;
  border:1px solid transparent;
  border-radius:10px;
  padding:.58rem .72rem!important;
  transition:all .18s ease;
}
div[role="radiogroup"] > label:hover{
  background:rgba(98,181,255,.045);
  border-color:var(--line);
}
div[role="radiogroup"] > label:has(input:checked){
  background:linear-gradient(90deg,rgba(98,181,255,.12),rgba(98,181,255,.035));
  border-color:rgba(98,181,255,.22);
}

.brand-wrap{padding:.3rem .2rem 1rem;}
.brand-mark{display:flex;align-items:center;gap:.6rem;}
.brand-dot{
  width:12px;height:12px;border-radius:50%;
  background:var(--good);
  box-shadow:0 0 0 5px rgba(70,216,154,.08),0 0 20px rgba(70,216,154,.20);
}
.brand{font-size:1.42rem;font-weight:850;letter-spacing:-.035em;}
.brand-sub{color:var(--muted);font-size:.73rem;margin-top:.25rem;padding-left:1.15rem;}

.page-kicker{color:#6e7f91;font-size:.7rem;font-weight:800;letter-spacing:.16em;text-transform:uppercase;}
.page-title{font-size:2.05rem;font-weight:850;letter-spacing:-.045em;margin:.18rem 0 .2rem;}
.page-subtitle{color:var(--muted);font-size:.9rem;margin-bottom:1.15rem;}

.command-bar{
  display:flex;align-items:center;justify-content:space-between;gap:1rem;
  background:rgba(10,16,24,.72);border:1px solid var(--line);
  border-radius:15px;padding:.78rem .9rem;margin-bottom:1rem;
  backdrop-filter:blur(10px);
}
.command-left{display:flex;align-items:center;gap:.65rem;min-width:0;}
.command-label{font-size:.73rem;color:var(--muted);text-transform:uppercase;letter-spacing:.09em;}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 0 5px rgba(70,216,154,.08);}
.command-right{font-size:.76rem;color:var(--muted);white-space:nowrap;}

.hero-panel{
  background:radial-gradient(circle at 80% 10%,rgba(98,181,255,.09),transparent 34%),
             linear-gradient(135deg,#0b121b,#0a0f16 62%,#0b1119);
  border:1px solid var(--line-strong);border-radius:18px;padding:1.2rem 1.25rem;
  margin-bottom:1rem;
}
.hero-title{font-size:1.35rem;font-weight:820;letter-spacing:-.025em;}
.hero-text{color:var(--muted);font-size:.86rem;line-height:1.65;max-width:900px;margin-top:.3rem;}
.hero-meta{display:flex;gap:1.1rem;flex-wrap:wrap;margin-top:.9rem;color:#a5b0bf;font-size:.74rem;}
.hero-meta strong{color:#e6edf5;font-weight:750;}

.metric-card{
  position:relative;overflow:hidden;
  background:linear-gradient(180deg,rgba(17,25,35,.96),rgba(11,17,25,.96));
  border:1px solid var(--line);border-radius:15px;padding:1rem 1.05rem;min-height:114px;
}
.metric-card:after{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:rgba(98,181,255,.34);}
.metric-label{color:var(--muted);font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;font-weight:800;}
.metric-value{font-size:2rem;font-weight:860;line-height:1.05;margin-top:.38rem;letter-spacing:-.035em;}
.metric-note{color:#7e8b9b;font-size:.72rem;margin-top:.3rem;}

.section-head{display:flex;align-items:end;justify-content:space-between;gap:1rem;margin:1.25rem 0 .65rem;}
.section-title{font-size:.95rem;font-weight:820;letter-spacing:-.015em;}
.section-note{color:var(--muted);font-size:.72rem;}

.status-pill{display:inline-flex;align-items:center;gap:.35rem;padding:.22rem .56rem;border-radius:999px;border:1px solid var(--line);font-size:.69rem;font-weight:800;}
.good{background:rgba(70,216,154,.075);color:#7be8b1;}
.warn{background:rgba(242,189,98,.075);color:#f7d38f;}
.bad{background:rgba(240,106,120,.075);color:#ff9da7;}
.neutral{background:rgba(148,163,184,.055);color:#c3ccd7;}
.info{background:rgba(98,181,255,.07);color:#a8d5ff;}

.incident-card{background:#0c131c;border:1px solid var(--line);border-radius:14px;padding:1rem 1.05rem;margin-bottom:.7rem;}
.incident-critical{border-color:rgba(240,106,120,.32);}
.incident-high{border-color:rgba(240,106,120,.22);}
.incident-medium{border-color:rgba(242,189,98,.20);}
.source-ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:750;}
.mini{font-size:.72rem;color:var(--muted);letter-spacing:.06em;}
.alert-banner{border:1px solid rgba(240,106,120,.24);background:linear-gradient(180deg,rgba(66,18,27,.40),rgba(34,13,20,.28));padding:.9rem 1rem;border-radius:13px;margin-bottom:1rem;}
.timeline-row{padding:.72rem 0;border-bottom:1px solid var(--line);}

.stButton>button{
  border-radius:10px;font-weight:760;background:#111a25;border:1px solid var(--line-strong);
  min-height:2.55rem;transition:all .18s ease;
}
.stButton>button:hover{border-color:rgba(98,181,255,.42);background:#152130;transform:translateY(-1px);}
.stTextInput input,.stTextArea textarea,.stSelectbox>div>div{border-radius:10px!important;}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:12px;overflow:hidden;}

.login-shell{max-width:1180px;margin:4.5vh auto 0;}
.login-panel{
  background:linear-gradient(145deg,rgba(13,20,29,.98),rgba(8,12,18,.98));
  border:1px solid var(--line-strong);border-radius:22px;padding:1.4rem;
  box-shadow:0 24px 80px rgba(0,0,0,.28);
}
.login-brand{font-size:2.1rem;font-weight:900;letter-spacing:-.055em;}
.login-kicker{font-size:.72rem;color:#6f7f90;letter-spacing:.15em;text-transform:uppercase;font-weight:800;}
.login-copy{color:var(--muted);line-height:1.75;font-size:.86rem;}
.feature-row{padding:.85rem 0;border-bottom:1px solid var(--line);}
.feature-row:last-child{border-bottom:0;}
.feature-no{color:#6283a2;font-size:.7rem;font-weight:850;letter-spacing:.08em;}
.feature-title{font-weight:820;margin:.15rem 0;}
.feature-sub{color:var(--muted);font-size:.74rem;}

@media (max-width:900px){
  .block-container{padding-left:1rem;padding-right:1rem;}
  .login-shell{margin-top:1.5vh;}
  .command-bar{align-items:flex-start;flex-direction:column;}
}
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
    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    left, right = st.columns([1.08, .92], gap="large")

    with left:
        st.markdown(
            '<div class="login-panel">'
            '<div class="login-kicker">SECURITY OPERATIONS PLATFORM</div>'
            '<div class="login-brand">GuardianEye</div>'
            '<div class="login-copy">مركز موحد لمراقبة صحة المنظومات، استقبال بيانات الحساس، اكتشاف السلوك الأمني، وإدارة الحوادث والأدلة.</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="feature-row"><div class="feature-no">01</div><div class="feature-title">Operational visibility</div><div class="feature-sub">مراقبة التوفر وزمن الاستجابة وحالة الحساس.</div></div>'
            '<div class="feature-row"><div class="feature-no">02</div><div class="feature-title">Security telemetry</div><div class="feature-sub">استقبال الأحداث الأمنية من داخل البيئة المصرح بها.</div></div>'
            '<div class="feature-row"><div class="feature-no">03</div><div class="feature-title">Incident workflow</div><div class="feature-sub">تحويل الأحداث إلى حوادث قابلة للمراجعة والتقرير.</div></div>'
            '<div style="margin-top:1rem;color:#66778a;font-size:.68rem;letter-spacing:.08em;">AUTHORIZED OPERATIONS ONLY</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="login-panel">', unsafe_allow_html=True)
        st.markdown('<div class="login-kicker">CONTROL CENTER</div>', unsafe_allow_html=True)
        st.markdown('### تسجيل الدخول', unsafe_allow_html=True)
        username = st.text_input("اسم المستخدم", placeholder="أدخل اسم المستخدم", key="login_username")
        password = st.text_input("كلمة المرور", type="password", placeholder="أدخل كلمة المرور", key="login_password")
        if st.button("دخول إلى مركز المراقبة", use_container_width=True):
            if username == ADMIN_USER and password == ADMIN_PASSWORD:
                st.session_state.logged_in = True
                st.session_state.pop("login_password", None)
                st.rerun()
            else:
                st.error("بيانات الدخول غير صحيحة.")
        st.caption("Authorized access only.")
        st.markdown('</div>', unsafe_allow_html=True)

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
    incidents = load_incidents(50)
    security_events = load_security_events(50)

    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    critical = sum(1 for i in open_incidents if i.get("severity") == "Critical")
    high = sum(1 for i in open_incidents if i.get("severity") == "High")
    online_agents = sum(1 for s in systems if agent_is_online(s))
    healthy = sum(1 for s in systems if s.get("status") == "Healthy")
    slow = sum(1 for s in systems if s.get("status") == "Slow")

    st.markdown('<div class="page-kicker">COMMAND CENTER</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-title">مركز المراقبة</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">الرؤية التشغيلية والأمنية للمنظومات المسجلة في الوقت الحالي</div>', unsafe_allow_html=True)

    st.markdown(
        f'<div class="command-bar"><div class="command-left"><span class="live-dot"></span><span class="command-label">GuardianEye Core</span><span style="color:#d8e0e8;font-size:.78rem;">Live monitoring</span></div><div class="command-right">Agent window · {AGENT_OFFLINE_SECONDS}s · Refresh · 10s</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f'<div class="hero-panel"><div class="hero-title">صورة تشغيلية موحدة</div>'
        f'<div class="hero-text">GuardianEye يجمع صحة الخدمات مع بيانات الحساس والأحداث الأمنية في مساحة واحدة، ثم يعرضها بصيغة مناسبة للمراقبة اليومية والتحقيق.</div>'
        f'<div class="hero-meta"><span>Healthy <strong>{healthy}</strong></span><span>Slow <strong>{slow}</strong></span><span>Agents online <strong>{online_agents}</strong></span><span>Open incidents <strong>{len(open_incidents)}</strong></span><span>High/Critical <strong>{high + critical}</strong></span></div></div>',
        unsafe_allow_html=True,
    )

    cols = st.columns(5)
    metrics = [
        ("المنظومات", len(systems), "مسجلة في قاعدة البيانات"),
        ("Healthy", healthy, "الخدمات المستجيبة"),
        ("الحساسات النشطة", online_agents, f"آخر {AGENT_OFFLINE_SECONDS} ثانية"),
        ("الحوادث المفتوحة", len(open_incidents), "تحتاج متابعة"),
        ("حرجة", critical, "أولوية قصوى"),
    ]
    for col, data in zip(cols, metrics):
        with col:
            st.markdown(metric_card(*data), unsafe_allow_html=True)

    if open_incidents:
        st.markdown('<div class="alert-banner"><strong>Security attention:</strong> توجد حوادث أمنية مفتوحة على منظومات المراقبة.</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-head"><div><div class="section-title">حالة المنظومات</div><div class="section-note">Operational health + agent telemetry</div></div></div>', unsafe_allow_html=True)
    rows = []
    for s in systems:
        rows.append({
            "المنظومة": s.get("company", "—"),
            "الحالة": s.get("status", "Not Checked"),
            "الاستجابة": response_ms_text(s.get("response_ms")),
            "الحساس": "Online" if agent_is_online(s) else "Offline",
            "آخر فحص": s.get("last_checked") or "—",
            "آخر إرسال": s.get("agent_last_seen") or "—",
        })
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("لا توجد منظومات بعد.")

    left, right = st.columns([1.18, .82], gap="large")
    with left:
        st.markdown('<div class="section-head"><div><div class="section-title">آخر الأحداث الأمنية</div><div class="section-note">Most recent detections</div></div></div>', unsafe_allow_html=True)
        if not security_events:
            st.info("لا توجد أحداث أمنية بعد.")
        else:
            for ev in security_events[:7]:
                st.markdown(
                    f'<div class="incident-card"><div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;"><div><strong>{safe_text(ev.get("attack_type") or ev.get("event_type"))}</strong><br><span class="source-ip">{safe_text(ev.get("source_ip") or "Unknown")}</span></div>{severity_badge(ev.get("severity") or "Medium")}</div><div class="small-muted" style="margin-top:.55rem;">{safe_text(ev.get("event_time"))}</div><div style="margin-top:.4rem;color:#b9c3ce;font-size:.78rem;line-height:1.55;">{safe_text(ev.get("evidence") or "")}</div></div>',
                    unsafe_allow_html=True,
                )
    with right:
        st.markdown('<div class="section-head"><div><div class="section-title">ملخص الحوادث</div><div class="section-note">Current incident posture</div></div></div>', unsafe_allow_html=True)
        summary_rows = [
            {"الفئة": "Critical", "العدد": critical},
            {"الفئة": "High", "العدد": high},
            {"الفئة": "Medium / Low", "العدد": sum(1 for i in open_incidents if i.get("severity") not in ("Critical", "High"))},
        ]
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)


def systems_page():
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
    events = load_security_events(500)
    incidents = load_incidents(200)
    systems = {s["id"]: s for s in load_systems()}

    st.markdown('<div class="page-title">المراقبة الأمنية</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">الأحداث القادمة من الحساس وتحليلها إلى حوادث</div>', unsafe_allow_html=True)

    a, b, c, d = st.columns(4)
    with a: st.markdown(metric_card("أحداث أمنية", len(events), "آخر 500 حدث"), unsafe_allow_html=True)
    with b: st.markdown(metric_card("حوادث مفتوحة", sum(i.get("status") == "Open" for i in incidents), "حوادث تحتاج متابعة"), unsafe_allow_html=True)
    with c: st.markdown(metric_card("عناوين مصادر", len({e.get("source_ip") for e in events if e.get("source_ip")}), "مصادر فريدة"), unsafe_allow_html=True)
    with d: st.markdown(metric_card("حساسات", sum(agent_is_online(s) for s in systems.values()), "نشطة حاليًا"), unsafe_allow_html=True)

    st.markdown("### اختبار التنبيه")
    st.caption("هذا الاختبار يولد حادثًا تجريبيًا داخل النظام دون تنفيذ هجوم حقيقي.")
    choices = [(s["id"], s.get("company", "Unknown")) for s in systems.values()]
    if choices:
        selected = st.selectbox("المنظومة", choices, format_func=lambda x: x[1])
        if st.button("إنشاء تنبيه تجريبي", use_container_width=True):
            system = systems[selected[0]]
            insert_demo_security_event(system)
            st.success("تم إنشاء التنبيه التجريبي.")
            st.rerun()

    st.markdown("### آخر الأحداث")
    if not events:
        st.info("لا توجد أحداث أمنية بعد.")
        return
    rows = []
    for e in events:
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

if not st.session_state.logged_in:
    login()
    st.stop()

with st.sidebar:
    st.markdown('<div class="brand">◉ GuardianEye</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-sub">Security Operations Platform</div>', unsafe_allow_html=True)
    st.divider()
    pages = [
        "Overview",
        "Systems",
        "Add System",
        "Security",
        "Incidents",
        "Analytics",
        "Events",
        "Agent Setup",
    ]
    if "page" not in st.session_state:
        st.session_state.page = "Overview"
    st.session_state.page = st.radio("Navigation", pages, index=pages.index(st.session_state.page))
    st.divider()
    st.markdown(f'<div class="small-muted">Signed in as<br><strong>{safe_text(ADMIN_USER)}</strong></div>', unsafe_allow_html=True)
    if st.button("تسجيل الخروج", use_container_width=True):
        logout()

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
