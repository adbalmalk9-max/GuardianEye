import base64
import datetime as dt
import hashlib
import io
import html
import json
import math
import re
import time
import uuid
import wave
from collections import Counter, defaultdict
from textwrap import dedent

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh


APP_NAME = "GuardianEye"
APP_VERSION = "12.0"
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
    st.markdown('<div class="brand">GUARDIANEYE · SECURITY OPERATIONS</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">مركز مراقبة أمني وتشغيلي للأنظمة المصرح بها</div>', unsafe_allow_html=True)
    left, right = st.columns([1.05, .95], gap="large")
    with left:
        st.markdown("### مراقبة من مكان واحد")
        st.write("راقب صحة الخدمات، استقبال المعلومات من الحساس الموجود داخل المنظومة، اكتشاف السلوك الهجومي، وإدارة الحوادث والتقارير.")
        st.markdown("""
        <div class="incident-card">
          <div class="mini">01</div><strong>صحة المنظومة</strong><br><span class="small-muted">التوفر وزمن الاستجابة</span>
        </div>
        <div class="incident-card">
          <div class="mini">02</div><strong>المراقبة الأمنية</strong><br><span class="small-muted">أحداث من داخل المنظومة وعناوين المصادر</span>
        </div>
        <div class="incident-card">
          <div class="mini">03</div><strong>الحوادث والتقارير</strong><br><span class="small-muted">تنبيه، تفاصيل، أدلة، وتقرير للمختصين</span>
        </div>
        """, unsafe_allow_html=True)
    with right:
        st.markdown("### تسجيل الدخول")
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
    online_agents = sum(1 for s in systems if agent_is_online(s))
    healthy = sum(1 for s in systems if s.get("status") == "Healthy")

    st.markdown('<div class="page-title">مركز المراقبة</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">الصحة التشغيلية والأمنية للمنظومات المسجلة</div>', unsafe_allow_html=True)

    cols = st.columns(5)
    metrics = [
        ("المنظومات", len(systems), "مسجلة في قاعدة البيانات"),
        ("Healthy", healthy, "الخدمات المستجيبة"),
        ("الحساسات النشطة", online_agents, "آخر 90 ثانية"),
        ("الحوادث المفتوحة", len(open_incidents), "تحتاج متابعة"),
        ("حرجة", critical, "تحتاج تدخلًا سريعًا"),
    ]
    for col, data in zip(cols, metrics):
        with col:
            st.markdown(metric_card(*data), unsafe_allow_html=True)

    if open_incidents:
        st.markdown('<div class="alert-banner"><strong>تنبيه أمني:</strong> توجد حوادث أمنية مفتوحة على منظومات مراقبة.</div>', unsafe_allow_html=True)

    st.markdown("### حالة المنظومات")
    rows = []
    for s in systems:
        rows.append({
            "المنظومة": s.get("company", "—"),
            "الحالة": s.get("status", "Not Checked"),
            "استجابة": response_ms_text(s.get("response_ms")),
            "الحساس": "Online" if agent_is_online(s) else "Offline",
            "آخر فحص": s.get("last_checked") or "—",
            "آخر إرسال أمني": s.get("agent_last_seen") or "—",
        })
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("لا توجد منظومات بعد.")

    st.markdown("### آخر الحوادث الأمنية")
    if not security_events:
        st.info("لا توجد أحداث أمنية بعد.")
    else:
        for ev in security_events[:8]:
            st.markdown(
                f'<div class="incident-card"><strong>{safe_text(ev.get("attack_type") or ev.get("event_type"))}</strong> '
                f'{severity_badge(ev.get("severity") or "Medium")} '
                f'<span class="small-muted"> · {safe_text(ev.get("event_time"))}</span><br>'
                f'<span class="source-ip">{safe_text(ev.get("source_ip") or "Unknown")}</span>'
                f' → {safe_text(ev.get("system_id"))}<br>{safe_text(ev.get("evidence") or "")}</div>',
                unsafe_allow_html=True,
            )


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


# ============================================================================
# GuardianEye v12 — Fusion SOC Experience Layer
# ============================================================================
# Design principle:
#   The UI is not a mock. Every panel below is backed by one of the existing
#   GuardianEye datasets (systems, events, security_events, incidents,
#   agent_heartbeats) or by deterministic calculations over those datasets.
#   No fictional telemetry is injected into the operational views.
# ============================================================================

V12_PAGE_ORDER = [
    ("Overview", "مركز المراقبة", "Command Center"),
    ("Fleet", "أسطول المنظومات", "Fleet Operations"),
    ("Add System", "إضافة منظومة", "Provisioning"),
    ("Security", "المراقبة الأمنية", "Security Operations"),
    ("Incidents", "الحوادث الأمنية", "Incident Response"),
    ("Threat Hunt", "البحث الأمني", "Threat Hunting"),
    ("Analytics", "التحليلات", "Security Analytics"),
    ("Events", "سجل الأحداث", "Event Stream"),
    ("Agents", "أسطول الحساسات", "Agent Fleet"),
    ("Agent Setup", "إعداد الحساس", "Agent Provisioning"),
    ("Operations", "العمليات", "Service Operations"),
    ("Reports", "التقارير", "Reporting"),
    ("Notifications", "التنبيهات", "Alert Center"),
    ("Settings", "الإعدادات", "Control Plane"),
]
V12_PAGES = [x[0] for x in V12_PAGE_ORDER]
V12_PAGE_LABELS = {x[0]: x[1] for x in V12_PAGE_ORDER}
V12_PAGE_KICKER = {x[0]: x[2] for x in V12_PAGE_ORDER}

V12_ATTACK_LABELS = {
    "Brute Force": "محاولات دخول متكررة",
    "Windows Brute Force": "محاولات دخول Windows",
    "Kerberos Authentication Failure": "فشل مصادقة Kerberos",
    "Security Log Cleared": "تم مسح سجل الأمان",
    "SQL Injection Pattern": "نمط SQL Injection",
    "Path Traversal": "Path Traversal",
    "Command Injection Pattern": "نمط Command Injection",
    "Web Scanner Activity": "نشاط Web Scanner",
    "HTTP Flood / High Rate": "معدل HTTP مرتفع",
    "Port Scan (Observed Connections)": "فحص منافذ مرصود",
}

V12_SEVERITY_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 20, "Info": 5}
V12_STATUS_WEIGHT = {"Down": 100, "Auth Error": 85, "Slow": 55, "Healthy": 0, "Not Checked": 30}

V12_DETECTION_CATALOG = [
    {
        "name": "Authentication Burst",
        "signal": "Repeated failed authentication attempts",
        "severity": "High",
        "source": "Linux auth.log / Windows Security Log",
        "attack_types": ["Brute Force", "Windows Brute Force"],
    },
    {
        "name": "Kerberos Failure",
        "signal": "Kerberos pre-authentication failure",
        "severity": "Medium",
        "source": "Windows Security Event 4771",
        "attack_types": ["Kerberos Authentication Failure"],
    },
    {
        "name": "Audit Log Destruction",
        "signal": "Windows security log cleared",
        "severity": "High",
        "source": "Windows Security Event 1102",
        "attack_types": ["Security Log Cleared"],
    },
    {
        "name": "SQLi Pattern",
        "signal": "SQL injection markers in web request path",
        "severity": "High",
        "source": "Apache / Nginx / IIS access logs",
        "attack_types": ["SQL Injection Pattern"],
    },
    {
        "name": "Path Traversal",
        "signal": "Traversal markers in requested path",
        "severity": "High",
        "source": "Apache / Nginx / IIS access logs",
        "attack_types": ["Path Traversal"],
    },
    {
        "name": "Command Injection",
        "signal": "Shell command markers in request path",
        "severity": "High",
        "source": "Apache / Nginx / IIS access logs",
        "attack_types": ["Command Injection Pattern"],
    },
    {
        "name": "Scanner Fingerprint",
        "signal": "Known scanner User-Agent signature",
        "severity": "Medium",
        "source": "Apache / Nginx / IIS access logs",
        "attack_types": ["Web Scanner Activity"],
    },
    {
        "name": "HTTP Burst",
        "signal": "High request rate within sliding window",
        "severity": "Medium",
        "source": "Apache / Nginx / IIS access logs",
        "attack_types": ["HTTP Flood / High Rate"],
    },
    {
        "name": "Observed Port Sweep",
        "signal": "Many local ports touched by one remote peer",
        "severity": "Medium",
        "source": "Host connection table",
        "attack_types": ["Port Scan (Observed Connections)"],
    },
]

V12_RESPONSE_LIBRARY = {
    "Brute Force": [
        "Validate the affected account(s).",
        "Review source IP reputation and recurrence.",
        "Check whether the event spans multiple monitored systems.",
        "Rotate exposed credentials if compromise is suspected.",
    ],
    "Windows Brute Force": [
        "Review failed logon events around the same timestamp.",
        "Inspect affected account and source address.",
        "Check other systems for the same source.",
        "Preserve evidence before remediation.",
    ],
    "Security Log Cleared": [
        "Treat the event as a high-priority audit signal.",
        "Preserve remaining Windows evidence.",
        "Review administrator activity around the event.",
        "Check for additional persistence or account changes.",
    ],
    "SQL Injection Pattern": [
        "Review the complete request and response context.",
        "Inspect the affected endpoint and query handling.",
        "Confirm parameterized queries and validation are enforced.",
        "Check for repeated sources across other applications.",
    ],
    "Path Traversal": [
        "Review requested paths and decoded variants.",
        "Verify filesystem access controls and web-root boundaries.",
        "Check whether sensitive files were successfully returned.",
        "Preserve the relevant web access records.",
    ],
    "Command Injection Pattern": [
        "Review the request path and execution context.",
        "Check application process activity if available.",
        "Validate input handling and command construction.",
        "Preserve logs and related evidence before cleanup.",
    ],
    "Web Scanner Activity": [
        "Profile the source across systems and endpoints.",
        "Check for follow-up exploit-like activity.",
        "Review high-value URLs touched by the source.",
        "Keep the activity correlated for future detections.",
    ],
    "HTTP Flood / High Rate": [
        "Measure request rate and service impact.",
        "Review source concentration and endpoint concentration.",
        "Check application and reverse-proxy capacity.",
        "Apply rate controls according to the organization policy.",
    ],
    "Port Scan (Observed Connections)": [
        "Identify the remote source and local service exposure.",
        "Check whether the same source touched other systems.",
        "Review exposed services against the expected baseline.",
        "Preserve the connection evidence for correlation.",
    ],
}

# ---------------------------------------------------------------------------
# Additional visual system.  Streamlit's native chrome is deliberately left
# alone except for the parts that are inside the app DOM.  The native sidebar
# collapse/expand button must remain available.
# ---------------------------------------------------------------------------

st.markdown(
    """
<style>
/* ===== v12 shell ======================================================== */
.v12-root{position:relative;}
.v12-topline{
  display:flex;justify-content:space-between;align-items:center;gap:1rem;
  padding:.55rem .8rem;border:1px solid rgba(80,130,175,.16);
  border-radius:12px;background:rgba(6,12,19,.78);margin-bottom:1rem;
}
.v12-topline-left{display:flex;align-items:center;gap:.65rem;}
.v12-dot{width:8px;height:8px;border-radius:50%;background:#3be3a4;box-shadow:0 0 14px rgba(59,227,164,.7);}
.v12-brand{font-size:.72rem;font-weight:900;letter-spacing:.18em;color:#8ba0b8;text-transform:uppercase;}
.v12-live{font-size:.72rem;font-weight:900;color:#69e8b7;letter-spacing:.08em;text-transform:uppercase;}
.v12-topline-right{font-size:.7rem;color:#71849a;}

/* ===== Navigation ====================================================== */
.v12-nav-wrap{position:sticky;top:.4rem;z-index:50;padding:.18rem 0 .4rem;}
.v12-nav-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:.42rem;}
.v12-nav-button{width:100%;}
.v12-nav-button button{
  min-height:43px!important;height:43px!important;padding:.35rem .45rem!important;
  border-radius:11px!important;font-size:.75rem!important;line-height:1.1!important;
  white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;
}
.v12-nav-spacer{height:.4rem;}

/* ===== Headers ========================================================= */
.v12-eyebrow{color:#62baff;font-size:.68rem;font-weight:900;letter-spacing:.24em;text-transform:uppercase;}
.v12-title{font-size:3.2rem;font-weight:950;letter-spacing:-.055em;line-height:.96;margin:.35rem 0 .55rem;}
.v12-subtitle{color:#8798ab;font-size:.94rem;line-height:1.8;max-width:1000px;margin-bottom:1rem;}
.v12-header-row{display:flex;justify-content:space-between;align-items:flex-end;gap:1.5rem;margin-bottom:1rem;}
.v12-header-right{text-align:right;min-width:190px;}

/* ===== Panels ========================================================== */
.v12-panel{
  border:1px solid rgba(124,155,184,.16);border-radius:18px;
  background:linear-gradient(180deg,rgba(12,21,31,.96),rgba(7,12,18,.99));
  padding:1rem 1.1rem;margin-bottom:1rem;box-shadow:0 12px 36px rgba(0,0,0,.12);
}
.v12-panel-accent{position:relative;overflow:hidden;}
.v12-panel-accent:before{content:"";position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,#46b5ff,#35dca1,transparent 78%);opacity:.9;}
.v12-panel-header{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:.9rem;}
.v12-panel-title{font-size:1rem;font-weight:900;}
.v12-panel-note{font-size:.68rem;color:#66798e;letter-spacing:.06em;text-transform:uppercase;}
.v12-panel-help{font-size:.77rem;color:#8193a7;line-height:1.7;}

/* ===== KPIs ============================================================ */
.v12-kpi-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.7rem;margin-bottom:1rem;}
.v12-kpi{min-height:124px;padding:.85rem;border:1px solid rgba(124,155,184,.14);border-radius:15px;background:linear-gradient(180deg,#0d1722,#0a1018);}
.v12-kpi-label{color:#7f91a5;font-size:.7rem;letter-spacing:.11em;text-transform:uppercase;}
.v12-kpi-value{font-size:2.25rem;font-weight:950;line-height:1;margin:.65rem 0 .38rem;}
.v12-kpi-note{color:#617489;font-size:.72rem;line-height:1.45;}
.v12-kpi-bad{border-color:rgba(255,95,115,.35);box-shadow:0 0 0 1px rgba(255,95,115,.06) inset;}
.v12-kpi-good{border-color:rgba(56,224,160,.24);}

/* ===== Security wall =================================================== */
.v12-wall{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.72rem;}
.v12-system-card{
  position:relative;min-height:188px;padding:1rem 1rem .9rem;border-radius:16px;
  border:1px solid rgba(124,155,184,.15);background:linear-gradient(165deg,#101b28,#09111a);
  transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease;
}
.v12-system-card:hover{transform:translateY(-2px);border-color:rgba(70,181,255,.38);box-shadow:0 16px 30px rgba(0,0,0,.18);}
.v12-system-card.attack{border-color:rgba(255,95,115,.72);box-shadow:0 0 25px rgba(255,95,115,.10),inset 0 0 0 1px rgba(255,95,115,.08);}
.v12-system-card.warning{border-color:rgba(243,199,107,.36);}
.v12-system-card.healthy{border-color:rgba(56,224,160,.26);}
.v12-system-dot{width:9px;height:9px;border-radius:50%;background:#72849a;display:inline-block;margin-right:.4rem;}
.v12-system-dot.green{background:#38e0a0;box-shadow:0 0 14px rgba(56,224,160,.7);}
.v12-system-dot.red{background:#ff5f73;box-shadow:0 0 16px rgba(255,95,115,.8);}
.v12-system-dot.yellow{background:#f3c76b;box-shadow:0 0 14px rgba(243,199,107,.65);}
.v12-system-top{display:flex;justify-content:space-between;align-items:center;gap:.6rem;}
.v12-system-name{font-size:1rem;font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.v12-system-status{font-size:.63rem;font-weight:900;letter-spacing:.09em;text-transform:uppercase;white-space:nowrap;}
.v12-attack-banner{margin:.75rem 0;padding:.48rem .6rem;border:1px solid rgba(255,95,115,.34);border-radius:9px;background:rgba(255,95,115,.08);color:#ff9aa7;font-size:.72rem;font-weight:900;letter-spacing:.05em;text-transform:uppercase;}
.v12-system-meta{display:grid;grid-template-columns:1fr 1fr;gap:.45rem;margin-top:.7rem;}
.v12-meta-cell{padding:.5rem .55rem;border:1px solid rgba(124,155,184,.10);border-radius:9px;background:rgba(4,9,14,.42);}
.v12-meta-label{display:block;color:#627488;font-size:.63rem;text-transform:uppercase;letter-spacing:.08em;}
.v12-meta-value{display:block;color:#dce5ed;font-size:.76rem;font-weight:800;margin-top:.15rem;}
.v12-mini-actions{display:flex;gap:.4rem;margin-top:.7rem;}

/* ===== Alarm =========================================================== */
.v12-alarm{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.7rem .85rem;border:1px solid rgba(255,95,115,.3);border-radius:12px;background:rgba(55,13,22,.34);margin-bottom:1rem;}
.v12-alarm-left{display:flex;align-items:center;gap:.6rem;}
.v12-alarm-pulse{width:10px;height:10px;border-radius:50%;background:#ff5f73;box-shadow:0 0 0 rgba(255,95,115,.5);animation:v12pulse 1.5s infinite;}
@keyframes v12pulse{0%{box-shadow:0 0 0 0 rgba(255,95,115,.48)}70%{box-shadow:0 0 0 13px rgba(255,95,115,0)}100%{box-shadow:0 0 0 0 rgba(255,95,115,0)}}
.v12-alarm-title{font-size:.76rem;font-weight:950;color:#ff9eaa;letter-spacing:.08em;text-transform:uppercase;}
.v12-alarm-count{font-size:.72rem;color:#8b9db0;}

/* ===== Feeds / tables ================================================== */
.v12-feed{display:flex;flex-direction:column;gap:.45rem;}
.v12-feed-row{display:grid;grid-template-columns:150px 1fr 160px 110px;align-items:center;gap:.65rem;padding:.62rem .7rem;border-bottom:1px solid rgba(124,155,184,.09);}
.v12-feed-row:last-child{border-bottom:0;}
.v12-feed-time{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#71869c;font-size:.68rem;}
.v12-feed-main{min-width:0;}
.v12-feed-title{font-size:.76rem;font-weight:850;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.v12-feed-sub{color:#617589;font-size:.66rem;margin-top:.12rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.v12-feed-source{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.68rem;color:#9cb0c3;}
.v12-chip{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .48rem;border-radius:999px;border:1px solid rgba(124,155,184,.16);font-size:.62rem;font-weight:900;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;}
.v12-chip.red{color:#ff8e9c;background:rgba(255,95,115,.07);border-color:rgba(255,95,115,.25);}
.v12-chip.green{color:#75edba;background:rgba(56,224,160,.07);border-color:rgba(56,224,160,.22);}
.v12-chip.yellow{color:#f2d18b;background:rgba(243,199,107,.07);border-color:rgba(243,199,107,.22);}
.v12-chip.blue{color:#8fcfff;background:rgba(70,181,255,.07);border-color:rgba(70,181,255,.22);}

/* ===== Detail / workspace ============================================= */
.v12-detail-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;}
.v12-detail-tile{padding:.78rem;border:1px solid rgba(124,155,184,.11);border-radius:12px;background:#0a1119;}
.v12-detail-tile .label{color:#65778b;font-size:.63rem;text-transform:uppercase;letter-spacing:.08em;}
.v12-detail-tile .value{color:#e7edf3;font-size:.86rem;font-weight:850;margin-top:.25rem;word-break:break-word;}
.v12-work-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:.75rem;}
.v12-keyline{height:1px;background:rgba(124,155,184,.10);margin:.7rem 0;}
.v12-timeline{position:relative;padding-left:1.1rem;}
.v12-timeline:before{content:"";position:absolute;left:.22rem;top:.35rem;bottom:.35rem;width:1px;background:rgba(70,181,255,.18);}
.v12-timeline-row{position:relative;padding:.55rem 0 .6rem;}
.v12-timeline-row:before{content:"";position:absolute;left:-.98rem;top:.85rem;width:7px;height:7px;border-radius:50%;background:#4bb6ff;box-shadow:0 0 10px rgba(75,182,255,.5);}
.v12-timeline-time{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#6f8195;font-size:.64rem;}
.v12-timeline-title{font-weight:850;font-size:.76rem;margin-top:.1rem;}
.v12-timeline-text{color:#7c8fa3;font-size:.69rem;line-height:1.6;margin-top:.12rem;}

/* ===== Empty / command ================================================= */
.v12-empty{text-align:center;padding:2.1rem 1rem;border:1px dashed rgba(124,155,184,.18);border-radius:16px;color:#73869b;}
.v12-empty-title{font-weight:900;color:#d6e0e8;margin-bottom:.25rem;}
.v12-command-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;margin-bottom:1rem;}
.v12-command-card{padding:.8rem;border:1px solid rgba(70,181,255,.12);border-radius:14px;background:linear-gradient(180deg,#0d1824,#09111a);}
.v12-command-label{font-size:.64rem;color:#6e8296;letter-spacing:.1em;text-transform:uppercase;}
.v12-command-value{font-size:1.15rem;font-weight:950;margin:.28rem 0;}
.v12-command-note{color:#6b7f93;font-size:.65rem;line-height:1.45;}

/* ===== Responsive ====================================================== */
@media(max-width:1200px){
  .v12-wall{grid-template-columns:repeat(2,minmax(0,1fr));}
  .v12-kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr));}
  .v12-nav-grid{grid-template-columns:repeat(4,minmax(0,1fr));}
  .v12-detail-grid{grid-template-columns:repeat(2,minmax(0,1fr));}
  .v12-work-grid{grid-template-columns:1fr;}
}
@media(max-width:720px){
  .v12-title{font-size:2.25rem;}
  .v12-wall{grid-template-columns:1fr;}
  .v12-kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr));}
  .v12-command-strip{grid-template-columns:1fr 1fr;}
  .v12-nav-grid{grid-template-columns:repeat(2,minmax(0,1fr));}
  .v12-feed-row{grid-template-columns:1fr;gap:.25rem;}
  .v12-detail-grid{grid-template-columns:1fr;}
}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Robust shared helpers
# ---------------------------------------------------------------------------

def v12_safe_db(label, fn, default):
    """Execute a database call without taking the control center offline."""
    try:
        value = fn()
        if value is None:
            return default
        return value
    except Exception as exc:
        st.session_state["v12_last_error"] = f"{label}: {database_error(exc)}"
        return default


def v12_parse_dt(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def v12_age_seconds(value):
    stamp = v12_parse_dt(value)
    if not stamp:
        return None
    now = utc_now()
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (now - stamp).total_seconds())


def v12_age_text(value):
    seconds = v12_age_seconds(value)
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{int(seconds)}s ago"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m ago"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)}h ago"
    return f"{int(hours / 24)}d ago"


def v12_severity_class(severity):
    return {
        "Critical": "red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Info": "blue",
    }.get(str(severity), "blue")


def v12_status_class(status):
    if status in {"Healthy", "Online"}:
        return "green"
    if status in {"Slow", "Auth Error", "Warning"}:
        return "yellow"
    if status in {"Down", "Offline"}:
        return "red"
    return "blue"


def v12_attack(event):
    return str(event.get("attack_type") or event.get("event_type") or "Unknown")


def v12_is_attack(event):
    severity = str(event.get("severity") or "").strip()
    return bool(event.get("attack_type")) or severity in {"Critical", "High", "Medium"}


def v12_event_sort_key(event):
    stamp = v12_parse_dt(event.get("event_time"))
    return stamp or dt.datetime.min.replace(tzinfo=dt.timezone.utc)


def v12_system_map(systems):
    return {str(item.get("id")): item for item in systems if item.get("id")}


def v12_incident_map(incidents):
    return {str(item.get("id")): item for item in incidents if item.get("id")}


def v12_events_by_system(events):
    output = defaultdict(list)
    for event in events:
        key = str(event.get("system_id") or "")
        if key:
            output[key].append(event)
    return output


def v12_latest_by_system(events, field="event_time"):
    output = {}
    for event in events:
        key = str(event.get("system_id") or "")
        if not key:
            continue
        current = output.get(key)
        if current is None or v12_parse_dt(event.get(field)) > v12_parse_dt(current.get(field)):
            output[key] = event
    return output


def v12_risk_for_system(system, incidents, events):
    sid = str(system.get("id") or "")
    score = float(V12_STATUS_WEIGHT.get(system.get("status"), 15))
    relevant_inc = [i for i in incidents if str(i.get("system_id")) == sid and i.get("status") == "Open"]
    relevant_events = [e for e in events if str(e.get("system_id")) == sid and v12_is_attack(e)]
    for incident in relevant_inc[:12]:
        score += V12_SEVERITY_WEIGHT.get(str(incident.get("severity")), 10) * .32
    for event in relevant_events[:30]:
        score += V12_SEVERITY_WEIGHT.get(str(event.get("severity")), 10) * .11
    freshness = v12_age_seconds(system.get("agent_last_seen"))
    if freshness is None:
        score += 12
    elif freshness > AGENT_OFFLINE_SECONDS:
        score += min(25, freshness / AGENT_OFFLINE_SECONDS * 9)
    return min(100, round(score, 1))


def v12_risk_band(score):
    if score >= 80:
        return "CRITICAL", "red"
    if score >= 55:
        return "ELEVATED", "yellow"
    if score >= 25:
        return "WATCH", "blue"
    return "STABLE", "green"


def v12_posture(systems, incidents, events):
    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    attacks = [e for e in events if v12_is_attack(e)]
    critical = sum(1 for e in attacks if e.get("severity") == "Critical")
    high = sum(1 for e in attacks if e.get("severity") == "High")
    healthy = sum(1 for s in systems if s.get("status") == "Healthy")
    agents = sum(1 for s in systems if agent_is_online(s))
    risk_scores = [v12_risk_for_system(s, incidents, events) for s in systems]
    fleet_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
    band, css = v12_risk_band(fleet_risk)
    return {
        "systems": len(systems),
        "healthy": healthy,
        "agents": agents,
        "open_incidents": len(open_incidents),
        "critical": critical,
        "high": high,
        "attacks": len(attacks),
        "fleet_risk": fleet_risk,
        "band": band,
        "css": css,
    }


def v12_security_counts(events):
    counts = Counter()
    for event in events:
        counts[str(event.get("severity") or "Info")] += 1
    return counts


def v12_attack_counts(events):
    counts = Counter()
    for event in events:
        if v12_is_attack(event):
            counts[v12_attack(event)] += 1
    return counts


def v12_source_counts(events):
    counts = Counter()
    for event in events:
        source = str(event.get("source_ip") or "Unknown")
        counts[source] += 1
    return counts


def v12_system_attack_counts(events):
    counts = Counter()
    for event in events:
        sid = str(event.get("system_id") or "")
        if sid and v12_is_attack(event):
            counts[sid] += 1
    return counts


def v12_cross_system_sources(events, min_systems=2):
    sources = defaultdict(set)
    source_events = defaultdict(list)
    for event in events:
        source = str(event.get("source_ip") or "").strip()
        system = str(event.get("system_id") or "").strip()
        if not source or not system:
            continue
        if v12_is_attack(event):
            sources[source].add(system)
            source_events[source].append(event)
    return {
        source: sorted(systems)
        for source, systems in sources.items()
        if len(systems) >= min_systems
    }, source_events


def v12_recent(events, hours=24):
    cutoff = utc_now() - dt.timedelta(hours=hours)
    return [
        e for e in events
        if (v12_parse_dt(e.get("event_time")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= cutoff
    ]


def v12_group_hour(events):
    buckets = Counter()
    for event in events:
        stamp = v12_parse_dt(event.get("event_time"))
        if stamp:
            key = stamp.astimezone(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
            buckets[key] += 1
    return buckets


def v12_render_kpi(label, value, note, css=""):
    return (
        f'<div class="v12-kpi {css}">'
        f'<div class="v12-kpi-label">{safe_text(label)}</div>'
        f'<div class="v12-kpi-value">{safe_text(value)}</div>'
        f'<div class="v12-kpi-note">{safe_text(note)}</div>'
        f'</div>'
    )


def v12_render_chip(text_value, css="blue"):
    return f'<span class="v12-chip {css}">{safe_text(text_value)}</span>'


def v12_render_alarm(posture):
    if posture["attacks"] <= 0 and posture["open_incidents"] <= 0:
        return
    text_value = "ACTIVE SECURITY ATTENTION"
    detail = f'{posture["attacks"]} security signals · {posture["open_incidents"]} open incidents'
    st.markdown(
        f'<div class="v12-alarm"><div class="v12-alarm-left">'
        f'<span class="v12-alarm-pulse"></span>'
        f'<div><div class="v12-alarm-title">{text_value}</div>'
        f'<div class="v12-alarm-count">{safe_text(detail)}</div></div></div>'
        f'<div>{v12_render_chip("REVIEW REQUIRED", "red")}</div></div>',
        unsafe_allow_html=True,
    )


def v12_render_header(kicker, title, subtitle, right_text=None):
    st.markdown('<div class="v12-header-row">', unsafe_allow_html=True)
    st.markdown(
        f'<div><div class="v12-eyebrow">{safe_text(kicker)}</div>'
        f'<div class="v12-title">{safe_text(title)}</div>'
        f'<div class="v12-subtitle">{safe_text(subtitle)}</div></div>',
        unsafe_allow_html=True,
    )
    if right_text:
        st.markdown(f'<div class="v12-header-right">{right_text}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


def v12_panel_start(title, note=None, accent=False):
    klass = "v12-panel v12-panel-accent" if accent else "v12-panel"
    st.markdown(f'<div class="{klass}">', unsafe_allow_html=True)
    note_html = f'<div class="v12-panel-note">{safe_text(note)}</div>' if note else ""
    st.markdown(
        f'<div class="v12-panel-header"><div class="v12-panel-title">{safe_text(title)}</div>{note_html}</div>',
        unsafe_allow_html=True,
    )


def v12_panel_end():
    st.markdown('</div>', unsafe_allow_html=True)


def v12_empty(title, message):
    st.markdown(
        f'<div class="v12-empty"><div class="v12-empty-title">{safe_text(title)}</div>'
        f'<div>{safe_text(message)}</div></div>',
        unsafe_allow_html=True,
    )


def v12_set_page(page):
    if page not in V12_PAGES:
        return
    st.session_state.page = page
    st.session_state.pop("selected_system", None)
    st.session_state.pop("selected_incident", None)
    st.rerun()


def v12_open_system(system_id):
    st.session_state.selected_system = str(system_id)
    st.session_state.page = "Fleet"
    st.rerun()


def v12_open_incident(incident_id):
    st.session_state.selected_incident = str(incident_id)
    st.session_state.page = "Incidents"
    st.rerun()


def v12_render_sidebar():
    current = st.session_state.get("page", "Overview")
    with st.sidebar:
        st.markdown(
            '<div class="brand-row"><div class="brand-mark">◉</div>'
            '<div><div class="brand-name">GUARDIANEYE</div>'
            '<div class="brand-sub">Global Security Operations</div></div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="panel-note">CONTROL CENTER</div>', unsafe_allow_html=True)
        st.caption("استخدم السهم الأصلي << لإخفاء الشريط، وسيظهر >> لإعادته.")
        st.divider()
        groups = [
            ("OPERATE", ["Overview", "Fleet", "Add System"]),
            ("SECURITY", ["Security", "Incidents", "Threat Hunt"]),
            ("OBSERVE", ["Analytics", "Events", "Agents"]),
            ("PLATFORM", ["Agent Setup", "Operations", "Reports", "Notifications", "Settings"]),
        ]
        for group_name, keys in groups:
            st.markdown(f'<div class="panel-note" style="margin:.55rem 0 .35rem">{group_name}</div>', unsafe_allow_html=True)
            for key in keys:
                label = V12_PAGE_LABELS[key]
                prefix_mark = "●" if current == key else "○"
                if st.button(f"{prefix_mark}  {label}", key=f"v12_side_{key}", use_container_width=True):
                    v12_set_page(key)
        st.divider()
        posture = st.session_state.get("v12_posture") or {}
        st.markdown(
            f'<div class="small-muted">Signed in as<br><strong>{safe_text(ADMIN_USER)}</strong></div>'
            f'<div style="margin-top:.7rem">{v12_render_chip(str(posture.get("band", "READY")), posture.get("css", "blue"))}</div>',
            unsafe_allow_html=True,
        )
        if st.button("تسجيل الخروج", use_container_width=True, key="v12_logout"):
            logout()


def v12_render_command_navigation():
    st.markdown('<div class="v12-nav-wrap">', unsafe_allow_html=True)
    st.markdown(
        '<div class="v12-topline"><div class="v12-topline-left">'
        '<span class="v12-dot"></span><span class="v12-brand">GUARDIANEYE COMMAND CENTER</span>'
        '<span class="v12-live">LIVE MONITORING</span></div>'
        f'<div class="v12-topline-right">Refresh {UI_REFRESH_INTERVAL_MS // 1000}s · Global fleet</div></div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(7)
    for index, (key, arabic, _english) in enumerate(V12_PAGE_ORDER[:7]):
        with cols[index]:
            if st.button(arabic, key=f"v12_top_{key}", use_container_width=True):
                v12_set_page(key)
    st.markdown('</div>', unsafe_allow_html=True)


def v12_render_system_card(system, risk, attack_count, agent_online):
    status = str(system.get("status") or "Not Checked")
    if attack_count:
        card_css = "attack"
        dot_css = "red"
        display_status = "ATTACK DETECTED"
    elif status == "Healthy" and agent_online:
        card_css = "healthy"
        dot_css = "green"
        display_status = "NOMINAL"
    elif status in {"Slow", "Not Checked"} or not agent_online:
        card_css = "warning"
        dot_css = "yellow"
        display_status = "WATCH"
    else:
        card_css = "attack"
        dot_css = "red"
        display_status = status.upper()
    band, band_css = v12_risk_band(risk)
    name = safe_text(system.get("company") or "Unnamed system")
    system_id = safe_text(short_id(system.get("id")))
    response = response_ms_text(system.get("response_ms"))
    last = v12_age_text(system.get("agent_last_seen")) if agent_online else "Offline"
    html_block = (
        f'<div class="v12-system-card {card_css}">'
        f'<div class="v12-system-top"><div class="v12-system-name">'
        f'<span class="v12-system-dot {dot_css}"></span>{name}</div>'
        f'<div class="v12-system-status">{safe_text(display_status)}</div></div>'
    )
    if attack_count:
        html_block += f'<div class="v12-attack-banner">{attack_count} security signals on this system</div>'
    html_block += (
        '<div class="v12-system-meta">'
        f'<div class="v12-meta-cell"><span class="v12-meta-label">System</span><span class="v12-meta-value">{system_id}</span></div>'
        f'<div class="v12-meta-cell"><span class="v12-meta-label">Risk</span><span class="v12-meta-value">{risk:.0f} · {band}</span></div>'
        f'<div class="v12-meta-cell"><span class="v12-meta-label">Endpoint</span><span class="v12-meta-value">{safe_text(status)}</span></div>'
        f'<div class="v12-meta-cell"><span class="v12-meta-label">Agent</span><span class="v12-meta-value">{safe_text(last)}</span></div>'
        '</div></div>'
    )
    st.markdown(html_block, unsafe_allow_html=True)
    a, b = st.columns(2)
    with a:
        if st.button("فتح المنظومة", key=f"open_system_{system.get('id')}", use_container_width=True):
            v12_open_system(system.get("id"))
    with b:
        if st.button("فحص", key=f"check_system_{system.get('id')}", use_container_width=True):
            result = check_system(system)
            old = system.get("status")
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
                st.success("تم الفحص")
            except Exception as exc:
                st.error(database_error(exc))
            st.rerun()


def v12_render_global_feed(events, systems, limit=14):
    if not events:
        v12_empty("لا توجد أحداث أمنية", "ستظهر هنا الأحداث التي يرسلها الحساس أو يولدها النظام.")
        return
    systems_by_id = v12_system_map(systems)
    recent = sorted(events, key=v12_event_sort_key, reverse=True)[:limit]
    rows = []
    for event in recent:
        severity = str(event.get("severity") or "Info")
        css = v12_severity_class(severity)
        system = systems_by_id.get(str(event.get("system_id")), {})
        source = str(event.get("source_ip") or "Unknown")
        rows.append(
            f'<div class="v12-feed-row">'
            f'<div class="v12-feed-time">{safe_text(v12_age_text(event.get("event_time")))}</div>'
            f'<div class="v12-feed-main"><div class="v12-feed-title">{safe_text(v12_attack(event))}</div>'
            f'<div class="v12-feed-sub">{safe_text(system.get("company") or short_id(event.get("system_id")))}</div></div>'
            f'<div class="v12-feed-source">{safe_text(source)}</div>'
            f'<div>{v12_render_chip(severity, css)}</div></div>'
        )
    st.markdown('<div class="v12-feed">' + "".join(rows) + '</div>', unsafe_allow_html=True)


def v12_render_source_correlation(events, systems):
    cross, source_events = v12_cross_system_sources(events, 2)
    if not cross:
        v12_empty("لا توجد علاقة متعددة المنظومات", "يظهر هذا القسم عندما يظهر نفس المصدر عبر منظومتين أو أكثر في بيانات الأحداث الأمنية.")
        return
    systems_by_id = v12_system_map(systems)
    for source, system_ids in sorted(cross.items(), key=lambda item: (-len(item[1]), item[0]))[:12]:
        names = [systems_by_id.get(sid, {}).get("company") or short_id(sid) for sid in system_ids]
        total = len(source_events.get(source, []))
        st.markdown(
            f'<div class="v12-feed-row"><div class="v12-feed-source">{safe_text(source)}</div>'
            f'<div class="v12-feed-main"><div class="v12-feed-title">Shared source across {len(names)} systems</div>'
            f'<div class="v12-feed-sub">{safe_text(" · ".join(names))}</div></div>'
            f'<div class="v12-feed-time">{total} signals</div>'
            f'<div>{v12_render_chip("CORRELATED", "red")}</div></div>',
            unsafe_allow_html=True,
        )


def v12_render_risk_board(systems, incidents, events):
    rows = []
    for system in systems:
        score = v12_risk_for_system(system, incidents, events)
        band, css = v12_risk_band(score)
        rows.append({
            "المنظومة": system.get("company") or short_id(system.get("id")),
            "Risk": score,
            "Band": band,
            "Status": system.get("status") or "Not Checked",
            "Agent": "Online" if agent_is_online(system) else "Offline",
        })
    if not rows:
        v12_empty("لا توجد منظومات", "أضف منظومة من صفحة إضافة منظومة.")
        return
    df = pd.DataFrame(rows).sort_values(["Risk", "المنظومة"], ascending=[False, True])
    st.dataframe(df, use_container_width=True, hide_index=True)


def v12_render_posture(posture):
    css = posture["css"]
    band = posture["band"]
    label = "STABLE" if band == "STABLE" else band
    st.markdown(
        f'<div class="v12-panel v12-panel-accent"><div class="v12-panel-header">'
        f'<div class="v12-panel-title">Security Posture</div>'
        f'<div>{v12_render_chip(label, css)}</div></div>'
        f'<div class="v12-panel-help">Fleet risk score: <strong>{posture["fleet_risk"]}</strong> · '
        f'{posture["systems"]} systems · {posture["agents"]} agents online · '
        f'{posture["attacks"]} security signals · {posture["open_incidents"]} open incidents.</div></div>',
        unsafe_allow_html=True,
    )


def v12_sound_alarm_payload():
    """Create a short self-contained WAV tone for a user-armed alert player."""
    import struct
    sample_rate = 8000
    duration = .45
    amplitude = 0.28
    freq = 880
    samples = int(sample_rate * duration)
    pcm = bytearray()
    for i in range(samples):
        sample = amplitude * math.sin(2 * math.pi * freq * i / sample_rate)
        pcm.extend(struct.pack("<h", int(sample * 32767)))
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(pcm)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def v12_alarm_controls(posture):
    if posture["attacks"] <= 0:
        return
    st.markdown("### إنذار العرض")
    if st.button("تسليح صوت الإنذار", key="v12_arm_alarm", use_container_width=False):
        st.session_state.v12_alarm_armed = True
    if st.session_state.get("v12_alarm_armed"):
        payload = v12_sound_alarm_payload()
        st.markdown(
            f'<audio controls autoplay><source src="data:audio/wav;base64,{payload}" type="audio/wav"></audio>',
            unsafe_allow_html=True,
        )
        st.caption("قد يمنع المتصفح التشغيل التلقائي حتى يتفاعل المستخدم مع الصفحة.")

# ---------------------------------------------------------------------------
# Authentication / landing page
# ---------------------------------------------------------------------------

def v12_login():
    left, right = st.columns([1.08, .92], gap="large")
    with left:
        st.markdown('<div class="login-shell">', unsafe_allow_html=True)
        st.markdown('<div class="brand-row"><div class="brand-mark">◉</div><div><div class="brand-name">GUARDIANEYE</div><div class="brand-sub">GLOBAL SECURITY OPERATIONS</div></div></div>', unsafe_allow_html=True)
        st.markdown('<div class="v12-eyebrow">SECURITY OPERATIONS / CONTROL PLANE</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-title">مركز القيادة<br>للمراقبة الأمنية.</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-rule"></div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-copy">رؤية مركزية للمنظومات المصرح بمراقبتها تجمع صحة الخدمات، إشارات الحساس، الأحداث الأمنية، الحوادث، والتحليلات في مساحة تشغيل واحدة.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        v12_panel_start("Operating model", "GuardianEye architecture")
        st.markdown(
            '<div class="v12-detail-grid">'
            '<div class="v12-detail-tile"><div class="label">Architecture</div><div class="value">Agent + Control Plane</div></div>'
            '<div class="v12-detail-tile"><div class="label">Visibility</div><div class="value">Fleet-wide</div></div>'
            '<div class="v12-detail-tile"><div class="label">Response</div><div class="value">Events → Incidents</div></div>'
            '<div class="v12-detail-tile"><div class="label">Access</div><div class="value">Authorized only</div></div>'
            '</div>',
            unsafe_allow_html=True,
        )
        v12_panel_end()
    with right:
        st.markdown('<div style="height:.55rem"></div>', unsafe_allow_html=True)
        v12_panel_start("بوابة الدخول", "Authorized control plane", accent=True)
        st.markdown('<div class="secure-badge"><span class="secure-dot"></span>Secure channel</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-title">تسجيل الدخول</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-note">الوصول إلى مركز المراقبة مخصص للمستخدمين المخولين فقط.</div>', unsafe_allow_html=True)
        with st.form("v12_login_form"):
            username = st.text_input("اسم المستخدم", placeholder="أدخل اسم المستخدم", key="login_username")
            password = st.text_input("كلمة المرور", type="password", placeholder="أدخل كلمة المرور", key="login_password")
            submitted = st.form_submit_button("دخول إلى مركز المراقبة", use_container_width=True)
        if submitted:
            if username == ADMIN_USER and password == ADMIN_PASSWORD:
                st.session_state.logged_in = True
                st.session_state.pop("login_password", None)
                st.session_state.page = "Overview"
                st.rerun()
            else:
                st.error("بيانات الدخول غير صحيحة.")
        st.caption("GuardianEye Control Plane · Session-protected")
        v12_panel_end()

# ---------------------------------------------------------------------------
# Overview — global fleet view
# ---------------------------------------------------------------------------

def v12_overview_page():
    run_health_monitoring()
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    posture = v12_posture(systems, incidents, events)
    st.session_state.v12_posture = posture

    v12_render_header(
        "COMMAND CENTER",
        "مركز المراقبة",
        "رؤية تشغيلية وأمنية موحدة لجميع المنظومات المسجلة في الوقت الحالي.",
        f'{v12_render_chip("LIVE", "green")}<div class="mini">Refresh {UI_REFRESH_INTERVAL_MS // 1000}s</div>',
    )
    v12_render_alarm(posture)
    v12_alarm_controls(posture)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("المنظومات", posture["systems"], "مسجلة في قاعدة البيانات")
        + v12_render_kpi("Healthy", posture["healthy"], "الخدمات المستجيبة", "v12-kpi-good")
        + v12_render_kpi("Agents Online", posture["agents"], "آخر 90 ثانية", "v12-kpi-good")
        + v12_render_kpi("Open Incidents", posture["open_incidents"], "حوادث تحتاج متابعة", "v12-kpi-bad" if posture["open_incidents"] else "")
        + v12_render_kpi("Critical / High", posture["critical"] + posture["high"], "إشارات مرتفعة", "v12-kpi-bad" if posture["critical"] + posture["high"] else "")
        + '</div>',
        unsafe_allow_html=True,
    )
    v12_render_posture(posture)

    v12_panel_start("Fleet Security Wall", "All monitored systems · global view", accent=True)
    if systems:
        events_by_system = v12_system_attack_counts(events)
        cols = st.columns(3)
        for index, system in enumerate(sorted(systems, key=lambda x: x.get("company") or "")):
            with cols[index % 3]:
                risk = v12_risk_for_system(system, incidents, events)
                v12_render_system_card(system, risk, events_by_system.get(str(system.get("id")), 0), agent_is_online(system))
    else:
        v12_empty("لا توجد منظومات بعد", "ابدأ بإضافة منظومة من قسم «إضافة منظومة».")
    v12_panel_end()

    left, right = st.columns([1.25, .75], gap="large")
    with left:
        v12_panel_start("Global Security Feed", "Newest signals")
        v12_render_global_feed(events, systems, 12)
        v12_panel_end()
    with right:
        v12_panel_start("Cross-System Correlation", "Shared sources")
        v12_render_source_correlation(events, systems)
        v12_panel_end()

    left, right = st.columns([1.1, .9], gap="large")
    with left:
        v12_panel_start("Fleet Risk Board", "Deterministic risk model")
        v12_render_risk_board(systems, incidents, events)
        v12_panel_end()
    with right:
        v12_panel_start("Detection Coverage", "Agent rule set")
        rows = []
        catalog_names = set()
        attack_seen = v12_attack_counts(events)
        for rule in V12_DETECTION_CATALOG:
            catalog_names.add(rule["name"])
            seen = sum(attack_seen.get(kind, 0) for kind in rule["attack_types"])
            rows.append({"Rule": rule["name"], "Severity": rule["severity"], "Signals": seen})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        v12_panel_end()

# ---------------------------------------------------------------------------
# Fleet — detail workspace
# ---------------------------------------------------------------------------

def v12_fleet_filters(systems):
    q = st.text_input("بحث", placeholder="اسم المؤسسة أو System ID", key="v12_fleet_q")
    status = st.selectbox("الحالة", ["All", "Healthy", "Slow", "Down", "Auth Error", "Not Checked"], key="v12_fleet_status")
    agent_state = st.selectbox("الحساس", ["All", "Online", "Offline"], key="v12_fleet_agent")
    output = []
    for system in systems:
        name = str(system.get("company") or "")
        sid = str(system.get("id") or "")
        if q.strip() and q.lower().strip() not in f"{name} {sid}".lower():
            continue
        if status != "All" and system.get("status") != status:
            continue
        online = agent_is_online(system)
        if agent_state == "Online" and not online:
            continue
        if agent_state == "Offline" and online:
            continue
        output.append(system)
    return output


def v12_fleet_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    selected = st.session_state.get("selected_system")
    if selected:
        system = v12_system_map(systems).get(str(selected))
        if system:
            v12_render_system_detail_page(system, systems, events, incidents)
            return
        st.session_state.pop("selected_system", None)

    v12_render_header("FLEET OPERATIONS", "أسطول المنظومات", "مراقبة كل المنظومات في واجهة واحدة مع الوصول السريع لتفاصيل كل منظومة.")
    filtered = v12_fleet_filters(systems)
    st.markdown(
        f'<div class="v12-command-strip">'
        f'<div class="v12-command-card"><div class="v12-command-label">Visible Systems</div><div class="v12-command-value">{len(filtered)}</div><div class="v12-command-note">After filters</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Healthy</div><div class="v12-command-value">{sum(s.get("status") == "Healthy" for s in filtered)}</div><div class="v12-command-note">Operational endpoints</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Agent Online</div><div class="v12-command-value">{sum(agent_is_online(s) for s in filtered)}</div><div class="v12-command-note">Last 90 seconds</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Under Attack</div><div class="v12-command-value">{sum(1 for s in filtered if any(str(e.get("system_id")) == str(s.get("id")) and v12_is_attack(e) for e in events))}</div><div class="v12-command-note">Security signals</div></div>'
        f'</div>', unsafe_allow_html=True)

    if not filtered:
        v12_empty("لا توجد نتائج", "غيّر عوامل البحث أو أضف منظومة جديدة.")
        return
    cols = st.columns(3)
    attack_counts = v12_system_attack_counts(events)
    for idx, system in enumerate(filtered):
        with cols[idx % 3]:
            risk = v12_risk_for_system(system, incidents, events)
            v12_render_system_card(system, risk, attack_counts.get(str(system.get("id")), 0), agent_is_online(system))


def v12_render_system_detail_page(system, systems, events, incidents, heartbeats=None):
    if heartbeats is None:
        heartbeats = load_heartbeats(500)
    sid = str(system.get("id"))
    related_events = sorted([e for e in events if str(e.get("system_id")) == sid], key=v12_event_sort_key, reverse=True)
    related_incidents = sorted([i for i in incidents if str(i.get("system_id")) == sid], key=lambda x: v12_parse_dt(x.get("last_seen")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc), reverse=True)
    hb = v12_latest_by_system(heartbeats, "seen_at").get(sid)
    risk = v12_risk_for_system(system, incidents, events)
    band, css = v12_risk_band(risk)
    st.button("← العودة إلى أسطول المنظومات", on_click=lambda: v12_set_page("Fleet"), key="v12_back_fleet")
    v12_render_header(
        "SYSTEM WORKSPACE",
        str(system.get("company") or "Unnamed system"),
        "مساحة تفاصيل تشغيلية وأمنية للمنظومة المحددة.",
        v12_render_chip(band, css),
    )
    if any(v12_is_attack(e) and str(e.get("severity")) in {"Critical", "High"} for e in related_events):
        st.markdown('<div class="v12-alarm"><div class="v12-alarm-left"><span class="v12-alarm-pulse"></span><div><div class="v12-alarm-title">ATTACK DETECTED</div><div class="v12-alarm-count">High/Critical signals detected on this system.</div></div></div></div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="v12-detail-grid">'
        f'<div class="v12-detail-tile"><div class="label">System ID</div><div class="value">{safe_text(system.get("id"))}</div></div>'
        f'<div class="v12-detail-tile"><div class="label">Operational status</div><div class="value">{safe_text(system.get("status") or "Not Checked")}</div></div>'
        f'<div class="v12-detail-tile"><div class="label">Risk</div><div class="value">{risk:.0f} · {safe_text(band)}</div></div>'
        f'<div class="v12-detail-tile"><div class="label">Agent</div><div class="value">{safe_text("Online" if agent_is_online(system) else "Offline")}</div></div>'
        '</div>', unsafe_allow_html=True)

    tabs = st.tabs(["نظرة عامة", "Timeline", "الأحداث", "الحوادث", "الحساس"])
    with tabs[0]:
        left, right = st.columns([1.1, .9], gap="large")
        with left:
            v12_panel_start("Operational telemetry", "Current state")
            st.write(f"**الرابط:** {system.get('url') or '—'}")
            st.write(f"**واجهة الفحص:** {system.get('api_url') or '—'}")
            st.write(f"**HTTP:** {system.get('http_status') or '—'}")
            st.write(f"**الاستجابة:** {response_ms_text(system.get('response_ms'))}")
            st.write(f"**آخر فحص:** {system.get('last_checked') or '—'}")
            st.write(f"**آخر رسالة:** {system.get('last_message') or '—'}")
            v12_panel_end()
        with right:
            v12_panel_start("Security summary", "This system")
            attack_count = sum(1 for e in related_events if v12_is_attack(e))
            open_incidents = sum(1 for i in related_incidents if i.get("status") == "Open")
            st.metric("Security signals", attack_count)
            st.metric("Open incidents", open_incidents)
            st.metric("Risk score", f"{risk:.0f}")
            v12_panel_end()
    with tabs[1]:
        v12_panel_start("Activity timeline", "Merged operational + security view")
        activity = []
        for event in related_events[:80]:
            activity.append({
                "stamp": v12_parse_dt(event.get("event_time")),
                "title": v12_attack(event),
                "text": str(event.get("evidence") or event.get("detected_by") or "Security event"),
                "type": "security",
            })
        for event in load_events(MAX_OPERATIONAL_EVENTS):
            if str(event.get("system_id")) != sid:
                continue
            activity.append({
                "stamp": v12_parse_dt(event.get("time")),
                "title": f"{event.get('old_status')} → {event.get('new_status')}",
                "text": str(event.get("message") or "Operational state change"),
                "type": "operation",
            })
        activity.sort(key=lambda x: x["stamp"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc), reverse=True)
        if not activity:
            v12_empty("لا يوجد نشاط", "لم تصل أحداث مرتبطة بهذه المنظومة بعد.")
        else:
            st.markdown('<div class="v12-timeline">', unsafe_allow_html=True)
            for item in activity[:60]:
                css = "red" if item["type"] == "security" else "blue"
                st.markdown(
                    f'<div class="v12-timeline-row"><div class="v12-timeline-time">{safe_text(item["stamp"].isoformat() if item["stamp"] else "—")}</div>'
                    f'<div class="v12-timeline-title">{safe_text(item["title"])}</div>'
                    f'<div class="v12-timeline-text">{safe_text(item["text"])}</div>'
                    f'<div>{v12_render_chip(item["type"], css)}</div></div>',
                    unsafe_allow_html=True,
                )
            st.markdown('</div>', unsafe_allow_html=True)
        v12_panel_end()
    with tabs[2]:
        v12_panel_start("Security events", "Signals associated with this system")
        v12_render_global_feed(related_events, systems, 80)
        v12_panel_end()
    with tabs[3]:
        v12_panel_start("Incidents", "Cases associated with this system")
        if not related_incidents:
            v12_empty("لا توجد حوادث", "لا توجد حوادث مفتوحة أو مغلقة مرتبطة بهذه المنظومة.")
        else:
            for incident in related_incidents[:50]:
                severity = str(incident.get("severity") or "Medium")
                c = v12_severity_class(severity)
                st.markdown(
                    f'<div class="v12-feed-row"><div class="v12-feed-time">{safe_text(v12_age_text(incident.get("last_seen")))}</div>'
                    f'<div class="v12-feed-main"><div class="v12-feed-title">{safe_text(incident.get("title") or incident.get("attack_type"))}</div>'
                    f'<div class="v12-feed-sub">{safe_text(incident.get("evidence_summary") or "No summary")}</div></div>'
                    f'<div>{v12_render_chip(str(incident.get("status") or "Open"), "green" if incident.get("status") == "Resolved" else "red")}</div>'
                    f'<div>{v12_render_chip(severity, c)}</div></div>', unsafe_allow_html=True)
                if st.button("فتح الحادث", key=f"system_incident_{incident.get('id')}"):
                    v12_open_incident(incident.get("id"))
        v12_panel_end()
    with tabs[4]:
        v12_panel_start("Agent heartbeat", "Latest health sample")
        if hb:
            st.markdown(
                '<div class="v12-detail-grid">'
                f'<div class="v12-detail-tile"><div class="label">Hostname</div><div class="value">{safe_text(hb.get("hostname"))}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">OS</div><div class="value">{safe_text(hb.get("os_name"))}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">Agent Version</div><div class="value">{safe_text(hb.get("agent_version"))}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">Seen</div><div class="value">{safe_text(v12_age_text(hb.get("seen_at")))}</div></div>'
                '</div>', unsafe_allow_html=True)
            st.write(f"CPU: {hb.get('cpu_percent') if hb.get('cpu_percent') is not None else '—'}%")
            st.write(f"Memory: {hb.get('memory_percent') if hb.get('memory_percent') is not None else '—'}%")
            st.write(f"Open connections: {hb.get('open_connections') if hb.get('open_connections') is not None else '—'}")
            st.write(f"Monitored logs: {', '.join(hb.get('monitored_logs') or []) or '—'}")
        else:
            v12_empty("لا توجد heartbeat", "شغّل الحساس داخل البيئة المصرح بها ليبدأ إرسال heartbeat.")
        v12_panel_end()

# ---------------------------------------------------------------------------
# Add System — preserve original workflow, but make the provisioning surface
# cleaner and safer.
# ---------------------------------------------------------------------------

def v12_add_system_page():
    v12_render_header("PROVISIONING", "إضافة منظومة", "تسجيل منظومة جديدة وإصدار هوية مستقلة للحساس.")
    left, right = st.columns([1.05, .95], gap="large")
    with left:
        v12_panel_start("System registration", "Required inputs", accent=True)
        with st.form("v12_add_system_form", clear_on_submit=True):
            company = st.text_input("اسم الشركة / المؤسسة", placeholder="Example Organization")
            url = st.text_input("الرابط الرئيسي", placeholder="https://example.com")
            api_url = st.text_input("واجهة الصحة / الفحص", placeholder="https://example.com/health")
            api_key = st.text_input("مفتاح API الخاص بالمنظومة", type="password")
            submitted = st.form_submit_button("تسجيل المنظومة وإصدار رمز الحساس", use_container_width=True)
        if submitted:
            if not company.strip() or not (url.strip() or api_url.strip()):
                st.error("اسم المنظومة ورابط صالح واحد على الأقل مطلوبان.")
            else:
                try:
                    system_id, token = create_system(company, url, api_url, api_key)
                    st.session_state.new_agent_credentials = {
                        "system_id": system_id,
                        "ingest_token": token,
                        "company": company.strip(),
                    }
                    st.success("تم تسجيل المنظومة بنجاح.")
                except Exception as exc:
                    st.error(database_error(exc))
        v12_panel_end()
    with right:
        v12_panel_start("Provisioning model", "One system · one agent identity")
        st.markdown(
            '<div class="v12-detail-grid">'
            '<div class="v12-detail-tile"><div class="label">1</div><div class="value">Register system</div></div>'
            '<div class="v12-detail-tile"><div class="label">2</div><div class="value">Issue System ID</div></div>'
            '<div class="v12-detail-tile"><div class="label">3</div><div class="value">Issue Ingest Token</div></div>'
            '<div class="v12-detail-tile"><div class="label">4</div><div class="value">Deploy agent</div></div>'
            '</div>', unsafe_allow_html=True)
        st.caption("الـIngest Token يظهر عند الإصدار فقط. قاعدة البيانات تحتفظ ببصمته، وليس بقيمته القابلة للاستخدام.")
        creds = st.session_state.get("new_agent_credentials")
        if creds:
            st.markdown("### بيانات الإصدار الأخيرة")
            st.code(json.dumps(creds, ensure_ascii=False, indent=2), language="json")
            st.warning("احفظ هذه القيم الآن. لا يمكن استرجاع الـIngest Token من قاعدة البيانات بعد اختفائه من جلسة الإصدار.")
            if st.button("إخفاء بيانات الإصدار", use_container_width=True):
                st.session_state.pop("new_agent_credentials", None)
                st.rerun()
        v12_panel_end()

# ---------------------------------------------------------------------------
# Security — global, not system-selective
# ---------------------------------------------------------------------------

def v12_security_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    incidents = load_incidents(MAX_INCIDENTS)
    v12_render_header("SECURITY OPERATIONS", "المراقبة الأمنية", "Global Security Feed: جميع الإشارات الأمنية عبر كل المنظومات، مع الارتباط بالمصدر والحادث.")

    attack_events = [e for e in events if v12_is_attack(e)]
    critical = sum(1 for e in attack_events if e.get("severity") == "Critical")
    high = sum(1 for e in attack_events if e.get("severity") == "High")
    sources = len({e.get("source_ip") for e in attack_events if e.get("source_ip")})
    correlated, _ = v12_cross_system_sources(attack_events, 2)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Signals", len(attack_events), "Detected security signals")
        + v12_render_kpi("Critical", critical, "Highest priority", "v12-kpi-bad" if critical else "")
        + v12_render_kpi("High", high, "High priority", "v12-kpi-bad" if high else "")
        + v12_render_kpi("Sources", sources, "Unique source addresses")
        + v12_render_kpi("Cross-system", len(correlated), "Sources spanning systems", "v12-kpi-bad" if correlated else "")
        + '</div>', unsafe_allow_html=True)

    severities = st.multiselect("الخطورة", ["Critical", "High", "Medium", "Low", "Info"], default=["Critical", "High", "Medium", "Low", "Info"], key="v12_sec_sev")
    types = sorted({v12_attack(e) for e in attack_events})
    selected_types = st.multiselect("نوع الإشارة", types, default=types, key="v12_sec_types")
    q = st.text_input("بحث عالمي", placeholder="Source IP / evidence / attack type / system", key="v12_sec_q")

    systems_by_id = v12_system_map(systems)
    filtered = []
    for event in attack_events:
        if event.get("severity") not in severities:
            continue
        if v12_attack(event) not in selected_types:
            continue
        system_name = str(systems_by_id.get(str(event.get("system_id")), {}).get("company") or "")
        hay = " ".join([
            str(event.get("source_ip") or ""),
            str(event.get("evidence") or ""),
            v12_attack(event),
            system_name,
        ]).lower()
        if q.strip() and q.lower().strip() not in hay:
            continue
        filtered.append(event)
    filtered.sort(key=v12_event_sort_key, reverse=True)

    left, right = st.columns([1.2, .8], gap="large")
    with left:
        v12_panel_start("Live security feed", f"{len(filtered)} matched")
        v12_render_global_feed(filtered, systems, 120)
        v12_panel_end()
    with right:
        v12_panel_start("Cross-system source correlation", "Global source intelligence")
        v12_render_source_correlation(filtered, systems)
        v12_panel_end()

    v12_panel_start("Detection catalogue", "What the Agent currently recognizes")
    catalog_rows = []
    counts = v12_attack_counts(filtered)
    for rule in V12_DETECTION_CATALOG:
        matched = sum(counts.get(kind, 0) for kind in rule["attack_types"])
        catalog_rows.append({
            "Detection": rule["name"],
            "Signal": rule["signal"],
            "Severity": rule["severity"],
            "Source": rule["source"],
            "Matched signals": matched,
        })
    st.dataframe(pd.DataFrame(catalog_rows), use_container_width=True, hide_index=True)
    v12_panel_end()

    v12_panel_start("Safe demonstration", "No real attack is executed")
    st.caption("ينشئ هذا الاختبار حدثًا تجريبيًا في قاعدة البيانات فقط، ويتيح عرض مسار Detection → Incident أمام اللجنة.")
    if systems:
        if st.button("إنشاء تنبيه تجريبي على جميع المنظومات", type="primary", use_container_width=True, key="v12_demo_all"):
            success = 0
            failures = 0
            for system in systems:
                try:
                    insert_demo_security_event(system)
                    success += 1
                except Exception:
                    failures += 1
            st.success(f"تم إنشاء {success} إشارات تجريبية." + (f" تعذر إنشاء {failures}." if failures else ""))
            st.rerun()
    else:
        st.info("أضف منظومة أولًا.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Incidents — response workspace
# ---------------------------------------------------------------------------

def v12_incidents_page():
    incidents = load_incidents(MAX_INCIDENTS)
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    selected_id = st.session_state.get("selected_incident")
    if selected_id:
        incident = v12_incident_map(incidents).get(str(selected_id))
        if incident:
            v12_render_incident_workspace(incident, systems, events)
            return
        st.session_state.pop("selected_incident", None)

    v12_render_header("INCIDENT RESPONSE", "الحوادث الأمنية", "مساحة تشغيلية لاستعراض الحوادث، ترتيبها، تتبع الأدلة، واستخراج تقرير.")
    open_incidents = [i for i in incidents if i.get("status") == "Open"]
    critical = [i for i in open_incidents if i.get("severity") == "Critical"]
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Open", len(open_incidents), "Active cases", "v12-kpi-bad" if open_incidents else "")
        + v12_render_kpi("Critical", len(critical), "Immediate review", "v12-kpi-bad" if critical else "")
        + v12_render_kpi("All cases", len(incidents), "Open + resolved")
        + v12_render_kpi("Systems affected", len({str(i.get("system_id")) for i in open_incidents}), "Unique systems")
        + v12_render_kpi("Sources", len({str(i.get("source_ip")) for i in incidents if i.get("source_ip")}), "Unique sources")
        + '</div>', unsafe_allow_html=True)

    left, right = st.columns([1.15, .85], gap="large")
    with left:
        v12_panel_start("Incident queue", "Sorted by severity + recency")
        rows = sorted(incidents, key=lambda x: (V12_SEVERITY_WEIGHT.get(str(x.get("severity")), 0), v12_parse_dt(x.get("last_seen")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)), reverse=True)
        systems_by_id = v12_system_map(systems)
        if not rows:
            v12_empty("لا توجد حوادث", "ستظهر الحوادث عند تجميع أحداث أمنية متكررة ضمن نافذة الارتباط.")
        else:
            for incident in rows[:80]:
                sev = str(incident.get("severity") or "Medium")
                css = v12_severity_class(sev)
                company = systems_by_id.get(str(incident.get("system_id")), {}).get("company") or short_id(incident.get("system_id"))
                status_css = "green" if incident.get("status") == "Resolved" else "red"
                st.markdown(
                    f'<div class="v12-feed-row"><div class="v12-feed-time">{safe_text(v12_age_text(incident.get("last_seen")))}</div>'
                    f'<div class="v12-feed-main"><div class="v12-feed-title">{safe_text(incident.get("title") or incident.get("attack_type"))}</div>'
                    f'<div class="v12-feed-sub">{safe_text(company)} · {safe_text(incident.get("source_ip") or "Unknown")}</div></div>'
                    f'<div>{v12_render_chip(str(incident.get("status") or "Open"), status_css)}</div>'
                    f'<div>{v12_render_chip(sev, css)}</div></div>', unsafe_allow_html=True)
                if st.button("فتح", key=f"open_inc_{incident.get('id')}"):
                    v12_open_incident(incident.get("id"))
        v12_panel_end()
    with right:
        v12_panel_start("Response library", "Contextual playbooks")
        st.caption("الإجراءات التالية إرشادية فقط؛ لا ينفذ GuardianEye إجراءات تخريبية أو تغييرات على الأنظمة من هذه الصفحة.")
        for attack, steps in list(V12_RESPONSE_LIBRARY.items())[:9]:
            with st.expander(V12_ATTACK_LABELS.get(attack, attack), expanded=False):
                for step in steps:
                    st.markdown(f"- {step}")
        v12_panel_end()


def v12_render_incident_workspace(incident, systems, events):
    sid = str(incident.get("system_id"))
    system = v12_system_map(systems).get(sid, {})
    related = [e for e in events if str(e.get("system_id")) == sid and str(e.get("attack_type")) == str(incident.get("attack_type"))]
    if incident.get("source_ip"):
        related = [e for e in related if str(e.get("source_ip")) == str(incident.get("source_ip"))]
    related = sorted(related, key=v12_event_sort_key, reverse=True)
    sev = str(incident.get("severity") or "Medium")
    css = v12_severity_class(sev)
    st.button("← العودة إلى قائمة الحوادث", on_click=lambda: v12_set_page("Incidents"), key="v12_back_inc")
    v12_render_header("INCIDENT WORKSPACE", str(incident.get("title") or incident.get("attack_type") or "Security Incident"), "مساحة تفصيل الحادث وأدلته ومسار الاستجابة.", v12_render_chip(sev, css))

    tabs = st.tabs(["ملخص", "Timeline", "الأدلة", "الاستجابة", "التقرير"])
    with tabs[0]:
        st.markdown(
            '<div class="v12-detail-grid">'
            f'<div class="v12-detail-tile"><div class="label">System</div><div class="value">{safe_text(system.get("company") or short_id(sid))}</div></div>'
            f'<div class="v12-detail-tile"><div class="label">Attack</div><div class="value">{safe_text(incident.get("attack_type"))}</div></div>'
            f'<div class="v12-detail-tile"><div class="label">Source</div><div class="value">{safe_text(incident.get("source_ip") or "Unknown")}</div></div>'
            f'<div class="v12-detail-tile"><div class="label">Status</div><div class="value">{safe_text(incident.get("status") or "Open")}</div></div>'
            '</div>', unsafe_allow_html=True)
        v12_panel_start("Evidence summary", "Case context")
        st.write(incident.get("evidence_summary") or "لا يوجد ملخص أدلة مسجل.")
        v12_panel_end()
        v12_panel_start("Case timestamps", "Timeline anchors")
        st.write(f"First seen: {incident.get('first_seen') or '—'}")
        st.write(f"Last seen: {incident.get('last_seen') or '—'}")
        st.write(f"Event count: {incident.get('event_count', 0)}")
        v12_panel_end()
    with tabs[1]:
        v12_panel_start("Incident timeline", "Related security events")
        if not related:
            v12_empty("لا توجد أحداث مرتبطة", "الحادث موجود لكن لا توجد أحداث متاحة حاليًا ضمن الفلاتر.")
        else:
            st.markdown('<div class="v12-timeline">', unsafe_allow_html=True)
            for event in related[:120]:
                st.markdown(
                    f'<div class="v12-timeline-row"><div class="v12-timeline-time">{safe_text(event.get("event_time"))}</div>'
                    f'<div class="v12-timeline-title">{safe_text(v12_attack(event))} · {safe_text(event.get("severity") or "Medium")}</div>'
                    f'<div class="v12-timeline-text">{safe_text(event.get("evidence") or "No evidence text")}</div></div>',
                    unsafe_allow_html=True,
                )
            st.markdown('</div>', unsafe_allow_html=True)
        v12_panel_end()
    with tabs[2]:
        v12_panel_start("Evidence matrix", "Fields captured with each signal")
        rows = []
        for event in related[:150]:
            rows.append({
                "Time": event.get("event_time"),
                "Source IP": event.get("source_ip") or "Unknown",
                "Source Port": event.get("source_port") or "—",
                "Destination Port": event.get("dest_port") or "—",
                "Protocol": event.get("protocol") or "—",
                "Severity": event.get("severity") or "—",
                "Confidence": event.get("confidence") or "—",
                "Detected By": event.get("detected_by") or "—",
            })
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            v12_empty("لا توجد أدلة", "لا تتوفر أحداث مرتبطة بهذا الحادث.")
        v12_panel_end()
    with tabs[3]:
        v12_panel_start("Response actions", "Operator guidance")
        attack = str(incident.get("attack_type") or "")
        for step in V12_RESPONSE_LIBRARY.get(attack, ["Review evidence", "Validate source", "Preserve logs", "Resolve after confirmation"]):
            st.markdown(f"#### {step}")
        if incident.get("status") == "Open":
            if st.button("وضع الحادث كمحلول", type="primary", use_container_width=True):
                try:
                    resolve_incident(incident["id"])
                    st.success("تم تحديث حالة الحادث.")
                    st.rerun()
                except Exception as exc:
                    st.error(database_error(exc))
        else:
            st.info("الحادث محلول.")
        v12_panel_end()
    with tabs[4]:
        v12_panel_start("Incident report", "Exportable artifact")
        report = build_incident_report(incident, system, related)
        st.code(report, language="markdown")
        st.download_button(
            "تصدير تقرير الحادث",
            data=report,
            file_name=f"GuardianEye_Incident_{short_id(incident['id'])}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        v12_panel_end()

# ---------------------------------------------------------------------------
# Threat Hunt — deterministic query surface over retained security events
# ---------------------------------------------------------------------------

def v12_threat_hunt_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("THREAT HUNTING", "البحث الأمني", "استعلام عالمي فوق الأحداث المحتفظ بها دون الحاجة لاختيار منظومة واحدة.")
    st.info("هذه الصفحة تبحث في البيانات التي وصل بها الحساس؛ ليست محرك بحث للشبكة وليست أداة هجومية.")
    c1, c2, c3 = st.columns(3)
    with c1:
        query = st.text_input("Search", placeholder="IP, evidence, detector, attack type", key="v12_hunt_query")
    with c2:
        system_choices = [("ALL", "كل المنظومات")] + [(str(s.get("id")), s.get("company") or short_id(s.get("id"))) for s in systems]
        selected_system = st.selectbox("System", system_choices, format_func=lambda x: x[1], key="v12_hunt_system")
    with c3:
        min_severity = st.selectbox("Minimum severity", ["Any", "Low", "Medium", "High", "Critical"], key="v12_hunt_sev")
    source = st.text_input("Source IP", placeholder="192.0.2.1", key="v12_hunt_source")
    attack = st.selectbox("Attack type", ["All"] + sorted({v12_attack(e) for e in events}), key="v12_hunt_attack")
    last_hours = st.slider("Time window (hours)", 1, 168, 24, key="v12_hunt_hours")

    minimum_weight = {"Any": 0, "Low": 20, "Medium": 40, "High": 70, "Critical": 100}.get(min_severity, 0)
    cutoff = utc_now() - dt.timedelta(hours=last_hours)
    matched = []
    for event in events:
        stamp = v12_parse_dt(event.get("event_time"))
        if not stamp or stamp < cutoff:
            continue
        if selected_system[0] != "ALL" and str(event.get("system_id")) != selected_system[0]:
            continue
        if attack != "All" and v12_attack(event) != attack:
            continue
        if str(event.get("source_ip") or "") and source.strip() and source.strip() != str(event.get("source_ip")):
            continue
        if V12_SEVERITY_WEIGHT.get(str(event.get("severity") or "Info"), 5) < minimum_weight:
            continue
        hay = " ".join([
            v12_attack(event), str(event.get("evidence") or ""), str(event.get("detected_by") or ""), str(event.get("raw_data") or ""),
        ]).lower()
        if query.strip() and query.lower().strip() not in hay:
            continue
        matched.append(event)
    matched.sort(key=v12_event_sort_key, reverse=True)

    st.markdown(
        '<div class="v12-command-strip">'
        f'<div class="v12-command-card"><div class="v12-command-label">Matches</div><div class="v12-command-value">{len(matched)}</div><div class="v12-command-note">Within selected window</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Unique Sources</div><div class="v12-command-value">{len({e.get("source_ip") for e in matched if e.get("source_ip")})}</div><div class="v12-command-note">Observed in results</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Systems</div><div class="v12-command-value">{len({e.get("system_id") for e in matched})}</div><div class="v12-command-note">Touched by results</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Critical / High</div><div class="v12-command-value">{sum(1 for e in matched if e.get("severity") in {"Critical", "High"})}</div><div class="v12-command-note">Priority results</div></div>'
        '</div>', unsafe_allow_html=True)

    v12_panel_start("Hunt results", f"{len(matched)} records")
    systems_by_id = v12_system_map(systems)
    if matched:
        rows = []
        for event in matched[:500]:
            rows.append({
                "Time": event.get("event_time"),
                "System": systems_by_id.get(str(event.get("system_id")), {}).get("company") or short_id(event.get("system_id")),
                "Attack": v12_attack(event),
                "Severity": event.get("severity") or "Info",
                "Source": event.get("source_ip") or "Unknown",
                "Protocol": event.get("protocol") or "—",
                "Detected by": event.get("detected_by") or "—",
                "Evidence": str(event.get("evidence") or "")[:240],
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("تصدير نتائج البحث CSV", data=df.to_csv(index=False).encode("utf-8"), file_name="GuardianEye_Threat_Hunt.csv", mime="text/csv", use_container_width=True)
    else:
        v12_empty("لا توجد نتائج", "غيّر شروط البحث أو نافذة الزمن.")
    v12_panel_end()

    v12_panel_start("Hunter context", "Source recurrence")
    cross, source_events = v12_cross_system_sources(matched, 2)
    if cross:
        v12_render_source_correlation(matched, systems)
    else:
        st.caption("لا يوجد مصدر ظهر عبر منظومتين أو أكثر ضمن النتائج الحالية.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Analytics — visual intelligence from actual retained data
# ---------------------------------------------------------------------------

def v12_analytics_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    incidents = load_incidents(MAX_INCIDENTS)
    heartbeats = load_heartbeats(500)
    v12_render_header("SECURITY ANALYTICS", "التحليلات", "مؤشرات مبنية على الأحداث والحوادث والـheartbeat وسلامة الخدمات.")

    recent = v12_recent(events, 24)
    severities = v12_security_counts(recent)
    attacks = v12_attack_counts(recent)
    posture = v12_posture(systems, incidents, recent)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("24h Signals", len(recent), "Recent security signals")
        + v12_render_kpi("24h High/Critical", sum(severities.get(s, 0) for s in ["Critical", "High"]), "Priority signals", "v12-kpi-bad" if sum(severities.get(s, 0) for s in ["Critical", "High"]) else "")
        + v12_render_kpi("Open Incidents", posture["open_incidents"], "Current cases", "v12-kpi-bad" if posture["open_incidents"] else "")
        + v12_render_kpi("Fleet Risk", posture["fleet_risk"], posture["band"])
        + v12_render_kpi("Heartbeats", len(heartbeats), "Retained heartbeat records")
        + '</div>', unsafe_allow_html=True)

    left, right = st.columns(2, gap="large")
    with left:
        v12_panel_start("24-hour security volume", "Hourly events")
        buckets = v12_group_hour(recent)
        if buckets:
            data = pd.DataFrame([{"hour": key.strftime("%H:%M"), "signals": value} for key, value in sorted(buckets.items())])
            fig = px.bar(data, x="hour", y="signals", title="Security signal volume")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
            st.plotly_chart(fig, use_container_width=True)
        else:
            v12_empty("لا توجد بيانات زمنية", "لا توجد إشارات أمنية خلال آخر 24 ساعة.")
        v12_panel_end()
    with right:
        v12_panel_start("Attack mix", "By detection type")
        if attacks:
            data = pd.DataFrame([{"attack": V12_ATTACK_LABELS.get(k, k), "count": v} for k, v in attacks.most_common(12)])
            fig = px.bar(data, x="count", y="attack", orientation="h", title="Detected attack patterns")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
            st.plotly_chart(fig, use_container_width=True)
        else:
            v12_empty("لا توجد إشارات", "لم تصل إشارات أمنية ضمن النافذة الحالية.")
        v12_panel_end()

    left, right = st.columns(2, gap="large")
    with left:
        v12_panel_start("Response time", "Current endpoint latency")
        rows = [{"system": s.get("company") or short_id(s.get("id")), "response_ms": s.get("response_ms")} for s in systems if s.get("response_ms") is not None]
        if rows:
            data = pd.DataFrame(rows).sort_values("response_ms", ascending=False)
            fig = px.bar(data, x="system", y="response_ms", title="Response time")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
            st.plotly_chart(fig, use_container_width=True)
        else:
            v12_empty("لا توجد قياسات", "نفذ الفحوصات التشغيلية أو انتظر دورة المراقبة.")
        v12_panel_end()
    with right:
        v12_panel_start("Risk distribution", "Fleet")
        risk_rows = []
        for system in systems:
            score = v12_risk_for_system(system, incidents, events)
            band, _ = v12_risk_band(score)
            risk_rows.append({"system": system.get("company") or short_id(system.get("id")), "risk": score, "band": band})
        if risk_rows:
            st.dataframe(pd.DataFrame(risk_rows).sort_values("risk", ascending=False), use_container_width=True, hide_index=True)
        else:
            v12_empty("لا توجد منظومات", "أضف منظومة لبدء الحساب.")
        v12_panel_end()

# ---------------------------------------------------------------------------
# Events — operational + security stream
# ---------------------------------------------------------------------------

def v12_events_page():
    operations = load_events(MAX_OPERATIONAL_EVENTS)
    security = load_security_events(MAX_SECURITY_EVENTS)
    systems = load_systems()
    v12_render_header("EVENT STREAM", "سجل الأحداث", "مجرى موحد للتغيرات التشغيلية والإشارات الأمنية.")
    tabs = st.tabs(["Security", "Operations", "Export"])
    with tabs[0]:
        v12_panel_start("Security event stream", "Latest 500")
        v12_render_global_feed(security, systems, 100)
        v12_panel_end()
    with tabs[1]:
        v12_panel_start("Operational changes", "Status transitions")
        if operations:
            rows = []
            systems_by_id = v12_system_map(systems)
            for event in operations[:500]:
                rows.append({
                    "Time": event.get("time"),
                    "System": systems_by_id.get(str(event.get("system_id")), {}).get("company") or event.get("company") or short_id(event.get("system_id")),
                    "From": event.get("old_status") or "—",
                    "To": event.get("new_status") or "—",
                    "Message": event.get("message") or "—",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            v12_empty("لا توجد أحداث تشغيلية", "ستظهر تغيرات الحالة هنا.")
        v12_panel_end()
    with tabs[2]:
        security_rows = []
        for event in security[:1000]:
            security_rows.append({
                "time": event.get("event_time"),
                "system_id": event.get("system_id"),
                "attack_type": v12_attack(event),
                "severity": event.get("severity"),
                "source_ip": event.get("source_ip"),
                "protocol": event.get("protocol"),
                "evidence": event.get("evidence"),
            })
        df = pd.DataFrame(security_rows)
        if df.empty:
            st.info("لا توجد أحداث أمنية لتصديرها.")
        else:
            st.download_button("تصدير الأمن CSV", data=df.to_csv(index=False).encode("utf-8"), file_name="GuardianEye_Security_Events.csv", mime="text/csv", use_container_width=True)

# ---------------------------------------------------------------------------
# Agents — fleet health
# ---------------------------------------------------------------------------

def v12_agents_page():
    systems = load_systems()
    heartbeats = load_heartbeats(1000)
    v12_render_header("AGENT FLEET", "أسطول الحساسات", "حالة الحساسات، آخر heartbeat، نظام التشغيل، موارد الجهاز، وعدد الاتصالات.")
    latest = v12_latest_by_system(heartbeats, "seen_at")
    online = [s for s in systems if agent_is_online(s)]
    offline = [s for s in systems if not agent_is_online(s)]
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Agents", len(systems), "Registered systems")
        + v12_render_kpi("Online", len(online), "Seen within 90 seconds", "v12-kpi-good")
        + v12_render_kpi("Offline", len(offline), "No recent heartbeat", "v12-kpi-bad" if offline else "")
        + v12_render_kpi("Heartbeats", len(heartbeats), "Retained samples")
        + v12_render_kpi("Versions", len({str(latest.get(str(s.get("id")), {}).get("agent_version") or "Unknown") for s in systems}), "Observed versions")
        + '</div>', unsafe_allow_html=True)

    rows = []
    for system in systems:
        hb = latest.get(str(system.get("id")), {})
        rows.append({
            "System": system.get("company") or short_id(system.get("id")),
            "Agent": "Online" if agent_is_online(system) else "Offline",
            "Hostname": hb.get("hostname") or "—",
            "OS": hb.get("os_name") or "—",
            "Version": hb.get("agent_version") or "—",
            "CPU %": hb.get("cpu_percent") if hb.get("cpu_percent") is not None else "—",
            "Memory %": hb.get("memory_percent") if hb.get("memory_percent") is not None else "—",
            "Connections": hb.get("open_connections") if hb.get("open_connections") is not None else "—",
            "Last heartbeat": v12_age_text(hb.get("seen_at")) if hb else "—",
        })
    v12_panel_start("Agent health matrix", "Fleet-wide")
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        v12_empty("لا توجد حساسات", "أضف منظومة ثم ثبت الحساس داخل البيئة المصرح بها.")
    v12_panel_end()

    v12_panel_start("Agent package", "Current deployment contract")
    st.markdown(
        '<div class="tag-row">'
        '<span class="tag">guardianeye_agent.py</span>'
        '<span class="tag">agent_config.json</span>'
        '<span class="tag">Windows</span>'
        '<span class="tag">Linux</span>'
        '<span class="tag">Heartbeat</span>'
        '<span class="tag">Security Events</span>'
        '</div>', unsafe_allow_html=True)
    st.caption("لكل منظومة هوية مستقلة. لا يتم عرض Ingest Token القديم من قاعدة البيانات لأن النظام يحتفظ ببصمته.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Agent setup — operational instructions and per-system state
# ---------------------------------------------------------------------------

def v12_agent_setup_page():
    systems = load_systems()
    v12_render_header("AGENT PROVISIONING", "إعداد الحساس", "إعداد الحساس لكل منظومة مع عرض حالة آخر اتصال دون كشف الأسرار.")
    if not systems:
        v12_empty("لا توجد منظومات", "أضف منظومة أولًا من صفحة إضافة منظومة.")
        return
    for system in systems:
        online = agent_is_online(system)
        status_css = "green" if online else "red"
        with st.expander(f'{system.get("company") or "Unnamed"} · {"Online" if online else "Offline"}', expanded=False):
            st.markdown(
                '<div class="v12-detail-grid">'
                f'<div class="v12-detail-tile"><div class="label">System ID</div><div class="value">{safe_text(system.get("id"))}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">Agent</div><div class="value">{safe_text("Online" if online else "Offline")}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">Last seen</div><div class="value">{safe_text(v12_age_text(system.get("agent_last_seen")))}</div></div>'
                f'<div class="v12-detail-tile"><div class="label">Status</div><div class="value">{safe_text(system.get("status") or "Not Checked")}</div></div>'
                '</div>', unsafe_allow_html=True)
    v12_panel_start("Client configuration", "Template")
    st.code(
        json.dumps({
            "supabase_url": "YOUR_PROJECT_URL",
            "supabase_anon_key": "YOUR_PUBLISHABLE_OR_ANON_KEY",
            "system_id": "SYSTEM_UUID",
            "ingest_token": "ONE_TIME_AGENT_TOKEN",
            "interval_seconds": 10,
            "log_paths": ["/var/log/auth.log", "/var/log/nginx/access.log"],
        }, ensure_ascii=False, indent=2), language="json")
    st.caption("لا تضع service_role أو أي secret إداري داخل الحساس.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Operations — global endpoint health control
# ---------------------------------------------------------------------------

def v12_operations_page():
    systems = load_systems()
    v12_render_header("SERVICE OPERATIONS", "العمليات", "مراقبة صحة الخدمات وزمن الاستجابة على مستوى الأسطول.")
    if st.button("تشغيل فحص لجميع المنظومات الآن", type="primary", use_container_width=True, key="v12_check_all"):
        successes = 0
        for system in systems:
            try:
                result = check_system(system)
                old = system.get("status")
                system.update({"status": result["status"], "http_status": result["http_status"], "response_ms": result["response_ms"], "last_message": result["message"], "last_checked": iso_now()})
                if old != "Not Checked" and old != result["status"]:
                    create_event(system, old, result["status"], result["message"])
                update_system(system)
                successes += 1
            except Exception:
                pass
        st.success(f"تم فحص {successes} منظومات.")
        st.rerun()

    counts = Counter(s.get("status") or "Not Checked" for s in systems)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Healthy", counts.get("Healthy", 0), "Operational")
        + v12_render_kpi("Slow", counts.get("Slow", 0), "Above latency threshold", "v12-kpi-bad" if counts.get("Slow", 0) else "")
        + v12_render_kpi("Down", counts.get("Down", 0), "Unavailable", "v12-kpi-bad" if counts.get("Down", 0) else "")
        + v12_render_kpi("Auth Error", counts.get("Auth Error", 0), "Endpoint rejected credentials", "v12-kpi-bad" if counts.get("Auth Error", 0) else "")
        + v12_render_kpi("Not Checked", counts.get("Not Checked", 0), "Awaiting first check")
        + '</div>', unsafe_allow_html=True)

    v12_panel_start("Endpoint control matrix", "Current health state")
    rows = []
    for system in systems:
        rows.append({
            "System": system.get("company") or short_id(system.get("id")),
            "Status": system.get("status") or "Not Checked",
            "HTTP": system.get("http_status") or "—",
            "Response": response_ms_text(system.get("response_ms")),
            "Last check": system.get("last_checked") or "—",
            "Message": system.get("last_message") or "—",
        })
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        v12_empty("لا توجد منظومات", "أضف منظومة لبدء التشغيل.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Reports — executive and technical report builders
# ---------------------------------------------------------------------------

def v12_build_executive_report(systems, incidents, events, heartbeats):
    posture = v12_posture(systems, incidents, events)
    lines = [
        "# GuardianEye Executive Security Report",
        "",
        f"Generated: {iso_now()}",
        "",
        "## Fleet posture",
        f"- Systems: {posture['systems']}",
        f"- Healthy: {posture['healthy']}",
        f"- Agents online: {posture['agents']}",
        f"- Open incidents: {posture['open_incidents']}",
        f"- Security signals: {posture['attacks']}",
        f"- Fleet risk: {posture['fleet_risk']} ({posture['band']})",
        "",
        "## Security signals by type",
    ]
    for attack, count in v12_attack_counts(events).most_common(20):
        lines.append(f"- {attack}: {count}")
    lines.extend(["", "## Open incidents"])
    for incident in incidents:
        if incident.get("status") == "Open":
            lines.append(f"- {incident.get('title') or incident.get('attack_type')} · {incident.get('severity')} · source={incident.get('source_ip') or 'Unknown'}")
    lines.extend(["", "## Agent fleet"])
    for system in systems:
        lines.append(f"- {system.get('company') or short_id(system.get('id'))}: {'Online' if agent_is_online(system) else 'Offline'} · last_seen={system.get('agent_last_seen') or '—'}")
    lines.extend(["", "Generated by GuardianEye."])
    return "\n".join(lines)


def v12_reports_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    heartbeats = load_heartbeats(1000)
    v12_render_header("REPORTING", "التقارير", "مخرجات تشغيلية وتقارير أمنية قابلة للتصدير بدون كشف الأسرار.")
    executive = v12_build_executive_report(systems, incidents, events, heartbeats)
    v12_panel_start("Executive report", "Current snapshot", accent=True)
    st.code(executive, language="markdown")
    st.download_button("تحميل التقرير التنفيذي", data=executive, file_name=f"GuardianEye_Executive_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.md", mime="text/markdown", use_container_width=True)
    v12_panel_end()
    v12_panel_start("Security event export", "Raw event fields", )
    rows = [{
        "time": e.get("event_time"),
        "system_id": e.get("system_id"),
        "attack_type": v12_attack(e),
        "severity": e.get("severity"),
        "confidence": e.get("confidence"),
        "source_ip": e.get("source_ip"),
        "source_port": e.get("source_port"),
        "dest_port": e.get("dest_port"),
        "protocol": e.get("protocol"),
        "evidence": e.get("evidence"),
        "detected_by": e.get("detected_by"),
    } for e in events]
    df = pd.DataFrame(rows)
    if not df.empty:
        st.download_button("تحميل أحداث الأمن CSV", data=df.to_csv(index=False).encode("utf-8"), file_name="GuardianEye_Security_Events.csv", mime="text/csv", use_container_width=True)
    else:
        st.info("لا توجد أحداث أمنية.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Notifications — current attention queue
# ---------------------------------------------------------------------------

def v12_notifications_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("ALERT CENTER", "التنبيهات", "قائمة واحدة بكل ما يحتاج انتباه المشغل الآن.")
    alerts = []
    for incident in incidents:
        if incident.get("status") == "Open":
            alerts.append({
                "time": v12_parse_dt(incident.get("last_seen")),
                "type": "Incident",
                "severity": incident.get("severity") or "Medium",
                "title": incident.get("title") or incident.get("attack_type"),
                "detail": incident.get("evidence_summary") or "Open incident",
            })
    for system in systems:
        status = system.get("status")
        if status in {"Down", "Auth Error"}:
            alerts.append({
                "time": v12_parse_dt(system.get("last_checked")),
                "type": "Operations",
                "severity": "High" if status == "Down" else "Medium",
                "title": f"{system.get('company') or 'System'} · {status}",
                "detail": system.get("last_message") or "Operational alert",
            })
    for event in events:
        if event.get("severity") in {"Critical", "High"}:
            alerts.append({
                "time": v12_parse_dt(event.get("event_time")),
                "type": "Security",
                "severity": event.get("severity"),
                "title": v12_attack(event),
                "detail": event.get("evidence") or "High-priority security signal",
            })
    alerts.sort(key=lambda x: (V12_SEVERITY_WEIGHT.get(str(x["severity"]), 0), x["time"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc)), reverse=True)

    if not alerts:
        v12_empty("لا توجد تنبيهات نشطة", "المركز لا يرى حاليًا عناصر تحتاج انتباهًا.")
        return
    for alert in alerts[:100]:
        css = v12_severity_class(alert["severity"])
        st.markdown(
            f'<div class="v12-feed-row"><div class="v12-feed-time">{safe_text(v12_age_text(alert["time"]))}</div>'
            f'<div class="v12-feed-main"><div class="v12-feed-title">{safe_text(alert["title"])}</div><div class="v12-feed-sub">{safe_text(alert["detail"])}</div></div>'
            f'<div>{v12_render_chip(alert["type"], "blue")}</div><div>{v12_render_chip(alert["severity"], css)}</div></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Settings — safe, non-secret view of control plane state
# ---------------------------------------------------------------------------

def v12_settings_page():
    systems = load_systems()
    v12_render_header("CONTROL PLANE", "الإعدادات", "حالة التشغيل والإعدادات التي يعتمد عليها مركز GuardianEye.")
    st.warning("لا يتم عرض مفاتيح Supabase أو كلمات مرور الإدارة أو مفتاح التشفير في هذه الصفحة.")
    rows = [
        {"Component": "Supabase URL", "State": "READY" if SUPABASE_URL else "MISSING", "Value": SUPABASE_URL or "—"},
        {"Component": "Service Role", "State": "READY" if SUPABASE_SERVICE_ROLE_KEY else "MISSING", "Value": "Configured" if SUPABASE_SERVICE_ROLE_KEY else "Missing"},
        {"Component": "Encryption", "State": "READY" if GUARDIAN_ENCRYPTION_KEY else "MISSING", "Value": "Configured" if GUARDIAN_ENCRYPTION_KEY else "Missing"},
        {"Component": "Admin", "State": "READY" if ADMIN_USER and ADMIN_PASSWORD else "MISSING", "Value": "Configured" if ADMIN_USER and ADMIN_PASSWORD else "Missing"},
        {"Component": "Database systems", "State": "READY" if systems else "EMPTY", "Value": str(len(systems))},
        {"Component": "App version", "State": "READY", "Value": APP_VERSION},
    ]
    v12_panel_start("Control plane status", "Safe configuration view")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    v12_panel_end()
    v12_panel_start("Detection capabilities", "Actual Agent detections")
    st.dataframe(pd.DataFrame([
        {"Detection": rule["name"], "Severity": rule["severity"], "Source": rule["source"], "Patterns": ", ".join(rule["attack_types"])}
        for rule in V12_DETECTION_CATALOG
    ]), use_container_width=True, hide_index=True)
    v12_panel_end()

# ---------------------------------------------------------------------------
# Compatibility wrappers / original function reuse
# ---------------------------------------------------------------------------

def overview_page():
    return v12_overview_page()


def systems_page():
    return v12_fleet_page()


def add_system_page():
    return v12_add_system_page()


def security_page():
    return v12_security_page()


def incidents_page():
    return v12_incidents_page()


def analytics_page():
    return v12_analytics_page()


def events_page():
    return v12_events_page()


def agent_setup_page():
    return v12_agent_setup_page()


# ============================================================================
# GuardianEye v13 — Analyst Workbench / Security Intelligence Layer
# ============================================================================
# The modules below are intentionally data-driven.  They do not fabricate
# telemetry and they do not require new Supabase tables.  They operate on the
# existing GuardianEye schema and session state so the application can be
# introduced without a destructive database migration.
# ============================================================================

V13_EXTRA_PAGES = [
    ("Campaigns", "الحملات الأمنية", "Security Correlation"),
    ("Security Matrix", "مصفوفة الأمن", "Coverage Matrix"),
    ("Evidence", "مستكشف الأدلة", "Evidence Explorer"),
    ("Investigation", "مكتب التحقيق", "Analyst Workbench"),
    ("Watchlist", "قائمة المراقبة", "Source Watchlist"),
    ("Detection Lab", "مختبر الكشف", "Detection Lab"),
    ("Data Quality", "جودة البيانات", "Telemetry Quality"),
    ("Snapshot", "لقطة المركز", "Security Snapshot"),
]

# Rebuild the page registry so the sidebar and dispatch both see the extended
# product surface.
V12_PAGE_ORDER = V12_PAGE_ORDER + V13_EXTRA_PAGES
V12_PAGES = [x[0] for x in V12_PAGE_ORDER]
V12_PAGE_LABELS = {x[0]: x[1] for x in V12_PAGE_ORDER}
V12_PAGE_KICKER = {x[0]: x[2] for x in V12_PAGE_ORDER}

V13_CAMPAIGN_WINDOW_MINUTES = 15
V13_WATCHLIST_KEY = "guardianeye_watchlist_sources"
V13_INVESTIGATION_KEY = "guardianeye_investigation"
V13_LAST_SNAPSHOT_KEY = "guardianeye_last_snapshot"

# ---------------------------------------------------------------------------
# Operator state
# ---------------------------------------------------------------------------

def v13_get_watchlist():
    value = st.session_state.get(V13_WATCHLIST_KEY)
    if not isinstance(value, list):
        value = []
        st.session_state[V13_WATCHLIST_KEY] = value
    return value


def v13_add_watch_source(source):
    source = str(source or "").strip()
    if not source:
        return
    watchlist = v13_get_watchlist()
    if source not in watchlist:
        watchlist.append(source)
        watchlist.sort()


def v13_remove_watch_source(source):
    source = str(source or "").strip()
    watchlist = v13_get_watchlist()
    st.session_state[V13_WATCHLIST_KEY] = [x for x in watchlist if x != source]


def v13_get_investigation():
    state = st.session_state.get(V13_INVESTIGATION_KEY)
    if not isinstance(state, dict):
        state = {
            "title": "",
            "objective": "",
            "system_ids": [],
            "event_ids": [],
            "incident_ids": [],
            "notes": [],
        }
        st.session_state[V13_INVESTIGATION_KEY] = state
    return state


def v13_reset_investigation():
    st.session_state[V13_INVESTIGATION_KEY] = {
        "title": "",
        "objective": "",
        "system_ids": [],
        "event_ids": [],
        "incident_ids": [],
        "notes": [],
    }


def v13_add_note(note):
    note = str(note or "").strip()
    if not note:
        return
    state = v13_get_investigation()
    state["notes"].append({"time": iso_now(), "text": note[:2000]})

# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def v13_campaigns(events):
    """Group compatible security signals into deterministic campaigns.

    A campaign is not an attribution claim.  It is a useful operator grouping
    based on source IP, attack type, and temporal proximity.
    """
    candidates = [
        e for e in events
        if v12_is_attack(e)
        and str(e.get("source_ip") or "").strip()
    ]
    candidates.sort(key=v12_event_sort_key)
    groups = []
    current = None
    for event in candidates:
        stamp = v12_parse_dt(event.get("event_time"))
        source = str(event.get("source_ip") or "").strip()
        attack = v12_attack(event)
        if stamp is None:
            continue
        if current is None:
            current = {
                "source": source,
                "first": stamp,
                "last": stamp,
                "systems": {str(event.get("system_id"))},
                "events": [event],
                "attack_types": {attack},
                "severities": {str(event.get("severity") or "Info")},
            }
            continue
        gap = (stamp - current["last"]).total_seconds() / 60
        same_source = source == current["source"]
        if same_source and gap <= V13_CAMPAIGN_WINDOW_MINUTES:
            current["last"] = stamp
            current["systems"].add(str(event.get("system_id")))
            current["events"].append(event)
            current["attack_types"].add(attack)
            current["severities"].add(str(event.get("severity") or "Info"))
        else:
            groups.append(current)
            current = {
                "source": source,
                "first": stamp,
                "last": stamp,
                "systems": {str(event.get("system_id"))},
                "events": [event],
                "attack_types": {attack},
                "severities": {str(event.get("severity") or "Info")},
            }
    if current is not None:
        groups.append(current)
    return groups


def v13_campaign_score(campaign):
    score = 20
    score += min(35, len(campaign.get("events", [])) * 4)
    score += min(25, len(campaign.get("systems", [])) * 12)
    if "Critical" in campaign.get("severities", set()):
        score += 25
    elif "High" in campaign.get("severities", set()):
        score += 15
    return min(100, score)


def v13_campaign_label(campaign):
    score = v13_campaign_score(campaign)
    if score >= 80:
        return "HIGH PRIORITY"
    if score >= 55:
        return "ELEVATED"
    return "OBSERVED CLUSTER"


def v13_campaign_table(campaigns, systems):
    mapping = v12_system_map(systems)
    rows = []
    for index, campaign in enumerate(campaigns, start=1):
        names = [mapping.get(sid, {}).get("company") or short_id(sid) for sid in campaign["systems"]]
        rows.append({
            "Campaign": f"CMP-{index:04d}",
            "Source": campaign["source"],
            "First seen": campaign["first"].isoformat(),
            "Last seen": campaign["last"].isoformat(),
            "Systems": len(names),
            "Signals": len(campaign["events"]),
            "Types": ", ".join(sorted(campaign["attack_types"])),
            "Priority": v13_campaign_label(campaign),
            "Affected": " · ".join(names),
        })
    return pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# Security matrix
# ---------------------------------------------------------------------------

def v13_security_matrix(systems, events):
    attack_types = sorted(v12_attack_counts(events).keys())
    if not attack_types:
        return pd.DataFrame()
    matrix = []
    counts = defaultdict(int)
    for event in events:
        sid = str(event.get("system_id") or "")
        attack = v12_attack(event)
        if sid and attack:
            counts[(sid, attack)] += 1
    for system in systems:
        row = {"System": system.get("company") or short_id(system.get("id"))}
        sid = str(system.get("id") or "")
        for attack in attack_types:
            row[V12_ATTACK_LABELS.get(attack, attack)] = counts.get((sid, attack), 0)
        matrix.append(row)
    return pd.DataFrame(matrix)


def v13_matrix_heatmap(df):
    if df.empty or len(df.columns) < 2:
        return None
    values = df.iloc[:, 1:].apply(pd.to_numeric, errors="coerce").fillna(0)
    fig = go.Figure(
        data=go.Heatmap(
            z=values.to_numpy(),
            x=list(values.columns),
            y=list(df.iloc[:, 0]),
            hovertemplate="%{y}<br>%{x}<br>Signals=%{z}<extra></extra>",
        )
    )
    fig.update_layout(
        title="Security signal matrix",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#dfe8f0",
        margin=dict(l=20, r=20, t=55, b=120),
    )
    return fig

# ---------------------------------------------------------------------------
# Evidence explorer
# ---------------------------------------------------------------------------

def v13_event_raw_json(event):
    raw = event.get("raw_data")
    if raw is None:
        raw = {}
    try:
        return json.dumps(raw, ensure_ascii=False, indent=2, default=str)
    except TypeError:
        return json.dumps({"value": str(raw)}, ensure_ascii=False, indent=2)


def v13_search_evidence(events, query):
    q = str(query or "").strip().lower()
    if not q:
        return events
    matched = []
    for event in events:
        haystack = " ".join([
            v12_attack(event),
            str(event.get("evidence") or ""),
            str(event.get("source_ip") or ""),
            str(event.get("protocol") or ""),
            str(event.get("detected_by") or ""),
            v13_event_raw_json(event),
        ]).lower()
        if q in haystack:
            matched.append(event)
    return matched


def v13_evidence_score(event):
    score = 0
    if event.get("evidence"):
        score += 25
    if event.get("source_ip"):
        score += 15
    if event.get("protocol"):
        score += 10
    if event.get("confidence") is not None:
        score += 15
    if event.get("raw_data"):
        score += 20
    if event.get("detected_by"):
        score += 15
    return score

# ---------------------------------------------------------------------------
# Data quality engine
# ---------------------------------------------------------------------------

def v13_quality_check(systems, incidents, events, heartbeats):
    issues = []
    system_ids = {str(s.get("id")) for s in systems if s.get("id")}
    for event in events:
        eid = str(event.get("id") or "Unknown")
        if not event.get("event_time"):
            issues.append({"Object": f"event:{eid}", "Issue": "Missing event_time", "Severity": "High"})
        if event.get("system_id") and str(event.get("system_id")) not in system_ids:
            issues.append({"Object": f"event:{eid}", "Issue": "Unknown system_id", "Severity": "High"})
        if not event.get("attack_type") and not event.get("event_type"):
            issues.append({"Object": f"event:{eid}", "Issue": "Missing event_type / attack_type", "Severity": "Medium"})
        if event.get("severity") not in {"Critical", "High", "Medium", "Low", "Info", None}:
            issues.append({"Object": f"event:{eid}", "Issue": "Unknown severity value", "Severity": "Medium"})
    for incident in incidents:
        iid = str(incident.get("id") or "Unknown")
        if incident.get("system_id") and str(incident.get("system_id")) not in system_ids:
            issues.append({"Object": f"incident:{iid}", "Issue": "Unknown system_id", "Severity": "High"})
        if not incident.get("last_seen"):
            issues.append({"Object": f"incident:{iid}", "Issue": "Missing last_seen", "Severity": "Medium"})
    for system in systems:
        if not system.get("url") and not system.get("api_url"):
            issues.append({"Object": f"system:{short_id(system.get('id'))}", "Issue": "No monitoring URL", "Severity": "High"})
    for hb in heartbeats:
        if not hb.get("seen_at"):
            issues.append({"Object": f"heartbeat:{hb.get('id') or 'Unknown'}", "Issue": "Missing seen_at", "Severity": "Medium"})
    return pd.DataFrame(issues)


def v13_quality_summary(df, systems, events, incidents, heartbeats):
    if df.empty:
        return {
            "score": 100,
            "issues": 0,
            "events": len(events),
            "incidents": len(incidents),
            "systems": len(systems),
            "heartbeats": len(heartbeats),
        }
    penalty = 0
    for sev in df["Severity"].tolist():
        penalty += {"High": 8, "Medium": 4, "Low": 1}.get(sev, 0)
    score = max(0, 100 - penalty)
    return {
        "score": score,
        "issues": len(df),
        "events": len(events),
        "incidents": len(incidents),
        "systems": len(systems),
        "heartbeats": len(heartbeats),
    }

# ---------------------------------------------------------------------------
# Snapshot / archive builder
# ---------------------------------------------------------------------------

def v13_snapshot_payload(systems, incidents, events, heartbeats):
    posture = v12_posture(systems, incidents, events)
    return {
        "product": APP_NAME,
        "version": APP_VERSION,
        "generated_at": iso_now(),
        "posture": posture,
        "systems": systems,
        "incidents": incidents,
        "security_events": events,
        "heartbeats": heartbeats,
    }


def v13_snapshot_zip(systems, incidents, events, heartbeats):
    payload = v13_snapshot_payload(systems, incidents, events, heartbeats)
    report = v12_build_executive_report(systems, incidents, events, heartbeats)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("GuardianEye_Snapshot.json", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        archive.writestr("GuardianEye_Executive_Report.md", report)
        event_rows = [{
            "time": e.get("event_time"),
            "system_id": e.get("system_id"),
            "attack_type": v12_attack(e),
            "severity": e.get("severity"),
            "source_ip": e.get("source_ip"),
            "confidence": e.get("confidence"),
            "evidence": e.get("evidence"),
        } for e in events]
        archive.writestr("Security_Events.csv", pd.DataFrame(event_rows).to_csv(index=False))
    return buffer.getvalue()

# ---------------------------------------------------------------------------
# Watchlist intelligence
# ---------------------------------------------------------------------------

def v13_watchlist_events(events):
    watchlist = set(v13_get_watchlist())
    if not watchlist:
        return []
    return [e for e in events if str(e.get("source_ip") or "") in watchlist]


def v13_watchlist_stats(events):
    matched = v13_watchlist_events(events)
    return {
        "signals": len(matched),
        "systems": len({str(e.get("system_id")) for e in matched}),
        "attacks": len({v12_attack(e) for e in matched}),
        "high": sum(1 for e in matched if e.get("severity") in {"Critical", "High"}),
    }

# ---------------------------------------------------------------------------
# Investigation export / evidence bundle
# ---------------------------------------------------------------------------

def v13_investigation_events(events):
    state = v13_get_investigation()
    ids = {str(x) for x in state.get("event_ids", [])}
    if not ids:
        return []
    return [e for e in events if str(e.get("id")) in ids]


def v13_investigation_incidents(incidents):
    state = v13_get_investigation()
    ids = {str(x) for x in state.get("incident_ids", [])}
    if not ids:
        return []
    return [i for i in incidents if str(i.get("id")) in ids]


def v13_investigation_bundle(systems, incidents, events):
    state = v13_get_investigation()
    selected_events = v13_investigation_events(events)
    selected_incidents = v13_investigation_incidents(incidents)
    systems_by_id = v12_system_map(systems)
    context_systems = [
        systems_by_id[sid]
        for sid in state.get("system_ids", [])
        if sid in systems_by_id
    ]
    markdown_lines = [
        "# GuardianEye Investigation Bundle",
        "",
        f"Title: {state.get('title') or 'Untitled investigation'}",
        f"Objective: {state.get('objective') or 'Not specified'}",
        f"Generated: {iso_now()}",
        "",
        "## Systems",
    ]
    for system in context_systems:
        markdown_lines.append(f"- {system.get('company')} · {system.get('id')}")
    markdown_lines.extend(["", "## Incidents"])
    for incident in selected_incidents:
        markdown_lines.append(f"- {incident.get('title') or incident.get('attack_type')} · {incident.get('severity')} · {incident.get('status')}")
    markdown_lines.extend(["", "## Events"])
    for event in selected_events:
        markdown_lines.append(f"- {event.get('event_time')} · {v12_attack(event)} · {event.get('severity')} · {event.get('source_ip') or 'Unknown'}")
    markdown_lines.extend(["", "## Notes"])
    for note in state.get("notes", []):
        markdown_lines.append(f"- {note.get('time')}: {note.get('text')}")
    return "\n".join(markdown_lines)

# ---------------------------------------------------------------------------
# Logical security wall: a richer version of the global fleet wall
# ---------------------------------------------------------------------------

def v13_system_security_state(system, incidents, events):
    sid = str(system.get("id") or "")
    system_events = [e for e in events if str(e.get("system_id")) == sid and v12_is_attack(e)]
    system_incidents = [i for i in incidents if str(i.get("system_id")) == sid and i.get("status") == "Open"]
    high = any(e.get("severity") in {"Critical", "High"} for e in system_events)
    if high:
        state = "ATTACK"
    elif system_incidents:
        state = "OPEN CASE"
    elif system.get("status") == "Healthy" and agent_is_online(system):
        state = "NOMINAL"
    elif system.get("status") in {"Down", "Auth Error"}:
        state = "SERVICE ISSUE"
    else:
        state = "WATCH"
    return {
        "state": state,
        "signals": len(system_events),
        "incidents": len(system_incidents),
        "risk": v12_risk_for_system(system, incidents, events),
    }


def v13_security_wall_rows(systems, incidents, events):
    rows = []
    for system in systems:
        state = v13_system_security_state(system, incidents, events)
        rows.append({
            "System": system.get("company") or short_id(system.get("id")),
            "State": state["state"],
            "Risk": state["risk"],
            "Signals": state["signals"],
            "Open incidents": state["incidents"],
            "Endpoint": system.get("status") or "Not Checked",
            "Agent": "Online" if agent_is_online(system) else "Offline",
            "Last seen": v12_age_text(system.get("agent_last_seen")),
        })
    return pd.DataFrame(rows).sort_values("Risk", ascending=False) if rows else pd.DataFrame()

# ---------------------------------------------------------------------------
# Page: Campaign correlation
# ---------------------------------------------------------------------------

def v13_campaigns_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("SECURITY CORRELATION", "الحملات الأمنية", "تجميع إشارات مرتبطة زمنيًا ومصدرًا لإعطاء المشغل صورة أوسع من الحدث المفرد.")
    campaigns = v13_campaigns(events)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Campaigns", len(campaigns), "Temporal source clusters")
        + v12_render_kpi("Multi-system", sum(1 for c in campaigns if len(c["systems"]) >= 2), "Spans more than one system", "v12-kpi-bad" if any(len(c["systems"]) >= 2 for c in campaigns) else "")
        + v12_render_kpi("High impact", sum(1 for c in campaigns if v13_campaign_score(c) >= 80), "Priority clusters")
        + v12_render_kpi("Sources", len({c["source"] for c in campaigns}), "Unique campaign sources")
        + v12_render_kpi("Window", V13_CAMPAIGN_WINDOW_MINUTES, "Minutes")
        + '</div>', unsafe_allow_html=True)
    v12_panel_start("Correlation table", "Deterministic grouping")
    df = v13_campaign_table(campaigns, systems)
    if df.empty:
        v12_empty("لا توجد حملات مرصودة", "ستظهر مجموعات الارتباط عندما توجد إشارات أمنية ذات مصدر وتوقيت صالحين.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("تصدير الحملات CSV", data=df.to_csv(index=False).encode("utf-8"), file_name="GuardianEye_Campaigns.csv", mime="text/csv", use_container_width=True)
    v12_panel_end()
    v12_panel_start("Correlation explanation", "Operator interpretation")
    st.markdown(
        "هذه ليست عملية Attribution. النظام يجمع الإشارات بناءً على مصدر واحد وقرب زمني محدد؛ الهدف هو مساعدة المحلل على رؤية نمط مشترك، خصوصًا عندما يمتد النشاط عبر أكثر من منظومة."
    )
    if campaigns:
        campaign = max(campaigns, key=v13_campaign_score)
        st.write(f"أعلى مجموعة حاليًا: {campaign['source']} · {len(campaign['events'])} إشارات · {len(campaign['systems'])} منظومات · score={v13_campaign_score(campaign)}")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Security Matrix
# ---------------------------------------------------------------------------

def v13_security_matrix_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("COVERAGE MATRIX", "مصفوفة الأمن", "توضح أين ظهرت أنواع الكشف الأمني عبر الأسطول بدل النظر إلى منظومة واحدة فقط.")
    df = v13_security_matrix(systems, events)
    v12_panel_start("System × detection matrix", "Observed signals")
    if df.empty:
        v12_empty("لا توجد إشارات", "المصفوفة ستتكون تلقائيًا من أنواع الإشارات التي وصلت إلى GuardianEye.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)
        fig = v13_matrix_heatmap(df)
        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
    v12_panel_end()
    v12_panel_start("Detection coverage", "Actual Agent rule catalogue")
    st.dataframe(pd.DataFrame(V12_DETECTION_CATALOG), use_container_width=True, hide_index=True)
    v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Evidence Explorer
# ---------------------------------------------------------------------------

def v13_evidence_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("EVIDENCE EXPLORER", "مستكشف الأدلة", "بحث مباشر داخل الأدلة والـraw_data التي وصلت إلى GuardianEye.")
    query = st.text_input("بحث في الأدلة", placeholder="IP / عبارة / detector / JSON field", key="v13_evidence_query")
    selected = v13_search_evidence(events, query)
    selected.sort(key=v12_event_sort_key, reverse=True)
    st.markdown(
        '<div class="v12-command-strip">'
        f'<div class="v12-command-card"><div class="v12-command-label">Matches</div><div class="v12-command-value">{len(selected)}</div><div class="v12-command-note">Evidence records</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Sources</div><div class="v12-command-value">{len({e.get("source_ip") for e in selected if e.get("source_ip")})}</div><div class="v12-command-note">Unique source IPs</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">High/Critical</div><div class="v12-command-value">{sum(1 for e in selected if e.get("severity") in {"High","Critical"})}</div><div class="v12-command-note">Priority evidence</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Systems</div><div class="v12-command-value">{len({e.get("system_id") for e in selected})}</div><div class="v12-command-note">Affected systems</div></div>'
        '</div>', unsafe_allow_html=True)

    v12_panel_start("Evidence index", "Searchable fields")
    if not selected:
        v12_empty("لا توجد نتائج", "غيّر عبارة البحث.")
    else:
        rows = []
        systems_by_id = v12_system_map(systems)
        for event in selected[:300]:
            rows.append({
                "Time": event.get("event_time"),
                "System": systems_by_id.get(str(event.get("system_id")), {}).get("company") or short_id(event.get("system_id")),
                "Attack": v12_attack(event),
                "Severity": event.get("severity") or "Info",
                "Source": event.get("source_ip") or "Unknown",
                "Evidence score": v13_evidence_score(event),
                "Detected by": event.get("detected_by") or "—",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    v12_panel_end()

    v12_panel_start("Evidence detail", "Select one record")
    if selected:
        labels = [
            f"{e.get('event_time')} · {v12_attack(e)} · {e.get('source_ip') or 'Unknown'}"
            for e in selected[:100]
        ]
        index = st.selectbox("السجل", list(range(len(labels))), format_func=lambda i: labels[i], key="v13_evidence_index")
        event = selected[index]
        st.code(v13_event_raw_json(event), language="json")
        st.download_button("تصدير raw_data", data=v13_event_raw_json(event), file_name="GuardianEye_raw_event.json", mime="application/json", use_container_width=True)
    else:
        st.info("لا توجد سجلات.")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Investigation Workbench
# ---------------------------------------------------------------------------

def v13_investigation_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    state = v13_get_investigation()
    v12_render_header("ANALYST WORKBENCH", "مكتب التحقيق", "مساحة عمل للمحلل لجمع منظومات وحوادث وأحداث وملاحظات في ملف تحقيق واحد خلال الجلسة.")

    left, right = st.columns([1.05, .95], gap="large")
    with left:
        v12_panel_start("Investigation scope", "Session workspace", accent=True)
        state["title"] = st.text_input("عنوان التحقيق", value=state.get("title", ""), key="v13_inv_title")
        state["objective"] = st.text_area("الهدف", value=state.get("objective", ""), key="v13_inv_objective", height=100)
        system_choices = [(str(s.get("id")), s.get("company") or short_id(s.get("id"))) for s in systems]
        selected_system_ids = st.multiselect("المنظومات", [x[0] for x in system_choices], default=state.get("system_ids", []), format_func=lambda sid: next((name for x, name in system_choices if x == sid), short_id(sid)), key="v13_inv_systems")
        state["system_ids"] = selected_system_ids
        incident_choices = [(str(i.get("id")), i.get("title") or i.get("attack_type") or short_id(i.get("id"))) for i in incidents[:200]]
        selected_incident_ids = st.multiselect("الحوادث", [x[0] for x in incident_choices], default=state.get("incident_ids", []), format_func=lambda iid: next((name for x, name in incident_choices if x == iid), short_id(iid)), key="v13_inv_incidents")
        state["incident_ids"] = selected_incident_ids
        event_choices = sorted(events, key=v12_event_sort_key, reverse=True)[:200]
        selected_event_ids = st.multiselect("أحداث أمنية", [str(e.get("id")) for e in event_choices], default=state.get("event_ids", []), format_func=lambda eid: next((f"{e.get('event_time')} · {v12_attack(e)} · {e.get('source_ip') or 'Unknown'}" for e in event_choices if str(e.get('id')) == eid), short_id(eid)), key="v13_inv_events")
        state["event_ids"] = selected_event_ids
        note = st.text_area("إضافة ملاحظة", placeholder="ملاحظة محلل / فرضية / خطوة تحقق", height=120, key="v13_inv_note")
        if st.button("حفظ الملاحظة", use_container_width=True):
            v13_add_note(note)
            st.session_state.v13_inv_note = ""
            st.rerun()
        c1, c2 = st.columns(2)
        with c1:
            if st.button("تفريغ مساحة التحقيق", use_container_width=True):
                v13_reset_investigation()
                st.rerun()
        with c2:
            bundle = v13_investigation_bundle(systems, incidents, events)
            st.download_button("تصدير التحقيق", data=bundle, file_name="GuardianEye_Investigation.md", mime="text/markdown", use_container_width=True)
        v12_panel_end()
    with right:
        v12_panel_start("Evidence board", "Current selection")
        selected_events = v13_investigation_events(events)
        selected_incidents = v13_investigation_incidents(incidents)
        st.metric("Selected systems", len(state.get("system_ids", [])))
        st.metric("Selected events", len(selected_events))
        st.metric("Selected incidents", len(selected_incidents))
        st.metric("Notes", len(state.get("notes", [])))
        if state.get("notes"):
            for note in reversed(state["notes"][-12:]):
                st.markdown(f"**{safe_text(note.get('time'))}** — {safe_text(note.get('text'))}")
        else:
            st.caption("لم تتم إضافة ملاحظات بعد.")
        v12_panel_end()

        v12_panel_start("Investigation narrative", "Generated from selected records")
        if selected_events or selected_incidents:
            attacks = Counter(v12_attack(e) for e in selected_events)
            sources = Counter(str(e.get("source_ip") or "Unknown") for e in selected_events)
            st.write(f"تم اختيار {len(selected_events)} حدثًا و{len(selected_incidents)} حادثًا.")
            if attacks:
                st.write("أكثر نمط ظاهر: " + attacks.most_common(1)[0][0])
            if sources:
                st.write("أكثر مصدر ظهورًا: " + sources.most_common(1)[0][0])
        else:
            st.caption("اختر سجلات من الجانب الأيسر لإنشاء سياق التحقيق.")
        v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Watchlist
# ---------------------------------------------------------------------------

def v13_watchlist_page():
    systems = load_systems()
    events = load_security_events(MAX_SECURITY_EVENTS)
    v12_render_header("SOURCE WATCHLIST", "قائمة المراقبة", "قائمة مصدر داخل جلسة المشغل؛ عند ظهوره في الأحداث يتم عرضه كإشارة اهتمام.")
    watchlist = v13_get_watchlist()
    left, right = st.columns([.75, 1.25], gap="large")
    with left:
        v12_panel_start("Manage watchlist", "Session only", accent=True)
        source = st.text_input("Source IP", placeholder="203.0.113.10", key="v13_watch_source")
        if st.button("إضافة للمراقبة", use_container_width=True):
            v13_add_watch_source(source)
            st.rerun()
        if watchlist:
            st.markdown("### Sources")
            for item in list(watchlist):
                c1, c2 = st.columns([1, .25])
                with c1:
                    st.code(item)
                with c2:
                    if st.button("×", key=f"watch_remove_{item}"):
                        v13_remove_watch_source(item)
                        st.rerun()
        else:
            st.caption("لا توجد مصادر في القائمة.")
        v12_panel_end()
    with right:
        stats = v13_watchlist_stats(events)
        st.markdown(
            '<div class="v12-kpi-grid">'
            + v12_render_kpi("Signals", stats["signals"], "Watchlist matches")
            + v12_render_kpi("Systems", stats["systems"], "Systems touched")
            + v12_render_kpi("Attack types", stats["attacks"], "Unique patterns")
            + v12_render_kpi("High/Critical", stats["high"], "Priority signals", "v12-kpi-bad" if stats["high"] else "")
            + '</div>', unsafe_allow_html=True)
        v12_panel_start("Watchlist activity", "Live retained events")
        matched = sorted(v13_watchlist_events(events), key=v12_event_sort_key, reverse=True)
        if matched:
            v12_render_global_feed(matched, systems, 80)
        else:
            v12_empty("لا توجد مطابقة", "عند ظهور أحد المصادر في الأحداث سيظهر هنا.")
        v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Detection Lab
# ---------------------------------------------------------------------------

def v13_detection_lab_page():
    systems = load_systems()
    v12_render_header("DETECTION LAB", "مختبر الكشف", "تشغيل سيناريوهات تجريبية داخل قاعدة بياناتك لعرض Detection → Incident بدون تنفيذ هجوم حقيقي.")
    v12_panel_start("Scenario builder", "Safe simulation", accent=True)
    if not systems:
        v12_empty("لا توجد منظومات", "أضف منظومة أولًا.")
        v12_panel_end()
        return
    choices = [(str(s.get("id")), s.get("company") or short_id(s.get("id"))) for s in systems]
    selected = st.selectbox("المنظومة", [x[0] for x in choices], format_func=lambda sid: next((name for x, name in choices if x == sid), sid), key="v13_lab_system")
    scenario = st.selectbox("سيناريو", [
        "Brute Force",
        "Windows Brute Force",
        "SQL Injection Pattern",
        "Path Traversal",
        "Command Injection Pattern",
        "Web Scanner Activity",
        "HTTP Flood / High Rate",
        "Port Scan (Observed Connections)",
    ], key="v13_lab_scenario")
    severity = st.selectbox("Severity", ["Medium", "High", "Critical"], index=1, key="v13_lab_severity")
    count = st.number_input("عدد الإشارات التجريبية", min_value=1, max_value=10, value=1, step=1, key="v13_lab_count")
    st.warning("هذا المختبر يكتب أحداث Demo إلى قاعدة البيانات فقط. لا ينفذ هجومًا ولا يرسل حركة هجومية إلى أي منظومة.")
    if st.button("إطلاق السيناريو التجريبي", type="primary", use_container_width=True):
        system = v12_system_map(systems).get(str(selected))
        if system:
            created = 0
            for index in range(int(count)):
                source_ip = f"192.0.2.{50 + index}"
                event = {
                    "id": str(uuid.uuid4()),
                    "system_id": system["id"],
                    "event_time": iso_now(),
                    "event_type": "demo_detection",
                    "attack_type": scenario,
                    "severity": severity,
                    "confidence": .95,
                    "source_ip": source_ip,
                    "source_port": 51000 + index,
                    "dest_port": 443 if "Web" in scenario or "Injection" in scenario or "Traversal" in scenario else 22,
                    "protocol": "TCP",
                    "evidence": f"GuardianEye Detection Lab: simulated {scenario} signal #{index + 1}.",
                    "status": "Open",
                    "detected_by": "GuardianEye Detection Lab",
                    "raw_data": {"demo": True, "lab": True, "scenario": scenario, "sequence": index + 1},
                }
                get_supabase().table("security_events").insert(event).execute()
                create_or_update_incident_from_event(event)
                created += 1
            st.success(f"تم إنشاء {created} حدث تجريبي.")
            st.rerun()
    v12_panel_end()

    v12_panel_start("Detection catalogue", "Coverage reference")
    st.dataframe(pd.DataFrame(V12_DETECTION_CATALOG), use_container_width=True, hide_index=True)
    v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Data Quality
# ---------------------------------------------------------------------------

def v13_data_quality_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    heartbeats = load_heartbeats(1000)
    v12_render_header("TELEMETRY QUALITY", "جودة البيانات", "فحوصات اتساق فوق البيانات الحالية للتأكد من أن المركز لا يعمل فوق سجلات ناقصة أو غير مترابطة.")
    df = v13_quality_check(systems, incidents, events, heartbeats)
    summary = v13_quality_summary(df, systems, events, incidents, heartbeats)
    quality_css = "v12-kpi-good" if summary["score"] >= 95 else "v12-kpi-bad" if summary["score"] < 80 else ""
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Quality score", summary["score"], "Deterministic validation", quality_css)
        + v12_render_kpi("Issues", summary["issues"], "Detected inconsistencies", "v12-kpi-bad" if summary["issues"] else "")
        + v12_render_kpi("Events checked", summary["events"], "Security events")
        + v12_render_kpi("Incidents", summary["incidents"], "Cases checked")
        + v12_render_kpi("Heartbeats", summary["heartbeats"], "Samples checked")
        + '</div>', unsafe_allow_html=True)
    v12_panel_start("Validation results", "Current database snapshot")
    if df.empty:
        v12_empty("البيانات متماسكة", "لم تكتشف فحوصات الجودة الحالية مشكلات بنيوية في السجلات التي تمت قراءتها.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)
    v12_panel_end()
    v12_panel_start("What is checked", "Scope")
    for item in [
        "ربط event وincident بـSystem ID صالح.",
        "وجود توقيت صالح للأحداث والحوادث وheartbeat.",
        "وجود نوع إشارة أو نوع حدث قابل للعرض.",
        "وجود رابط مراقبة واحد على الأقل للمنظومة.",
        "قيم severity المعروفة ضمن النموذج الحالي.",
    ]:
        st.markdown(f"- {item}")
    v12_panel_end()

# ---------------------------------------------------------------------------
# Page: Snapshot
# ---------------------------------------------------------------------------

def v13_snapshot_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    heartbeats = load_heartbeats(1000)
    v12_render_header("CONTROL SNAPSHOT", "لقطة المركز", "تجميع حالة GuardianEye الحالية في ملف JSON وحزمة قابلة للتنزيل من جلسة واحدة.")
    posture = v12_posture(systems, incidents, events)
    st.markdown(
        '<div class="v12-command-strip">'
        f'<div class="v12-command-card"><div class="v12-command-label">Fleet</div><div class="v12-command-value">{posture["systems"]}</div><div class="v12-command-note">Systems</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Security</div><div class="v12-command-value">{posture["attacks"]}</div><div class="v12-command-note">Signals</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Cases</div><div class="v12-command-value">{posture["open_incidents"]}</div><div class="v12-command-note">Open incidents</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">Posture</div><div class="v12-command-value">{posture["fleet_risk"]:.0f}</div><div class="v12-command-note">{posture["band"]}</div></div>'
        '</div>', unsafe_allow_html=True)
    payload = v13_snapshot_payload(systems, incidents, events, heartbeats)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    v12_panel_start("Snapshot preview", "Read-only")
    st.code(raw[:20000], language="json")
    v12_panel_end()
    v12_panel_start("Export package", "JSON + report + CSV", accent=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
    st.download_button("تحميل Snapshot JSON", data=raw, file_name=f"GuardianEye_Snapshot_{stamp}.json", mime="application/json", use_container_width=True)
    bundle = v13_snapshot_zip(systems, incidents, events, heartbeats)
    st.download_button("تحميل حزمة Snapshot", data=bundle, file_name=f"GuardianEye_Snapshot_{stamp}.zip", mime="application/zip", use_container_width=True)
    v12_panel_end()
    st.session_state[V13_LAST_SNAPSHOT_KEY] = iso_now()

# ---------------------------------------------------------------------------
# Enhanced Overview — richer command-center experience
# ---------------------------------------------------------------------------

def v13_render_security_wall(systems, incidents, events):
    df = v13_security_wall_rows(systems, incidents, events)
    if df.empty:
        v12_empty("لا توجد منظومات", "أضف منظومات لمتابعتها.")
        return
    st.dataframe(df, use_container_width=True, hide_index=True)
    attack_systems = df[df["State"] == "ATTACK"]
    if not attack_systems.empty:
        st.error(f"ATTACK WALL: {len(attack_systems)} منظومة تحمل إشارات هجوم عالية الأولوية.")


def v13_render_posture_pulse(systems, incidents, events):
    recent = v12_recent(events, 6)
    buckets = v12_group_hour(recent)
    if not buckets:
        return
    data = pd.DataFrame([{"hour": k.strftime("%H:%M"), "signals": v} for k, v in sorted(buckets.items())])
    fig = px.area(data, x="hour", y="signals", title="Security pulse · last 6 hours")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
    st.plotly_chart(fig, use_container_width=True)


def v13_overview_page():
    run_health_monitoring()
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    heartbeats = load_heartbeats(500)
    posture = v12_posture(systems, incidents, events)
    st.session_state.v12_posture = posture

    v12_render_header(
        "GLOBAL SECURITY OPERATIONS",
        "مركز القيادة",
        "مركز تشغيل موحد يراقب الأسطول كاملًا، يربط الإشارات بالحوادث، ويمنح المحلل مسارًا من التنبيه إلى الأدلة.",
        f'{v12_render_chip("LIVE", "green")}<div class="mini">All systems · refresh {UI_REFRESH_INTERVAL_MS // 1000}s</div>',
    )
    v12_render_alarm(posture)
    v12_alarm_controls(posture)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("المنظومات", posture["systems"], "Fleet monitored")
        + v12_render_kpi("Healthy", posture["healthy"], "Current endpoint state", "v12-kpi-good" if posture["healthy"] else "")
        + v12_render_kpi("Agents Online", posture["agents"], "Last 90 seconds", "v12-kpi-good" if posture["agents"] else "")
        + v12_render_kpi("Open Incidents", posture["open_incidents"], "Require analyst attention", "v12-kpi-bad" if posture["open_incidents"] else "")
        + v12_render_kpi("Critical / High", posture["critical"] + posture["high"], "Priority security signals", "v12-kpi-bad" if posture["critical"] + posture["high"] else "")
        + '</div>', unsafe_allow_html=True)

    st.markdown(
        '<div class="v12-command-strip">'
        f'<div class="v12-command-card"><div class="v12-command-label">FLEET RISK</div><div class="v12-command-value">{posture["fleet_risk"]:.0f}</div><div class="v12-command-note">{posture["band"]}</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">SECURITY SIGNALS</div><div class="v12-command-value">{posture["attacks"]}</div><div class="v12-command-note">Retained current dataset</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">AGENT FLEET</div><div class="v12-command-value">{posture["agents"]}/{posture["systems"]}</div><div class="v12-command-note">Online / registered</div></div>'
        f'<div class="v12-command-card"><div class="v12-command-label">HEARTBEATS</div><div class="v12-command-value">{len(heartbeats)}</div><div class="v12-command-note">Recent retained samples</div></div>'
        '</div>', unsafe_allow_html=True)

    v12_panel_start("Global Security Wall", "Every monitored system", accent=True)
    v13_render_security_wall(systems, incidents, events)
    v12_panel_end()

    left, right = st.columns([1.25, .75], gap="large")
    with left:
        v12_panel_start("Security pulse", "Last six hours")
        v13_render_posture_pulse(systems, incidents, events)
        v12_panel_end()
    with right:
        v12_panel_start("Cross-system intelligence", "Shared sources")
        v12_render_source_correlation(events, systems)
        v12_panel_end()

    left, right = st.columns([1.05, .95], gap="large")
    with left:
        v12_panel_start("Global security feed", "Newest events")
        v12_render_global_feed(events, systems, 14)
        v12_panel_end()
    with right:
        v12_panel_start("Top campaigns", "Source correlation")
        campaigns = v13_campaigns(events)
        df = v13_campaign_table(campaigns, systems)
        if df.empty:
            v12_empty("لا توجد حملات", "لا توجد مجموعات ارتباط حالية.")
        else:
            st.dataframe(df.head(8), use_container_width=True, hide_index=True)
        v12_panel_end()

# ---------------------------------------------------------------------------
# Enhanced sidebar: native collapse control is never hidden by CSS.
# ---------------------------------------------------------------------------

def v13_render_sidebar():
    current = st.session_state.get("page", "Overview")
    with st.sidebar:
        st.markdown(
            '<div class="brand-row"><div class="brand-mark">◉</div>'
            '<div><div class="brand-name">GUARDIANEYE</div>'
            '<div class="brand-sub">Global Security Operations</div></div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="panel-note">CONTROL CENTER</div>', unsafe_allow_html=True)
        st.caption("يمكنك طي الشريط من سهم Streamlit <<، وسيظهر سهم >> لإعادته.")
        st.divider()
        groups = [
            ("OPERATE", ["Overview", "Fleet", "Add System", "Operations"]),
            ("SECURITY", ["Security", "Incidents", "Campaigns", "Security Matrix", "Threat Hunt", "Evidence", "Watchlist", "Detection Lab"]),
            ("OBSERVE", ["Analytics", "Events", "Agents", "Data Quality"]),
            ("ANALYST", ["Investigation", "Reports", "Notifications", "Snapshot"]),
            ("PLATFORM", ["Agent Setup", "Settings"]),
        ]
        for group_name, keys in groups:
            st.markdown(f'<div class="panel-note" style="margin:.6rem 0 .35rem">{group_name}</div>', unsafe_allow_html=True)
            for key in keys:
                label = V12_PAGE_LABELS.get(key, key)
                prefix_mark = "●" if current == key else "○"
                if st.button(f"{prefix_mark}  {label}", key=f"v13_side_{key}", use_container_width=True):
                    v12_set_page(key)
        st.divider()
        posture = st.session_state.get("v12_posture") or {}
        if posture:
            st.markdown(
                f'<div class="small-muted">Fleet posture</div>'
                f'<div style="margin-top:.25rem">{v12_render_chip(str(posture.get("band", "UNKNOWN")), posture.get("css", "blue"))}</div>'
                f'<div class="small-muted" style="margin-top:.5rem">Open incidents: {posture.get("open_incidents", 0)}<br>Agents online: {posture.get("agents", 0)}/{posture.get("systems", 0)}</div>',
                unsafe_allow_html=True,
            )
        st.markdown(f'<div class="small-muted" style="margin-top:.8rem">Signed in as<br><strong>{safe_text(ADMIN_USER)}</strong></div>', unsafe_allow_html=True)
        if st.button("تسجيل الخروج", use_container_width=True, key="v13_logout"):
            logout()

# Compatibility: redefine overview after adding v13 features.
overview_page = v13_overview_page


# ---------------------------------------------------------------------------
# Advanced operator analytics: anomaly lens + fleet concentration
# ---------------------------------------------------------------------------

def v13_source_profile(events):
    profiles = defaultdict(lambda: {
        "signals": 0,
        "systems": set(),
        "attack_types": Counter(),
        "high": 0,
        "first": None,
        "last": None,
    })
    for event in events:
        source = str(event.get("source_ip") or "").strip()
        if not source:
            continue
        profile = profiles[source]
        profile["signals"] += 1
        if event.get("system_id"):
            profile["systems"].add(str(event.get("system_id")))
        profile["attack_types"][v12_attack(event)] += 1
        if event.get("severity") in {"High", "Critical"}:
            profile["high"] += 1
        stamp = v12_parse_dt(event.get("event_time"))
        if stamp:
            profile["first"] = stamp if profile["first"] is None else min(profile["first"], stamp)
            profile["last"] = stamp if profile["last"] is None else max(profile["last"], stamp)
    return profiles


def v13_source_priority(profile):
    score = 0
    score += min(45, profile["signals"] * 3)
    score += min(30, len(profile["systems"]) * 12)
    score += min(25, profile["high"] * 6)
    return min(100, score)


def v13_source_priority_band(score):
    if score >= 75:
        return "PRIORITY"
    if score >= 45:
        return "WATCH"
    return "OBSERVED"


def v13_source_profile_dataframe(events, systems):
    mapping = v12_system_map(systems)
    profiles = v13_source_profile(events)
    rows = []
    for source, profile in profiles.items():
        score = v13_source_priority(profile)
        names = [mapping.get(sid, {}).get("company") or short_id(sid) for sid in profile["systems"]]
        rows.append({
            "Source": source,
            "Priority": v13_source_priority_band(score),
            "Score": score,
            "Signals": profile["signals"],
            "High/Critical": profile["high"],
            "Systems": len(profile["systems"]),
            "Affected": " · ".join(names),
            "Attack mix": " · ".join(f"{k}:{v}" for k, v in profile["attack_types"].most_common(4)),
        })
    return pd.DataFrame(rows).sort_values(["Score", "Signals"], ascending=False) if rows else pd.DataFrame()


def v13_current_latency_statistics(systems):
    values = [float(s["response_ms"]) for s in systems if s.get("response_ms") is not None]
    if not values:
        return {"count": 0, "median": None, "p90": None, "max": None}
    values.sort()
    mid = values[len(values) // 2]
    p90_index = min(len(values) - 1, max(0, math.ceil(len(values) * .9) - 1))
    return {
        "count": len(values),
        "median": round(mid, 1),
        "p90": round(values[p90_index], 1),
        "max": round(max(values), 1),
    }


def v13_latency_outliers(systems):
    stats = v13_current_latency_statistics(systems)
    median = stats["median"]
    if median is None:
        return pd.DataFrame()
    threshold = max(HEALTHY_THRESHOLD_MS, median * 1.8)
    rows = []
    for system in systems:
        value = system.get("response_ms")
        if value is None:
            continue
        if float(value) >= threshold:
            rows.append({
                "System": system.get("company") or short_id(system.get("id")),
                "Response ms": round(float(value), 1),
                "Median ms": median,
                "Ratio": round(float(value) / max(.1, median), 2),
                "Status": system.get("status") or "Not Checked",
            })
    return pd.DataFrame(rows).sort_values("Response ms", ascending=False) if rows else pd.DataFrame()


def v13_render_latency_outliers(systems):
    df = v13_latency_outliers(systems)
    if df.empty:
        st.caption("لا توجد قياسات شاذة واضحة وفق القاعدة الحالية.")
        return
    st.dataframe(df, use_container_width=True, hide_index=True)


def v13_recent_attack_density(events, hours=6):
    recent = v12_recent(events, hours)
    if not recent:
        return {"signals": 0, "per_hour": 0.0, "sources": 0, "systems": 0}
    return {
        "signals": len(recent),
        "per_hour": round(len(recent) / max(1, hours), 2),
        "sources": len({str(e.get("source_ip")) for e in recent if e.get("source_ip")}),
        "systems": len({str(e.get("system_id")) for e in recent if e.get("system_id")}),
    }


def v13_security_concentration(events, systems):
    density = v13_recent_attack_density(events, 6)
    profiles = v13_source_profile(v12_recent(events, 24))
    system_counts = v12_system_attack_counts(v12_recent(events, 24))
    hottest_system_id = max(system_counts, key=system_counts.get) if system_counts else None
    mapping = v12_system_map(systems)
    hottest_source = None
    if profiles:
        hottest_source = max(profiles, key=lambda source: v13_source_priority(profiles[source]))
    return {
        "density": density,
        "hottest_system": mapping.get(hottest_system_id, {}).get("company") if hottest_system_id else None,
        "hottest_system_signals": system_counts.get(hottest_system_id, 0) if hottest_system_id else 0,
        "hottest_source": hottest_source,
        "hottest_source_score": v13_source_priority(profiles[hottest_source]) if hottest_source else 0,
    }


def v13_build_anomaly_narrative(systems, incidents, events):
    concentration = v13_security_concentration(events, systems)
    posture = v12_posture(systems, incidents, events)
    parts = []
    if concentration["hottest_system"]:
        parts.append(f"أعلى كثافة أمنية حاليًا على {concentration['hottest_system']} ({concentration['hottest_system_signals']} إشارات خلال 24 ساعة).")
    if concentration["hottest_source"]:
        parts.append(f"المصدر الأكثر تكرارًا وفق مؤشر الأولوية الحالي هو {concentration['hottest_source']}.")
    if posture["open_incidents"]:
        parts.append(f"هناك {posture['open_incidents']} حوادث مفتوحة تحتاج متابعة.")
    if not parts:
        parts.append("لا توجد إشارة تركيز بارزة ضمن البيانات الحالية.")
    return " ".join(parts)


def v13_analytics_page():
    systems = load_systems()
    incidents = load_incidents(MAX_INCIDENTS)
    events = load_security_events(MAX_SECURITY_EVENTS)
    heartbeats = load_heartbeats(1000)
    posture = v12_posture(systems, incidents, events)
    v12_render_header("SECURITY ANALYTICS", "التحليلات المتقدمة", "رؤية عملية للكثافة، مصادر الأحداث، مخاطر الأسطول، وشذوذ الاستجابة.")
    concentration = v13_security_concentration(events, systems)
    latency_stats = v13_current_latency_statistics(systems)
    st.markdown(
        '<div class="v12-kpi-grid">'
        + v12_render_kpi("Fleet risk", f"{posture['fleet_risk']:.0f}", posture["band"])
        + v12_render_kpi("6h signals", concentration["density"]["signals"], f"{concentration['density']['per_hour']} / hour")
        + v12_render_kpi("Cross-system sources", len(v12_cross_system_sources(events, 2)[0]), "Shared sources", "v12-kpi-bad" if v12_cross_system_sources(events, 2)[0] else "")
        + v12_render_kpi("Median latency", f"{latency_stats['median']} ms" if latency_stats["median"] is not None else "—", "Current checks")
        + v12_render_kpi("Open incidents", posture["open_incidents"], "Cases requiring attention", "v12-kpi-bad" if posture["open_incidents"] else "")
        + '</div>', unsafe_allow_html=True)

    v12_panel_start("Analyst narrative", "Deterministic signal summary", accent=True)
    st.markdown(v13_build_anomaly_narrative(systems, incidents, events))
    v12_panel_end()

    left, right = st.columns(2, gap="large")
    with left:
        v12_panel_start("Source priority map", "24-hour source profiles")
        source_df = v13_source_profile_dataframe(v12_recent(events, 24), systems)
        if source_df.empty:
            v12_empty("لا توجد مصادر", "لا توجد أحداث بمصادر IP خلال النافذة الحالية.")
        else:
            st.dataframe(source_df.head(30), use_container_width=True, hide_index=True)
        v12_panel_end()
    with right:
        v12_panel_start("Latency outliers", "Current fleet checks")
        v13_render_latency_outliers(systems)
        v12_panel_end()

    left, right = st.columns(2, gap="large")
    with left:
        v12_panel_start("Attack density", "Last 24 hours")
        recent = v12_recent(events, 24)
        buckets = v12_group_hour(recent)
        if buckets:
            df = pd.DataFrame([{"Hour": k.strftime("%m-%d %H:%M"), "Signals": v} for k, v in sorted(buckets.items())])
            fig = px.area(df, x="Hour", y="Signals", title="Security density")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
            st.plotly_chart(fig, use_container_width=True)
        else:
            v12_empty("لا توجد بيانات", "لا توجد إشارات ضمن آخر 24 ساعة.")
        v12_panel_end()
    with right:
        v12_panel_start("Agent heartbeat coverage", "Observed samples")
        hb_latest = v12_latest_by_system(heartbeats, "seen_at")
        rows = []
        for system in systems:
            hb = hb_latest.get(str(system.get("id")), {})
            rows.append({
                "System": system.get("company") or short_id(system.get("id")),
                "Heartbeat": v12_age_text(hb.get("seen_at")) if hb else "No data",
                "CPU": hb.get("cpu_percent") if hb.get("cpu_percent") is not None else "—",
                "Memory": hb.get("memory_percent") if hb.get("memory_percent") is not None else "—",
                "Connections": hb.get("open_connections") if hb.get("open_connections") is not None else "—",
            })
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            v12_empty("لا توجد حساسات", "لا توجد heartbeat records.")
        v12_panel_end()

    v12_panel_start("Detection mix", "Current retained security events")
    attacks = v12_attack_counts(events)
    if attacks:
        df = pd.DataFrame([{"Detection": V12_ATTACK_LABELS.get(k, k), "Signals": v} for k, v in attacks.most_common(15)])
        fig = px.bar(df, x="Signals", y="Detection", orientation="h", title="Detection mix")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dfe8f0")
        st.plotly_chart(fig, use_container_width=True)
    else:
        v12_empty("لا توجد إشارات", "لم تصل أحداث أمنية حتى الآن.")
    v12_panel_end()

analytics_page = v13_analytics_page

# ---------------------------------------------------------------------------
# Final session / dispatch layer
# ---------------------------------------------------------------------------

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "page" not in st.session_state:
    st.session_state.page = "Overview"
if "selected_system" not in st.session_state:
    st.session_state.selected_system = None
if "selected_incident" not in st.session_state:
    st.session_state.selected_incident = None
if "last_health_run" not in st.session_state:
    st.session_state.last_health_run = 0.0
if "v12_alarm_armed" not in st.session_state:
    st.session_state.v12_alarm_armed = False
if "v12_last_error" not in st.session_state:
    st.session_state.v12_last_error = ""
if "v12_posture" not in st.session_state:
    st.session_state.v12_posture = {}
if V13_WATCHLIST_KEY not in st.session_state:
    st.session_state[V13_WATCHLIST_KEY] = []
if V13_INVESTIGATION_KEY not in st.session_state:
    v13_reset_investigation()

if not st.session_state.logged_in:
    v12_login()
    st.stop()

# Keep global health state current before rendering any page.
try:
    run_health_monitoring()
except Exception as exc:
    st.session_state["v12_last_error"] = database_error(exc)

try:
    systems_now = load_systems()
    incidents_now = load_incidents(MAX_INCIDENTS)
    events_now = load_security_events(MAX_SECURITY_EVENTS)
    st.session_state.v12_posture = v12_posture(systems_now, incidents_now, events_now)
except Exception as exc:
    st.session_state["v12_last_error"] = database_error(exc)

v13_render_sidebar()

try:
    page = st.session_state.page
    if page == "Overview":
        overview_page()
    elif page in {"Fleet", "Systems"}:
        v12_fleet_page()
    elif page == "Add System":
        add_system_page()
    elif page == "Security":
        security_page()
    elif page == "Incidents":
        incidents_page()
    elif page == "Campaigns":
        v13_campaigns_page()
    elif page == "Security Matrix":
        v13_security_matrix_page()
    elif page == "Threat Hunt":
        v12_threat_hunt_page()
    elif page == "Evidence":
        v13_evidence_page()
    elif page == "Investigation":
        v13_investigation_page()
    elif page == "Watchlist":
        v13_watchlist_page()
    elif page == "Detection Lab":
        v13_detection_lab_page()
    elif page == "Analytics":
        analytics_page()
    elif page == "Events":
        events_page()
    elif page == "Agents":
        v12_agents_page()
    elif page == "Data Quality":
        v13_data_quality_page()
    elif page == "Agent Setup":
        agent_setup_page()
    elif page == "Operations":
        v12_operations_page()
    elif page == "Reports":
        v12_reports_page()
    elif page == "Notifications":
        v12_notifications_page()
    elif page == "Snapshot":
        v13_snapshot_page()
    elif page == "Settings":
        v12_settings_page()
    else:
        st.session_state.page = "Overview"
        st.rerun()
except Exception as exc:
    st.error("تعذر تحميل الوحدة الحالية، وتم إبقاء المركز متاحًا للتنقل.")
    st.caption(database_error(exc))