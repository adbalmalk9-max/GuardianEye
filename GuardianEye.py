import datetime
import json
import time
import uuid
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ============================================================
# GuardianEye - Monitoring Center
# ============================================================

st.set_page_config(
    page_title="GuardianEye",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Visual system
# -----------------------------
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap');

:root {
    --bg: #090d14;
    --panel: #101722;
    --panel2: #151e2c;
    --line: rgba(148,163,184,.16);
    --text: #edf4ff;
    --muted: #8ea0b9;
    --accent: #35a8ff;
    --good: #26d07c;
    --warn: #ffb84d;
    --bad: #ff5d6c;
}

html, body, [class*="css"] { font-family: "Cairo", sans-serif; }
body {
    background:
        radial-gradient(circle at 15% 10%, rgba(53,168,255,.10), transparent 28%),
        radial-gradient(circle at 85% 15%, rgba(38,208,124,.08), transparent 24%),
        var(--bg);
    color: var(--text);
}
.block-container { max-width: 1500px; padding-top: 1.5rem; }

.guardian-title { font-size: 2.65rem; font-weight: 800; letter-spacing: -.03em; }
.guardian-subtitle { color: var(--muted); margin-top: .15rem; margin-bottom: 1.6rem; }

.status-pill {
    display: inline-block; padding: .28rem .72rem; border-radius: 999px;
    font-size: .82rem; font-weight: 700; border: 1px solid var(--line);
}
.pill-good { background: rgba(38,208,124,.12); color: #6df0ad; }
.pill-warn { background: rgba(255,184,77,.12); color: #ffd28a; }
.pill-bad { background: rgba(255,93,108,.12); color: #ff98a1; }
.pill-neutral { background: rgba(142,160,185,.10); color: #c4d0df; }

.metric-card {
    background: linear-gradient(180deg, rgba(21,30,44,.92), rgba(16,23,34,.92));
    border: 1px solid var(--line); border-radius: 16px; padding: 1rem 1.1rem;
    min-height: 125px; box-shadow: 0 12px 32px rgba(0,0,0,.18);
}
.metric-label { color: var(--muted); font-size: .86rem; margin-bottom: .45rem; }
.metric-value { font-size: 1.85rem; font-weight: 800; }
.metric-note { color: var(--muted); font-size: .78rem; margin-top: .25rem; }

div[data-testid="stSidebar"] { background: #0b1018; border-right: 1px solid var(--line); }
div[data-testid="stSidebar"] hr { border-color: var(--line); }
.stButton > button {
    border-radius: 10px; border: 1px solid rgba(53,168,255,.22);
    background: #111b28; color: var(--text); font-weight: 700; transition: .18s ease;
}
.stButton > button:hover { border-color: rgba(53,168,255,.60); background: #16263a; }
div[data-testid="stTextInput"] input { background: #0d141f; color: var(--text); border-color: var(--line); }
.small-muted { color: var(--muted); font-size: .82rem; }
.incident-row { padding: .75rem 0; border-bottom: 1px solid var(--line); }
</style>
""",
    unsafe_allow_html=True,
)

# Refresh the interface every 5 seconds; monitoring itself is rate-limited.
st_autorefresh(interval=5000, limit=None, key="guardian_ui_refresh")

# -----------------------------
# Requested admin account
# -----------------------------
# For a public production deployment, move these to Streamlit Secrets/OIDC.
ADMIN_USER = "MalkX03"
ADMIN_PASSWORD = "KALIABDALMALK107"

# -----------------------------
# Persistent files
# -----------------------------
DATA_FILE = Path("systems.json")
EVENT_FILE = Path("events.json")
SETTINGS_FILE = Path("guardian_settings.json")

DEFAULT_SETTINGS = {
    "check_interval": 15,
    "default_timeout": 8,
    "auto_monitor": True,
}


def _load_json(path: Path, default):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return default


def _save_json(path: Path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    tmp.replace(path)


def load_systems():
    data = _load_json(DATA_FILE, [])
    return data if isinstance(data, list) else []


def save_systems(data):
    _save_json(DATA_FILE, data)


def load_events():
    data = _load_json(EVENT_FILE, [])
    return data if isinstance(data, list) else []


def save_events(data):
    _save_json(EVENT_FILE, data[-500:])


def load_settings():
    data = _load_json(SETTINGS_FILE, {})
    result = DEFAULT_SETTINGS.copy()
    if isinstance(data, dict):
        result.update(data)
    return result


if "systems" not in st.session_state:
    st.session_state.systems = load_systems()
if "events" not in st.session_state:
    st.session_state.events = load_events()
if "settings" not in st.session_state:
    st.session_state.settings = load_settings()
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "page" not in st.session_state:
    st.session_state.page = "Overview"
if "last_monitor_run" not in st.session_state:
    st.session_state.last_monitor_run = 0.0

# API keys are kept only in the current Streamlit session.
# They are NEVER written to systems.json.
if "api_keys" not in st.session_state:
    st.session_state.api_keys = {}

# Remove any legacy _api_key values that may exist in an older
# systems.json from a previous version of GuardianEye.
for _system in st.session_state.systems:
    _system.pop("_api_key", None)


def now_string():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short_id(value):
    return value[:8] if value else "—"


def status_badge(status):
    mapping = {
        "Healthy": ("pill-good", "● Healthy"),
        "Slow": ("pill-warn", "● Slow"),
        "Down": ("pill-bad", "● Down"),
        "Auth Error": ("pill-bad", "● Auth Error"),
        "Not Checked": ("pill-neutral", "● Not Checked"),
    }
    css, label = mapping.get(status, ("pill-neutral", f"● {status}"))
    return f'<span class="status-pill {css}">{label}</span>'


def response_ms_text(value):
    return "—" if value is None else f"{value:.0f} ms"


def add_event(system, old_status, new_status, message):
    event = {
        "id": str(uuid.uuid4()),
        "time": now_string(),
        "system_id": system["id"],
        "company": system["company"],
        "old_status": old_status,
        "new_status": new_status,
        "message": message,
    }
    st.session_state.events.append(event)
    save_events(st.session_state.events)


# -----------------------------
# Monitoring engine
# -----------------------------

def check_system(system):
    target = (system.get("api_url") or system.get("url") or "").strip()
    api_key = st.session_state.api_keys.get(system.get("id"), "").strip()
    timeout = int(st.session_state.settings["default_timeout"])

    if not target:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": "No monitoring URL configured.",
        }

    headers = {
        "User-Agent": "GuardianEye-Monitor/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.perf_counter()
    try:
        response = requests.get(
            target,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
        elapsed = (time.perf_counter() - started) * 1000
        code = response.status_code

        if code in (401, 403):
            status = "Auth Error"
            message = f"Endpoint returned HTTP {code}."
        elif 200 <= code < 400:
            status = "Slow" if elapsed >= 1500 else "Healthy"
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
            "message": f"Request timeout after {timeout}s.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": f"Connection error: {str(exc)[:140]}",
        }


def run_monitoring():
    if not st.session_state.settings.get("auto_monitor", True):
        return

    interval = int(st.session_state.settings["check_interval"])
    now = time.time()
    if now - st.session_state.last_monitor_run < interval:
        return

    st.session_state.last_monitor_run = now
    changed = False

    for system in st.session_state.systems:
        result = check_system(system)
        old_status = system.get("status", "Not Checked")
        system.update(
            {
                "status": result["status"],
                "http_status": result["http_status"],
                "response_ms": result["response_ms"],
                "last_message": result["message"],
                "last_checked": now_string(),
            }
        )

        if old_status != "Not Checked" and old_status != result["status"]:
            add_event(system, old_status, result["status"], result["message"])
        changed = True

    if changed:
        save_systems(st.session_state.systems)


# -----------------------------
# Login
# -----------------------------

def login():
    st.markdown(
        """
        <div style="max-width:620px;margin:8vh auto 0 auto;padding:2rem;border-radius:22px;
                    border:1px solid rgba(148,163,184,.16);background:#101722;
                    box-shadow:0 25px 70px rgba(0,0,0,.35);">
            <div style="font-size:3rem">🛡️</div>
            <div class="guardian-title">GuardianEye</div>
            <div class="guardian-subtitle">مركز مراقبة المنظومات والخدمات المصرّح لك بإدارتها</div>
        """,
        unsafe_allow_html=True,
    )

    username = st.text_input("اسم المستخدم", placeholder="أدخل اسم المستخدم", key="login_username")
    password = st.text_input(
        "كلمة المرور",
        type="password",
        placeholder="أدخل كلمة المرور",
        key="login_password",
    )

    if st.button("دخول إلى مركز المراقبة", use_container_width=True):
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("بيانات الدخول غير صحيحة.")

    st.markdown(
        '<div class="small-muted" style="margin-top:1rem">الوصول محمي. لا تشارك بيانات الدخول.</div></div>',
        unsafe_allow_html=True,
    )


def logout():
    st.session_state.logged_in = False
    st.session_state.login_username = ""
    st.session_state.login_password = ""
    st.rerun()


# -----------------------------
# Pages
# -----------------------------

def overview_page():
    run_monitoring()
    systems = st.session_state.systems
    healthy = sum(1 for s in systems if s.get("status") == "Healthy")
    slow = sum(1 for s in systems if s.get("status") == "Slow")
    incidents = sum(1 for s in systems if s.get("status") in ("Down", "Auth Error"))

    st.markdown('<div class="guardian-title">GuardianEye</div>', unsafe_allow_html=True)
    st.markdown('<div class="guardian-subtitle">مركز المراقبة المركزي للمنظومات والخدمات</div>', unsafe_allow_html=True)

    metrics = [
        ("المنظومات", len(systems), "إجمالي الأنظمة"),
        ("Healthy", healthy, "استجابة طبيعية"),
        ("Slow", slow, "زمن استجابة مرتفع"),
        ("Incidents", incidents, "حالات تحتاج انتباه"),
    ]
    cols = st.columns(4)
    for col, (label, value, note) in zip(cols, metrics):
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
                unsafe_allow_html=True,
            )

    st.write("")
    if not systems:
        st.info("لا توجد منظومات بعد. استخدم «إضافة منظومة» لبدء المراقبة.")
        return

    rows = []
    for system in systems:
        rows.append(
            {
                "ID": short_id(system.get("id")),
                "المنظومة": system.get("company", "—"),
                "الحالة": system.get("status", "Not Checked"),
                "HTTP": system.get("http_status") or "—",
                "Response": response_ms_text(system.get("response_ms")),
                "آخر فحص": system.get("last_checked") or "—",
                "آخر نتيجة": system.get("last_message", "—"),
            }
        )

    st.subheader("حالة المنظومات")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.subheader("آخر الأحداث")
    recent = list(reversed(st.session_state.events[-8:]))
    if not recent:
        st.info("لا توجد أحداث مسجلة حتى الآن.")
    else:
        for event in recent:
            st.markdown(
                f'<div class="incident-row"><strong>{event["company"]}</strong>'
                f'<span class="small-muted"> · {event["time"]}</span><br>'
                f'{event["old_status"]} → {event["new_status"]} · {event["message"]}</div>',
                unsafe_allow_html=True,
            )


def add_system_page():
    st.header("إضافة منظومة")
    with st.form("add_system_form", clear_on_submit=True):
        company = st.text_input("اسم الشركة / المؤسسة")
        url = st.text_input("الرابط الرئيسي", placeholder="https://example.com")
        api_url = st.text_input(
            "Endpoint المراقبة / API",
            placeholder="https://example.com/api/health",
        )
        api_key = st.text_input(
            "مفتاح API",
            type="password",
            help="يُستخدم أثناء الفحص ولا يُحفظ داخل systems.json أو GitHub.",
        )
        st.caption("🔐 المفتاح يبقى في جلسة GuardianEye الحالية ولا يُكتب في ملف الأنظمة.")
        submitted = st.form_submit_button("إضافة المنظومة", use_container_width=True)

    if not submitted:
        return

    if not company.strip() or not (url.strip() or api_url.strip()):
        st.error("أدخل اسم المنظومة ورابطًا صالحًا للمراقبة.")
        return

    system = {
        "id": str(uuid.uuid4()),
        "company": company.strip(),
        "url": url.strip(),
        "api_url": api_url.strip(),
        "status": "Not Checked",
        "http_status": None,
        "response_ms": None,
        "last_message": "Waiting for first check.",
        "last_checked": None,
        "created_at": now_string(),
    }

    # Keep the API key only in Streamlit session memory.
    # It is intentionally not part of the persisted system record.
    st.session_state.api_keys[system["id"]] = api_key.strip()

    st.session_state.systems.append(system)
    save_systems(st.session_state.systems)
    st.success(f"تمت إضافة {company.strip()}.")
    st.rerun()


def systems_page():
    run_monitoring()
    st.header("المنظومات")
    if not st.session_state.systems:
        st.info("لا توجد منظومات مسجلة.")
        return

    for system in st.session_state.systems:
        with st.expander(f'{system.get("company", "Unknown")} · {system.get("status", "Not Checked")}'):
            left, right = st.columns([2.2, 1])
            with left:
                st.markdown(status_badge(system.get("status", "Not Checked")), unsafe_allow_html=True)
                st.write(f'**الرابط:** {system.get("url") or "—"}')
                st.write(f'**API / Health Endpoint:** {system.get("api_url") or "—"}')
                st.write(f'**HTTP:** {system.get("http_status") or "—"}')
                st.write(f'**Response Time:** {response_ms_text(system.get("response_ms"))}')
                st.write(f'**آخر فحص:** {system.get("last_checked") or "—"}')
                st.caption(system.get("last_message", ""))

            with right:
                if st.button("فحص الآن", key=f'check_{system["id"]}', use_container_width=True):
                    result = check_system(system)
                    old_status = system.get("status", "Not Checked")
                    system.update(
                        {
                            "status": result["status"],
                            "http_status": result["http_status"],
                            "response_ms": result["response_ms"],
                            "last_message": result["message"],
                            "last_checked": now_string(),
                        }
                    )
                    if old_status != "Not Checked" and old_status != result["status"]:
                        add_event(system, old_status, result["status"], result["message"])
                    save_systems(st.session_state.systems)
                    st.rerun()

                if st.button("حذف نهائي", key=f'delete_{system["id"]}', use_container_width=True):
                    system_id = system["id"]
                    deleted_name = system.get("company", "Unknown")

                    # Remove from persistent systems file first.
                    st.session_state.systems = [
                        item for item in st.session_state.systems if item.get("id") != system_id
                    ]
                    save_systems(st.session_state.systems)

                    # Remove the in-memory API key together with the system.
                    st.session_state.api_keys.pop(system_id, None)

                    # Also remove its related audit events permanently.
                    st.session_state.events = [
                        event for event in st.session_state.events if event.get("system_id") != system_id
                    ]
                    save_events(st.session_state.events)

                    st.success(f"تم حذف {deleted_name} نهائيًا من التخزين.")
                    st.rerun()


def analytics_page():
    run_monitoring()
    st.header("التحليلات")
    systems = st.session_state.systems
    if not systems:
        st.info("أضف منظومات أولًا.")
        return

    df = pd.DataFrame(
        [
            {
                "company": s.get("company", "Unknown"),
                "status": s.get("status", "Not Checked"),
                "response_ms": s.get("response_ms"),
            }
            for s in systems
        ]
    )

    col1, col2 = st.columns(2)
    with col1:
        counts = df["status"].value_counts().reset_index()
        counts.columns = ["status", "count"]
        fig = px.pie(counts, names="status", values="count", hole=.58, title="توزيع الحالات")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        r = df.dropna(subset=["response_ms"])
        if r.empty:
            st.info("لا توجد قياسات Response Time كافية.")
        else:
            fig = px.bar(r, x="company", y="response_ms", title="Response Time", labels={"response_ms": "ms", "company": ""})
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)


def events_page():
    st.header("سجل الأحداث")
    events = list(reversed(st.session_state.events))
    if not events:
        st.info("لا توجد أحداث بعد.")
        return

    for event in events:
        st.markdown(
            f'<div class="incident-row"><strong>{event["company"]}</strong>'
            f'<span class="small-muted"> · {event["time"]} · {short_id(event["id"])}</span><br>'
            f'الحالة: {event["old_status"]} → {event["new_status"]}<br>{event["message"]}</div>',
            unsafe_allow_html=True,
        )


def settings_page():
    st.header("إعدادات المراقبة")
    interval = st.number_input(
        "فترة الفحص بالثواني",
        min_value=5,
        max_value=3600,
        value=int(st.session_state.settings["check_interval"]),
        step=5,
    )
    timeout = st.number_input(
        "مهلة طلب HTTP بالثواني",
        min_value=2,
        max_value=60,
        value=int(st.session_state.settings["default_timeout"]),
        step=1,
    )
    auto_monitor = st.checkbox(
        "تفعيل المراقبة التلقائية",
        value=bool(st.session_state.settings["auto_monitor"]),
    )

    if st.button("حفظ إعدادات المراقبة", use_container_width=True):
        st.session_state.settings.update(
            {
                "check_interval": int(interval),
                "default_timeout": int(timeout),
                "auto_monitor": bool(auto_monitor),
            }
        )
        _save_json(SETTINGS_FILE, st.session_state.settings)
        st.success("تم حفظ إعدادات المراقبة.")


# -----------------------------
# Router
# -----------------------------

if not st.session_state.logged_in:
    login()
    st.stop()

with st.sidebar:
    st.markdown(
        '<div style="font-size:1.8rem;font-weight:800">🛡️ GuardianEye</div>'
        '<div class="small-muted">Operations Monitoring Center</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    pages = ["Overview", "Systems", "Add System", "Analytics", "Events", "Settings"]
    st.session_state.page = st.radio("Navigation", pages, index=pages.index(st.session_state.page))
    st.divider()
    st.markdown(
        f'<div class="small-muted">Logged in as<br><strong style="color:#edf4ff">{ADMIN_USER}</strong></div>',
        unsafe_allow_html=True,
    )
    if st.button("تسجيل الخروج", use_container_width=True):
        logout()

if st.session_state.page == "Overview":
    overview_page()
elif st.session_state.page == "Systems":
    systems_page()
elif st.session_state.page == "Add System":
    add_system_page()
elif st.session_state.page == "Analytics":
    analytics_page()
elif st.session_state.page == "Events":
    events_page()
elif st.session_state.page == "Settings":
    settings_page()