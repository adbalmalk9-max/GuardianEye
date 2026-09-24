import datetime as dt
import json
import os
import time
import uuid
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# =========================
# App configuration
# =========================
st.set_page_config(page_title="GuardianEye", page_icon="🛡️", layout="wide")

DATA_FILE = Path("systems.json")
LOG_FILE = Path("events.json")
CHECK_INTERVAL_SECONDS = 15
REQUEST_TIMEOUT_SECONDS = 8

STATUS_LABELS = {
    "HEALTHY": "✅ سليم",
    "DEGRADED": "⚠️ بطيء",
    "DOWN": "🔴 متوقف",
    "AUTH_ERROR": "🔐 فشل المصادقة",
    "ERROR": "❌ خطأ",
    "UNKNOWN": "❔ غير مفحوص",
}

# =========================
# Minimal UI styling
# =========================
st.markdown(
    """
    <style>
    .guardian-card {
        border: 1px solid rgba(148, 163, 184, .20);
        border-radius: 14px;
        padding: 16px;
        background: rgba(15, 23, 42, .55);
        margin-bottom: 12px;
    }
    .muted { color: #94a3b8; font-size: 0.9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================
# Persistence helpers
# =========================
def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path: Path, data):
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    temp_path.replace(path)


def load_systems():
    raw = load_json(DATA_FILE, [])
    systems = []
    for item in raw:
        system = dict(item)
        # Never persist API secrets in systems.json.
        system.pop("api_key", None)
        system.setdefault("id", str(uuid.uuid4()))
        system.setdefault("status_code", None)
        system.setdefault("response_ms", None)
        system.setdefault("last_error", None)
        system.setdefault("last_check", None)
        system.setdefault("check_count", 0)
        system.setdefault("last_state", "UNKNOWN")
        systems.append(system)
    return systems


def save_systems(systems):
    safe_systems = []
    for system in systems:
        safe = dict(system)
        # Defensive: remove secrets even if an old object contains one.
        safe.pop("api_key", None)
        safe_systems.append(safe)
    save_json(DATA_FILE, safe_systems)


def append_event(system_name, state, message):
    events = load_json(LOG_FILE, [])
    events.append(
        {
            "time": dt.datetime.now().isoformat(timespec="seconds"),
            "system": system_name,
            "state": state,
            "message": message,
        }
    )
    save_json(LOG_FILE, events[-500:])


# =========================
# Runtime state
# =========================
if "systems" not in st.session_state:
    st.session_state.systems = load_systems()
if "api_keys" not in st.session_state:
    st.session_state.api_keys = {}
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# =========================
# Authentication
# =========================
import os

ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER")
ADMIN_PASSWORD = os.getenv("GUARDIAN_ADMIN_PASSWORD") 

def login():
    st.sidebar.subheader("تسجيل الدخول")

    if not ADMIN_USER or not ADMIN_PASSWORD:
        st.sidebar.error("لم يتم ضبط بيانات المدير في متغيرات البيئة.")
        st.info(
            "قبل تشغيل النسخة اضبط GUARDIAN_ADMIN_USER "
            "و GUARDIAN_ADMIN_PASSWORD"
        )
        return

    username = st.sidebar.text_input(
        "اسم المستخدم",
        key="username_field"
    )

    password = st.sidebar.text_input(
        "كلمة المرور",
        type="password",
        key="password_field"
    )

    if st.sidebar.button("دخول", use_container_width=True):
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.sidebar.error("بيانات الدخول غير صحيحة")

if not st.session_state.logged_in:
    st.title("🛡️ GuardianEye")
    st.caption("مركز مراقبة للمنظومات المصرح لك بإدارتها ومراقبتها")
    login()
    st.stop()

# =========================
# Session controls
# =========================
def logout():
    st.session_state.logged_in = False
    st.session_state.api_keys = {}
    st.rerun()


st.sidebar.button("تسجيل الخروج", on_click=logout, use_container_width=True)

# Refresh the UI, but do not hammer targets every second.
st_autorefresh(interval=1000, limit=None, key="guardian_refresh")

# =========================
# Monitoring engine
# =========================
def classify_state(status_code, response_ms, error=None):
    if error == "AUTH_ERROR":
        return "AUTH_ERROR"
    if error:
        return "ERROR"
    if status_code is None:
        return "UNKNOWN"
    if 200 <= status_code < 400:
        return "HEALTHY" if response_ms is not None and response_ms < 1000 else "DEGRADED"
    if status_code in (401, 403):
        return "AUTH_ERROR"
    if 400 <= status_code < 600:
        return "DOWN"
    return "ERROR"


def check_system(system):
    url = (system.get("api_url") or system.get("url") or "").strip()
    if not url:
        return None

    headers = {"User-Agent": "GuardianEye-Monitor/1.0"}
    api_key = st.session_state.api_keys.get(system["id"], "")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.perf_counter()
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        error = "AUTH_ERROR" if response.status_code in (401, 403) else None
        return {
            "state": classify_state(response.status_code, elapsed_ms, error),
            "status_code": response.status_code,
            "response_ms": elapsed_ms,
            "error": error,
        }
    except requests.RequestException as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "state": "DOWN",
            "status_code": None,
            "response_ms": elapsed_ms,
            "error": str(exc),
        }


def perform_due_checks():
    now = dt.datetime.now()
    changed = False

    for system in st.session_state.systems:
        last_check = system.get("last_check")
        due = True
        if last_check:
            try:
                previous = dt.datetime.fromisoformat(last_check)
                due = (now - previous).total_seconds() >= CHECK_INTERVAL_SECONDS
            except ValueError:
                due = True

        if not due:
            continue

        result = check_system(system)
        if result is None:
            continue

        old_state = system.get("last_state", "UNKNOWN")
        new_state = result["state"]
        system["last_state"] = new_state
        system["status"] = STATUS_LABELS[new_state]
        system["status_code"] = result["status_code"]
        system["response_ms"] = result["response_ms"]
        system["last_error"] = result["error"]
        system["last_check"] = now.isoformat(timespec="seconds")
        system["check_count"] = int(system.get("check_count", 0)) + 1
        changed = True

        if old_state != "UNKNOWN" and old_state != new_state:
            append_event(
                system.get("company", system.get("name", "Unknown")),
                new_state,
                f"تغيرت الحالة من {STATUS_LABELS.get(old_state, old_state)} إلى {STATUS_LABELS[new_state]}",
            )

    if changed:
        save_systems(st.session_state.systems)


perform_due_checks()

# =========================
# Header
# =========================
st.title("GuardianEye Dashboard")
st.caption("مراقبة دورية للحالة، زمن الاستجابة، وأحداث المنظومات")

# =========================
# Add system
# =========================
st.subheader("إضافة منظومة")
with st.form("add_system_form", clear_on_submit=True):
    company = st.text_input("اسم الشركة / المؤسسة")
    url = st.text_input("رابط المنظومة")
    api_url = st.text_input("رابط Health/API للفحص", placeholder="https://example.com/health")
    api_key = st.text_input("API Key", type="password", help="لا يتم حفظ المفتاح داخل systems.json")
    submitted = st.form_submit_button("إضافة المنظومة", use_container_width=True)

    if submitted:
        if not company.strip() or not url.strip():
            st.error("اسم الشركة والرابط مطلوبان.")
        else:
            system_id = str(uuid.uuid4())
            system = {
                "id": system_id,
                "company": company.strip(),
                "url": url.strip(),
                "api_url": api_url.strip() or url.strip(),
                "status": STATUS_LABELS["UNKNOWN"],
                "last_state": "UNKNOWN",
                "status_code": None,
                "response_ms": None,
                "last_error": None,
                "last_check": None,
                "check_count": 0,
            }
            st.session_state.systems.append(system)
            if api_key:
                st.session_state.api_keys[system_id] = api_key
            save_systems(st.session_state.systems)
            st.success(f"تمت إضافة {company.strip()} ✅")
            st.rerun()

# =========================
# Overview metrics
# =========================
all_states = [s.get("last_state", "UNKNOWN") for s in st.session_state.systems]
healthy_count = sum(state == "HEALTHY" for state in all_states)
down_count = sum(state == "DOWN" for state in all_states)
auth_count = sum(state == "AUTH_ERROR" for state in all_states)

m1, m2, m3, m4 = st.columns(4)
m1.metric("المنظومات", len(st.session_state.systems))
m2.metric("سليمة", healthy_count)
m3.metric("متوقفة", down_count)
m4.metric("مصادقة", auth_count)

# =========================
# Systems table
# =========================
st.subheader("المنظومات")
if not st.session_state.systems:
    st.info("لا توجد منظومات مضافة بعد.")
else:
    table = pd.DataFrame(
        [
            {
                "المؤسسة": s.get("company", ""),
                "الحالة": s.get("status", STATUS_LABELS["UNKNOWN"]),
                "HTTP": s.get("status_code"),
                "الاستجابة (ms)": s.get("response_ms"),
                "آخر فحص": s.get("last_check", "—"),
                "عدد الفحوص": s.get("check_count", 0),
            }
            for s in st.session_state.systems
        ]
    )
    st.dataframe(table, use_container_width=True, hide_index=True)

    for index, system in enumerate(st.session_state.systems):
        name = system.get("company", f"System {index + 1}")
        with st.expander(name):
            st.write(f"**الرابط:** {system.get('url', '—')}")
            st.write(f"**Endpoint:** {system.get('api_url', '—')}")
            st.write(f"**الحالة:** {system.get('status', STATUS_LABELS['UNKNOWN'])}")
            st.write(f"**HTTP:** {system.get('status_code', '—')}")
            st.write(f"**زمن الاستجابة:** {system.get('response_ms', '—')} ms")
            st.write(f"**آخر فحص:** {system.get('last_check', '—')}")
            if system.get("last_error"):
                st.error(f"الخطأ: {system['last_error']}")

            new_key = st.text_input(
                "تحديث API Key (اختياري)",
                type="password",
                key=f"api_key_{system['id']}",
            )
            c1, c2 = st.columns(2)
            with c1:
                if st.button("حفظ المفتاح", key=f"save_{system['id']}", use_container_width=True):
                    if new_key:
                        st.session_state.api_keys[system["id"]] = new_key
                        st.success("تم تحديث المفتاح في الجلسة الحالية.")
                    else:
                        st.warning("أدخل مفتاحًا أولًا.")
            with c2:
                if st.button("حذف المنظومة", key=f"delete_{system['id']}", use_container_width=True):
                    st.session_state.api_keys.pop(system["id"], None)
                    st.session_state.systems.pop(index)
                    save_systems(st.session_state.systems)
                    st.rerun()

# =========================
# Statistics
# =========================
st.subheader("الإحصائيات")
if st.session_state.systems:
    stats_df = pd.DataFrame(
        {
            "المؤسسة": [s.get("company", "") for s in st.session_state.systems],
            "الحالة": [s.get("status", STATUS_LABELS["UNKNOWN"]) for s in st.session_state.systems],
            "الاستجابة": [s.get("response_ms") or 0 for s in st.session_state.systems],
        }
    )
    fig_status = px.pie(stats_df, names="الحالة", title="توزيع حالات المنظومات")
    st.plotly_chart(fig_status, use_container_width=True)

    fig_latency = px.bar(
        stats_df,
        x="المؤسسة",
        y="الاستجابة",
        title="زمن الاستجابة الحالي",
        labels={"الاستجابة": "ms"},
    )
    st.plotly_chart(fig_latency, use_container_width=True)

# =========================
# Events
# =========================
st.subheader("سجل الأحداث")
events = load_json(LOG_FILE, [])
if events:
    events_df = pd.DataFrame(events[::-1])
    st.dataframe(events_df.head(100), use_container_width=True, hide_index=True)
else:
    st.info("لا توجد أحداث انتقال حالة حتى الآن.")

st.caption("GuardianEye — يراقب فقط نقاط النهاية التي يحددها المستخدم وبصلاحية الوصول التي يملكها.")


