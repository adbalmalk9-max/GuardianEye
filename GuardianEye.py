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
    page_icon="GE",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Visual system
# -----------------------------
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #070b11;
    --panel: #0e141d;
    --panel-soft: #0b1119;
    --line: rgba(148,163,184,.14);
    --line-strong: rgba(148,163,184,.23);
    --text: #f4f7fb;
    --muted: #8d9aab;
    --accent: #4da3ff;
    --good: #2fd27c;
    --warn: #f2b34c;
    --bad: #f26470;
}

html, body, [class*="css"] { font-family: "Cairo", sans-serif; }
body { background: var(--bg); color: var(--text); }
.block-container { max-width: 1480px; padding-top: 1.2rem; padding-bottom: 2rem; }

.guardian-title { font-size: 2.5rem; font-weight: 800; line-height: 1.15; letter-spacing: -.025em; }
.guardian-subtitle { color: var(--muted); margin-top: .35rem; margin-bottom: 1.5rem; }

.guardian-wordmark { display: flex; align-items: center; gap: .78rem; direction: ltr; }
.guardian-mark {
    width: 42px; height: 42px; display: grid; place-items: center;
    border: 1px solid var(--line-strong); border-radius: 11px; background: var(--panel-soft);
}
.guardian-mark svg { width: 25px; height: 25px; }
.wordmark-name { font-size: 1.42rem; font-weight: 800; letter-spacing: -.02em; }
.wordmark-meta { color: var(--muted); font-size: .7rem; letter-spacing: .08em; text-transform: uppercase; }

.status-pill {
    display: inline-flex; align-items: center; gap: .35rem; padding: .26rem .68rem;
    border-radius: 999px; font-size: .79rem; font-weight: 700; border: 1px solid var(--line);
}
.pill-good { background: rgba(47,210,124,.08); color: #69e8a4; }
.pill-warn { background: rgba(242,179,76,.08); color: #f6cc83; }
.pill-bad { background: rgba(242,100,112,.08); color: #ff9ca4; }
.pill-neutral { background: rgba(148,163,184,.06); color: #bec8d5; }

.metric-card {
    background: var(--panel); border: 1px solid var(--line); border-radius: 15px;
    padding: 1rem 1.1rem; min-height: 118px;
}
.metric-label { color: var(--muted); font-size: .82rem; margin-bottom: .35rem; }
.metric-value { font-size: 1.8rem; font-weight: 800; }
.metric-note { color: var(--muted); font-size: .75rem; margin-top: .22rem; }

div[data-testid="stSidebar"] { background: #090e15; border-right: 1px solid var(--line); }
div[data-testid="stSidebar"] hr { border-color: var(--line); }

.stButton > button {
    border-radius: 9px; border: 1px solid var(--line-strong);
    background: #0f1722; color: var(--text); font-weight: 700; min-height: 42px;
    transition: border-color .15s ease, background .15s ease;
}
.stButton > button:hover { border-color: rgba(77,163,255,.55); background: #121d2b; }

div[data-testid="stTextInput"] input {
    background: #0b1119; color: var(--text); border: 1px solid var(--line);
    border-radius: 9px; min-height: 44px;
}
div[data-testid="stTextInput"] input:focus {
    border-color: rgba(77,163,255,.65); box-shadow: 0 0 0 1px rgba(77,163,255,.15);
}

.small-muted { color: var(--muted); font-size: .8rem; }
.incident-row { padding: .72rem 0; border-bottom: 1px solid var(--line); }

/* Landing / login */
.login-brand, .login-panel {
    border: 1px solid var(--line); border-radius: 22px; box-sizing: border-box;
    min-height: 540px;
}
.login-brand {
    padding: 3rem 2.6rem; background: var(--panel-soft);
    display: flex; flex-direction: column; justify-content: space-between;
}
.login-panel {
    padding: 2.8rem 2.3rem; background: var(--panel);
    display: flex; flex-direction: column; justify-content: center;
}
.login-brand-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: .8rem; margin-top: 2rem;
}
.login-brand-grid div {
    border-top: 1px solid var(--line); padding-top: .7rem;
    color: var(--muted); font-size: .74rem;
}
.login-label {
    font-size: .76rem; color: var(--muted); text-transform: uppercase; letter-spacing: .11em;
}
.login-title { font-size: 1.95rem; font-weight: 800; margin-top: .35rem; }
.login-copy { color: var(--muted); font-size: .88rem; line-height: 1.9; margin: .6rem 0 1.7rem; }
.login-status { display: flex; align-items: center; gap: .45rem; margin-top: 1.3rem; color: var(--muted); font-size: .76rem; }
.login-status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--good); box-shadow: 0 0 0 3px rgba(47,210,124,.08); }

@media (max-width: 900px) {
    .login-brand, .login-panel { min-height: auto; }
    .login-brand { margin-bottom: 1rem; }
}
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

# ============================================================
# Persistent database: Supabase
# ============================================================

ADMIN_USER = "MalkX03"
ADMIN_PASSWORD = "KALIABDALMALK107"

def required_secret(name):
    try:
        value = str(st.secrets[name]).strip()
    except Exception as exc:
        raise RuntimeError(
            f"Missing Streamlit Secret: {name}"
        ) from exc
    if not value:
        raise RuntimeError(
            f"Streamlit Secret '{name}' is empty."
        )
    return value


@st.cache_resource(show_spinner=False)
def get_supabase():
    from supabase import create_client
    return create_client(
        required_secret("SUPABASE_URL"),
        required_secret("SUPABASE_SERVICE_ROLE_KEY"),
    )


@st.cache_resource(show_spinner=False)
def get_fernet():
    from cryptography.fernet import Fernet
    return Fernet(
        required_secret("GUARDIAN_ENCRYPTION_KEY").encode("utf-8")
    )


def encrypt_api_key(value):
    if not value:
        return ""
    return get_fernet().encrypt(
        value.encode("utf-8")
    ).decode("utf-8")


def decrypt_api_key(value):
    if not value:
        return ""
    try:
        return get_fernet().decrypt(
            value.encode("utf-8")
        ).decode("utf-8")
    except Exception:
        return ""


def load_systems():
    result = (
        get_supabase()
        .table("systems")
        .select(
            "id,company,url,api_url,api_key_enc,status,"
            "http_status,response_ms,last_message,last_checked,created_at"
        )
        .order("created_at", desc=False)
        .execute()
    )
    return result.data or []


def load_events(limit=500):
    result = (
        get_supabase()
        .table("events")
        .select(
            "id,time,system_id,company,old_status,new_status,message"
        )
        .order("time", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data or []


def create_system(company, url, api_url, api_key):
    row = {
        "id": str(uuid.uuid4()),
        "company": company.strip(),
        "url": url.strip(),
        "api_url": api_url.strip(),
        "api_key_enc": encrypt_api_key(api_key.strip()),
        "status": "Not Checked",
        "http_status": None,
        "response_ms": None,
        "last_message": "Waiting for first check.",
    }
    return (
        get_supabase()
        .table("systems")
        .insert(row)
        .execute()
    )


def update_system(system):
    payload = {
        "status": system.get("status"),
        "http_status": system.get("http_status"),
        "response_ms": system.get("response_ms"),
        "last_message": system.get("last_message"),
        "last_checked": system.get("last_checked"),
    }
    return (
        get_supabase()
        .table("systems")
        .update(payload)
        .eq("id", system["id"])
        .execute()
    )


def create_event(system, old_status, new_status, message):
    row = {
        "id": str(uuid.uuid4()),
        "system_id": system["id"],
        "company": system["company"],
        "old_status": old_status,
        "new_status": new_status,
        "message": message,
    }
    return (
        get_supabase()
        .table("events")
        .insert(row)
        .execute()
    )


def permanently_delete_system(system_id):
    # Hard delete: remove audit records then the actual system row.
    get_supabase().table("events").delete().eq(
        "system_id", system_id
    ).execute()

    return (
        get_supabase().table("systems").delete()
        .eq("id", system_id)
        .execute()
    )


def database_error(exc):
    text = str(exc).strip()
    return text[:400] if text else "Unknown database error."


def run_monitoring():
    now = time.time()
    last = st.session_state.get(
        "last_monitor_run",
        0.0,
    )

    if now - last < 15:
        return

    st.session_state.last_monitor_run = now

    try:
        systems = load_systems()
    except Exception:
        return

    for system in systems:
        result = check_system(system)
        old_status = system.get(
            "status",
            "Not Checked",
        )

        system.update(
            {
                "status": result["status"],
                "http_status": result["http_status"],
                "response_ms": result["response_ms"],
                "last_message": result["message"],
                "last_checked": (
                    datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat()
                ),
            }
        )

        if (
            old_status != "Not Checked"
            and old_status != result["status"]
        ):
            try:
                create_event(
                    system,
                    old_status,
                    result["status"],
                    result["message"],
                )
            except Exception:
                pass

        try:
            update_system(system)
        except Exception:
            pass


# -----------------------------
# Streamlit session state
# -----------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "last_monitor_run" not in st.session_state:
    st.session_state.last_monitor_run = 0.0

if "page" not in st.session_state:
    st.session_state.page = "Overview"



# ============================================================
# Authentication
# ============================================================

def login():
    left, right = st.columns([1.15, 0.85], gap="large")

    with left:
        st.markdown(
            """
            <div class="login-brand" dir="rtl">
                <div>
                    <div class="guardian-wordmark" style="direction:ltr;justify-content:flex-end">
                        <div>
                            <div class="wordmark-name">GuardianEye</div>
                            <div class="wordmark-meta">OPERATIONS MONITORING CENTER</div>
                        </div>
                        <div class="guardian-mark" aria-hidden="true">
                            <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M5 16c3.2-5 7-7.5 11-7.5S23.8 11 27 16c-3.2 5-7 7.5-11 7.5S8.2 21 5 16Z" stroke="#4DA3FF" stroke-width="1.8"/>
                                <circle cx="16" cy="16" r="3.5" stroke="#E7EEF7" stroke-width="1.8"/>
                                <circle cx="16" cy="16" r="1.4" fill="#4DA3FF"/>
                            </svg>
                        </div>
                    </div>

                    <div style="margin-top:4.8rem;max-width:620px">
                        <div style="font-size:2.55rem;font-weight:800;line-height:1.28">
                            رؤية تشغيلية واضحة.<br>
                            مراقبة في مكان واحد.
                        </div>
                        <div style="color:#8D9AAB;font-size:.95rem;line-height:1.95;margin-top:1rem">
                            منصة GuardianEye تجمع حالة المنظومات، زمن الاستجابة، وسجل الأحداث
                            في مساحة تشغيلية واحدة للأنظمة المصرّح لك بمراقبتها.
                        </div>
                    </div>

                    <div class="login-brand-grid" style="direction:rtl">
                        <div>System Health</div>
                        <div>Response Metrics</div>
                        <div>Incident History</div>
                    </div>
                </div>

                <div class="small-muted">Authorized monitoring platform · GuardianEye</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        st.markdown(
            """
            <div class="login-panel" dir="rtl">
                <div class="login-label">Secure access</div>
                <div class="login-title">تسجيل الدخول</div>
                <div class="login-copy">
                    ادخل إلى مركز العمليات لمشاهدة المنظومات وإدارة عمليات المراقبة.
                </div>
            """,
            unsafe_allow_html=True,
        )

        username = st.text_input(
            "اسم المستخدم",
            placeholder="أدخل اسم المستخدم",
            key="login_username",
        )
        password = st.text_input(
            "كلمة المرور",
            type="password",
            placeholder="أدخل كلمة المرور",
            key="login_password",
        )

        if st.button(
            "دخول إلى مركز المراقبة",
            use_container_width=True,
        ):
            if username == ADMIN_USER and password == ADMIN_PASSWORD:
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("بيانات الدخول غير صحيحة.")

        st.markdown(
            """
            <div class="login-status" dir="rtl">
                <span class="login-status-dot"></span>
                منصة المراقبة جاهزة
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="small-muted" style="margin-top:2.2rem">'
            'الوصول محمي. لا تشارك بيانات الدخول.'
            '</div></div>',
            unsafe_allow_html=True,
        )

def logout():
    st.session_state.logged_in = False
    st.session_state.pop("login_password", None)
    st.rerun()


# ============================================================
# Monitoring engine
# ============================================================

def check_system(system):
    target = (
        system.get("api_url")
        or system.get("url")
        or ""
    ).strip()

    api_key = decrypt_api_key(
        system.get("api_key_enc", "")
    )

    if not target:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": "No monitoring URL configured.",
        }

    headers = {
        "User-Agent": "GuardianEye-Monitor/4.0",
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

        elapsed = (
            time.perf_counter() - started
        ) * 1000
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
            "message": "Request timed out after 8 seconds.",
        }

    except requests.exceptions.RequestException as exc:
        return {
            "status": "Down",
            "http_status": None,
            "response_ms": None,
            "message": f"Connection error: {str(exc)[:140]}",
        }


# ============================================================
# Pages
# ============================================================

def overview_page():
    run_monitoring()

    try:
        systems = load_systems()
        events = load_events()
    except Exception as exc:
        st.error("تعذر الاتصال بقاعدة البيانات.")
        st.code(database_error(exc))
        return

    healthy = sum(
        1 for system in systems
        if system.get("status") == "Healthy"
    )
    slow = sum(
        1 for system in systems
        if system.get("status") == "Slow"
    )
    incidents = sum(
        1 for system in systems
        if system.get("status")
        in ("Down", "Auth Error")
    )

    st.markdown(
        '<div class="guardian-title">GuardianEye</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="guardian-subtitle">'
        "مركز المراقبة المركزي للمنظومات والخدمات"
        "</div>",
        unsafe_allow_html=True,
    )

    values = [
        ("المنظومات", len(systems), "من قاعدة البيانات"),
        ("Healthy", healthy, "استجابة طبيعية"),
        ("Slow", slow, "زمن استجابة مرتفع"),
        ("Incidents", incidents, "حالات تحتاج انتباه"),
    ]

    columns = st.columns(4)
    for column, (label, value, note) in zip(
        columns,
        values,
    ):
        with column:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div>'
                f'<div class="metric-note">{note}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.write("")

    if not systems:
        st.info(
            "لا توجد منظومات. استخدم «إضافة منظومة»."
        )
        return

    rows = []
    for system in systems:
        rows.append(
            {
                "ID": short_id(system.get("id")),
                "المنظومة": system.get(
                    "company",
                    "—",
                ),
                "الحالة": system.get(
                    "status",
                    "Not Checked",
                ),
                "HTTP": system.get(
                    "http_status"
                ) or "—",
                "Response": response_ms_text(
                    system.get("response_ms")
                ),
                "آخر فحص": system.get(
                    "last_checked"
                ) or "—",
                "آخر نتيجة": system.get(
                    "last_message"
                ) or "—",
            }
        )

    st.subheader("حالة المنظومات")
    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("آخر الأحداث")

    if not events:
        st.info("لا توجد أحداث بعد.")
    else:
        for event in events[:8]:
            st.markdown(
                f'<div class="incident-row">'
                f'<strong>{event["company"]}</strong>'
                f'<span class="small-muted"> · {event["time"]}'
                f'</span><br>'
                f'{event["old_status"]}'
                f' → {event["new_status"]}'
                f' · {event["message"]}'
                f'</div>',
                unsafe_allow_html=True,
            )


# -----------------------------
# UI helpers
# -----------------------------

def short_id(value):
    return str(value)[:8] if value else "—"


def response_ms_text(value):
    if value is None:
        return "—"
    try:
        return f"{float(value):.0f} ms"
    except (TypeError, ValueError):
        return "—"


def status_badge(status):
    mapping = {
        "Healthy": ("pill-good", "● Healthy"),
        "Slow": ("pill-warn", "● Slow"),
        "Down": ("pill-bad", "● Down"),
        "Auth Error": ("pill-bad", "● Auth Error"),
        "Not Checked": ("pill-neutral", "● Not Checked"),
    }
    css, label = mapping.get(
        status, ("pill-neutral", f"● {status}")
    )
    return f'<span class="status-pill {css}">{label}</span>'


def add_system_page():
    st.header("إضافة منظومة")

    with st.form(
        "add_system_form",
        clear_on_submit=True,
    ):
        company = st.text_input(
            "اسم الشركة / المؤسسة",
            placeholder="Example Corp",
        )
        url = st.text_input(
            "الرابط الرئيسي",
            placeholder="https://example.com",
        )
        api_url = st.text_input(
            "Endpoint المراقبة / API",
            placeholder="https://example.com/api/health",
        )
        api_key = st.text_input(
            "مفتاح API",
            type="password",
            help=(
                "يُشفّر قبل تخزينه في قاعدة البيانات "
                "ولا يظهر في لوحة المراقبة."
            ),
        )

        submitted = st.form_submit_button(
            "إضافة المنظومة",
            use_container_width=True,
        )

    if not submitted:
        return

    if not company.strip():
        st.error(
            "اكتب اسم الشركة أو المؤسسة."
        )
        return

    if not (
        url.strip()
        or api_url.strip()
    ):
        st.error(
            "أدخل رابطًا صالحًا للمراقبة."
        )
        return

    try:
        create_system(
            company,
            url,
            api_url,
            api_key,
        )
    except Exception as exc:
        st.error("فشل حفظ المنظومة.")
        st.code(database_error(exc))
        return

    st.success(
        "تمت إضافة المنظومة إلى قاعدة البيانات."
    )
    st.rerun()


def systems_page():
    run_monitoring()

    try:
        systems = load_systems()
    except Exception as exc:
        st.error(
            "تعذر تحميل المنظومات."
        )
        st.code(database_error(exc))
        return

    st.header("المنظومات")

    if not systems:
        st.info(
            "لا توجد منظومات مسجلة."
        )
        return

    st.caption(
        "الحذف النهائي يتم مباشرة من قاعدة البيانات."
    )

    for system in systems:
        system_id = system["id"]
        company = system.get(
            "company",
            "Unknown",
        )
        status = system.get(
            "status",
            "Not Checked",
        )

        with st.container(border=True):
            top_left, top_right = st.columns(
                [3, 1]
            )

            with top_left:
                st.markdown(
                    f'<div style="font-size:1.25rem;'
                    f'font-weight:800">'
                    f'{company}</div>',
                    unsafe_allow_html=True,
                )
                st.caption(
                    f"ID: {short_id(system_id)}"
                )

            with top_right:
                st.markdown(
                    status_badge(status),
                    unsafe_allow_html=True,
                )

            left, middle, right = st.columns(
                [1.6, 1.2, 1]
            )

            with left:
                st.write(
                    f"**الرابط:** "
                    f"{system.get('url') or '—'}"
                )
                st.write(
                    f"**Endpoint:** "
                    f"{system.get('api_url') or '—'}"
                )

            with middle:
                st.write(
                    f"**HTTP:** "
                    f"{system.get('http_status') or '—'}"
                )
                st.write(
                    f"**Response:** "
                    f"{response_ms_text(system.get('response_ms'))}"
                )
                st.caption(
                    system.get(
                        "last_message"
                    ) or "—"
                )

            with right:
                if st.button(
                    "🔄 فحص الآن",
                    key=f"check_{system_id}",
                    use_container_width=True,
                ):
                    result = check_system(
                        system
                    )
                    old_status = system.get(
                        "status",
                        "Not Checked",
                    )

                    system.update(
                        {
                            "status": result["status"],
                            "http_status": result[
                                "http_status"
                            ],
                            "response_ms": result[
                                "response_ms"
                            ],
                            "last_message": result[
                                "message"
                            ],
                            "last_checked": (
                                datetime.datetime.now(
                                    datetime.timezone.utc
                                ).isoformat()
                            ),
                        }
                    )

                    if (
                        old_status != "Not Checked"
                        and old_status
                        != result["status"]
                    ):
                        try:
                            create_event(
                                system,
                                old_status,
                                result["status"],
                                result["message"],
                            )
                        except Exception:
                            pass

                    try:
                        update_system(system)
                    except Exception as exc:
                        st.error(
                            "فشل تحديث نتيجة الفحص."
                        )
                        st.code(
                            database_error(exc)
                        )
                    else:
                        st.success(
                            "تم تنفيذ الفحص."
                        )
                        st.rerun()

                if st.button(
                    "🗑️ حذف نهائي",
                    key=f"delete_{system_id}",
                    use_container_width=True,
                ):
                    st.session_state[
                        f"confirm_delete_{system_id}"
                    ] = True
                    st.rerun()

            if st.session_state.get(
                f"confirm_delete_{system_id}",
                False,
            ):
                st.error(
                    f"سيتم حذف «{company}» "
                    "نهائيًا من قاعدة البيانات."
                )

                yes, no = st.columns(2)

                with yes:
                    if st.button(
                        "تأكيد الحذف النهائي",
                        key=f"confirm_yes_{system_id}",
                        use_container_width=True,
                    ):
                        try:
                            permanently_delete_system(
                                system_id
                            )
                        except Exception as exc:
                            st.error(
                                "فشل الحذف من قاعدة البيانات."
                            )
                            st.code(
                                database_error(exc)
                            )
                        else:
                            st.success(
                                f"تم حذف «{company}» "
                                "نهائيًا."
                            )
                            st.session_state.pop(
                                f"confirm_delete_{system_id}",
                                None,
                            )
                            st.rerun()

                with no:
                    if st.button(
                        "إلغاء",
                        key=f"confirm_no_{system_id}",
                        use_container_width=True,
                    ):
                        st.session_state.pop(
                            f"confirm_delete_{system_id}",
                            None,
                        )
                        st.rerun()


def analytics_page():
    run_monitoring()

    try:
        systems = load_systems()
    except Exception as exc:
        st.error(
            "تعذر تحميل بيانات التحليل."
        )
        st.code(database_error(exc))
        return

    st.header("التحليلات")

    if not systems:
        st.info(
            "أضف منظومات أولًا."
        )
        return

    df = pd.DataFrame(
        [
            {
                "company": system.get(
                    "company",
                    "Unknown",
                ),
                "status": system.get(
                    "status",
                    "Not Checked",
                ),
                "response_ms": system.get(
                    "response_ms"
                ),
            }
            for system in systems
        ]
    )

    left, right = st.columns(2)

    with left:
        counts = (
            df["status"]
            .value_counts()
            .reset_index()
        )
        counts.columns = [
            "status",
            "count",
        ]

        fig = px.pie(
            counts,
            names="status",
            values="count",
            hole=.58,
            title="توزيع الحالات",
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    with right:
        response = df.dropna(
            subset=["response_ms"]
        )

        if response.empty:
            st.info(
                "لا توجد قياسات Response Time كافية."
            )
        else:
            fig = px.bar(
                response,
                x="company",
                y="response_ms",
                title="Response Time",
                labels={
                    "response_ms": "ms",
                    "company": "",
                },
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(
                fig,
                use_container_width=True,
            )


def events_page():
    st.header("سجل الأحداث")

    try:
        events = load_events()
    except Exception as exc:
        st.error(
            "تعذر تحميل سجل الأحداث."
        )
        st.code(database_error(exc))
        return

    if not events:
        st.info("لا توجد أحداث بعد.")
        return

    for event in events:
        st.markdown(
            f'<div class="incident-row">'
            f'<strong>{event["company"]}</strong>'
            f'<span class="small-muted"> · {event["time"]} · '
            f'{short_id(event["id"])}'
            f'</span><br>'
            f'الحالة: {event["old_status"]}'
            f' → {event["new_status"]}<br>'
            f'{event["message"]}'
            f'</div>',
            unsafe_allow_html=True,
        )


# ============================================================
# Router
# ============================================================

if not st.session_state.logged_in:
    login()
    st.stop()


with st.sidebar:
    st.markdown(
        """
        <div class="guardian-wordmark" style="justify-content:flex-start">
            <div class="guardian-mark" aria-hidden="true">
                <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M5 16c3.2-5 7-7.5 11-7.5S23.8 11 27 16c-3.2 5-7 7.5-11 7.5S8.2 21 5 16Z" stroke="#4DA3FF" stroke-width="1.8"/>
                    <circle cx="16" cy="16" r="3.5" stroke="#E7EEF7" stroke-width="1.8"/>
                    <circle cx="16" cy="16" r="1.4" fill="#4DA3FF"/>
                </svg>
            </div>
            <div>
                <div class="wordmark-name">GuardianEye</div>
                <div class="wordmark-meta">OPERATIONS MONITORING</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    pages = [
        "Overview",
        "Systems",
        "Add System",
        "Analytics",
        "Events",
    ]

    current_index = (
        pages.index(st.session_state.page)
        if st.session_state.page in pages
        else 0
    )

    st.session_state.page = st.radio(
        "Navigation",
        pages,
        index=current_index,
    )

    st.divider()

    st.markdown(
        f'<div class="small-muted">'
        f'Logged in as<br>'
        f'<strong style="color:#edf4ff">'
        f'{ADMIN_USER}'
        f'</strong>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if st.button(
        "تسجيل الخروج",
        use_container_width=True,
    ):
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
