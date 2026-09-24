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
    st.markdown(
        """
        <div style="
            max-width:620px;
            margin:8vh auto 0 auto;
            padding:2rem;
            border-radius:22px;
            border:1px solid rgba(148,163,184,.16);
            background:#101722;
            box-shadow:0 25px 70px rgba(0,0,0,.35);
        ">
            <div style="font-size:3rem">🛡️</div>
            <div class="guardian-title">GuardianEye</div>
            <div class="guardian-subtitle">
                مركز مراقبة المنظومات والخدمات المصرّح لك بإدارتها
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
        if (
            username == ADMIN_USER
            and password == ADMIN_PASSWORD
        ):
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("بيانات الدخول غير صحيحة.")

    st.markdown(
        '<div class="small-muted" style="margin-top:1rem">'
        "الوصول محمي. لا تشارك بيانات الدخول."
        "</div></div>",
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
        "🛡️ الحذف النهائي يتم مباشرة من قاعدة البيانات."
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
        '<div style="font-size:1.8rem;font-weight:800">'
        '🛡️ GuardianEye'
        '</div>'
        '<div class="small-muted">'
        'Operations Monitoring Center'
        '</div>',
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