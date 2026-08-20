import streamlit as st
import pandas as pd
import datetime
import plotly.express as px
import json
import os

# =========================
# إعداد الصفحة
# =========================
st.set_page_config(page_title="GuardianEye", layout="wide")

# ====================
# لمسات تصميمية للواجهة
# ====================
st.markdown("""
<style>
/* خلفية متدرجة متحركة */
@keyframes gradientMove {
    0% {background-position: 0% 50%;}
    50% {background-position: 100% 50%;}
    100% {background-position: 0% 50%;}
}
body {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    background-size: 200% 200%;
    animation: gradientMove 15s ease infinite;
    color: #f8fafc;
}

/* تأثير نيون على النص */
h1 {
    color: #38bdf8 !important;
    text-shadow: 0 0 10px #00c8ff, 0 0 20px #00c8ff, 0 0 30px #00c8ff;
    font-family: 'Cairo', sans-serif;
    font-weight: bold;
    animation: glow 2s ease-in-out infinite alternate;
}
@keyframes glow {
    from { text-shadow: 0 0 10px #00c8ff; }
    to { text-shadow: 0 0 30px #00c8ff, 0 0 60px #00c8ff; }
}

/* الأزرار */
.stButton>button {
    background-color: #1e293b;
    color: #f8fafc;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: bold;
    transition: 0.3s;
    box-shadow: 0 0 15px #00c8ff;
}
.stButton>button:hover {
    background-color: #38bdf8;
    color: #0f172a;
}
</style>
""", unsafe_allow_html=True)
from streamlit_autorefresh import st_autorefresh
# يحدث الصفحة كل ثانية (1000 ملي ثانية)
st_autorefresh(interval=1000, limit=None, key="refresh")

# =========================
# ملف تخزين البيانات
# =========================
DATA_FILE = "systems.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# =========================
# Session State
# =========================
if "systems" not in st.session_state:
    st.session_state.systems = load_data()
if "logs" not in st.session_state:
    st.session_state.logs = []
if "users" not in st.session_state:
    st.session_state.users = {"MalkX07":"abdalmalk107"}  # مستخدم افتراضي
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "role" not in st.session_state:
    st.session_state.role = None

# =========================
# نظام تسجيل الدخول
# =========================
def login():
    st.sidebar.subheader("🔑 تسجيل الدخول")
    username = st.sidebar.text_input("اسم المستخدم")
    password = st.sidebar.text_input("كلمة المرور", type="password")
    if st.sidebar.button("دخول"):
        if username in st.session_state.users and st.session_state.users[username] == password:
            st.session_state.logged_in = True
            st.session_state.role = "admin" if username == "MalkX07" else "user"
            st.success("تم تسجيل الدخول بنجاح ✅")
        else:
            st.error("بيانات الدخول غير صحيحة ❌")

def logout():
    st.session_state.logged_in = False
    st.session_state.role = None
    st.sidebar.success("تم تسجيل الخروج ✅")
if st.session_state.get("logged_in", False):
    st.title("👁️ GuardianEye Dashboard")
    st.success("مرحباً بك يا مدير النظام ✅")

    # قسم المنظومات
    st.header("🏢 المنظومات")
    if st.session_state.systems:
        st.table(st.session_state.systems)
    else:
        st.info("لا توجد منظومات مسجلة حالياً")

    # قسم الإحصائيات
    st.header("📊 الإحصائيات")
    st.metric("عدد المنظومات", len(st.session_state.systems))
    st.line_chart([1, 3, 2, 4])

    # قسم سجل الأحداث
    st.header("📜 سجل الأحداث")
    if st.session_state.logs:
        for log in st.session_state.logs:
            st.write(log)
    else:
        st.info("لا توجد أحداث مسجلة")

    # قسم الإعدادات
    st.header("⚙️ الإعدادات")
    st.write("إعدادات النظام ستظهر هنا")

    # زر إضافة منظومة جديدة
    if st.button("➕ إضافة منظومة جديدة"):
        st.write("هنا تقدر تضيف منظومة جديدة")

# =========================
# دوال كشف الهجمات
# =========================
def detect_attack(url):
    attacks = {
        "SQL Injection": ["sql", "union", "select", "' OR '1'='1"],
        "XSS": ["<script>", "alert(", "onerror=", "javascript:"],
        "Directory Traversal": ["../", "/etc/passwd", "c:\\windows"]
    }
    for attack, patterns in attacks.items():
        for p in patterns:
            if p.lower() in url.lower():
                return attack
    return None
# =========================
# واجهة الموقع
# =========================
st.markdown("""
<h1 style='text-align:center; color:#00BFFF;'>👁️ GuardianEye</h1>
<h3 style='text-align:center; color:#FFD700;'>🛡️ مركز مراقبة الشركات والمنظومات</h3>
""", unsafe_allow_html=True)
# =========================
# تحقق من تسجيل الدخول
# =========================
if not st.session_state.logged_in:
    login()
else:
    st.sidebar.button("🚪 تسجيل الخروج", on_click=logout)

    # ====================
    # ساعة رقمية متوهجة
    # ====================
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"<h3 style='text-align:center; color:#38bdf8;'>🕒 {now}</h3>", unsafe_allow_html=True)

    # ====================
    # Tabs رئيسية
    # ====================
    tab1, tab2, tab3, tab4 = st.tabs(["🏢 المنظومات", "📊 الإحصائيات", "📜 سجل الأحداث", "⚙️ الإعدادات"])

    # =========================
    # Tab 1: المنظومات
    # =========================
    with tab1:
        st.subheader("➕ إضافة منظومة جديدة")
        company = st.text_input("اسم الشركة/المؤسسة:")
        url = st.text_input("رابط المنظومة:")
        if st.button("إضافة"):
            if company and url:
                attack = detect_attack(url)
                status = "🚨 تحت هجوم" if attack else "✅ سليم"
                entry = {
                    "company": company,
                    "url": url,
                    "status": status,
                    "attack": attack if attack else "لا يوجد",
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                st.session_state.systems.append(entry)
                save_data(st.session_state.systems)
                if attack:
                    st.session_state.logs.append(f"{company} تعرض لهجوم {attack} في {entry['time']}")
                st.success(f"تمت إضافة {company} بنجاح ✅")

        # عدادات
        col1, col2, col3 = st.columns(3)
        col1.metric("عدد المنظومات", len(st.session_state.systems))
        col2.metric("عدد الهجمات المكتشفة", sum(1 for s in st.session_state.systems if s["status"] == "🚨 تحت هجوم"))
        col3.metric("عدد المنظومات السليمة", sum(1 for s in st.session_state.systems if s["status"] == "✅ سليم"))

        # جدول المنظومات
        if st.session_state.systems:
            df = pd.DataFrame(st.session_state.systems)
            search = st.text_input("🔍 بحث عن منظومة")
            if search:
                df = df[df["company"].str.contains(search)]
            st.dataframe(df, width="stretch")

            # زر تصدير
            st.download_button("⬇️ تحميل CSV", df.to_csv(index=False).encode("utf-8"), "systems.csv", "text/csv")

            # تفاصيل + تعديل + حذف
            for i, s in enumerate(st.session_state.systems):
                with st.expander(f"تفاصيل {s['company']}"):
                    st.write(f"🔗 الرابط: {s['url']}")
                    st.write(f"📌 الحالة: {s['status']}")
                    st.write(f"⚠️ نوع الهجوم: {s['attack']}")
                    st.write(f"⏰ آخر فحص: {s['time']}")

                    new_name = st.text_input(f"تعديل اسم المؤسسة {i}", s["company"])
                    new_url = st.text_input(f"تعديل الرابط {i}", s["url"])
                    if st.button(f"تعديل {i}"):
                        st.session_state.systems[i]["company"] = new_name
                        st.session_state.systems[i]["url"] = new_url
                        save_data(st.session_state.systems)
                        st.success("تم تعديل البيانات ✅")

                    if st.button(f"حذف {i}"):
                        st.session_state.systems.pop(i)
                        save_data(st.session_state.systems)
                        st.warning("تم حذف المؤسسة ❌")

    # =========================
    # Tab 2: الإحصائيات
    # =========================      with tab2:
        st.subheader("📊 إحصائيات المنظومات")
        if st.session_state.systems:
            df = pd.DataFrame(st.session_state.systems)
            fig1 = px.pie(df, names="status", title="نسبة الحالات")
            st.plotly_chart(fig1, width="stretch")

            fig2 = px.bar(df, x="company", y="status", color="status", title="حالة كل منظومة")
            st.plotly_chart(fig2, width="stretch")

            attacks = df["attack"].value_counts()
            fig3 = px.bar(attacks, x=attacks.index, y=attacks.values, title="أكثر أنواع الهجمات شيوعًا")
            st.plotly_chart(fig3, width="stretch")
        else:
            st.info("لا توجد بيانات بعد.")

    # =========================
    # Tab 3: سجل الأحداث
    # =========================
    with tab3:
        st.subheader("📜 سجل الأحداث")
        if st.session_state.logs:
            for log in st.session_state.logs:
                st.warning(log)
        else:
            st.info("لا توجد أحداث بعد.")

    # =========================
    # Tab 4: الإعدادات
    # =========================
    with tab4:
        st.subheader("⚙️ إعدادات الموقع")
        theme = st.radio("اختر الثيم:", ["Light", "Dark", "Corporate"])
        lang = st.radio("اختر اللغة:", ["العربية", "English"])
        st.success(f"تم تطبيق الإعدادات: {theme}, {lang}")

    # =========================
    # إنذار صوتي عند الهجوم
    # =========================
    if any(s["status"] == "🚨 تحت هجوم" for s in st.session_state.systems):
        st.markdown("""
        <audio autoplay>
        <source src="https://www.soundjay.com/button/beep-07.wav" type="audio/wav">
        </audio>
        """, unsafe_allow_html=True)

# =========================
# ميزات الأمان المتقدمة
# =========================
import smtplib
from email.mime.text import MIMEText

def send_email_alert(company, attack):
    sender = "guardianeye.alerts@example.com"
    receiver = "admin@example.com"
    msg = MIMEText(f"🚨 الشركة {company} تعرضت لهجوم {attack}")
    msg["Subject"] = "GuardianEye Alert"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(sender, "password")
            server.sendmail(sender, receiver, msg.as_string())
        st.success("📧 تم إرسال تنبيه بالبريد الإلكتروني")
    except Exception as e:
        st.error(f"فشل إرسال البريد: {e}")

# =========================
# مصادقة ثنائية (2FA)
# =========================
import random

def generate_2fa_code():
    return str(random.randint(100000, 999999))

if "twofa_code" not in st.session_state:
    st.session_state["twofa_code"] = None

def two_factor_auth():
    if st.session_state.role == "admin":
        if st.session_state["twofa_code"] is None:
         st.session_state["twofa_code"] = generate_2fa_code()
        st.info(f"رمز المصادقة الثنائية: {st.session_state['twofa_code']}")
        code = st.text_input("أدخل رمز 2FA:")
        if st.button("تحقق"):
            if code == st.session_state["twofa_code"]:
                st.success("✅ تم التحقق بنجاح")
                st.session_state["twofa_code"] = None
            else:
                st.error("❌ رمز غير صحيح")

# =========================
# API للتكامل الخارجي
# =========================
import flask
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/api/systems", methods=["GET"])
def get_systems():
    return jsonify(st.session_state.systems)

@app.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify(st.session_state.logs)

# =========================
# Webhook للتنبيهات
# =========================
import requests

def send_webhook(company, attack):
    url = "https://hooks.slack.com/services/XXXX/XXXX/XXXX"
    payload = {"text": f"🚨 الشركة {company} تعرضت لهجوم {attack}"}
    try:
        requests.post(url, json=payload)
        st.success("📡 تم إرسال تنبيه عبر Webhook")
    except Exception as e:
        st.error(f"فشل إرسال Webhook: {e}")

# =========================
# دعم لغتين كامل
# =========================
translations = {
    "ar": {
        "add_system": "➕ إضافة منظومة جديدة",
        "stats": "📊 إحصائيات المنظومات",
        "logs": "📜 سجل الأحداث",
        "settings": "⚙️ إعدادات الموقع"
    },
    "en": {
        "add_system": "➕ Add New System",
        "stats": "📊 Systems Statistics",
        "logs": "📜 Event Logs",
        "settings": "⚙️ Site Settings"
    }
}

def t(key):
    lang = "ar" if "lang" not in st.session_state else st.session_state.lang
    return translations[lang][key]

# =========================
# تحسينات إضافية في الواجهة
# =========================
def show_dashboard():
    st.markdown("<h2 style='color:#32CD32;'>📊 Dashboard حيّ</h2>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    col1.metric("عدد المؤسسات", len(st.session_state.systems))
    col2.metric("عدد الهجمات", sum(1 for s in st.session_state.systems if s["status"] == "🚨 تحت هجوم"))
    col3.metric("عدد السليمة", sum(1 for s in st.session_state.systems if s["status"] == "✅ سليم"))

    if st.session_state.systems:
        latest = st.session_state.systems[-1]
        st.info(f"آخر مؤسسة تمت إضافتها: {latest['company']} ({latest['status']})")

# =========================
# استدعاء الميزات
# =========================
if st.session_state.logged_in:
    show_dashboard()
    two_factor_auth()
