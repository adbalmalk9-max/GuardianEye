import streamlit as st
import datetime
import pandas as pd
from streamlit_autorefresh import st_autorefresh  
import json
import os
import plotly.express as px

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
    st.session_state.users = {"MalkX03": "Abdalmalk10722"}  # مدير النظام
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "role" not in st.session_state:
    st.session_state.role = None

# =========================
# نظام تسجيل الدخول
# =========================
def login():
    st.sidebar.subheader(" تسجيل الدخول")
    username = st.sidebar.text_input("اسم المستخدم", key="username_field")
    password = st.sidebar.text_input("كلمة المرور", type="password", key="password_field")
    if st.sidebar.button("دخول", key="login_submit"):
        if username in st.session_state.users and st.session_state.users[username] == password:
            st.session_state.logged_in = True
            st.session_state.role = "admin" if username == "MalkX03" else "user"
            st.success("تم تسجيل الدخول بنجاح ✅")
        else:
            st.error("بيانات الدخول غير صحيحة ❌")

def logout():
    st.session_state.logged_in = False
    st.session_state.role = None
    st.sidebar.success("تم تسجيل الخروج ✅")

# =========================
# تحقق من تسجيل الدخول
# =========================
if not st.session_state.logged_in:
    # واجهة البداية تظهر فقط قبل الدخول
    st.markdown("""
    <h1 style='text-align:center; color:#00BFFF;'> GuardianEye</h1>
    <h3 style='text-align:center; color:#FFD700;'>🛡️ مركز مراقبة الشركات والمنظومات</h3>
    """, unsafe_allow_html=True)
    login()
else:
    st.title(" GuardianEye Dashboard")
    st.success("مرحباً بك يا مدير النظام ")
    st.sidebar.button(" تسجيل الخروج", on_click=logout, key="logout_button")

    # ساعة رقمية متوهجة
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"<h3 style='text-align:center; color:#38bdf8;'> {now}</h3>", unsafe_allow_html=True)

    # قسم المنظومات
    st.header(" المنظومات")
    st.subheader("+ إضافة منظومة جديدة")
    company = st.text_input("اسم الشركة/المؤسسة:")
    url = st.text_input("رابط المنظومة:")
    api_url = st.text_input("رابط الـ API (اختياري):")
    api_key = st.text_input("مفتاح الـ API (اختياري):", type="password")

    if st.button("إضافة"):
        if company and url:
            attack = detect_attack(url)
            status = "🚨 تحت هجوم" if attack else "✅ سليم"
            entry = {
                "company": company,
                "url": url,
                "api_url": api_url,
                "api_key": api_key if api_key else "لا يوجد",
                "status": status,
                "attack": attack if attack else "لا يوجد",
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            st.session_state.systems.append(entry)
            save_data(st.session_state.systems)  # يحفظ مباشرة في قاعدة البيانات
            if attack:
                st.session_state.logs.append(f"{company} تعرض لهجوم {attack} في {entry['time']}")
            st.success(f"تمت إضافة {company} بنجاح ✅")

    # جدول المنظومات + تعديل + حذف + تصدير
    if st.session_state.systems:
        df = pd.DataFrame(st.session_state.systems)
        st.dataframe(df, width="stretch")

        for i, s in enumerate(st.session_state.systems):
            with st.expander(f"تفاصيل {s['company']}"):
                st.write(f"🔗 الرابط: {s['url']}")
                st.write(f"📌 الحالة: {s['status']}")
                st.write(f"⚠️ نوع الهجوم: {s['attack']}")
                st.write(f"⏰ آخر فحص: {s['time']}")

                if st.button(f"حذف {i}"):
                    st.session_state.systems.pop(i)
                    save_data(st.session_state.systems)  # تحديث الملف مباشرة
                    st.success("✅ تم الحذف نهائيًا من النظام والملف")

    # =========================
    # قسم الإحصائيات
    # =========================
    st.header("📊 إحصائيات المنظومات")
    if st.session_state.systems:
        df = pd.DataFrame(st.session_state.systems)
        fig1 = px.pie(df, names="status", title="نسبة الحالات")
        st.plotly_chart(fig1, use_container_width=True)

        fig2 = px.bar(df, x="company", y="status", color="status", title="حالة كل منظومة")
        st.plotly_chart(fig2, use_container_width=True)

        attacks = df["attack"].value_counts()
        fig3 = px.bar(attacks, x=attacks.index, y=attacks.values, title="أكثر أنواع الهجمات شيوعًا")
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("لا توجد بيانات بعد.")

    # =========================
    # قسم سجل الأحداث
    # =========================
    st.header(" سجل الأحداث")
    if st.session_state.logs:
        for log in st.session_state.logs:
            st.warning(log)
    else:
        st.info("لا توجد أحداث بعد.")

    # =========================
    # قسم الإعدادات
    # =========================
    st.header("⚙️ إعدادات الموقع")
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
                st.success(" تم التحقق بنجاح")
                st.session_state["twofa_code"] = None
            else:
                st.error(" رمز غير صحيح")
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


    # توقيع باسم صاحب المشروع
st.markdown(
    "<div style='text-align:left; color:white; font-size:22px; font-weight:bold; text-shadow: 0 0 8px #00f, 0 0 15px #00f;'>Abdalmalk Kareem</div>",
    unsafe_allow_html=True
)
