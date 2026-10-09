
import streamlit as st
import re
import ipaddress
import pandas as pd
import joblib
from urllib.parse import urlparse, unquote

st.set_page_config(
    page_title="LinkGuard | لينك قارد",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------- تحميل نموذج الذكاء الاصطناعي --------------------

@st.cache_resource
def load_linkguard_model():
    try:
        return joblib.load("linkguard_model.pkl")
    except Exception:
        return None

ML_MODEL = load_linkguard_model()

MODEL_FEATURES = [
    "url_length",
    "has_https",
    "has_ip",
    "has_at",
    "has_dash",
]

# -------------------- التصميم --------------------

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #070707, #19040a, #30000b);
    color: #f8f8f8;
}
.block-container {
    max-width: 1150px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}
.hero {
    text-align: center;
    padding: 25px 10px 18px;
}
.hero h1 {
    font-size: 54px;
    font-weight: 900;
    color: #ffffff;
    text-shadow: 0 0 22px #ff1744;
    margin-bottom: 4px;
}
.hero p {
    color: #e3aab5;
    font-size: 18px;
}
.panel {
    background: rgba(18, 8, 11, 0.95);
    border: 1px solid #642032;
    padding: 23px;
    border-radius: 18px;
    margin: 12px 0;
}
.result {
    background: linear-gradient(120deg, #21070e, #10090b);
    border: 1px solid #a51c3c;
    border-radius: 18px;
    padding: 25px;
    text-align: center;
}
.result-number {
    font-size: 56px;
    font-weight: 900;
    color: #ff536b;
}
.reason {
    background: #1c0b10;
    border-right: 4px solid #ff3457;
    padding: 12px 15px;
    border-radius: 8px;
    margin: 8px 0;
}
.small-note {
    color: #c6aeb4;
    font-size: 13px;
}
.stTextInput input {
    background: #0b0809 !important;
    color: white !important;
    border: 1px solid #8a1b35 !important;
    border-radius: 10px !important;
}
.stButton button {
    border-radius: 10px;
    min-height: 47px;
    font-weight: 800;
}
div[data-testid="stMetric"] {
    background: #170a0e;
    border: 1px solid #4b1827;
    border-radius: 12px;
    padding: 12px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>🛡️ لينك قارد</h1>
    <p>LinkGuard — منصة تحليل مؤشرات خطورة الروابط</p>
</div>
""", unsafe_allow_html=True)

# -------------------- إعدادات الكشف --------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "ow.ly", "buff.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "rebrand.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "password",
    "signin", "account", "wallet", "payment",
    "reset", "confirm", "auth", "credential"
}

# -------------------- تحليل الرابط --------------------

def analyze_url(raw_url):
    original = raw_url.strip()

    if not original:
        raise ValueError("أدخل رابطًا أولًا.")

    if any(ord(char) < 32 for char in original):
        raise ValueError("الرابط يحتوي على محارف غير مسموحة.")

    if re.search(r"\s", original):
        raise ValueError("الرابط يحتوي على مسافات. تحقق من كتابته.")

    candidate = original
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("تعذر تحليل الرابط. تحقق من الرابط والمنفذ.")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("المسموح هو روابط HTTP وHTTPS فقط.")

    if not hostname:
        raise ValueError("لم يتم العثور على اسم نطاق صالح.")

    hostname = hostname.lower().rstrip(".")

    if not hostname or "." not in hostname:
        raise ValueError("أدخل اسم نطاق كاملًا، مثل example.com.")

    if len(hostname) > 253:
        raise ValueError("اسم النطاق أطول من الحد المعتاد.")

    if any(not label for label in hostname.split(".")):
        raise ValueError("اسم النطاق يحتوي على أجزاء فارغة.")

    decoded_url = unquote(candidate)
    host_for_ip = hostname.strip("[]")

    try:
        ipaddress.ip_address(host_for_ip)
        is_ip = True
    except ValueError:
        is_ip = False

    score = 0
    findings = []

    def add_finding(points, message):
        nonlocal score
        score += points
        findings.append((points, message))

    if parsed.scheme.lower() != "https":
        add_finding(15, "الاتصال يستخدم HTTP بدل HTTPS.")

    if is_ip:
        add_finding(25, "وجهة الرابط عنوان IP مباشر بدل اسم نطاق.")

    if "@" in parsed.netloc:
        add_finding(25, "وجود @ في جزء الوجهة قد يخفي اسم المضيف الحقيقي.")

    labels = hostname.split(".")
    if not is_ip and len(labels) >= 5:
        add_finding(15, "اسم النطاق يحتوي على أجزاء فرعية كثيرة.")

    if "-" in hostname:
        add_finding(5, "اسم النطاق يحتوي على شرطة؛ وهي إشارة ضعيفة بمفردها.")

    if any(label.startswith("xn--") for label in labels):
        add_finding(15, "اسم النطاق يحتوي على صيغة Punycode تستحق التحقق.")

    if "%" in candidate and decoded_url != candidate:
        add_finding(10, "الرابط يحتوي على محارف مرمّزة.")

    path_and_query = (parsed.path + "?" + parsed.query).lower()

    found_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            path_and_query
        )
    )

    if found_words:
        add_finding(
            10,
            "المسار أو الاستعلام يحتوي على كلمات ترتبط أحيانًا "
            "بتسجيل الدخول أو بيانات الحساب."
        )

    if len(candidate) > 100:
        add_finding(10, "الرابط طويل بشكل ملحوظ.")

    is_shortener = hostname in SHORTENERS

    if is_shortener:
        add_finding(
            15,
            "خدمة اختصار روابط؛ لا يمكن معرفة الوجهة النهائية من الرابط وحده."
        )

    if port is not None and port not in (80, 443):
        add_finding(5, f"الرابط يستخدم منفذًا غير شائع: {port}.")

    score = min(score, 100)

    if score >= 60:
        level = "مرتفعة"
        icon = "🚨"
        color = "#ff405d"
    elif score >= 30:
        level = "متوسطة"
        icon = "⚠️"
        color = "#ffb547"
    else:
        level = "منخفضة حسب القواعد"
        icon = "🔎"
        color = "#55d6a5"

    # -------------------- تنبؤ نموذج التعلم الآلي --------------------

    model_prediction = None
    model_error = None

    if ML_MODEL is not None:
        try:
            features = pd.DataFrame(
                [[
                    len(candidate),
                    int(parsed.scheme.lower() == "https"),
                    int(is_ip),
                    int("@" in parsed.netloc),
                    int("-" in hostname),
                ]],
                columns=MODEL_FEATURES,
            )

            model_prediction = int(ML_MODEL.predict(features)[0])

        except Exception as error:
            model_error = str(error)

    return {
        "url": candidate,
        "hostname": hostname,
        "score": score,
        "level": level,
        "icon": icon,
        "color": color,
        "findings": findings,
        "is_https": parsed.scheme.lower() == "https",
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "length": len(candidate),
        "found_words": found_words,
        "model_prediction": model_prediction,
        "model_error": model_error,
    }

# -------------------- سجل الجلسة --------------------

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# -------------------- واجهة الفحص --------------------

st.markdown('<div class="panel">', unsafe_allow_html=True)
st.subheader("🔎 فحص رابط")

with st.form("link_scan_form"):
    url_input = st.text_input(
        "أدخل الرابط المراد تحليله",
        placeholder="https://example.com/page",
    )

    submitted = st.form_submit_button(
        "🛡️ تحليل الرابط",
        type="primary",
        use_container_width=True,
    )

if submitted:
    try:
        result = analyze_url(url_input)
        st.session_state.latest_result = result

        st.session_state.scan_history.insert(0, {
            "الرابط": result["url"],
            "درجة المؤشرات": result["score"],
            "مستوى المؤشرات": result["level"],
            "تصنيف النموذج": (
                result["model_prediction"]
                if result["model_prediction"] is not None
                else "غير متاح"
            ),
        })

        st.session_state.scan_history = (
            st.session_state.scan_history[:20]
        )

    except ValueError as error:
        st.session_state.latest_result = None
        st.error(str(error))

st.markdown(
    '<p class="small-note">يحلل النظام خصائص الرابط فقط، ولا يفتح الموقع '
    'ولا يضمن اكتشاف جميع التهديدات.</p>',
    unsafe_allow_html=True,
)

st.markdown('</div>', unsafe_allow_html=True)

# -------------------- عرض النتائج --------------------

result = st.session_state.get("latest_result")

if result:
    st.markdown("## 📊 نتيجة التحليل")

    st.markdown(f"""
    <div class="result">
        <div style="font-size:48px">{result["icon"]}</div>
        <div class="result-number" style="color:{result["color"]}">
            {result["score"]}/100
        </div>
        <h2>مستوى المؤشرات: {result["level"]}</h2>
        <p class="small-note">
            هذه درجة تجريبية مبنية على قواعد، وليست احتمالًا إحصائيًا
            مؤكدًا لأن يكون الرابط خبيثًا.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # -------------------- نتيجة الذكاء الاصطناعي --------------------

    st.markdown("### 🤖 تصنيف نموذج التعلم الآلي")

    if result["model_prediction"] is not None:
        prediction = result["model_prediction"]

        st.info(
            f"تصنيف النموذج: الفئة {prediction}\n\n"
            "هذا تصنيف تجريبي. يجب التأكد من معنى الفئات في بيانات "
            "التدريب قبل تفسيرها على أنها آمنة أو خبيثة."
        )

    elif result["model_error"]:
        st.warning(
            "تعذر الحصول على تنبؤ من النموذج. "
            "ما زال تحليل القواعد متاحًا."
        )

    else:
        st.warning(
            "نموذج الذكاء الاصطناعي غير متاح. "
            "تأكد من وجود linkguard_model.pkl داخل مجلد المشروع."
        )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("طول الرابط", f'{result["length"]} حرفًا')
    c2.metric("HTTPS", "نعم" if result["is_https"] else "لا")
    c3.metric("عنوان IP", "نعم" if result["is_ip"] else "لا")
    c4.metric(
        "رابط مختصر",
        "نعم" if result["is_shortener"] else "لا"
    )

    st.markdown("### 🧠 لماذا حصل على هذه النتيجة؟")

    if result["findings"]:
        for points, message in result["findings"]:
            st.markdown(
                f'<div class="reason"><b>+{points} نقطة</b> — '
                f'{message}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.success(
            "لم ترصد القواعد الحالية مؤشرات الاشتباه التي تبحث عنها."
        )

    if result["found_words"]:
        st.markdown(
            "**الكلمات التي رُصدت في المسار أو الاستعلام:**"
        )
        st.write(", ".join(result["found_words"]))

    with st.expander("عرض التفاصيل التقنية"):
        st.write("**اسم المضيف المستخرج:**")
        st.code(result["hostname"])

        st.write("**الرابط المحلل:**")
        st.code(result["url"])

    st.warning(
        "لا تدخل كلمات مرور أو بيانات شخصية في أي موقع مشكوك فيه. "
        "انخفاض الدرجة لا يثبت أن الموقع آمن، وHTTPS لا يثبت "
        "موثوقية صاحبه."
    )

# -------------------- سجل الفحوصات --------------------

st.markdown("---")
st.subheader("🗂️ سجل الفحوصات")

if st.session_state.scan_history:
    st.dataframe(
        st.session_state.scan_history,
        use_container_width=True,
        hide_index=True,
    )

    if st.button("🗑️ مسح سجل الجلسة"):
        st.session_state.scan_history = []
        st.rerun()
else:
    st.caption("ستظهر هنا آخر نتائج الفحص خلال الجلسة الحالية.")

st.markdown("---")

st.caption(
    "LinkGuard | نموذج أولي تعليمي للأمن السيبراني — "
    "النتائج إرشادية وليست شهادة بسلامة المواقع تم انشاء لينك قارد من قبل حسام الحارثي."
)