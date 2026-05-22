import streamlit as st
import pandas as pd
import joblib
import bcrypt
import time
from datetime import datetime
import os
import random
import plotly.graph_objects as go
import smtplib
from email.message import EmailMessage

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="AI/ML Enhanced MFA", layout="wide")

# --- 1. INITIALIZE MOCK DATABASE & SESSION STATE ---
if "users_db" not in st.session_state:
    hashed_pw = bcrypt.hashpw("Secure123!".encode('utf-8'), bcrypt.gensalt())
    st.session_state.users_db = {
        "student1": {
            "password_hash": hashed_pw,
            "known_device": "laptop-01",
            "email": "davidleesi2201@gmail.com" # <--- PUT YOUR EMAIL HERE
        }
    }

if "tracker" not in st.session_state:
    st.session_state.tracker = {} 

if "auth_stage" not in st.session_state:
    st.session_state.auth_stage = "login" 

if "current_username" not in st.session_state:
    st.session_state.current_username = ""

if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = []

if "otp_attempts" not in st.session_state:
    st.session_state.otp_attempts = 0

if "sent_otp" not in st.session_state:
    st.session_state.sent_otp = None

# --- 2. HELPER FUNCTIONS ---
def get_tracker(username):
    if username not in st.session_state.tracker:
        st.session_state.tracker[username] = {
            "failed_attempts": 0,
            "last_attempt_time": 0.0,
            "blocked_until": 0.0
        }
    return st.session_state.tracker[username]

def check_password(plain_pwd, hashed_pwd):
    return bcrypt.checkpw(plain_pwd.encode('utf-8'), hashed_pwd)

def extract_features(username, device_id, password_correct, tracker):
    current_time = time.time()
    f1_failed_attempts = tracker["failed_attempts"]
    f2_short_interval = 1 if (current_time - tracker["last_attempt_time"]) < 5 else 0
    
    f3_unknown_device = 1
    if username in st.session_state.users_db:
        if device_id == st.session_state.users_db[username]["known_device"]:
            f3_unknown_device = 0
            
    current_hour = datetime.now().hour
    f4_unusual_hour = 1 if 0 <= current_hour < 5 else 0
    f5_password_match = 1 if password_correct else 0
    
    tracker["last_attempt_time"] = current_time
    return [f1_failed_attempts, f2_short_interval, f3_unknown_device, f4_unusual_hour, f5_password_match]

def create_gauge_chart(risk_score):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = risk_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Statistical Risk Probability", 'font': {'size': 18}},
        number = {'suffix': "%"},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkgray"},
            'bar': {'color': "black"}, 
            'steps': [
                {'range': [0, 33], 'color': "#00cc96"},   
                {'range': [33, 66], 'color': "#ffa15a"},  
                {'range': [66, 100], 'color': "#ef553b"}  
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': risk_score
            }
        }
    ))
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=40, b=10))
    return fig

def log_event(username, ip, location, risk_level, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.audit_logs.insert(0, {
        "Time": timestamp,
        "User": username,
        "IP Address": ip,
        "Location": location,
        "Risk": risk_level,
        "Action Taken": action
    })

def send_email_otp(receiver_email, otp_code):
    sender_email = "davidleesi2201@gmail.com" 
    app_password = "csrb aatw tpln hhmm"  

    msg = EmailMessage()
    msg.set_content(f"Your secure verification code is: {otp_code}\n\nDo not share this code with anyone.")
    msg['Subject'] = "Security Alert: Your Login OTP"
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Failed to send email. Error: {e}")
        return False

# --- 3. LOAD THE ML MODEL ---
@st.cache_resource
def load_model():
    try:
        return joblib.load("rf_risk_model.pkl")
    except FileNotFoundError:
        st.error("Model not found! Please run train_model.py first.")
        st.stop()

rf_model = load_model()

# --- 4. UI AND LOGIC FLOW ---

st.title("🛡️ AI/ML-Enhanced MFA System")

# Dynamic Status Tracker Header
stage_colors = {
    "login": "🔵 Step 1: Login & Signal Extraction",
    "captcha": "🟠 Step 2: Anomaly Verification Challenge",
    "otp": "🟡 Step 3: Step-Up MFA (Email OTP)",
    "success": "🟢 Step 4: Secure Access Granted"
}
st.caption(f"**Current System State:** {stage_colors.get(st.session_state.auth_stage)}")
st.markdown("---")

# =========================================================
# STAGE 1: LOGIN
# =========================================================
if st.session_state.auth_stage == "login":
    
    with st.container(border=True):
        st.markdown("### 🔐 Enter Credentials & Context")
        st.write("Simulate a login attempt by providing user credentials and behavioral metadata.")
        
        with st.form("login_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                username = st.text_input("Username", help="Demo account is 'student1'").strip()
                password = st.text_input("Password", type="password", help="Demo password is 'Secure123!'")
                device_id = st.text_input("Device ID", placeholder="laptop-01", help="Use 'laptop-01' for familiar device, or 'hacker-pc' to simulate anomaly.").strip()
                
            with col2:
                ip_address = st.text_input("IP Address", placeholder="192.168.1.100", help="Simulate network location.").strip()
                location = st.text_input("Location", placeholder="Sarawak, MY", help="Geographic context.").strip()
                
            submit_col1, submit_col2, submit_col3 = st.columns([1,2,1])
            with submit_col2:
                submit_button = st.form_submit_button("Sign In via Secure Portal", type="primary", use_container_width=True)

    if submit_button:
        if not username or not password or not device_id or not ip_address or not location:
            st.warning("⚠️ Please fill in all signal fields to simulate the login.")
        else:
            tracker = get_tracker(username)
            current_time = time.time()
            
            # Check if user is actively blocked
            if current_time < tracker["blocked_until"]:
                countdown_placeholder = st.empty()
                while time.time() < tracker["blocked_until"]:
                    remaining = int(tracker["blocked_until"] - time.time())
                    countdown_placeholder.error(f"🚨 Account locked. Try again in {remaining}s.")
                    time.sleep(1)
                countdown_placeholder.empty()
                st.rerun()
            else:
                # OPTION A: Handle Password Logic BEFORE the ML Engine
                password_correct = False
                if username in st.session_state.users_db:
                    stored_hash = st.session_state.users_db[username]["password_hash"]
                    password_correct = check_password(password, stored_hash)

                if not password_correct:
                    # Increment failed attempts
                    tracker["failed_attempts"] += 1
                    
                    if tracker["failed_attempts"] >= 5:
                        # STRIKE 5: Lockout
                        tracker["blocked_until"] = time.time() + 60
                        log_event(username, ip_address, location, "HIGH", "Blocked due to brute-force")
                        countdown_placeholder = st.empty()
                        for remaining in range(60, 0, -1):
                            countdown_placeholder.error(f"🛑 Account temporarily locked to prevent brute-force. Please wait {remaining} seconds.")
                            time.sleep(1)
                        countdown_placeholder.empty()
                        st.rerun()
                        
                    elif tracker["failed_attempts"] >= 3:
                        # STRIKES 3 & 4: Route to CAPTCHA
                        log_event(username, ip_address, location, "MEDIUM", "Failed Pass Triggered CAPTCHA")
                        st.error("⚠️ Multiple failed attempts. Forcing anomaly verification.")
                        time.sleep(2)
                        
                        num1, num2 = random.randint(1, 10), random.randint(1, 10)
                        st.session_state.captcha_answer = num1 + num2
                        st.session_state.captcha_question = f"What is {num1} + {num2}?"
                        
                        st.session_state.current_username = username
                        st.session_state.auth_stage = "captcha" 
                        st.rerun()
                        
                    else:
                        # STRIKES 1 & 2: Simple warning (No ML involvement)
                        log_event(username, ip_address, location, "LOW", "Failed Password")
                        st.error("❌ Invalid credentials. Please try again.")

                else:
                    # SUCCESSFUL PASSWORD: Now we let the ML engine check the Context (Device, IP)
                    with st.spinner("🧠 Credentials verified! ML Engine analyzing behavioral context..."):
                        time.sleep(1.2)

                    features = extract_features(username, device_id, password_correct, tracker)
                    probabilities = rf_model.predict_proba([features])[0]
                    raw_prediction = rf_model.predict([features])[0]
                    
                    if isinstance(raw_prediction, str):
                        risk_level = raw_prediction.upper()
                    else:
                        risk_mapping = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
                        risk_level = risk_mapping.get(raw_prediction, "HIGH")

                    model_classes = list(rf_model.classes_)
                    prob_low, prob_med, prob_high = 0.0, 0.0, 0.0
                    
                    for idx, class_label in enumerate(model_classes):
                        label_str = str(class_label).upper()
                        if label_str in ["LOW", "0"]: prob_low = probabilities[idx]
                        elif label_str in ["MEDIUM", "1"]: prob_med = probabilities[idx]
                        elif label_str in ["HIGH", "2"]: prob_high = probabilities[idx]
                    
                    risk_percentage = round((prob_med * 50) + (prob_high * 100), 1)

                    st.divider()
                    
                    if risk_level == "LOW":
                        st.success(f"**ML Engine Context Output:** Classified as `{risk_level}` Risk.")
                    elif risk_level == "MEDIUM":
                        st.warning(f"**ML Engine Context Output:** Classified as `{risk_level}` Risk.")
                    else:
                        st.error(f"**ML Engine Context Output:** Classified as `{risk_level}` Risk.")
                    
                    chart_col1, chart_col2, chart_col3 = st.columns([1, 2, 1])
                    with chart_col2:
                        st.plotly_chart(create_gauge_chart(risk_percentage), use_container_width=True)
                    
                    if risk_level == "HIGH":
                        tracker["blocked_until"] = time.time() + 60
                        log_event(username, ip_address, location, "HIGH", "Blocked due to suspicious context")
                        
                        countdown_placeholder = st.empty()
                        for remaining in range(60, 0, -1):
                            countdown_placeholder.error(f"🛑 Hijack attempt detected. Account locked for {remaining} seconds.")
                            time.sleep(1)
                        countdown_placeholder.empty()
                        st.rerun()

                    elif risk_level == "MEDIUM":
                        log_event(username, ip_address, location, "MEDIUM", "Context Triggered CAPTCHA")
                        st.warning("⚠️ Unfamiliar device detected. Routing to CAPTCHA...")
                        time.sleep(2) 
                        num1, num2 = random.randint(1, 10), random.randint(1, 10)
                        st.session_state.captcha_answer = num1 + num2
                        st.session_state.captcha_question = f"What is {num1} + {num2}?"
                        
                        st.session_state.current_username = username
                        st.session_state.auth_stage = "captcha" 
                        st.rerun()

                    elif risk_level == "LOW":
                        log_event(username, ip_address, location, "LOW", "Standard MFA")
                        
                        generated_otp = str(random.randint(100000, 999999))
                        st.session_state.sent_otp = generated_otp 
                        user_email = st.session_state.users_db[username]["email"]
                        send_email_otp(user_email, generated_otp)
                        
                        st.session_state.current_username = username
                        st.session_state.auth_stage = "otp"
                        st.rerun()

# =========================================================
# STAGE 1.5: CAPTCHA VERIFICATION
# =========================================================
elif st.session_state.auth_stage == "captcha":
    username = st.session_state.current_username
    
    with st.container(border=True):
        st.warning("⚠️ **Unusual behavioral patterns detected.** Please solve the CAPTCHA to prove you are human.")
        
        with st.form("captcha_form"):
            user_answer = st.text_input(f"Mathematical Challenge: **{st.session_state.captcha_question}**")
            verify_captcha = st.form_submit_button("Verify & Proceed to OTP", type="primary")
            
        if verify_captcha:
            if str(user_answer).strip() == str(st.session_state.captcha_answer):
                st.success("✅ CAPTCHA passed! Generating and sending secure OTP...")
                log_event(username, "Verified-CAPTCHA", "Unknown", "MEDIUM", "CAPTCHA Passed")
                
                generated_otp = str(random.randint(100000, 999999))
                st.session_state.sent_otp = generated_otp 
                user_email = st.session_state.users_db[username]["email"]
                send_email_otp(user_email, generated_otp)
                
                st.session_state.auth_stage = "otp"
                st.rerun()
            else:
                st.error("❌ Incorrect CAPTCHA. Access Denied.")
                get_tracker(username)["failed_attempts"] += 1
                log_event(username, "Failed-CAPTCHA", "Unknown", "MEDIUM", "CAPTCHA Failed")
                time.sleep(2)
                st.session_state.auth_stage = "login"
                st.rerun()

# =========================================================
# STAGE 2: OTP VERIFICATION
# =========================================================
elif st.session_state.auth_stage == "otp":
    username = st.session_state.current_username
    masked_email = st.session_state.users_db[username]["email"][:4] + "***@***.com"
    
    with st.container(border=True):
        st.info(f"📧 **Step-Up Verification Required:** A 6-digit code has been sent to **{masked_email}**.")
        
        with st.form("otp_form"):
            entered_otp = st.text_input("Enter your 6-digit OTP code here:", help="Check your email inbox for the code.")
            verify_button = st.form_submit_button("Verify Authenticator Code", type="primary")
            
        if verify_button:
            if entered_otp.strip() == st.session_state.sent_otp:
                get_tracker(username)["failed_attempts"] = 0
                st.session_state.otp_attempts = 0
                st.session_state.sent_otp = None
                log_event(username, "Verified-Device", "Verified-Loc", "LOW", "Access Granted")
                st.session_state.auth_stage = "success"
                st.rerun()
            else:
                st.session_state.otp_attempts += 1
                remaining_attempts = 3 - st.session_state.otp_attempts
                
                if remaining_attempts <= 0:
                    st.error("❌ Maximum OTP attempts reached. Account Locked.")
                    get_tracker(username)["failed_attempts"] += 1
                    log_event(username, "Failed-OTP", "Unknown", "HIGH", "Max OTP Attempts Failed")
                    
                    st.session_state.otp_attempts = 0
                    st.session_state.sent_otp = None
                    st.session_state.auth_stage = "login"
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error(f"❌ Invalid OTP. Remaining attempts: {remaining_attempts}")
                    
    if st.button("Cancel & Return to Login"):
        st.session_state.otp_attempts = 0
        st.session_state.sent_otp = None
        st.session_state.auth_stage = "login"
        st.rerun()

# =========================================================
# STAGE 3: SUCCESS
# =========================================================
elif st.session_state.auth_stage == "success":
    st.balloons()
    st.success(f"🎉 **Authentication Complete!** Welcome to the secure portal, {st.session_state.current_username}.")
    
    if st.button("Log Out & Restart System"):
        st.session_state.auth_stage = "login"
        st.session_state.current_username = ""
        st.session_state.sent_otp = None
        st.session_state.otp_attempts = 0
        st.rerun()

# =========================================================
# STEP 6: AUDIT LOGS
# =========================================================
st.divider()
st.subheader("📊 System Audit Logs")
st.caption("Live monitoring dashboard reflecting Step 6 of the architecture framework.")

if st.session_state.audit_logs:
    st.dataframe(pd.DataFrame(st.session_state.audit_logs), use_container_width=True)
else:
    st.info("System initialized. No authentication events recorded yet.")