import streamlit as st
import hashlib
import base64
import json
import os
import time
from cryptography.fernet import Fernet

# --- Constants ---
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
LOCK_DURATION = 30  # seconds

# --- Fernet Key Load/Generate ---
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    KEY = f.read()
cipher = Fernet(KEY)

# --- Data Handling ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# --- Hashing ---
def hash_passkey(passkey, salt="static_salt"):
    dk = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return base64.b64encode(dk).decode()

# --- Encryption ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Session Init ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_authorized" not in st.session_state:
    st.session_state.is_authorized = True
if "lock_time" not in st.session_state:
    st.session_state.lock_time = 0

# --- Lockout Timer ---
if st.session_state.failed_attempts >= 3:
    elapsed = time.time() - st.session_state.lock_time
    if elapsed < LOCK_DURATION:
        st.error(f"🔒 Locked out for {int(LOCK_DURATION - elapsed)}s.")
        st.stop()
    else:
        st.session_state.failed_attempts = 0
        st.session_state.lock_time = 0
        st.session_state.is_authorized = True

# --- UI Design ---
st.markdown("<h1 style='color:#6C63FF;'>🔐 Secure Multi-User Encryption App</h1>", unsafe_allow_html=True)

menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.radio("Navigation", menu)

# --- HOME ---
if choice == "🏠 Home":
    st.markdown("### 👋 Welcome to Your Secure Vault")
    st.write("This app allows **encrypted storage** and **secure retrieval** of data using your passkey.")
    st.markdown("**✨ Features:**")
    st.markdown("- 🔐 AES Encryption with Fernet")
    st.markdown("- 🔒 PBKDF2 Passkey Hashing")
    st.markdown("- 🧑‍💻 Multi-User Support")
    st.markdown("- ⏳ Lockout After 3 Failed Tries")
    st.markdown(
    """
    <div style='text-align: center; padding-top: 2rem; font-size: 1rem;'>
        ✅ Built with 💖 by <a href='https://github.com/Zaibunis' target='_blank' style='text-decoration: none; color: #6366f1; font-weight: bold;'>Faria Mustaqim</a>
    </div>
    """,
    unsafe_allow_html=True
)


# --- STORE DATA ---
elif choice == "📂 Store Data":
    st.markdown("### 🔒 Store Your Secret")

    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("👤 Username")
    with col2:
        passkey = st.text_input("🔑 Passkey", type="password")

    user_data = st.text_area("📝 Enter your secret data")

    if st.button("💾 Encrypt & Save"):
        if username and passkey and user_data:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored_data[username] = {"data": encrypted, "passkey": hashed}
            save_data(stored_data)
            st.success("✅ Your data has been securely stored.")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill in all fields.")

# --- RETRIEVE DATA ---
elif choice == "🔍 Retrieve Data":
    st.markdown("### 🔓 Access Your Encrypted Data")

    if not st.session_state.is_authorized:
        st.warning("🚫 Too many failed attempts. Please reauthorize.")
        st.stop()

    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("👤 Username")
    with col2:
        passkey = st.text_input("🔑 Passkey", type="password")

    if st.button("🔍 Decrypt"):
        if username and passkey:
            if username not in stored_data:
                st.error("❌ User not found.")
            else:
                stored_hash = stored_data[username]["passkey"]
                if hash_passkey(passkey) == stored_hash:
                    decrypted = decrypt_data(stored_data[username]["data"])
                    st.success("✅ Data successfully decrypted!")
                    st.text_area("🔓 Your Data:", decrypted, height=100)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Wrong passkey. Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lock_time = time.time()
                        st.session_state.is_authorized = False
                        st.experimental_rerun()
        else:
            st.warning("⚠️ Please complete all fields.")

# --- LOGIN PAGE ---
elif choice == "🔑 Login":
    st.markdown("### 🛡️ Reauthorize Access")

    master = st.text_input("🔐 Master Password", type="password")

    if st.button("✅ Login"):
        if master == "faria123":
            st.session_state.failed_attempts = 0
            st.session_state.is_authorized = True
            st.success("✅ Reauthorization successful. You're back in!")
        else:
            st.error("❌ Incorrect master password.")
