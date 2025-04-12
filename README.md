# 🔐 Secure Multi-User Encryption App

Welcome to the **Secure Multi-User Encryption App**! This application allows you to securely store and retrieve your sensitive data using encryption and hashing techniques. All data is encrypted using **Fernet** encryption, and your passkey is hashed with **PBKDF2** to ensure the highest level of security.

## ✨ Features
- 🔐 **AES Encryption** with **Fernet** for secure data storage
- 🔒 **PBKDF2** Passkey **Hashing** for extra security
- 🧑‍💻 **Multi-User** support for storing encrypted data for different users
- ⏳ **Lockout** after 3 failed attempts to protect against brute-force attacks
- 🔑 **Master Password** for reauthorizing access

## 🚀 Installation

```bash
git clone https://github.com/Zaibunis/secure-data-encryption-by-faria-mustaqim.git
cd secure-data-encryption-by-faria-mustaqim
2. Install required dependencies
pip install -r requirements.txt
3. Run the application
streamlit run app.py
```

📝 How to Use
🏠 Home Page
Upon opening the app, you'll see the Home Page where you can navigate to various sections.

📂 Store Data
Enter your Username and Passkey.

Input the secret data you wish to store.

The app will encrypt the data and hash your passkey before saving it securely.

🔍 Retrieve Data
Enter your Username and Passkey.

If the credentials are correct, the app will decrypt and display your stored data.

🔑 Login Page
You can reauthorize the app using the Master Password to reset failed attempts and unlock the app.

🛠️ Technologies Used
🧑‍💻 Streamlit: For the user interface.

🔒 Cryptography: For encryption and hashing.

🛠️ Python: The primary programming language.

🙋‍♀️ Author
Faria Mustaqim
