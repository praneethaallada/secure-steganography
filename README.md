# Secure Steganographic Communication System 🔐🖼️

A secure image-based communication system that encrypts confidential messages and hides them inside images using cryptography and steganography techniques.

## 🔹 Problem Statement
Design and implement a secure system that:
- Encrypts secret messages using **AES-256 encryption**
- Conceals the encrypted data inside an image using **LSB steganography**
- Allows message extraction only with the correct password

## 🔹 Features
- Strong AES-256 encryption with password protection  
- Image-based steganography using Least Significant Bit (LSB) technique  
- Lossless PNG image support for high visual fidelity  
- Secure decoding with graceful handling of incorrect passwords  
- Simple and interactive Streamlit-based user interface  

## 🔹 Tech Stack
- **Python**
- **Cryptography** (AES, PBKDF2)
- **Pillow** (Image Processing)
- **Streamlit** (Web Interface)

## 🔹 How to Run
```bash
pip install -r requirements.txt
streamlit run streamlit_ui.py
