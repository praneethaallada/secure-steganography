# streamlit_ui.py
import streamlit as st
from secure_stego import encode_image, decode_image   # reuse functions from your secure_stego.py
from PIL import Image
import io

st.set_page_config(page_title="Secure Stego UI", layout="wide")

st.title("Secure Stego — AES + LSB (Python)")

col1, col2 = st.columns(2)

with col1:
    st.header("Encode")
    uploaded = st.file_uploader("Choose a cover image (PNG recommended)", type=["png","jpg","jpeg"])
    secret = st.text_area("Secret message", height=120)
    pwd = st.text_input("Password", type="password")
    if st.button("Encode & Download"):
        if not uploaded:
            st.error("Upload a cover image first.")
        elif not secret:
            st.error("Enter a secret message.")
        elif not pwd:
            st.error("Enter a password.")
        else:
            # Save uploaded file to temp bytes and run encode_image
            img_bytes = uploaded.read()
            # write to a temp file in memory
            cover_path = "tmp_cover.png"
            with open(cover_path, "wb") as f:
                f.write(img_bytes)
            try:
                out = "stego_output.png"
                encode_image(cover_path, secret, pwd, out)
                with open(out, "rb") as f:
                    st.success("Encoded successfully — download below.")
                    st.download_button("Download stego PNG", f, file_name=out, mime="image/png")
                    st.image(out, caption="Stego preview")
            except Exception as e:
                st.error(f"Encoding failed: {e}")

with col2:
    st.header("Decode")
    st_write = st.file_uploader("Upload stego PNG to decode", type=["png","jpg","jpeg"], key="decode")
    pwd2 = st.text_input("Password for decoding", type="password", key="pwd2")
    if st.button("Decode"):
        if not st_write:
            st.error("Upload the stego image.")
        elif not pwd2:
            st.error("Enter password for decoding.")
        else:
            # save uploaded file and call decode_image
            path = "tmp_stego.png"
            with open(path, "wb") as f:
                f.write(st_write.read())
            try:
                recovered = decode_image(path, pwd2)
                st.success("Decoded successfully.")
                st.text_area("Recovered message", value=recovered, height=200)
            except Exception as e:
                st.error(f"Decoding failed: {e}")

st.markdown("---")
st.caption("Notes: Use PNG (lossless). This UI uses your existing secure_stego functions.")
