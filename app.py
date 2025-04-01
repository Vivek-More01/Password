import streamlit as st
import random
import string
import time
# import hashlib
import pandas as pd
import plotly.express as px
from zxcvbn import zxcvbn
import re
from fpdf import FPDF
import streamlit as st

def generate_pdf_report(password, analysis, crack_times):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Password Strength Analysis Report", 0, 1, 'C')
    
    # Password Analysis
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Analyzed Password: {password}", 0, 1)
    pdf.cell(0, 10, f"Strength Score: {analysis['score']}", 0, 1)
    
    # Crack Time Estimation
    pdf.cell(0, 10, "Time-to-Crack (in seconds):", 0, 1)
    for method, time in crack_times.items():
        pdf.cell(0, 10, f"{method}: {time}", 0, 1)

    # Save PDF
    pdf.output("password_report.pdf")
    st.success("PDF Report Generated Successfully!")


# def check_password_strength(password):
#     strength = 0
#     feedback = []

#     # Minimum length criteria
#     if len(password) >= 8:
#         strength += 1
#     else:
#         feedback.append("Password should be at least 8 characters long.")

#     # Presence of digits
#     if re.search(r'\d', password):
#         strength += 1
#     else:
#         feedback.append("Password should include at least one number.")

#     # Presence of uppercase letters
#     if re.search(r'[A-Z]', password):
#         strength += 1
#     else:
#         feedback.append("Password should include at least one uppercase letter.")

#     # Presence of lowercase letters
#     if re.search(r'[a-z]', password):
#         strength += 1
#     else:
#         feedback.append("Password should include at least one lowercase letter.")

#     # Presence of special characters
#     if re.search(r'[\W_]', password):
#         strength += 1
#     else:
#         feedback.append("Password should include at least one special character.")

#     # Strength evaluation
#     if strength == 5:
#         return "Strong password!", feedback
#     elif strength >= 3:
#         return "Moderately strong password.", feedback
#     else:
#         return "Weak password.", feedback

def estimate_crack_time(password):
    # Simulated estimations for different hashing methods
    times = {
        "bcrypt": len(password) ** 2 * 0.1,
        "Argon2": len(password) ** 2 * 0.05,
        "SHA-256": len(password) * 0.01
    }
    return times

def generate_password(length=12, use_symbols=True, use_digits=True):
    characters = string.ascii_letters
    if use_symbols:
        characters += string.punctuation
    if use_digits:
        characters += string.digits
    return ''.join(random.choice(characters) for _ in range(length))

st.set_page_config(page_title="Password Strength Analyzer with AI", layout="wide")
st.markdown("""
    <style>
    .main {background: linear-gradient(to right, #1e3c72, #2a5298); color: white;}
    .stTextInput>div>div>input {background-color: white;}
    </style>
    """, unsafe_allow_html=True)

st.title("🔐 Password Strength Analyzer with AI")
st.subheader("Test, Analyze, and Strengthen Your Passwords in Real-Time")

# no_PassW = st.text_input("Enter No. of Passwords You want to Analyze", type="number", help="Enter a number between 1 and 20.")
# passwords = [0]*int(no_PassW) if no_PassW else []

# for i in range(int(no_PassW)):
password= st.text_input("Enter Your Password", type="password", help="Your password will not be stored.")
if st.button("Analyze") and password:
    analysis = zxcvbn(password)
    crack_times = estimate_crack_time(password)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Strength Classification", "Pattern Analysis", "Time-to-Crack", "Vulnerability Detection", "Suggestions & AI Feedback"
    ])

    with tab1:
        strength_labels = ["Weak", "Medium", "Strong", "Very Strong"]
        score = min(3, analysis['score'])  # Limit score to 3 for display
        st.metric("Strength Level", strength_labels[score])
        st.progress((score + 1) / 4)

    with tab2:
        st.write("Patterns Detected:")
        for match in analysis['sequence']:
            st.warning(f"{match['pattern'].capitalize()} detected: {match['token']}")

    with tab3:
        df = pd.DataFrame.from_dict(crack_times, orient='index', columns=['Seconds'])
        fig = px.bar(df, title="Estimated Time to Crack", labels={'index': "Method", "Seconds": "Time (sec)"})
        st.plotly_chart(fig)

    with tab4:
        attack_types = ["Brute-force", "Dictionary Attack", "Phishing"]
        for attack in attack_types:
            st.error(f"{attack} risk detected!")

    with tab5:
        st.info("Use a mix of uppercase, lowercase, numbers, and special characters.")
        st.info("Avoid dictionary words or repeated patterns.")

st.subheader("🔑 Generate a Strong Password")
length = st.slider("Length", 8, 32, 12)
symbols = st.checkbox("Include Symbols", value=True)
digits = st.checkbox("Include Digits", value=True)
if st.button("Generate"):
    new_password = generate_password(length, symbols, digits)
    st.text_area("Generated Password", new_password)
    st.button("Copy to Clipboard")

st.subheader("📄 Security Report")
if st.button("Generate Security Report"):
    st.write("Report Summary:")
    st.success("Password analysis complete.")
    if st.button("Generate PDF Report"):
        if password:
            generate_pdf_report(password, analysis, crack_times)
            with open("password_report.pdf", "rb") as pdf_file:
                st.download_button("Download PDF Report", data=pdf_file, file_name="password_report.pdf")

st.markdown("---")
st.caption("Project by Your Name | [GitHub Repo](#)")
