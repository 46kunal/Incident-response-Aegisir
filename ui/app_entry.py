import streamlit as st

st.set_page_config(page_title="AegisIR Access Portal", layout="wide")

# Clean Landing Page
st.markdown("""
<style>
body {
    background-color: #0f172a;
}
.center-box {
    text-align: center;
    margin-top: 100px;
}
.big-title {
    font-size: 40px;
    font-weight: bold;
    color: white;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='center-box'>", unsafe_allow_html=True)
st.markdown("<div class='big-title'>🛡 AegisIR Secure Access</div>", unsafe_allow_html=True)
st.markdown("<br><br>", unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    if st.button("🔐 Admin Login", use_container_width=True):
        st.session_state["role"] = "Admin"
        st.switch_page("pages/admin_dashboard.py")

with col2:
    if st.button("👤 User Login", use_container_width=True):
        st.session_state["role"] = "User"
        st.switch_page("pages/user_dashboard.py")
