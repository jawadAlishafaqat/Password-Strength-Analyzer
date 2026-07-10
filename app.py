

# Password Strength Analyzer
# Streamlit Application


# Import libraries
import streamlit as st
import pandas as pd

from analyzer import analyze_password


# Page configuration
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Custom CSS
st.markdown("""
<style>

.main{
    padding-top:20px;
}

.title{
    text-align:center;
    font-size:40px;
    font-weight:bold;
    color:#1f77b4;
}

.subtitle{
    text-align:center;
    color:gray;
    font-size:18px;
    margin-bottom:30px;
}

.metric-card{

    background:#f7f9fc;

    padding:18px;

    border-radius:12px;

    text-align:center;

    box-shadow:0px 2px 8px rgba(0,0,0,0.15);

}

.section{

    background:white;

    padding:20px;

    border-radius:12px;

    margin-top:20px;

    box-shadow:0px 2px 6px rgba(0,0,0,0.10);

}

.footer{

    text-align:center;

    color:gray;

    margin-top:40px;

}

</style>
""", unsafe_allow_html=True)


# Sidebar
st.sidebar.title("🔐 Password Analyzer")

st.sidebar.markdown("---")

st.sidebar.info(
"""
This application evaluates password strength using:

- Password Score
- Entropy
- Dictionary Detection
- Keyboard Pattern Detection
- Sequential Number Detection
- Password Statistics
- Attack Prediction
- Crack Time Estimation
"""
)

st.sidebar.markdown("---")

st.sidebar.success(
"Developed for Educational Purposes"
)


# Header
st.markdown(
'<p class="title">🔐 Password Strength Analyzer</p>',
unsafe_allow_html=True
)

st.markdown(
'<p class="subtitle">Professional Password Security Assessment Tool</p>',
unsafe_allow_html=True
)


# Password Input
password = st.text_input(

    "Enter Password",

    type="password",

    placeholder="Type your password here..."

)


# Analyze Button
analyze_button = st.button(

    "Analyze Password",

    use_container_width=True

)

if analyze_button:

    if password.strip() == "":

        st.warning("Please enter a password.")

    else:

        report = analyze_password(password)

        # Progress Bar
        st.subheader("Password Score")

        st.progress(report["Score"] / 100)

        st.write(f"**{report['Score']} / 100**")

        st.markdown("---")

        # Summary Cards
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Strength",
                report["Strength"]
            )

        with col2:
            st.metric(
                "Entropy",
                f"{report['Entropy']} bits"
            )

        with col3:
            st.metric(
                "Attack Type",
                report["Attack Type"]
            )

        with col4:
            st.metric(
                "Crack Time",
                report["Estimated Crack Time"]
            )

        st.markdown("---")

        # Password Statistics
        st.subheader("Password Statistics")

        stats = report["Statistics"]

        stats_df = pd.DataFrame({

            "Metric": stats.keys(),

            "Value": stats.values()

        })

        st.dataframe(
            stats_df,
            use_container_width=True,
            hide_index=True
        )

        st.markdown("---")

        # Weaknesses
        st.subheader("Weaknesses")

        if report["Weaknesses"]:

            for weakness in report["Weaknesses"]:

                st.error(weakness)

        else:

            st.success("No weaknesses found.")

        st.markdown("---")

        # Recommendations
        st.subheader("Recommendations")

        for recommendation in report["Recommendations"]:

            st.info(recommendation)



        st.markdown("---")

        # Password Security Tips
        st.subheader("Password Security Tips")

        tips = [

            "Use at least 15 characters.",

            "Combine uppercase, lowercase, numbers and symbols.",

            "Avoid dictionary words.",

            "Avoid sequential numbers such as 123456.",

            "Avoid keyboard patterns like qwerty or asdf.",

            "Never reuse passwords across different accounts.",

            "Enable Multi-Factor Authentication (MFA)."

        ]

        for tip in tips:

            st.success(tip)

        st.markdown("---")


# Dataset Preview
st.subheader("Sample Dataset")

try:

    df = pd.read_csv("sample_passwords.csv")

    st.dataframe(

        df.head(10),

        use_container_width=True,

        hide_index=True

    )

    st.caption(f"Total Passwords : {len(df)}")

except FileNotFoundError:

    st.warning("sample_passwords.csv not found.")


st.markdown("---")


# About Project
with st.expander("About This Project"):

    st.write("""

This project was developed to evaluate password security using
multiple password analysis techniques.

### Features

- Password Strength Scoring
- Entropy Calculation
- Effective Entropy
- Dictionary Word Detection
- Keyboard Pattern Detection
- Sequential Number Detection
- Repeated Character Detection
- Password Statistics
- Password Recommendations
- Attack Type Prediction
- Estimated Password Crack Time
- Dataset Analysis

### Technologies Used

- Python
- Streamlit
- Pandas
- NumPy

""")


st.markdown("---")


# Footer
st.markdown("""

<div style="text-align:center;
padding:15px;
color:gray;">

Developed using ❤️ with Python & Streamlit

<br>

Password Strength Analyzer © 2026

</div>

""", unsafe_allow_html=True)

