import re
import math
import streamlit as st

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Smart Password Auditor",
    page_icon="🔐",
    layout="wide"
)

# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #07111f, #10243d);
    color: white;
}

h1, h2, h3, p, label {
    color: white !important;
}

div[data-testid="stMetric"] {
    background: #152b45;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #294767;
}

div.stButton > button {
    background-color: #00c896;
    color: #07111f;
    border-radius: 8px;
    border: none;
    font-weight: bold;
    width: 100%;
}

div.stButton > button:hover {
    background-color: #00e6ac;
    color: #07111f;
}

.security-card {
    background: #152b45;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #294767;
    margin-bottom: 12px;
}

.small-text {
    color: #b8c7d9;
    font-size: 14px;
}
</style>
""", unsafe_allow_html=True)


# ==========================================
# PASSWORD ANALYSIS
# ==========================================

COMMON_PASSWORDS = {
    "password", "password123", "123456",
    "12345678", "qwerty", "qwerty123",
    "admin", "admin123", "letmein",
    "welcome", "iloveyou"
}

COMMON_SEQUENCES = [
    "123456", "12345678", "abcdef",
    "qwerty", "asdfgh", "password"
]


def analyze_password(password, min_length=12):
    """
    Analyze password quality locally.
    The password is not saved by this function.
    """

    checks = {
        "Minimum length": len(password) >= min_length,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Number": bool(re.search(r"[0-9]", password)),
        "Special character": bool(
            re.search(r"[^A-Za-z0-9]", password)
        ),
    }

    reasons = []
    suggestions = []

    # Detect an entirely common password.
    normalized = password.lower()

    if normalized in COMMON_PASSWORDS:
        reasons.append("This is a commonly used password.")
        suggestions.append(
            "Replace it with a unique password or passphrase."
        )

    # Detect common predictable sequences.
    if any(
        sequence in normalized
        for sequence in COMMON_SEQUENCES
    ):
        reasons.append(
            "A common or predictable sequence was detected."
        )
        suggestions.append(
            "Avoid predictable sequences such as 123456 or qwerty."
        )

    # Detect repeated characters.
    if re.search(r"(.)\1{2,}", password):
        reasons.append(
            "Three or more consecutive identical characters were found."
        )
        suggestions.append(
            "Avoid long runs of repeated characters."
        )

    # Check whether the password is entirely alphabetic or numeric.
    if password.isalpha() and password:
        reasons.append("The password contains only letters.")

    if password.isdigit() and password:
        reasons.append("The password contains only numbers.")

    # Educational score, not a true crack-time estimate.
    score = 0

    if len(password) >= 8:
        score += 15

    if len(password) >= min_length:
        score += 20

    if len(password) >= 16:
        score += 10

    score += 10 if checks["Uppercase letter"] else 0
    score += 10 if checks["Lowercase letter"] else 0
    score += 10 if checks["Number"] else 0
    score += 10 if checks["Special character"] else 0

    if len(set(password)) >= 8:
        score += 5

    if len(password) >= 20:
        score += 10

    # Penalize known weaknesses.
    if normalized in COMMON_PASSWORDS:
        score -= 35

    if any(
        sequence in normalized
        for sequence in COMMON_SEQUENCES
    ):
        score -= 20

    if re.search(r"(.)\1{2,}", password):
        score -= 10

    score = max(0, min(score, 100))

    # Require policy compliance and no detected common patterns
    # before assigning the strongest category.
    policy_passed = all(checks.values())
    has_pattern = bool(reasons)

    if not password:
        strength = "Not evaluated"
        color = "⚪"
    elif (
        score >= 80
        and policy_passed
        and not has_pattern
    ):
        strength = "Strong"
        color = "🟢"
    elif score >= 50:
        strength = "Moderate"
        color = "🟡"
    else:
        strength = "Weak"
        color = "🔴"

    # Recommendations
    if len(password) < min_length:
        suggestions.append(
            f"Use at least {min_length} characters."
        )

    if not checks["Uppercase letter"]:
        suggestions.append(
            "Include uppercase letters if required by your policy."
        )

    if not checks["Lowercase letter"]:
        suggestions.append(
            "Include lowercase letters if required by your policy."
        )

    if not checks["Number"]:
        suggestions.append(
            "Include numbers if required by your policy."
        )

    if not checks["Special character"]:
        suggestions.append(
            "Consider special characters if required by your policy."
        )

    if not suggestions and not reasons:
        suggestions.append(
            "Keep this password unique and use a password manager."
        )

    return {
        "score": score,
        "strength": strength,
        "color": color,
        "checks": checks,
        "reasons": reasons,
        "suggestions": list(dict.fromkeys(suggestions)),
    }


# ==========================================
# HEADER
# ==========================================

st.title("🔐 Smart Password Strength & Policy Auditor")

st.markdown(
    "### Cybersecurity • Password Analysis • Security Awareness"
)

st.markdown(
    "Evaluate password quality, identify common weaknesses, "
    "and receive recommendations for improving security."
)

st.info(
    "Privacy: Password analysis runs in this application. "
    "Do not enter a real password. Use a fictional test password "
    "for demonstrations."
)

st.divider()


# ==========================================
# SIDEBAR SETTINGS
# ==========================================

st.sidebar.title("⚙️ Security Policy")

min_length = st.sidebar.slider(
    "Minimum password length",
    min_value=8,
    max_value=20,
    value=12
)

st.sidebar.markdown("---")

st.sidebar.markdown("### Password Policy")

st.sidebar.write(
    f"Minimum length: {min_length} characters"
)

st.sidebar.write("Uppercase: Checked")
st.sidebar.write("Lowercase: Checked")
st.sidebar.write("Number: Checked")
st.sidebar.write("Special character: Checked")

st.sidebar.caption(
    "These are configurable educational checks. "
    "Actual policy requirements depend on the organization."
)


# ==========================================
# INPUT
# ==========================================

st.subheader("🧪 Test Your Password")

password = st.text_input(
    "Enter a fictional test password",
    type="password",
    placeholder="Enter a sample password..."
)

show_password = st.checkbox(
    "Show test password while analyzing"
)

if password:
    result = analyze_password(password, min_length)

    if show_password:
        st.caption(f"Test input: {password}")

    st.divider()

    # ======================================
    # METRICS
    # ======================================

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Security Score",
        f"{result['score']}/100"
    )

    col2.metric(
        "Password Strength",
        result["strength"]
    )

    col3.metric(
        "Password Length",
        f"{len(password)} characters"
    )

    st.progress(result["score"] / 100)

    st.markdown(
        f"## {result['color']} {result['strength']} Password"
    )

    st.caption(
        "The score is an educational heuristic, not a "
        "measured probability of compromise."
    )

    # ======================================
    # POLICY CHECKS
    # ======================================

    st.subheader("📋 Password Policy Audit")

    left, right = st.columns(2)

    items = list(result["checks"].items())

    for index, (name, passed) in enumerate(items):
        target = left if index % 2 == 0 else right

        with target:
            if passed:
                st.success(f"✅ {name}: Passed")
            else:
                st.error(f"❌ {name}: Not satisfied")

    # ======================================
    # WEAKNESSES
    # ======================================

    st.subheader("🔍 Security Findings")

    if result["reasons"]:
        for reason in result["reasons"]:
            st.warning(reason)
    else:
        st.success(
            "No listed common patterns were detected by "
            "this basic checker."
        )

    # ======================================
    # RECOMMENDATIONS
    # ======================================

    st.subheader("💡 Recommendations")

    for suggestion in result["suggestions"]:
        st.write(f"• {suggestion}")

    # ======================================
    # POLICY SUMMARY
    # ======================================

    st.subheader("🛡️ Policy Compliance")

    if all(result["checks"].values()):
        st.success(
            "The password satisfies the configured "
            "character and length checks."
        )
    else:
        st.warning(
            "The password does not satisfy every configured "
            "character and length check."
        )

else:
    st.info(
        "Enter a fictional test password above to start "
        "the security analysis."
    )


# ==========================================
# SECURITY TIPS
# ==========================================

st.divider()

st.subheader("🔒 Password Security Best Practices")

tip1, tip2, tip3 = st.columns(3)

with tip1:
    st.markdown("""
    <div class="security-card">
        <h3>📏 Use Longer Passwords</h3>
        <p class="small-text">
        Prefer long, unique passwords or passphrases.
        </p>
    </div>
    """, unsafe_allow_html=True)

with tip2:
    st.markdown("""
    <div class="security-card">
        <h3>🔑 Avoid Reuse</h3>
        <p class="small-text">
        Use a different password for every important account.
        </p>
    </div>
    """, unsafe_allow_html=True)

with tip3:
    st.markdown("""
    <div class="security-card">
        <h3>🛡️ Enable MFA</h3>
        <p class="small-text">
        Use multifactor authentication whenever available.
        </p>
    </div>
    """, unsafe_allow_html=True)

st.caption(
    "Smart Password Auditor | Educational cybersecurity project"
)