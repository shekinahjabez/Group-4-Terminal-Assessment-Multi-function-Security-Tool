import re
import hashlib
import requests
from zxcvbn import zxcvbn

from .utils import COMMON_PASSWORDS, DICTIONARY_WORDS, SQL_KEYWORDS


class PasswordAssessor:
    @staticmethod
    def evaluate_password(password):
        feedback = []
        score = 0

        # 1. Common Password Check
        if password.lower() in COMMON_PASSWORDS:
            return "Weak", "Password is commonly used."

        # 2. Dictionary Word Check
        for word in DICTIONARY_WORDS:
            if word in password.lower():
                return "Weak", "Password contains a dictionary word."

        # 3. Criteria Checks
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("• Minimum 12 characters required.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("• Add uppercase letters.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("• Add lowercase letters.")

        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("• Add numbers.")

        if re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>?/\\|]", password):
            score += 1
        else:
            feedback.append("• Add special characters.")

        # 4. Final Rating Logic based on MO-IT142
        if score <= 2:
            return "Weak", "\n".join(feedback)
        elif score <= 4:
            return "Moderate", "\n".join(feedback)
        else:
            return "Strong", "Password meets security requirements."
