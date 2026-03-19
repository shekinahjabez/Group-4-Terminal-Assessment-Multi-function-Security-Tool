import secrets
import string
import hashlib
import bcrypt
import os
from datetime import datetime


class ProcessGenerator:
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        numbers = string.digits
        symbols = "!@#$%^&*()_-+={}[];:,.?"

        # Ensure minimum requirements
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(numbers),
            secrets.choice(symbols),
        ]

        all_chars = uppercase + lowercase + numbers + symbols
        for _ in range(max(0, length - 4)):
            password.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    @staticmethod
    def hash_sha256(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_bcrypt(password: str, rounds: int = 12) -> str:
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_bcrypt(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    @staticmethod
    def log_generation(password: str, sha256_hash: str, bcrypt_hash: str) -> str:
        # NOTE: Logging plaintext passwords is a security risk.
        # If you must keep logs for grading/demo, consider removing the password field.
        os.makedirs("logs", exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("logs/security_log.txt", "a", encoding="utf-8") as f:
            f.write(
                f"Timestamp: {timestamp}\n"
                f"SHA-256 Hash: {sha256_hash}\n"
                f"Bcrypt Hash: {bcrypt_hash}\n"
                + "-" * 30
                + "\n"
            )

        return timestamp

    @staticmethod
    def generate(length: int = 16):
        pwd = ProcessGenerator.generate_secure_password(length)
        sha = ProcessGenerator.hash_sha256(pwd)
        bcr = ProcessGenerator.hash_bcrypt(pwd)
        ts = ProcessGenerator.log_generation(pwd, sha, bcr)
        return pwd, sha, bcr, ts
