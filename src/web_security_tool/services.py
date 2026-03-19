from .password_generator import ProcessGenerator
from .password_assessor import PasswordAssessor
from .input_validator import InputValidator


def generate_password(length: int):
    return ProcessGenerator.generate(length)


def assess_password(password: str):
    return PasswordAssessor.evaluate_password(password)


def sanitize_and_validate(field_type: str, value: str):
    """
    Uses your new InputValidator logic.
    Returns a consistent JSON-friendly payload.
    """
    ft = (field_type or "").lower().strip()

    sanitized_value, was_sanitized, notes = InputValidator.sanitize_input(value, ft)

    if ft in ("name", "full_name", "fullname"):
        is_valid, errors = InputValidator.validate_full_name(sanitized_value)
        ft_out = "name"
    elif ft == "email":
        is_valid, errors = InputValidator.validate_email_simple(sanitized_value)
    elif ft == "username":
        is_valid, errors = InputValidator.validate_username(sanitized_value)
    elif ft == "message":
        is_valid, errors = InputValidator.validate_message(sanitized_value)
    else:
        raise ValueError("Unknown field_type. Use: name, email, username, message")

    return {
        "field_type": ft_out if "ft_out" in locals() else ft,
        "original": value,
        "sanitized": sanitized_value,
        "was_sanitized": was_sanitized,
        "notes": notes,
        "is_valid": is_valid,
        "errors": errors,
    }
