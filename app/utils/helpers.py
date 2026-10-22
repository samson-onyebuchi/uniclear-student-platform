# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/utils/helpers.py
#
# PURPOSE:
# 1. Generate numeric OTP verification codes.
# 2. Normalize clearance stage names.
# 3. Format clearance stage names for display.
# 4. Provide consistent JSON response helpers.
# 5. Provide reusable validation utilities.
# 6. Convert MongoDB values into JSON-safe values.
# ==========================================================

import secrets
import re

from datetime import datetime, date, timezone
from bson import ObjectId

try:
    from bson.decimal128 import Decimal128
except ImportError:
    Decimal128 = None


# ==========================================================
# OTP GENERATION
# ==========================================================

def generate_otp(length=6):
    """
    Generate a cryptographically secure numeric OTP.
    """

    if not isinstance(length, int) or isinstance(length, bool) or length < 1:
        raise ValueError("OTP length must be a positive integer.")

    if length > 12:
        raise ValueError("OTP length cannot exceed 12 digits.")

    lower = 10 ** (length - 1)
    upper = (10 ** length) - 1

    return str(secrets.randbelow(upper - lower + 1) + lower)


# ==========================================================
# CLEARANCE STAGE UTILITIES
# ==========================================================

def normalize_stage_name(stage):
    """
    Normalize a clearance stage name.

    Examples:
        'Student Affairs' -> 'student_affairs'
        ' FINANCE '       -> 'finance'
    """

    if not isinstance(stage, str):
        return ""

    stage = stage.strip().lower()
    stage = re.sub(r"[\s-]+", "_", stage)
    stage = re.sub(r"_+", "_", stage)

    return stage.strip("_")


def format_stage_name(stage):
    """
    Convert a clearance stage identifier into readable text.

    Example:
        'student_affairs' -> 'Student Affairs'
    """

    if not isinstance(stage, str) or not stage.strip():
        return ""

    return normalize_stage_name(stage).replace("_", " ").title()


# ==========================================================
# DATE AND TIME UTILITIES
# ==========================================================

def get_utc_now():
    """
    Return the current timezone-aware UTC datetime.
    """

    return datetime.now(timezone.utc)


def get_utc_iso_timestamp():
    """
    Return the current UTC timestamp in ISO 8601 format.
    """

    return get_utc_now().isoformat()


# ==========================================================
# INPUT VALIDATION UTILITIES
# ==========================================================

def is_valid_email(email):
    """
    Perform basic email-format validation.

    This checks the general structure of an email address.
    It does not confirm that the mailbox exists.
    """

    if not isinstance(email, str):
        return False

    email = email.strip()

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.fullmatch(pattern, email))


def is_valid_otp(otp, length=6):
    """
    Check whether an OTP contains exactly the required
    number of numeric digits.
    """

    if not isinstance(otp, str):
        return False

    return (
        isinstance(length, int)
        and not isinstance(length, bool)
        and length > 0
        and len(otp) == length
        and otp.isascii()
        and otp.isdigit()
    )


# ==========================================================
# JSON-SAFE SERIALIZATION UTILITIES
# ==========================================================

def serialize_mongo_value(value):
    """
    Recursively convert MongoDB and Python values into
    values that can safely be serialized as JSON.

    ObjectId values become strings.
    Datetimes and dates become ISO timestamps.
    Dictionaries, lists, and tuples are processed recursively.
    """

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if Decimal128 is not None and isinstance(value, Decimal128):
        return str(value.to_decimal())

    if isinstance(value, dict):
        return {
            str(key): serialize_mongo_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [serialize_mongo_value(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


def serialize_document(document):
    """
    Serialize a MongoDB document into JSON-safe data.

    Returns None when the supplied document is None.
    """

    if document is None:
        return None

    if isinstance(document, dict):
        return serialize_mongo_value(document)

    return serialize_mongo_value(document)


# ==========================================================
# STANDARD RESPONSE UTILITIES
# ==========================================================

def success_response(message, data=None):
    """
    Build a consistent successful API response.

    Returns a dictionary, not a Flask Response object.
    """

    response = {
        "success": True,
        "message": message
    }

    if data is not None:
        response["data"] = serialize_mongo_value(data)

    return response


def error_response(message, errors=None):
    """
    Build a consistent unsuccessful API response.

    Returns a dictionary, not a Flask Response object.
    """

    response = {
        "success": False,
        "message": message
    }

    if errors is not None:
        response["errors"] = serialize_mongo_value(errors)

    return response