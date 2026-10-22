# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/utils/__init__.py
#
# PURPOSE:
# 1. Mark the utils directory as a Python package.
# 2. Export reusable helper functions.
# 3. Make shared utilities available to student and staff
#    modules through a consistent import path.
# ==========================================================

from app.utils.helpers import (
    generate_otp,
    normalize_stage_name,
    format_stage_name,
    get_utc_now,
    get_utc_iso_timestamp,
    is_valid_email,
    is_valid_otp,
    success_response,
    error_response,
)

__all__ = [
    "generate_otp",
    "normalize_stage_name",
    "format_stage_name",
    "get_utc_now",
    "get_utc_iso_timestamp",
    "is_valid_email",
    "is_valid_otp",
    "success_response",
    "error_response",
]