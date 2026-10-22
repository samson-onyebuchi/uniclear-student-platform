# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/code/general_function.py
#
# PURPOSE:
# 1. Define the official clearance stages.
# 2. Provide reusable database lookup functions.
# 3. Standardize clearance-stage validation.
# 4. Serialize MongoDB ObjectId and datetime values.
# 5. Provide shared response and student-status helpers.
# 6. Support the student and staff API modules.
# 7. Validate student and staff account status.
# 8. Map staff roles to their assigned clearance stages.
# 9. Provide consistent UTC timestamps.
# 10. Support final-year student clearance.
# ==========================================================

from datetime import datetime, timezone

from bson import ObjectId
from flask import jsonify

from app import mongo

from app.utils import (
    normalize_stage_name,
    format_stage_name,
    success_response,
    error_response,
)


# ==========================================================
# CLEARANCE WORKFLOW CONFIGURATION
# ==========================================================

CLEARANCE_STAGES = [
    "finance",
    "department",
    "faculty",
    "library",
    "health",
    "student_affairs",
    "final",
]

# The position of each stage determines the required order.
STAGE_ORDER = {
    stage: index
    for index, stage in enumerate(CLEARANCE_STAGES)
}

FINAL_CLEARANCE_STAGE = CLEARANCE_STAGES[-1]


# ==========================================================
# STAFF ROLE CONFIGURATION
# ==========================================================

STAFF_STAGE_ROLES = {
    "Finance Clearance Officer": "finance",
    "Department Clearance Officer": "department",
    "Faculty Clearance Officer": "faculty",
    "Library Clearance Officer": "library",
    "Health Clearance Officer": "health",
    "Student Affairs Clearance Officer": "student_affairs",
    "Final Clearance Officer": "final",
}


# ==========================================================
# TIME UTILITIES
# ==========================================================

def utc_now():
    """
    Return the current timezone-aware UTC datetime.
    """

    return datetime.now(timezone.utc)


def utc_timestamp():
    """
    Return the current UTC time as an ISO 8601 string.
    """

    return utc_now().isoformat()


# ==========================================================
# CLEARANCE STAGE UTILITIES
# ==========================================================

def get_clearance_stages():
    """
    Return a copy of the configured clearance-stage sequence.
    """

    return CLEARANCE_STAGES.copy()


def get_stage_index(stage):
    """
    Return the numeric position of a clearance stage.

    Returns:
        int or None: Stage index, or None if invalid.
    """

    normalized_stage = normalize_stage_name(stage)

    return STAGE_ORDER.get(normalized_stage)


def is_valid_clearance_stage(stage):
    """
    Check whether a stage belongs to the official workflow.
    """

    return normalize_stage_name(stage) in STAGE_ORDER


def get_next_clearance_stage(stage):
    """
    Return the next stage after the supplied stage.

    Returns:
        str or None: Next stage, or None for the final stage
                     or an invalid stage.
    """

    normalized_stage = normalize_stage_name(stage)
    stage_index = STAGE_ORDER.get(normalized_stage)

    if stage_index is None:
        return None

    next_index = stage_index + 1

    if next_index >= len(CLEARANCE_STAGES):
        return None

    return CLEARANCE_STAGES[next_index]


def get_previous_clearance_stage(stage):
    """
    Return the stage immediately before the supplied stage.

    Returns:
        str or None: Previous stage, or None if this is the
                     first stage or the stage is invalid.
    """

    normalized_stage = normalize_stage_name(stage)
    stage_index = STAGE_ORDER.get(normalized_stage)

    if stage_index is None or stage_index == 0:
        return None

    return CLEARANCE_STAGES[stage_index - 1]


def get_stage_role(stage):
    """
    Return the recognized staff role for a clearance stage.
    """

    normalized_stage = normalize_stage_name(stage)

    for role, assigned_stage in STAFF_STAGE_ROLES.items():
        if assigned_stage == normalized_stage:
            return role

    return None


def get_assigned_stage(role):
    """
    Resolve a recognized staff role to its clearance stage.

    Returns None for an unrecognized role.
    """

    if not isinstance(role, str):
        return None

    role = role.strip()

    return STAFF_STAGE_ROLES.get(role)


def get_stage_display_name(stage):
    """
    Return a human-readable clearance-stage name.
    """

    return format_stage_name(stage)


# ==========================================================
# DATABASE LOOKUP UTILITIES
# ==========================================================

def get_student_by_reg_no(reg_no):
    """
    Retrieve a student using their registration number.

    Returns:
        dict or None
    """

    if not isinstance(reg_no, str) or not reg_no.strip():
        return None

    return mongo.db.students.find_one({
        "reg_no": reg_no.strip()
    })


def get_staff_by_id(staff_id):
    """
    Retrieve a staff member using their staff ID.

    Returns:
        dict or None
    """

    if not isinstance(staff_id, str) or not staff_id.strip():
        return None

    return mongo.db.staff.find_one({
        "staff_id": staff_id.strip()
    })


def get_clearance_by_reg_no(reg_no):
    """
    Retrieve a student's clearance record using reg_no.
    """

    if not isinstance(reg_no, str) or not reg_no.strip():
        return None

    return mongo.db.clearances.find_one({
        "reg_no": reg_no.strip()
    })


# ==========================================================
# STUDENT STATUS UTILITIES
# ==========================================================

def calculate_study_duration(admission_year, current_year=None):
    """
    Calculate the number of years since admission.

    Rule:
        Study duration = current year - admission year.

    Returns:
        int or None if the supplied year is invalid.
    """

    if current_year is None:
        current_year = datetime.now().year

    try:
        admission_year = int(admission_year)
        current_year = int(current_year)
    except (TypeError, ValueError):
        return None

    if admission_year < 1900 or admission_year > current_year:
        return None

    return current_year - admission_year


def determine_student_status(admission_year, current_year=None):
    """
    Classify a student according to study duration.

    More than six years: external.
    Six years or fewer: regular.

    Returns:
        str or None
    """

    duration = calculate_study_duration(
        admission_year,
        current_year,
    )

    if duration is None:
        return None

    return "external" if duration > 6 else "regular"


# ==========================================================
# MONGODB SERIALIZATION UTILITIES
# ==========================================================

def serialize_mongo_value(value):
    """
    Convert MongoDB and Python values into JSON-compatible
    values.

    Handles ObjectId, datetime, dictionaries, lists and tuples.
    """

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): serialize_mongo_value(item)
            for key, item in value.items()
            if key != "_id"
        }

    if isinstance(value, (list, tuple)):
        return [
            serialize_mongo_value(item)
            for item in value
        ]

    return value


def serialize_document(document):
    """
    Serialize a MongoDB document without exposing its _id field.

    Returns None when no document is supplied.
    """

    if document is None:
        return None

    return serialize_mongo_value(document)


# ==========================================================
# STANDARD JSON RESPONSE UTILITIES
# ==========================================================

def json_success(message, data=None, status_code=200):
    """
    Return a standardized successful JSON response.
    """

    return jsonify(
        success_response(message, data)
    ), status_code


def json_error(message, status_code=400, errors=None):
    """
    Return a standardized unsuccessful JSON response.
    """

    return jsonify(
        error_response(message, errors)
    ), status_code


# ==========================================================
# ACCOUNT VALIDATION UTILITIES
# ==========================================================

def is_active_account(account):
    """
    Check whether a student or staff account is active.

    Accounts without account_status default to active for
    compatibility with records using the older schema.
    """

    if not isinstance(account, dict):
        return False

    return (
        str(account.get("account_status", "active"))
        .strip()
        .lower()
        == "active"
    )


def is_stage_assigned_to_staff(staff, stage):
    """
    Confirm that an active staff member is assigned to the
    requested official clearance stage.
    """

    if not isinstance(staff, dict):
        return False

    if not is_active_account(staff):
        return False

    assigned_stage = normalize_stage_name(
        staff.get("assigned_stage", "")
    )

    requested_stage = normalize_stage_name(stage)

    return (
        bool(assigned_stage)
        and assigned_stage == requested_stage
        and is_valid_clearance_stage(requested_stage)
    )


# ==========================================================
# FULL-NAME UTILITIES
# ==========================================================

def get_student_full_name(student):
    """
    Build a student's full name from their profile fields.
    """

    if not isinstance(student, dict):
        return ""

    name_parts = [
        student.get("first_name", ""),
        student.get("other_names", ""),
        student.get("surname", ""),
    ]

    return " ".join(
        str(part).strip()
        for part in name_parts
        if part and str(part).strip()
    )


def get_staff_full_name(staff):
    """
    Build a staff member's full name from their profile fields.
    """

    if not isinstance(staff, dict):
        return ""

    name_parts = [
        staff.get("first_name", ""),
        staff.get("other_names", ""),
        staff.get("surname", ""),
    ]

    return " ".join(
        str(part).strip()
        for part in name_parts
        if part and str(part).strip()
    )