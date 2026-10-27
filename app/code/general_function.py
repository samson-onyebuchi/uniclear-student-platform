
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
# 11. Validate that previous clearance stages are approved.
# 12. Validate clearance current-stage consistency.
# 13. Normalize registration numbers consistently.
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

# IMPORTANT:
# Do not change the order without updating the entire
# clearance workflow and testing every stage transition.

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

# Recognized stage states.
# These constants provide consistent spellings throughout
# the application.
STAGE_STATUS_PENDING = "pending"
STAGE_STATUS_AWAITING_SUBMISSION = "awaiting_submission"
STAGE_STATUS_UNDER_REVIEW = "under_review"
STAGE_STATUS_APPROVED = "approved"
STAGE_STATUS_REJECTED = "rejected"


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
# REGISTRATION NUMBER UTILITIES
# ==========================================================

def normalize_reg_no(reg_no):
    """
    Normalize a student registration number consistently.

    Registration numbers are stripped of surrounding
    whitespace and converted to uppercase.

    Returns:
        str: Normalized registration number.
        str: Empty string when the input is invalid.

    IMPORTANT:
    Existing student records should use this same format.
    """

    if not isinstance(reg_no, str):
        return ""

    return reg_no.strip().upper()


# ==========================================================
# CLEARANCE STAGE NORMALIZATION
# ==========================================================

def normalize_clearance_stage(stage):
    """
    Normalize a stage and return it only when it is an
    official clearance stage.

    Unlike a general text normalizer, this helper does not
    treat an arbitrary non-empty string as a valid stage.

    Returns:
        str: Official normalized stage.
        str: Empty string for an invalid stage.
    """

    if not isinstance(stage, str) or not stage.strip():
        return ""

    normalized_stage = normalize_stage_name(stage)

    if not isinstance(normalized_stage, str):
        return ""

    normalized_stage = normalized_stage.strip().lower()

    if normalized_stage not in STAGE_ORDER:
        return ""

    return normalized_stage


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

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return None

    return STAGE_ORDER.get(normalized_stage)


def is_valid_clearance_stage(stage):
    """
    Check whether a stage belongs to the official workflow.
    """

    return bool(normalize_clearance_stage(stage))


def get_next_clearance_stage(stage):
    """
    Return the next stage after the supplied stage.

    Returns:
        str or None: Next stage, or None for the final stage
                     or an invalid stage.
    """

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return None

    stage_index = STAGE_ORDER[normalized_stage]
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

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return None

    stage_index = STAGE_ORDER[normalized_stage]

    if stage_index == 0:
        return None

    return CLEARANCE_STAGES[stage_index - 1]


def get_stage_role(stage):
    """
    Return the recognized staff role for a clearance stage.
    """

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return None

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

    normalized_role = role.strip().casefold()

    for configured_role, assigned_stage in STAFF_STAGE_ROLES.items():
        if configured_role.casefold() == normalized_role:
            return assigned_stage

    return None


def get_stage_display_name(stage):
    """
    Return a human-readable clearance-stage name.

    Invalid stages return an empty string rather than being
    presented as official workflow stages.
    """

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return ""

    return format_stage_name(normalized_stage)


# ==========================================================
# STAGE RECORD UTILITIES
# ==========================================================

def get_stage_record(clearance, stage):
    """
    Retrieve a stage record from a clearance document.

    Supports both dictionary-based stage records and legacy
    list-based records.

    Returns:
        dict: Stage record, or an empty dictionary if absent.
    """

    if not isinstance(clearance, dict):
        return {}

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return {}

    stages = clearance.get("stages", {})

    if isinstance(stages, dict):
        # The standard schema uses official stage names as keys.
        record = stages.get(normalized_stage)

        if isinstance(record, dict):
            return record

        # Allow existing records whose keys differ only in
        # capitalization or harmless stage-name formatting.
        for stored_name, stored_record in stages.items():
            if (
                normalize_clearance_stage(stored_name)
                == normalized_stage
                and isinstance(stored_record, dict)
            ):
                return stored_record

        return {}

    if isinstance(stages, list):
        for record in stages:
            if not isinstance(record, dict):
                continue

            record_stage = normalize_clearance_stage(
                record.get("stage", "")
            )

            if record_stage == normalized_stage:
                return record

    return {}


def get_clearance_current_stage(clearance):
    """
    Return the normalized official current stage.

    Returns:
        str: Valid stage name, or an empty string if invalid.
    """

    if not isinstance(clearance, dict):
        return ""

    return normalize_clearance_stage(
        clearance.get("current_stage", "")
    )


def are_previous_stages_approved(clearance, stage):
    """
    Check whether every official stage before the supplied
    stage has status 'approved'.

    The first stage has no previous stages, so it passes this
    ordering check when the clearance is a valid dictionary
    with a dictionary or list of stage records.

    This helper does not approve stages, update the database,
    or independently authorize a stage transition.

    Returns:
        bool: True only when all preceding stages are approved
              and the clearance stage data is structurally valid.
    """

    if not isinstance(clearance, dict):
        return False

    normalized_stage = normalize_clearance_stage(stage)

    if not normalized_stage:
        return False

    stages = clearance.get("stages")

    if not isinstance(stages, (dict, list)):
        return False

    # Verify that the requested stage itself has a stage record.
    if not get_stage_record(clearance, normalized_stage):
        return False

    stage_index = STAGE_ORDER[normalized_stage]

    for previous_stage in CLEARANCE_STAGES[:stage_index]:
        previous_record = get_stage_record(
            clearance,
            previous_stage,
        )

        if previous_record.get("status") != STAGE_STATUS_APPROVED:
            return False

    return True


def is_clearance_stage_consistent(clearance):
    """
    Validate the clearance's current-stage status against
    the official stage sequence.

    For an active clearance:
      - current_stage must be an official stage.
      - every earlier stage must be approved.
      - the current stage must have a recognized workflow status.
      - later stages must not already be approved.

    A completed clearance must have the final stage approved
    and the current_stage set to the final stage.

    This helper checks consistency, not whether the current
    request is authorized to perform an operation.
    """

    if not isinstance(clearance, dict):
        return False

    current_stage = get_clearance_current_stage(clearance)

    if not current_stage:
        return False

    stages = clearance.get("stages")

    if not isinstance(stages, (dict, list)):
        return False

    current_record = get_stage_record(clearance, current_stage)

    if not current_record:
        return False

    current_status = current_record.get("status")

    valid_statuses = {
        STAGE_STATUS_PENDING,
        STAGE_STATUS_AWAITING_SUBMISSION,
        STAGE_STATUS_UNDER_REVIEW,
        STAGE_STATUS_APPROVED,
        STAGE_STATUS_REJECTED,
    }

    if current_status not in valid_statuses:
        return False

    if not are_previous_stages_approved(clearance, current_stage):
        return False

    current_index = STAGE_ORDER[current_stage]

    # Later stages must not be approved before the workflow
    # reaches them. This catches premature advancement or
    # inconsistent stage records.
    for later_stage in CLEARANCE_STAGES[current_index + 1:]:
        later_record = get_stage_record(clearance, later_stage)

        if later_record.get("status") == STAGE_STATUS_APPROVED:
            return False

    clearance_status = str(
        clearance.get("status", "")
    ).strip().lower()

    if clearance_status == "completed":
        return (
            current_stage == FINAL_CLEARANCE_STAGE
            and current_status == STAGE_STATUS_APPROVED
        )

    # A non-completed clearance must not have already approved
    # the final stage.
    if current_stage == FINAL_CLEARANCE_STAGE:
        if current_status == STAGE_STATUS_APPROVED:
            return False

    return True


# ==========================================================
# DATABASE LOOKUP UTILITIES
# ==========================================================

def get_student_by_reg_no(reg_no):
    """
    Retrieve a student using a normalized registration number.

    Returns:
        dict or None

    IMPORTANT:
    Existing student documents should store reg_no in
    normalized uppercase form for consistent lookups.
    """

    normalized_reg_no = normalize_reg_no(reg_no)

    if not normalized_reg_no:
        return None

    return mongo.db.students.find_one({
        "reg_no": normalized_reg_no
    })


def get_staff_by_id(staff_id):
    """
    Retrieve a staff member using a normalized staff ID.

    Returns:
        dict or None
    """

    if not isinstance(staff_id, str) or not staff_id.strip():
        return None

    return mongo.db.staff.find_one({
        "staff_id": staff_id.strip().upper()
    })


def get_clearance_by_reg_no(reg_no):
    """
    Retrieve a student's clearance record using a normalized
    registration number.
    """

    normalized_reg_no = normalize_reg_no(reg_no)

    if not normalized_reg_no:
        return None

    return mongo.db.clearances.find_one({
        "reg_no": normalized_reg_no
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

    assigned_stage = normalize_clearance_stage(
        staff.get("assigned_stage", "")
    )

    requested_stage = normalize_clearance_stage(stage)

    return (
        bool(assigned_stage)
        and bool(requested_stage)
        and assigned_stage == requested_stage
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
