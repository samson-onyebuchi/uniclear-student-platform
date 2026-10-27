# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/code/staff.py
#
# PURPOSE:
# 1. Preserve the existing staff onboarding and password pattern.
# 2. Authenticate staff members and support password recovery.
# 3. Provide stage-specific student lists and dashboard counts.
# 4. Let staff open student/clearance details for their stage.
# 5. Preserve processed, approved and rejected student history.
# 6. Approve/reject only submissions under review.
# 7. Require a rejection reason and include it in student email.
# 8. Update stage and document statuses consistently.
# 9. Issue and verify no-expiry stage-transition OTPs.
# 10. Record review and stage-verification history.
# 11. Notify students of clearance decisions and transitions.
#
# API ENDPOINTS:
# POST /api/v1/clearance/admin/onboard/staff
# POST /api/v1/clearance/login/staff
# POST /api/v1/clearance/forgot-password/staff
# POST /api/v1/clearance/reset-password/staff
# POST /api/v1/clearance/otp-reset-password/staff
# POST /api/v1/clearance/change-password/staff
# POST /api/v1/clearance/staff/students
# POST /api/v1/clearance/staff/student-details
# POST /api/v1/clearance/staff/review-stage
# POST /api/v1/clearance/staff/verify-stage-otp
#
# IMPORTANT SECURITY NOTE:
# Staff onboarding authorization is intentionally deferred to
# the future administrator module. The onboarding endpoint
# MUST NOT be exposed publicly until administrator authorization
# has been implemented.
#
# CLEARANCE WORKFLOW:
# 1. A student submits the current stage document.
# 2. The stage becomes under_review.
# 3. The assigned officer approves or rejects the stage.
# 4. Approval generates a no-expiry OTP for the next stage.
# 5. The assigned officer for the next stage verifies the OTP.
# 6. Successful verification advances current_stage and makes
#    the next stage available for document submission.
#
# STAGE OTP RULE:
# Stage OTPs have no time-based expiry. They remain valid until
# used or invalidated.
#
# PASSWORD RESET OTP RULE:
# Staff password-reset OTPs expire after ten minutes.
#
# AUTHENTICATION:
# This module does not introduce token authentication or
# token logout.
# ==========================================================

import secrets
import bcrypt
import logging

from datetime import timedelta

from flask import request
from flask_restful import Resource
from pymongo import ReturnDocument

from app import api, mongo
from app.email_util import EmailSender
from app.utils import (
    generate_otp,
    get_utc_now,
    is_valid_email,
    is_valid_otp,
)
from app.code.general_function import (
    CLEARANCE_STAGES,
    STAFF_STAGE_ROLES,
    FINAL_CLEARANCE_STAGE,
    get_assigned_stage,
    get_next_clearance_stage,
    get_staff_by_id,
    get_student_by_reg_no,
    get_clearance_by_reg_no,
    get_student_full_name,
    get_staff_full_name,
    is_active_account,
    is_stage_assigned_to_staff,
    normalize_stage_name,
)


logger = logging.getLogger(__name__)


# ==========================================================
# EMAIL UTILITY
# ==========================================================

def safe_send_email(method, *args, **kwargs):
    """
    Attempt an email operation without allowing an unexpected
    email-provider exception to invalidate a completed database
    operation.

    A True result means the email utility reported success.
    It does not guarantee delivery to the recipient's inbox.
    """

    try:
        return bool(method(*args, **kwargs))

    except Exception:
        logger.exception("Staff email operation failed.")
        return False


# ==========================================================
# PASSWORD UTILITIES
# ==========================================================

def hash_staff_password(password):
    """Hash a staff password using bcrypt."""

    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_staff_password(password, password_hash):
    """Verify a staff password against its stored bcrypt hash."""

    if not isinstance(password, str):
        return False

    if not isinstance(password_hash, str):
        return False

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def normalize_staff_id(staff_id):
    """Normalize a staff ID."""

    if not isinstance(staff_id, str):
        return ""

    return staff_id.strip().upper()


def validate_new_password(password):
    """Require a password of at least eight characters."""

    return isinstance(password, str) and len(password) >= 8


def generate_staff_otp():
    """Generate a six-digit staff password-reset OTP."""

    return generate_otp(6)


def hash_staff_reset_otp(otp):
    """Hash a staff password-reset OTP before database storage."""

    return bcrypt.hashpw(
        otp.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_staff_reset_otp(otp, stored_hash):
    """Verify an OTP against a bcrypt hash."""

    if not isinstance(otp, str):
        return False

    if not isinstance(stored_hash, str):
        return False

    try:
        return bcrypt.checkpw(
            otp.encode("utf-8"),
            stored_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def get_staff_assigned_stage(staff):
    """Return the normalized clearance stage assigned to a staff account."""

    if not isinstance(staff, dict):
        return ""

    stage = normalize_stage_name(staff.get("assigned_stage", ""))
    if stage in CLEARANCE_STAGES:
        return stage

    stage = get_assigned_stage(staff.get("role", ""))
    return stage if stage in CLEARANCE_STAGES else ""


def get_staff_public_profile(staff):
    """Return staff profile data without sensitive credentials."""

    assigned_stage = get_staff_assigned_stage(staff)
    return {
        "staff_id": staff.get("staff_id"),
        "surname": staff.get("surname"),
        "first_name": staff.get("first_name"),
        "other_names": staff.get("other_names", ""),
        "email": staff.get("email"),
        "department": staff.get("department"),
        "faculty": staff.get("faculty"),
        "role": staff.get("role"),
        "assigned_stage": assigned_stage or staff.get("assigned_stage"),
        "account_status": staff.get("account_status", "active"),
        "must_change_password": staff.get(
            "must_change_password",
            False,
        ),
        # The existing frontend can use this to route the staff member
        # to the shared stage-aware dashboard after login.
        "dashboard_stage": assigned_stage,
        "redirect_to": (
            f"staff-dashboard.html?stage={assigned_stage}"
            if assigned_stage else "staff-dashboard.html"
        ),
    }


def json_safe_staff_value(value):
    """Recursively convert dates/ObjectIds and MongoDB values for JSON."""

    if isinstance(value, dict):
        return {
            str(key): json_safe_staff_value(item)
            for key, item in value.items()
            if key not in {
                "_id", "grid_file_id", "password", "reset_otp",
                "reset_otp_hash", "reset_otp_expiry",
            }
        }
    if isinstance(value, (list, tuple)):
        return [json_safe_staff_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat") and callable(value.isoformat):
        try:
            return value.isoformat()
        except (TypeError, ValueError):
            pass
    # ObjectId, Decimal128, and other non-JSON database objects.
    return str(value)


def public_staff_document(document, stage):
    """Build safe document metadata and relative viewer/download URLs."""

    if not isinstance(document, dict):
        return {}

    document_id = str(document.get("document_id", ""))
    public_data = {
        "document_id": document_id,
        "document_name": document.get("document_name", ""),
        "file_name": document.get("file_name", ""),
        "original_filename": document.get("original_filename", ""),
        "content_type": document.get("content_type", ""),
        "file_size": document.get("file_size", 0),
        "stage": document.get("stage", stage),
        "status": document.get("status", "under_review"),
        "uploaded_at": document.get("uploaded_at"),
        "rejection_comment": document.get("rejection_comment", ""),
        "reviewed_by": document.get("reviewed_by"),
        "reviewed_at": document.get("reviewed_at"),
    }
    if document_id:
        public_data["view_url"] = (
            f"/api/v1/clearance/document/view/{document_id}"
        )
        public_data["download_url"] = (
            f"/api/v1/clearance/document/download/{document_id}"
        )
    return json_safe_staff_value(public_data)


def public_staff_stage_record(stage_record, stage):
    """Return a safe, dashboard-ready representation of one stage."""

    if not isinstance(stage_record, dict):
        stage_record = {}

    documents = stage_record.get("documents", [])
    if not isinstance(documents, list):
        documents = []

    history = stage_record.get("review_history", [])
    if not isinstance(history, list):
        history = []

    return {
        "stage": stage,
        "status": stage_record.get("status", "pending"),
        "rejection_comment": stage_record.get("rejection_comment", ""),
        "reviewed_by": stage_record.get("reviewed_by"),
        "reviewed_at": json_safe_staff_value(stage_record.get("reviewed_at")),
        "verified_by": stage_record.get("verified_by"),
        "verified_at": json_safe_staff_value(stage_record.get("verified_at")),
        "otp_verified_by": stage_record.get("otp_verified_by"),
        "otp_verified_at": json_safe_staff_value(stage_record.get("otp_verified_at")),
        "documents": [public_staff_document(doc, stage) for doc in documents],
        "review_history": json_safe_staff_value(history),
    }


def stage_review_history(stage_record):
    """Return a stage's review history, including legacy records if needed."""

    if not isinstance(stage_record, dict):
        return []

    history = stage_record.get("review_history", [])
    if isinstance(history, list) and history:
        return history

    # Records created before review_history existed still show their latest
    # review in the processed section via these legacy fields.
    staff_id = stage_record.get("reviewed_by")
    status = stage_record.get("status")
    if staff_id and status in {"approved", "rejected"}:
        return [{
            "action": "reject" if status == "rejected" else "approve",
            "staff_id": staff_id,
            "reason": stage_record.get("rejection_comment", ""),
            "reviewed_at": stage_record.get("reviewed_at"),
        }]
    return []


def stage_was_processed_by(stage_record, staff_id):
    return any(
        isinstance(entry, dict) and entry.get("staff_id") == staff_id
        for entry in stage_review_history(stage_record)
    ) or (
        isinstance(stage_record, dict)
        and stage_record.get("reviewed_by") == staff_id
    )


def stage_was_rejected_by(stage_record, staff_id):
    return any(
        isinstance(entry, dict)
        and entry.get("staff_id") == staff_id
        and str(entry.get("action", "")).lower() in {"reject", "rejected"}
        for entry in stage_review_history(stage_record)
    ) or (
        isinstance(stage_record, dict)
        and stage_record.get("reviewed_by") == staff_id
        and stage_record.get("status") == "rejected"
    )


def make_staff_student_summary(student, clearance, stage, staff_id):
    """Create one table row for the assigned-stage staff dashboard."""

    stage_record = get_stage_record(clearance, stage)
    documents = stage_record.get("documents", [])
    if not isinstance(documents, list):
        documents = []

    public_documents = [
        public_staff_document(document, stage)
        for document in documents
        if isinstance(document, dict)
    ]
    latest_document = public_documents[-1] if public_documents else {}
    history = stage_review_history(stage_record)
    latest_review = history[-1] if history else {}
    current_stage = get_current_clearance_stage(clearance)
    is_current = current_stage == stage and clearance.get("status") != "completed"
    was_processed = stage_was_processed_by(stage_record, staff_id)
    was_rejected = stage_was_rejected_by(stage_record, staff_id)

    student_status = student.get("student_status")
    if student_status is None:
        student_status = student.get("study_status", "")

    return {
        "reg_no": str(clearance.get("reg_no", student.get("reg_no", ""))).upper(),
        "student_name": get_student_full_name(student),
        "surname": student.get("surname", ""),
        "first_name": student.get("first_name", ""),
        "other_names": student.get("other_names", ""),
        "email": student.get("email", ""),
        "department": student.get("department", ""),
        "faculty": student.get("faculty", ""),
        "student_status": student_status or "",
        "clearance_status": clearance.get("status", "in_progress"),
        "current_stage": current_stage,
        "assigned_stage": stage,
        "stage_status": stage_record.get("status", "pending"),
        "document_status": latest_document.get("status", "not_submitted"),
        "document_count": len(public_documents),
        "latest_document": latest_document or None,
        "documents": public_documents,
        "uploaded_at": latest_document.get("uploaded_at"),
        "rejection_comment": (
            stage_record.get("rejection_comment")
            or latest_document.get("rejection_comment", "")
        ),
        "reviewed_by": stage_record.get("reviewed_by"),
        "reviewed_at": json_safe_staff_value(stage_record.get("reviewed_at")),
        "latest_review": json_safe_staff_value(latest_review) if latest_review else None,
        "review_history": json_safe_staff_value(history),
        "is_current_stage": is_current,
        "is_pending_review": is_current and stage_record.get("status") == "under_review",
        "was_processed_by_staff": was_processed,
        "was_rejected_by_staff": was_rejected,
        "updated_at": json_safe_staff_value(clearance.get("updated_at")),
    }


def get_stage_record(clearance, stage):
    """Retrieve a stage record from a clearance document."""

    if not isinstance(clearance, dict):
        return {}

    stages = clearance.get("stages", {})

    if isinstance(stages, dict):
        record = stages.get(stage, {})
        return record if isinstance(record, dict) else {}

    if isinstance(stages, list):
        for record in stages:
            if (
                isinstance(record, dict)
                and normalize_stage_name(
                    record.get("stage", "")
                ) == stage
            ):
                return record

    return {}


def get_current_clearance_stage(clearance):
    """Return the normalized current clearance stage."""

    if not isinstance(clearance, dict):
        return ""

    return normalize_stage_name(
        clearance.get("current_stage", "")
    )


def stage_is_under_review(clearance, stage):
    """Check whether a stage is awaiting staff review."""

    return (
        get_stage_record(clearance, stage).get("status")
        == "under_review"
    )


def update_stage_record(
    reg_no,
    stage,
    updates,
    *,
    staff_id=None,
    document_status=None,
    review_history_entry=None,
):
    """
    Conditionally update a stage still under review. When a review decision is
    made, synchronize every currently-under-review document with the stage's
    decision and append a durable history item. Older rejected documents remain
    rejected when a student uploads a corrected replacement.
    """

    update_fields = {
        f"stages.{stage}.{field}": value
        for field, value in updates.items()
    }
    update_document = {"$set": {**update_fields, "updated_at": get_utc_now()}}
    array_filters = None

    if document_status:
        document_path = f"stages.{stage}.documents.$[doc]"
        update_document["$set"].update({
            f"{document_path}.status": document_status,
            f"{document_path}.reviewed_by": staff_id,
            f"{document_path}.reviewed_at": updates.get("reviewed_at"),
            f"{document_path}.rejection_comment": updates.get(
                "rejection_comment", ""
            ),
        })
        array_filters = [{"doc.status": "under_review"}]

    if review_history_entry is not None:
        update_document.setdefault("$push", {})[
            f"stages.{stage}.review_history"
        ] = review_history_entry

    query = {
        "reg_no": reg_no,
        "current_stage": stage,
        "status": {"$ne": "completed"},
        f"stages.{stage}.status": "under_review",
    }

    if array_filters is not None:
        return mongo.db.clearances.update_one(
            query, update_document, array_filters=array_filters
        )
    return mongo.db.clearances.update_one(query, update_document)


def invalidate_pending_stage_otps(reg_no, now, reason):
    """Invalidate pending or stranded verification OTPs."""

    mongo.db.stage_otps.update_many(
        {
            "reg_no": reg_no,
            "status": {"$in": ["pending", "verifying"]},
        },
        {
            "$set": {
                "status": "invalidated",
                "invalidated_at": now,
                "invalidated_reason": reason,
            }
        },
    )


def restore_claimed_stage_otp(otp_id, staff_id):
    """
    Return a claimed OTP to pending if advancement fails.

    The operation only affects an OTP still owned by the current
    verification request.
    """

    return mongo.db.stage_otps.update_one(
        {
            "_id": otp_id,
            "status": "verifying",
            "verifying_staff_id": staff_id,
        },
        {
            "$set": {
                "status": "pending",
            },
            "$unset": {
                "verifying_staff_id": "",
                "verifying_at": "",
            },
        },
    )


# ==========================================================
# 1. ONBOARD STAFF
# ==========================================================

class OnboardStaff(Resource):
    """
    Create a staff account for a clearance stage.

    The staff member supplies their own password during
    onboarding. The password is validated and hashed before
    it is saved to MongoDB.

    SECURITY:
    This endpoint currently has no administrator authorization.
    It must not be exposed publicly until the admin module
    protects it.
    """

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        required_fields = [
            "staff_id",
            "surname",
            "first_name",
            "email",
            "department",
            "faculty",
            "role",
            "password",
            "confirm_password",
        ]

        missing_fields = [
            field
            for field in required_fields
            if (
                not isinstance(data.get(field), str)
                or not data[field].strip()
            )
        ]

        if missing_fields:
            return {
                "success": False,
                "message": "Some required fields are missing.",
                "errors": {
                    "missing_fields": missing_fields,
                },
            }, 400

        staff_id = normalize_staff_id(data["staff_id"])
        email = data["email"].strip().lower()
        role = data["role"].strip()
        password = data["password"]
        confirm_password = data["confirm_password"]

        # --------------------------------------------------
        # VALIDATE PASSWORD
        # --------------------------------------------------

        if not validate_new_password(password):
            return {
                "success": False,
                "message": (
                    "Password must contain at least 8 characters."
                ),
            }, 400

        if password != confirm_password:
            return {
                "success": False,
                "message": "Passwords do not match.",
            }, 400

        assigned_stage = get_assigned_stage(role)

        if assigned_stage is None:
            return {
                "success": False,
                "message": (
                    "The supplied role is not a recognized "
                    "clearance officer role."
                ),
                "allowed_roles": list(STAFF_STAGE_ROLES.keys()),
            }, 400

        if not is_valid_email(email):
            return {
                "success": False,
                "message": "Please provide a valid email address.",
            }, 400

        # --------------------------------------------------
        # CHECK FOR DUPLICATE STAFF ID OR EMAIL
        # --------------------------------------------------

        try:
            duplicate = mongo.db.staff.find_one({
                "$or": [
                    {"staff_id": staff_id},
                    {"email": email},
                ]
            })

        except Exception:
            logger.exception(
                "Staff onboarding duplicate lookup failed."
            )

            return {
                "success": False,
                "message": (
                    "Unable to check staff registration details "
                    "at this time."
                ),
            }, 503

        if duplicate:
            if duplicate.get("staff_id") == staff_id:
                return {
                    "success": False,
                    "message": "This staff ID is already registered.",
                }, 409

            return {
                "success": False,
                "message": (
                    "This email address is already registered "
                    "to a staff account."
                ),
            }, 409

        # --------------------------------------------------
        # CREATE STAFF ACCOUNT
        # --------------------------------------------------

        now = get_utc_now()

        staff = {
            "staff_id": staff_id,
            "surname": data["surname"].strip(),
            "first_name": data["first_name"].strip(),
            "other_names": str(
                data.get("other_names") or ""
            ).strip(),
            "email": email,
            "department": data["department"].strip(),
            "faculty": data["faculty"].strip(),
            "role": role,
            "assigned_stage": assigned_stage,
            "account_status": "active",
            "password": hash_staff_password(password),
            "must_change_password": False,
            "created_at": now,
            "updated_at": now,
        }

        try:
            result = mongo.db.staff.insert_one(staff)
            staff["_id"] = result.inserted_id

        except Exception:
            logger.exception(
                "Staff onboarding database insertion failed."
            )

            return {
                "success": False,
                "message": "Unable to create the staff account.",
            }, 500

        # --------------------------------------------------
        # SEND STAFF ONBOARDING EMAIL
        # --------------------------------------------------
        #
        # Follow the safe email-handling approach used by
        # student registration.
        #
        # No temporary password is generated or emailed because
        # the staff member supplied their own password.
        #
        # The final argument is None to indicate that there is
        # no temporary password to send. The existing email
        # utility is left unchanged.
        # --------------------------------------------------

        email_sent = safe_send_email(
            EmailSender.send_staff_onboarding_email,
            email,
            get_staff_full_name(staff),
            staff_id,
            role,
            None,
        )

        if email_sent:
            logger.info(
                "Staff onboarding email accepted by email utility "
                "for staff ID: %s",
                staff_id,
            )
        else:
            logger.error(
                "Staff onboarding email failed for staff ID: %s",
                staff_id,
            )

        return {
            "success": True,
            "message": "Staff account created successfully.",
            "email_sent": email_sent,
            "data": get_staff_public_profile(staff),
        }, 201


# ==========================================================
# 2. STAFF LOGIN
# ==========================================================

class StaffLogin(Resource):
    """Authenticate a staff member with staff ID and password."""

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        password = data.get("password")

        if (
            not staff_id
            or not isinstance(password, str)
            or not password
        ):
            return {
                "success": False,
                "message": "Staff ID and password are required.",
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff or not verify_staff_password(
            password,
            staff.get("password", ""),
        ):
            return {
                "success": False,
                "message": "Invalid staff ID or password.",
            }, 401

        if not is_active_account(staff):
            return {
                "success": False,
                "message": "Your staff account is not active.",
            }, 403

        profile = get_staff_public_profile(staff)
        return {
            "success": True,
            "message": "Staff login successful.",
            "must_change_password": staff.get(
                "must_change_password",
                False,
            ),
            "assigned_stage": profile.get("assigned_stage"),
            "dashboard_stage": profile.get("dashboard_stage"),
            "redirect_to": profile.get("redirect_to"),
            "data": profile,
        }, 200


# ==========================================================
# 3. STAFF FORGOT PASSWORD
# ==========================================================

class StaffForgotPassword(Resource):
    """Generate and email a ten-minute staff password-reset OTP."""

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))

        if not staff_id:
            return {
                "success": False,
                "message": "Staff ID is required.",
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff:
            return {
                "success": True,
                "message": (
                    "If the staff account exists, password-reset "
                    "instructions will be sent."
                ),
            }, 200

        if not is_active_account(staff):
            return {
                "success": False,
                "message": "Your staff account is not active.",
            }, 403

        otp = generate_staff_otp()
        otp_hash = hash_staff_reset_otp(otp)
        now = get_utc_now()
        expiry = now + timedelta(minutes=10)

        try:
            result = mongo.db.staff.update_one(
                {
                    "_id": staff["_id"],
                    "account_status": staff.get(
                        "account_status",
                        "active",
                    ),
                },
                {
                    "$set": {
                        "reset_otp_hash": otp_hash,
                        "reset_otp_expiry": expiry,
                        "reset_otp_created_at": now,
                        "updated_at": now,
                    },
                    "$unset": {
                        "reset_otp": "",
                    },
                },
            )

        except Exception:
            logger.exception(
                "Staff password-reset OTP database update failed."
            )

            return {
                "success": False,
                "message": (
                    "Unable to create a password-reset request."
                ),
            }, 500

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "Unable to create a password-reset request. "
                    "Please try again."
                ),
            }, 409

        email_sent = safe_send_email(
            EmailSender.send_staff_forgot_password_email,
            staff.get("email"),
            get_staff_full_name(staff),
            otp,
        )

        if not email_sent:
            try:
                mongo.db.staff.update_one(
                    {
                        "_id": staff["_id"],
                        "reset_otp_hash": otp_hash,
                    },
                    {
                        "$unset": {
                            "reset_otp_hash": "",
                            "reset_otp_expiry": "",
                            "reset_otp_created_at": "",
                        }
                    },
                )

            except Exception:
                logger.exception(
                    "Failed to clear unsent staff reset OTP."
                )

            return {
                "success": False,
                "message": (
                    "Unable to send the password-reset email. "
                    "Please try again later."
                ),
            }, 503

        return {
            "success": True,
            "message": "Password-reset OTP sent to your email.",
            "otp_expiry_minutes": 10,
        }, 200


# ==========================================================
# 4. STAFF RESET PASSWORD WITH OTP
# ==========================================================

class StaffResetPasswordWithOTP(Resource):
    """Reset a staff password using a valid OTP."""

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        otp = data.get("otp")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if (
            not staff_id
            or not isinstance(otp, str)
            or not is_valid_otp(otp, 6)
            or not isinstance(new_password, str)
        ):
            return {
                "success": False,
                "message": (
                    "Staff ID, six-digit OTP and new password "
                    "are required."
                ),
            }, 400

        if not isinstance(confirm_password, str):
            return {
                "success": False,
                "message": "Password confirmation is required.",
            }, 400

        if confirm_password != new_password:
            return {
                "success": False,
                "message": "Passwords do not match.",
            }, 400

        if not validate_new_password(new_password):
            return {
                "success": False,
                "message": "Password must contain at least 8 characters.",
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff or not is_active_account(staff):
            return {
                "success": False,
                "message": "Invalid staff ID or OTP.",
            }, 400

        stored_hash = staff.get("reset_otp_hash")
        expiry = staff.get("reset_otp_expiry")
        now = get_utc_now()

        # Support older records that stored the OTP in plaintext.
        # New reset requests always store a bcrypt hash.
        legacy_otp = staff.get("reset_otp")
        otp_valid = (
            verify_staff_reset_otp(otp, stored_hash)
            if stored_hash
            else (
                isinstance(legacy_otp, str)
                and secrets.compare_digest(legacy_otp, otp)
            )
        )

        if not otp_valid:
            return {
                "success": False,
                "message": "Invalid staff ID or OTP.",
            }, 400

        if not expiry:
            return {
                "success": False,
                "message": "OTP has expired. Request a new OTP.",
            }, 400

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=now.tzinfo)

        if now >= expiry:
            expiry_filter = staff.get("reset_otp_expiry")

            mongo.db.staff.update_one(
                {
                    "_id": staff["_id"],
                    "reset_otp_expiry": expiry_filter,
                },
                {
                    "$unset": {
                        "reset_otp_hash": "",
                        "reset_otp": "",
                        "reset_otp_expiry": "",
                        "reset_otp_created_at": "",
                    }
                },
            )

            return {
                "success": False,
                "message": "OTP has expired. Request a new OTP.",
            }, 400

        # Atomically consume the matching OTP and expiry before
        # completing the password reset.
        otp_filter = {
            "_id": staff["_id"],
            "reset_otp_expiry": staff.get("reset_otp_expiry"),
        }

        if stored_hash:
            otp_filter["reset_otp_hash"] = stored_hash
        else:
            otp_filter["reset_otp"] = legacy_otp

        result = mongo.db.staff.update_one(
            otp_filter,
            {
                "$set": {
                    "password": hash_staff_password(new_password),
                    "must_change_password": False,
                    "updated_at": now,
                },
                "$unset": {
                    "reset_otp_hash": "",
                    "reset_otp": "",
                    "reset_otp_expiry": "",
                    "reset_otp_created_at": "",
                },
            },
        )

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "The OTP has already been consumed or replaced. "
                    "Request a new OTP and try again."
                ),
            }, 409

        email_sent = safe_send_email(
            EmailSender.send_staff_password_changed_email,
            staff.get("email"),
            get_staff_full_name(staff),
        )

        return {
            "success": True,
            "message": "Staff password reset successfully.",
            "email_sent": email_sent,
        }, 200


# ==========================================================
# 5. LEGACY STAFF OTP-RESET ENDPOINT
# ==========================================================

class OTPResetStaffPassword(Resource):
    """
    Maintain compatibility with the legacy OTP-reset endpoint.

    This endpoint uses the same validation and single-use OTP
    behavior as StaffResetPasswordWithOTP, but confirm_password
    is optional for clients using the older request format.
    """

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        if "confirm_password" not in data:
            data = dict(data)
            data["confirm_password"] = data.get("new_password")

        return self._reset_password(data)

    def _reset_password(self, data):
        staff_id = normalize_staff_id(data.get("staff_id", ""))
        otp = data.get("otp")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if (
            not staff_id
            or not isinstance(otp, str)
            or not is_valid_otp(otp, 6)
            or not isinstance(new_password, str)
        ):
            return {
                "success": False,
                "message": (
                    "Staff ID, six-digit OTP and new password "
                    "are required."
                ),
            }, 400

        if confirm_password != new_password:
            return {
                "success": False,
                "message": "Passwords do not match.",
            }, 400

        if not validate_new_password(new_password):
            return {
                "success": False,
                "message": "Password must contain at least 8 characters.",
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff or not is_active_account(staff):
            return {
                "success": False,
                "message": "Invalid staff ID or OTP.",
            }, 400

        stored_hash = staff.get("reset_otp_hash")
        expiry = staff.get("reset_otp_expiry")
        legacy_otp = staff.get("reset_otp")
        now = get_utc_now()

        otp_valid = (
            verify_staff_reset_otp(otp, stored_hash)
            if stored_hash
            else (
                isinstance(legacy_otp, str)
                and secrets.compare_digest(legacy_otp, otp)
            )
        )

        if not otp_valid:
            return {
                "success": False,
                "message": "Invalid staff ID or OTP.",
            }, 400

        if not expiry:
            return {
                "success": False,
                "message": "OTP has expired. Request a new OTP.",
            }, 400

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=now.tzinfo)

        if now >= expiry:
            return {
                "success": False,
                "message": "OTP has expired. Request a new OTP.",
            }, 400

        otp_filter = {
            "_id": staff["_id"],
            "reset_otp_expiry": staff.get("reset_otp_expiry"),
        }

        if stored_hash:
            otp_filter["reset_otp_hash"] = stored_hash
        else:
            otp_filter["reset_otp"] = legacy_otp

        result = mongo.db.staff.update_one(
            otp_filter,
            {
                "$set": {
                    "password": hash_staff_password(new_password),
                    "must_change_password": False,
                    "updated_at": now,
                },
                "$unset": {
                    "reset_otp_hash": "",
                    "reset_otp": "",
                    "reset_otp_expiry": "",
                    "reset_otp_created_at": "",
                },
            },
        )

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "The OTP has already been consumed or replaced. "
                    "Request a new OTP and try again."
                ),
            }, 409

        email_sent = safe_send_email(
            EmailSender.send_staff_password_changed_email,
            staff.get("email"),
            get_staff_full_name(staff),
        )

        return {
            "success": True,
            "message": "Staff password reset successfully.",
            "email_sent": email_sent,
        }, 200


# ==========================================================
# 6. STAFF CHANGE PASSWORD
# ==========================================================

class ChangeStaffPassword(Resource):
    """Change a staff password after checking the current password."""

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if (
            not staff_id
            or not isinstance(current_password, str)
            or not current_password
            or not isinstance(new_password, str)
            or not new_password
        ):
            return {
                "success": False,
                "message": (
                    "Staff ID, current password and new password "
                    "are required."
                ),
            }, 400

        if (
            confirm_password is not None
            and confirm_password != new_password
        ):
            return {
                "success": False,
                "message": "Passwords do not match.",
            }, 400

        if not validate_new_password(new_password):
            return {
                "success": False,
                "message": "Password must contain at least 8 characters.",
            }, 400

        if current_password == new_password:
            return {
                "success": False,
                "message": (
                    "Your new password must differ from your "
                    "current password."
                ),
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff or not verify_staff_password(
            current_password,
            staff.get("password", ""),
        ):
            return {
                "success": False,
                "message": "Invalid staff ID or current password.",
            }, 401

        if not is_active_account(staff):
            return {
                "success": False,
                "message": "Your staff account is not active.",
            }, 403

        result = mongo.db.staff.update_one(
            {
                "_id": staff["_id"],
                "password": staff["password"],
            },
            {
                "$set": {
                    "password": hash_staff_password(new_password),
                    "must_change_password": False,
                    "updated_at": get_utc_now(),
                }
            },
        )

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "The password could not be changed. "
                    "Please try again."
                ),
            }, 409

        email_sent = safe_send_email(
            EmailSender.send_staff_password_changed_email,
            staff.get("email"),
            get_staff_full_name(staff),
        )

        return {
            "success": True,
            "message": "Staff password changed successfully.",
            "email_sent": email_sent,
        }, 200


# ==========================================================
# 7. APPROVE OR REJECT CLEARANCE STAGE
# ==========================================================

class StaffApproveRejectClearanceStage(Resource):
    """
    Approve or reject a student's current-stage submission.

    Only an active officer assigned to the current stage can act, and only
    while the stage is under_review. Rejection requires a reason, which is
    saved to the stage, its currently submitted documents, review history,
    and the student rejection email.
    """

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        reg_no = str(data.get("reg_no", "")).strip().upper()
        action = str(data.get("action", "")).strip().lower()
        comment = str(data.get("reason", data.get("comment", ""))).strip()

        if not staff_id or not reg_no or action not in {"approve", "reject"}:
            return {
                "success": False,
                "message": (
                    "Staff ID, registration number and a valid "
                    "action (approve or reject) are required."
                ),
            }, 400

        if action == "reject" and not comment:
            return {
                "success": False,
                "message": "A rejection reason is required before rejecting a stage.",
                "field": "reason",
            }, 400

        staff = get_staff_by_id(staff_id)
        if not staff:
            return {"success": False, "message": "Staff account not found."}, 404
        if not is_active_account(staff):
            return {"success": False, "message": "Your staff account is not active."}, 403

        student = get_student_by_reg_no(reg_no)
        if not student:
            return {"success": False, "message": "Student not found."}, 404

        clearance = get_clearance_by_reg_no(reg_no)
        if not clearance:
            return {"success": False, "message": "Clearance record not found."}, 404
        if clearance.get("status") == "completed":
            return {"success": False, "message": "This student's clearance is already complete."}, 409

        stage = get_current_clearance_stage(clearance)
        if not stage or stage not in CLEARANCE_STAGES:
            return {"success": False, "message": "Invalid current clearance stage."}, 409
        if not is_stage_assigned_to_staff(staff, stage):
            return {
                "success": False,
                "message": "You are not authorized to review this clearance stage.",
                "current_stage": stage,
                "assigned_stage": get_staff_assigned_stage(staff),
            }, 403
        if not stage_is_under_review(clearance, stage):
            return {
                "success": False,
                "message": (
                    "This stage is not awaiting review. The student must submit "
                    "the required document before it can be approved or rejected."
                ),
                "stage_status": get_stage_record(clearance, stage).get("status"),
            }, 409

        now = get_utc_now()
        student_name = get_student_full_name(student)
        student_email = student.get("email")
        history_entry = {
            "action": action,
            "staff_id": staff_id,
            "staff_name": get_staff_full_name(staff),
            "reason": comment if action == "reject" else "",
            "reviewed_at": now,
        }

        if action == "reject":
            result = update_stage_record(
                reg_no,
                stage,
                {
                    "status": "rejected",
                    "rejection_comment": comment,
                    "reviewed_by": staff_id,
                    "reviewed_at": now,
                },
                staff_id=staff_id,
                document_status="rejected",
                review_history_entry=history_entry,
            )
            if result.modified_count != 1:
                return {
                    "success": False,
                    "message": (
                        "The stage has changed or is no longer awaiting review. "
                        "Refresh and try again."
                    ),
                }, 409

            invalidate_pending_stage_otps(reg_no, now, "stage_rejected")
            email_sent = safe_send_email(
                EmailSender.send_student_clearance_stage_rejected_email,
                student_email,
                student_name,
                reg_no,
                stage,
                comment,
            )
            return {
                "success": True,
                "message": f"{stage.replace('_', ' ').title()} clearance stage rejected.",
                "stage": stage,
                "status": "rejected",
                "rejection_reason": comment,
                "email_sent": email_sent,
                "refresh_dashboard": True,
            }, 200

        next_stage = get_next_clearance_stage(stage)

        # ==================================================
        # ATOMIC FINAL CLEARANCE APPROVAL AND COMPLETION
        # ==================================================
        #
        # Final-stage approval and overall clearance completion
        # must be written in a single conditional MongoDB update.
        #
        # This prevents the final stage being approved while the
        # overall clearance record remains incomplete if a second
        # database update fails.
        #
        # The final stage never generates a next-stage OTP.
        # ==================================================

        if stage == FINAL_CLEARANCE_STAGE or next_stage is None:
            completion_update = {
                "$set": {
                    f"stages.{stage}.status": "approved",
                    f"stages.{stage}.reviewed_by": staff_id,
                    f"stages.{stage}.reviewed_at": now,
                    f"stages.{stage}.rejection_comment": "",
                    f"stages.{stage}.documents.$[doc].status": "approved",
                    f"stages.{stage}.documents.$[doc].reviewed_by": staff_id,
                    f"stages.{stage}.documents.$[doc].reviewed_at": now,
                    f"stages.{stage}.documents.$[doc].rejection_comment": "",
                    "status": "completed",
                    "completed_at": now,
                    "updated_at": now,
                },
                "$push": {
                    f"stages.{stage}.review_history": history_entry,
                    "workflow_history": {
                        "action": "clearance_completed",
                        "stage": stage,
                        "staff_id": staff_id,
                        "occurred_at": now,
                    },
                },
            }

            completion_result = mongo.db.clearances.update_one(
                {
                    "reg_no": reg_no,
                    "current_stage": stage,
                    "status": {"$ne": "completed"},
                    f"stages.{stage}.status": "under_review",
                },
                completion_update,
                array_filters=[{"doc.status": "under_review"}],
            )

            if completion_result.modified_count != 1:
                return {
                    "success": False,
                    "message": (
                        "The final stage has changed or is no longer awaiting review. "
                        "No completion update was applied. Refresh the clearance record "
                        "and check its current status before trying again."
                    ),
                }, 409

            # Invalidate outstanding stage OTPs only after the atomic
            # completion update has succeeded.
            try:
                invalidate_pending_stage_otps(
                    reg_no,
                    now,
                    "clearance_completed",
                )
            except Exception:
                # Completion has already been recorded. Log cleanup failure
                # without incorrectly claiming the clearance was not completed.
                logger.exception(
                    "Clearance completed but pending OTP invalidation failed for %s",
                    reg_no,
                )

            # Send the dedicated congratulatory email only after MongoDB has
            # successfully recorded both final-stage approval and completion.
            email_sent = safe_send_email(
                EmailSender.send_student_clearance_completed_email,
                receiver_email=student_email,
                student_name=student_name,
                reg_no=reg_no,
            )

            return {
                "success": True,
                "message": (
                    "Congratulations! Your final-year clearance process "
                    "has been completed successfully. There are no further "
                    "clearance stages to complete."
                ),
                "reg_no": reg_no,
                "stage": stage,
                "stage_status": "approved",
                "status": "approved",
                "clearance_status": "completed",
                "clearance_completed": True,
                "next_stage": None,
                "otp_generated": False,
                "email_sent": email_sent,
                "email_status": (
                    "Clearance completion email accepted by the email utility."
                    if email_sent
                    else (
                        "Clearance was completed successfully, but the email "
                        "could not be confirmed as sent. Check SMTP configuration "
                        "and application logs."
                    )
                ),
                "refresh_dashboard": True,
            }, 200

        # ==================================================
        # NON-FINAL STAGE APPROVAL
        # ==================================================
        #
        # Approve the current stage and its submitted documents,
        # then issue a no-expiry OTP for the next stage.
        # ==================================================

        result = update_stage_record(
            reg_no,
            stage,
            {
                "status": "approved",
                "reviewed_by": staff_id,
                "reviewed_at": now,
                "rejection_comment": "",
            },
            staff_id=staff_id,
            document_status="approved",
            review_history_entry=history_entry,
        )

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "The stage has changed or is no longer awaiting review. "
                    "Refresh and try again."
                ),
            }, 409

        # Create a single-use, no-expiry OTP for the next stage.
        otp = generate_otp(6)
        otp_record = {
            "reg_no": reg_no,
            "previous_stage": stage,
            "next_stage": next_stage,
            "otp": otp,
            "status": "pending",
            "created_at": now,
            "expires_at": None,
            "created_by": staff_id,
        }

        try:
            mongo.db.stage_otps.insert_one(otp_record)

        except Exception:
            logger.exception(
                "Could not create the next-stage OTP for %s",
                reg_no,
            )

            # Roll the stage and document decision back to under_review
            # so the student is not blocked if no transition OTP exists.
            try:
                mongo.db.clearances.update_one(
                    {
                        "reg_no": reg_no,
                        "current_stage": stage,
                        f"stages.{stage}.status": "approved",
                        f"stages.{stage}.reviewed_by": staff_id,
                        f"stages.{stage}.reviewed_at": now,
                    },
                    {
                        "$set": {
                            f"stages.{stage}.status": "under_review",
                            f"stages.{stage}.reviewed_by": None,
                            f"stages.{stage}.reviewed_at": None,
                            f"stages.{stage}.documents.$[doc].status": "under_review",
                            "updated_at": get_utc_now(),
                        },
                        "$unset": {
                            f"stages.{stage}.documents.$[doc].reviewed_by": "",
                            f"stages.{stage}.documents.$[doc].reviewed_at": "",
                        },
                        "$pull": {
                            f"stages.{stage}.review_history": history_entry,
                        },
                    },
                    array_filters=[
                        {
                            "doc.reviewed_at": now,
                            "doc.status": "approved",
                        }
                    ],
                )

            except Exception:
                logger.exception(
                    "Failed to roll back stage review for %s",
                    reg_no,
                )

            return {
                "success": False,
                "message": (
                    "Stage approval could not be completed because the next-stage "
                    "OTP could not be created. Please refresh and retry."
                ),
            }, 500

        email_sent = safe_send_email(
            EmailSender.send_student_clearance_stage_approved_email,
            student_email,
            student_name,
            reg_no,
            stage,
            next_stage=next_stage,
            otp=otp,
            otp_expiry_minutes=None,
        )

        return {
            "success": True,
            "message": f"{stage.replace('_', ' ').title()} clearance stage approved successfully.",
            "stage": stage,
            "status": "approved",
            "next_stage": next_stage,
            "otp_expiry_minutes": None,
            "otp_expiry": "No expiry; valid until used or invalidated",
            "email_sent": email_sent,
            "refresh_dashboard": True,
        }, 200


# ==========================================================
# 8. VERIFY STAGE OTP
# ==========================================================

class StaffVerifyStageOTP(Resource):
    """
    Verify a student's OTP for the next clearance stage.

    Only active staff assigned to the target stage may verify it.
    A successful verification consumes the OTP and advances the
    clearance to the target stage.

    IMPORTANT:
    OTP verification does not require the target stage to be
    under_review. The student must verify the OTP before being
    allowed to submit the target stage's document.
    """

    def post(self):
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        reg_no = str(data.get("reg_no", "")).strip().upper()
        otp = data.get("otp")

        if (
            not staff_id
            or not reg_no
            or not isinstance(otp, str)
            or not is_valid_otp(otp, 6)
        ):
            return {
                "success": False,
                "message": (
                    "Staff ID, registration number and a valid "
                    "six-digit OTP are required."
                ),
            }, 400

        staff = get_staff_by_id(staff_id)

        if not staff:
            return {
                "success": False,
                "message": "Staff account not found.",
            }, 404

        if not is_active_account(staff):
            return {
                "success": False,
                "message": "Your staff account is not active.",
            }, 403

        student = get_student_by_reg_no(reg_no)

        if not student:
            return {
                "success": False,
                "message": "Student not found.",
            }, 404

        clearance = get_clearance_by_reg_no(reg_no)

        if not clearance:
            return {
                "success": False,
                "message": "Clearance record not found.",
            }, 404

        if clearance.get("status") == "completed":
            return {
                "success": False,
                "message": "This student's clearance is already complete.",
            }, 409

        # Fetch only a pending OTP for this registration number.
        otp_record = mongo.db.stage_otps.find_one({
            "reg_no": reg_no,
            "otp": otp,
            "status": "pending",
        })

        if not otp_record:
            return {
                "success": False,
                "message": (
                    "The OTP is invalid, has already been used, "
                    "or has been invalidated."
                ),
            }, 400

        previous_stage = normalize_stage_name(
            otp_record.get("previous_stage", "")
        )

        next_stage = normalize_stage_name(
            otp_record.get("next_stage", "")
        )

        if (
            previous_stage not in CLEARANCE_STAGES
            or next_stage not in CLEARANCE_STAGES
            or get_next_clearance_stage(previous_stage) != next_stage
        ):
            return {
                "success": False,
                "message": "The OTP is associated with an invalid stage.",
            }, 409

        if not is_stage_assigned_to_staff(staff, next_stage):
            return {
                "success": False,
                "message": (
                    "You are not authorized to verify the OTP "
                    "for this clearance stage."
                ),
                "required_stage": next_stage,
                "assigned_stage": staff.get("assigned_stage"),
            }, 403

        if get_current_clearance_stage(clearance) != previous_stage:
            return {
                "success": False,
                "message": (
                    "The clearance stage has changed. "
                    "This OTP cannot advance the current stage."
                ),
            }, 409

        previous_record = get_stage_record(clearance, previous_stage)

        if previous_record.get("status") != "approved":
            return {
                "success": False,
                "message": (
                    "The previous clearance stage has not been approved."
                ),
            }, 409

        # The next stage may be pending or awaiting_submission.
        # It must not already have documents under review or be
        # approved/rejected.
        next_record = get_stage_record(clearance, next_stage)
        next_status = next_record.get("status")

        if next_status not in {"pending", "awaiting_submission"}:
            return {
                "success": False,
                "message": (
                    "The next stage is not in a state that permits "
                    "OTP verification."
                ),
                "next_stage_status": next_status,
            }, 409

        now = get_utc_now()

        # Atomically claim the OTP. Concurrent verification attempts
        # cannot both claim the same pending OTP.
        claimed_otp = mongo.db.stage_otps.find_one_and_update(
            {
                "_id": otp_record["_id"],
                "status": "pending",
            },
            {
                "$set": {
                    "status": "verifying",
                    "verifying_staff_id": staff_id,
                    "verifying_at": now,
                }
            },
            return_document=ReturnDocument.AFTER,
        )

        if not claimed_otp:
            return {
                "success": False,
                "message": (
                    "This OTP has already been used or is being "
                    "verified by another request."
                ),
            }, 409

        # Advance the stage using a conditional write.
        result = mongo.db.clearances.update_one(
            {
                "reg_no": reg_no,
                "current_stage": previous_stage,
                "status": {"$ne": "completed"},
                f"stages.{previous_stage}.status": "approved",
                f"stages.{next_stage}.status": next_status,
            },
            {
                "$set": {
                    "current_stage": next_stage,
                    f"stages.{next_stage}.status": "awaiting_submission",
                    f"stages.{next_stage}.otp_verified_by": staff_id,
                    f"stages.{next_stage}.otp_verified_at": now,
                    f"stages.{next_stage}.verified_by": staff_id,
                    f"stages.{next_stage}.verified_at": now,
                    "updated_at": now,
                },
                "$push": {
                    "workflow_history": {
                        "action": "stage_otp_verified",
                        "previous_stage": previous_stage,
                        "current_stage": next_stage,
                        "staff_id": staff_id,
                        "occurred_at": now,
                    }
                },
            },
        )

        if result.modified_count != 1:
            restore_claimed_stage_otp(
                otp_record["_id"],
                staff_id,
            )

            return {
                "success": False,
                "message": (
                    "The clearance record changed before verification "
                    "could finish. Refresh and try again."
                ),
            }, 409

        # The clearance has advanced. Mark the claimed OTP as used.
        consumed_result = mongo.db.stage_otps.update_one(
            {
                "_id": otp_record["_id"],
                "status": "verifying",
                "verifying_staff_id": staff_id,
            },
            {
                "$set": {
                    "status": "used",
                    "used_at": now,
                    "used_by": staff_id,
                }
            },
        )

        if consumed_result.modified_count != 1:
            mongo.db.stage_otps.update_one(
                {
                    "_id": otp_record["_id"],
                    "status": "verifying",
                },
                {
                    "$set": {
                        "status": "invalidated",
                        "invalidated_at": get_utc_now(),
                        "invalidated_reason": (
                            "clearance_advanced_consumption_failed"
                        ),
                    }
                },
            )

            return {
                "success": False,
                "message": (
                    "The clearance stage advanced, but the OTP "
                    "status could not be confirmed. Check the "
                    "clearance record before retrying."
                ),
            }, 500

        # Invalidate any other pending OTPs associated with this
        # clearance. Only one transition should be usable at a time.
        mongo.db.stage_otps.update_many(
            {
                "reg_no": reg_no,
                "_id": {"$ne": otp_record["_id"]},
                "status": "pending",
            },
            {
                "$set": {
                    "status": "invalidated",
                    "invalidated_at": now,
                    "invalidated_reason": "stage_advanced",
                }
            },
        )

        email_sent = safe_send_email(
            EmailSender.send_student_clearance_stage_otp_verified_email,
            student.get("email"),
            get_student_full_name(student),
            reg_no,
            previous_stage,
            next_stage,
        )

        return {
            "success": True,
            "message": "Stage OTP verified successfully.",
            "previous_stage": previous_stage,
            "current_stage": next_stage,
            "dashboard_stage": get_staff_assigned_stage(staff),
            "otp_used": True,
            "email_sent": email_sent,
            "refresh_dashboard": True,
        }, 200


# ==========================================================
# 9. LIST STUDENTS FOR THE STAFF MEMBER'S ASSIGNED STAGE
# ==========================================================

class StaffListStudents(Resource):
    """
    Return students relevant to the signed-in staff member's assigned stage.

    Request JSON:
        {"staff_id": "FIN001", "view": "current"}

    Supported views:
        current        All students whose live current_stage is this stage.
        pending_review Current-stage students with a submission under review.
        processed      Students this staff member has approved/rejected before.
        rejected       Students this staff member has rejected before.
        all            Current-stage students plus the staff member's history.

    The response is table-ready and contains safe document metadata, never
    MongoDB GridFS identifiers or staff/student password fields.
    """

    def post(self):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        view = str(data.get("view", "current")).strip().lower().replace("-", "_")
        view_aliases = {
            "pending": "pending_review",
            "under_review": "pending_review",
            "history": "processed",
            "approved": "processed",
            "rejections": "rejected",
        }
        view = view_aliases.get(view, view)
        allowed_views = {"current", "pending_review", "processed", "rejected", "all"}

        if not staff_id:
            return {"success": False, "message": "Staff ID is required."}, 400
        if view not in allowed_views:
            return {
                "success": False,
                "message": "Unsupported student-list view.",
                "allowed_views": sorted(allowed_views),
            }, 400

        staff = get_staff_by_id(staff_id)
        if not staff:
            return {"success": False, "message": "Staff account not found."}, 404
        if not is_active_account(staff):
            return {"success": False, "message": "Your staff account is not active."}, 403

        stage = get_staff_assigned_stage(staff)
        if not stage or stage not in CLEARANCE_STAGES:
            return {
                "success": False,
                "message": "This staff account does not have a valid clearance-stage assignment.",
            }, 403

        query = {
            "$or": [
                {"current_stage": stage},
                {f"stages.{stage}.reviewed_by": staff_id},
                {f"stages.{stage}.review_history.staff_id": staff_id},
            ]
        }

        try:
            clearances = list(mongo.db.clearances.find(query))
            candidate_rows = []
            seen = set()
            for clearance in clearances:
                reg_no = str(clearance.get("reg_no", "")).strip().upper()
                if not reg_no or reg_no in seen:
                    continue
                seen.add(reg_no)

                stage_record = get_stage_record(clearance, stage)
                current_stage = get_current_clearance_stage(clearance)
                is_current = (
                    current_stage == stage
                    and clearance.get("status") != "completed"
                )
                is_pending_review = (
                    is_current and stage_record.get("status") == "under_review"
                )
                was_processed = stage_was_processed_by(stage_record, staff_id)
                was_rejected = stage_was_rejected_by(stage_record, staff_id)

                # Count/return every student relevant to this staff member, then
                # apply the requested tab filter below. Dashboard totals therefore
                # remain stable when staff switch between table tabs.
                if not (is_current or was_processed):
                    continue

                student = get_student_by_reg_no(reg_no)
                if not student:
                    # Keep the clearance visible even if a legacy student
                    # record is missing; the table can flag incomplete data.
                    student = {
                        "reg_no": reg_no,
                        "surname": "",
                        "first_name": "Student record unavailable",
                        "email": "",
                        "department": "",
                        "faculty": "",
                    }

                summary = make_staff_student_summary(
                    student,
                    clearance,
                    stage,
                    staff_id,
                )
                summary["is_current_stage"] = is_current
                summary["is_pending_review"] = is_pending_review
                summary["was_processed_by_staff"] = was_processed
                summary["was_rejected_by_staff"] = was_rejected
                candidate_rows.append(summary)

        except Exception:
            logger.exception("Staff student-list lookup failed for %s", staff_id)
            return {
                "success": False,
                "message": "Unable to retrieve the student list right now. Please try again.",
            }, 503

        counts = {
            "current": sum(1 for row in candidate_rows if row.get("is_current_stage")),
            "pending_review": sum(1 for row in candidate_rows if row.get("is_pending_review")),
            "processed": sum(1 for row in candidate_rows if row.get("was_processed_by_staff")),
            "rejected": sum(1 for row in candidate_rows if row.get("was_rejected_by_staff")),
            "returned": 0,
        }

        rows = [
            row for row in candidate_rows
            if (
                view == "current" and row.get("is_current_stage")
                or view == "pending_review" and row.get("is_pending_review")
                or view == "processed" and row.get("was_processed_by_staff")
                or view == "rejected" and row.get("was_rejected_by_staff")
                or view == "all" and (
                    row.get("is_current_stage") or row.get("was_processed_by_staff")
                )
            )
        ]

        # Sort newest-updated rows first without relying on mixed datetime/string
        # fields from older records.
        rows.sort(
            key=lambda row: str(row.get("updated_at") or row.get("uploaded_at") or ""),
            reverse=True,
        )
        counts["returned"] = len(rows)
        return {
            "success": True,
            "message": "Staff student list retrieved successfully.",
            "staff": get_staff_public_profile(staff),
            "assigned_stage": stage,
            "view": view,
            "counts": counts,
            "total": len(rows),
            "data": rows,
        }, 200


# ==========================================================
# 10. VIEW STUDENT AND CLEARANCE DETAILS FOR THE ASSIGNED STAGE
# ==========================================================

class StaffGetStudentClearanceDetails(Resource):
    """Return student/clearance details to an authorized stage officer."""

    def post(self):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {
                "success": False,
                "message": "Request body must be valid JSON.",
            }, 400

        staff_id = normalize_staff_id(data.get("staff_id", ""))
        reg_no = str(data.get("reg_no", "")).strip().upper()
        if not staff_id or not reg_no:
            return {
                "success": False,
                "message": "Staff ID and student registration number are required.",
            }, 400

        staff = get_staff_by_id(staff_id)
        if not staff:
            return {"success": False, "message": "Staff account not found."}, 404
        if not is_active_account(staff):
            return {"success": False, "message": "Your staff account is not active."}, 403

        assigned_stage = get_staff_assigned_stage(staff)
        if not assigned_stage or assigned_stage not in CLEARANCE_STAGES:
            return {"success": False, "message": "Invalid staff stage assignment."}, 403

        student = get_student_by_reg_no(reg_no)
        if not student:
            return {"success": False, "message": "Student not found."}, 404
        clearance = get_clearance_by_reg_no(reg_no)
        if not clearance:
            return {"success": False, "message": "Clearance record not found."}, 404

        assigned_record = get_stage_record(clearance, assigned_stage)
        current_stage = get_current_clearance_stage(clearance)
        has_access = (
            current_stage == assigned_stage
            or stage_was_processed_by(assigned_record, staff_id)
            or stage_was_rejected_by(assigned_record, staff_id)
        )
        if not has_access:
            return {
                "success": False,
                "message": (
                    "This student is not currently at your stage, and you have "
                    "no previous review record for this student's stage."
                ),
                "assigned_stage": assigned_stage,
                "current_stage": current_stage,
            }, 403

        public_stages = {}
        stage_map = clearance.get("stages", {})
        if isinstance(stage_map, dict):
            for stage in CLEARANCE_STAGES:
                public_stages[stage] = public_staff_stage_record(
                    stage_map.get(stage, {}),
                    stage,
                )

        student_profile = {
            "reg_no": student.get("reg_no", reg_no),
            "surname": student.get("surname", ""),
            "first_name": student.get("first_name", ""),
            "other_names": student.get("other_names", ""),
            "full_name": get_student_full_name(student),
            "email": student.get("email", ""),
            "phone_number": student.get("phone_number", ""),
            "department": student.get("department", ""),
            "faculty": student.get("faculty", ""),
            "gender": student.get("gender", ""),
            "admission_year": student.get("admission_year"),
            "student_status": student.get("student_status", ""),
            "account_status": student.get("account_status", student.get("status", "")),
        }

        safe_clearance = {
            "reg_no": reg_no,
            "status": clearance.get("status", "in_progress"),
            "current_stage": current_stage,
            "created_at": json_safe_staff_value(clearance.get("created_at")),
            "updated_at": json_safe_staff_value(clearance.get("updated_at")),
            "completed_at": json_safe_staff_value(clearance.get("completed_at")),
            "stages": public_stages,
            "workflow_history": json_safe_staff_value(
                clearance.get("workflow_history", [])
            ),
        }

        return {
            "success": True,
            "message": "Student clearance details retrieved successfully.",
            "staff": get_staff_public_profile(staff),
            "assigned_stage": assigned_stage,
            "student": json_safe_staff_value(student_profile),
            "clearance": safe_clearance,
            "stage_record": public_stages.get(assigned_stage, {}),
            "can_review": (
                current_stage == assigned_stage
                and assigned_record.get("status") == "under_review"
                and clearance.get("status") != "completed"
            ),
        }, 200


# ==========================================================
# REGISTER STAFF API ROUTES
# ==========================================================

api.add_resource(
    StaffListStudents,
    "/api/v1/clearance/staff/students",
)

api.add_resource(
    StaffGetStudentClearanceDetails,
    "/api/v1/clearance/staff/student-details",
)

api.add_resource(
    OnboardStaff,
    "/api/v1/clearance/admin/onboard/staff",
)

api.add_resource(
    StaffLogin,
    "/api/v1/clearance/login/staff",
)

api.add_resource(
    StaffForgotPassword,
    "/api/v1/clearance/forgot-password/staff",
)

api.add_resource(
    StaffResetPasswordWithOTP,
    "/api/v1/clearance/reset-password/staff",
)

api.add_resource(
    OTPResetStaffPassword,
    "/api/v1/clearance/otp-reset-password/staff",
)

api.add_resource(
    ChangeStaffPassword,
    "/api/v1/clearance/change-password/staff",
)

api.add_resource(
    StaffApproveRejectClearanceStage,
    "/api/v1/clearance/staff/review-stage",
)

api.add_resource(
    StaffVerifyStageOTP,
    "/api/v1/clearance/staff/verify-stage-otp",
)