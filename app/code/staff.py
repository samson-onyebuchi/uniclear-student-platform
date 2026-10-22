# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/code/staff.py
#
# PURPOSE:
# 1. Onboard clearance officers.
# 2. Authenticate staff members.
# 3. Reset staff passwords using OTP verification.
# 4. Support the legacy staff OTP-reset endpoint.
# 5. Allow staff to change their passwords.
# 6. Approve student clearance stages.
# 7. Reject student clearance stages with comments.
# 8. Generate OTPs for the next clearance stage.
# 9. Verify stage OTPs and advance clearance progress.
# 10. Notify students of clearance decisions.
# 11. Support final clearance completion.
#
# API ENDPOINTS:
# POST /api/v1/clearance/admin/onboard/staff
# POST /api/v1/clearance/login/staff
# POST /api/v1/clearance/forgot-password/staff
# POST /api/v1/clearance/reset-password/staff
# POST /api/v1/clearance/otp-reset-password/staff
# POST /api/v1/clearance/change-password/staff
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

def safe_send_email(method, *args):
    """
    Attempt an email operation without allowing an unexpected
    email-provider exception to invalidate a completed database
    operation.

    A True result means the email utility reported success.
    It does not guarantee delivery to the recipient's inbox.
    """

    try:
        return bool(method(*args))

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


def get_staff_public_profile(staff):
    """Return staff profile data without sensitive credentials."""

    return {
        "staff_id": staff.get("staff_id"),
        "surname": staff.get("surname"),
        "first_name": staff.get("first_name"),
        "other_names": staff.get("other_names", ""),
        "email": staff.get("email"),
        "department": staff.get("department"),
        "faculty": staff.get("faculty"),
        "role": staff.get("role"),
        "assigned_stage": staff.get("assigned_stage"),
        "account_status": staff.get("account_status", "active"),
        "must_change_password": staff.get(
            "must_change_password",
            False,
        ),
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


def update_stage_record(reg_no, stage, updates):
    """
    Update stage fields only when the stage remains under review.

    The conditional update prevents a rejection from overwriting
    a concurrent approval or another completed review.
    """

    update_fields = {
        f"stages.{stage}.{field}": value
        for field, value in updates.items()
    }

    return mongo.db.clearances.update_one(
        {
            "reg_no": reg_no,
            "current_stage": stage,
            "status": {"$ne": "completed"},
            f"stages.{stage}.status": "under_review",
        },
        {
            "$set": {
                **update_fields,
                "updated_at": get_utc_now(),
            }
        },
    )


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

        return {
            "success": True,
            "message": "Staff login successful.",
            "must_change_password": staff.get(
                "must_change_password",
                False,
            ),
            "data": get_staff_public_profile(staff),
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
    Allow an assigned staff member to approve or reject a student's
    current clearance stage.

    Approval generates an OTP for the next stage. The OTP does not
    expire based on time; it remains valid until used or invalidated.
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
        comment = str(data.get("comment", "")).strip()

        if not staff_id or not reg_no or action not in {
            "approve",
            "reject",
        }:
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
                "message": (
                    "A rejection comment is required when rejecting "
                    "a clearance stage."
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

        stage = get_current_clearance_stage(clearance)

        if not stage or stage not in CLEARANCE_STAGES:
            return {
                "success": False,
                "message": "Invalid current clearance stage.",
            }, 409

        if not is_stage_assigned_to_staff(staff, stage):
            return {
                "success": False,
                "message": (
                    "You are not authorized to review this "
                    "clearance stage."
                ),
                "current_stage": stage,
                "assigned_stage": staff.get("assigned_stage"),
            }, 403

        if not stage_is_under_review(clearance, stage):
            return {
                "success": False,
                "message": (
                    "This stage is not awaiting review. "
                    "The student must submit the required document "
                    "before it can be approved or rejected."
                ),
            }, 409

        now = get_utc_now()
        student_name = get_student_full_name(student)
        student_email = student.get("email")

        # ------------------------------------------------------
        # REJECTION
        # ------------------------------------------------------

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
            )

            if result.modified_count != 1:
                return {
                    "success": False,
                    "message": (
                        "The stage has changed or is no longer "
                        "awaiting review. Refresh and try again."
                    ),
                }, 409

            invalidate_pending_stage_otps(
                reg_no,
                now,
                "stage_rejected",
            )

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
                "message": (
                    f"{stage.replace('_', ' ').title()} "
                    "clearance stage rejected."
                ),
                "stage": stage,
                "status": "rejected",
                "email_sent": email_sent,
            }, 200

        # ------------------------------------------------------
        # APPROVAL
        # ------------------------------------------------------

        next_stage = get_next_clearance_stage(stage)

        # Claim the review by changing under_review to approved
        # only if the stage is still the current stage.
        result = mongo.db.clearances.update_one(
            {
                "reg_no": reg_no,
                "current_stage": stage,
                "status": {"$ne": "completed"},
                f"stages.{stage}.status": "under_review",
            },
            {
                "$set": {
                    f"stages.{stage}.status": "approved",
                    f"stages.{stage}.reviewed_by": staff_id,
                    f"stages.{stage}.reviewed_at": now,
                    f"stages.{stage}.rejection_comment": "",
                    "updated_at": now,
                }
            },
        )

        if result.modified_count != 1:
            return {
                "success": False,
                "message": (
                    "The stage has changed or is no longer awaiting "
                    "review. Refresh and try again."
                ),
            }, 409

        # ------------------------------------------------------
        # FINAL STAGE APPROVAL
        # ------------------------------------------------------

        if next_stage is None:
            completion_result = mongo.db.clearances.update_one(
                {
                    "reg_no": reg_no,
                    "current_stage": stage,
                    "status": {"$ne": "completed"},
                },
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": now,
                        "updated_at": now,
                    }
                },
            )

            if completion_result.modified_count != 1:
                return {
                    "success": False,
                    "message": (
                        "The final stage was approved, but clearance "
                        "completion could not be recorded. "
                        "Check the clearance record before retrying."
                    ),
                }, 500

            invalidate_pending_stage_otps(
                reg_no,
                now,
                "clearance_completed",
            )

            email_sent = safe_send_email(
                EmailSender.send_student_clearance_stage_approved_email,
                student_email,
                student_name,
                reg_no,
                stage,
            )

            return {
                "success": True,
                "message": "Final clearance approved successfully.",
                "stage": stage,
                "status": "approved",
                "clearance_status": "completed",
                "email_sent": email_sent,
            }, 200

        # ------------------------------------------------------
        # GENERATE OTP FOR THE NEXT STAGE
        # ------------------------------------------------------

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
            # Roll back the approval if the next-stage OTP could
            # not be created. The conditional rollback avoids
            # overwriting a later change to the clearance record.
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
                        "updated_at": get_utc_now(),
                    }
                },
            )

            return {
                "success": False,
                "message": (
                    "The stage approval could not be completed "
                    "because the next-stage OTP could not be created."
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
            "message": (
                f"{stage.replace('_', ' ').title()} "
                "clearance stage approved successfully."
            ),
            "stage": stage,
            "status": "approved",
            "next_stage": next_stage,
            "otp_expiry_minutes": None,
            "otp_expiry": "No expiry; valid until used or invalidated",
            "email_sent": email_sent,
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
                    "updated_at": now,
                }
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
            "otp_used": True,
            "email_sent": email_sent,
        }, 200


# ==========================================================
# REGISTER STAFF API ROUTES
# ==========================================================

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