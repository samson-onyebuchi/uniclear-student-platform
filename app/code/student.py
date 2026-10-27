# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/code/student.py
#
# PURPOSE:
# 1. Register and authenticate students.
# 2. Manage student password recovery and changes.
# 3. Create and view final-year clearance records.
# 4. Upload documents for the current clearance stage.
# 5. View uploaded document metadata and statuses.
# 6. View or download documents stored in MongoDB GridFS.
# 7. Support corrected document uploads after rejection.
# 8. Prevent MongoDB ObjectId serialization errors.
# 9. Return consistent JSON errors for expected failures.
# 10. Avoid relying on local disk for persistent file storage.
# 11. Prevent Flask Response objects from being JSON-encoded.
# 12. Validate the clearance stage order before document uploads.
# 13. Reject explicit uploads to an earlier or later stage.
# 14. Prevent any document uploads after final clearance.
# 15. Expose clearance completion status to the frontend.
#
# API ENDPOINTS:
# POST /api/v1/clearance/register/student
# POST /api/v1/clearance/login/student
# POST /api/v1/clearance/forgot-password/student
# POST /api/v1/clearance/otp-reset-password/student
# POST /api/v1/clearance/change-password/student
# POST /api/v1/clearance/create
# POST /api/v1/clearance/view
# POST /api/v1/clearance/upload-document
# POST /api/v1/clearance/documents
# GET  /api/v1/clearance/document/view/<document_id>
# GET  /api/v1/clearance/document/download/<document_id>
# ==========================================================

import bcrypt
import secrets
import mimetypes
import logging

from datetime import date, datetime, timedelta
from decimal import Decimal
from io import BytesIO

from bson import ObjectId
from bson.decimal128 import Decimal128
from gridfs import GridFS
from gridfs.errors import NoFile
from pymongo.errors import DuplicateKeyError, PyMongoError

from flask import request, send_file, Response
from flask_restful import Resource
from werkzeug.utils import secure_filename

from app import api, mongo
from app.email_util import EmailSender

from app.utils import (
    generate_otp,
    get_utc_now,
    is_valid_email,
)

from app.code.general_function import (
    CLEARANCE_STAGES,
    calculate_study_duration,
    determine_student_status,
    get_student_by_reg_no,
    get_student_full_name,
    get_clearance_by_reg_no,
    serialize_document,
    normalize_clearance_stage,
    are_previous_stages_approved,
    is_clearance_stage_consistent,
)


logger = logging.getLogger(__name__)


# ==========================================================
# FILE STORAGE AND VALIDATION CONFIGURATION
# ==========================================================

ALLOWED_DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx"}
MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10 MB

grid_fs = None


def get_grid_fs():
    """Return the MongoDB GridFS storage interface."""

    global grid_fs

    if grid_fs is None:
        grid_fs = GridFS(mongo.db)

    return grid_fs


# ==========================================================
# JSON SERIALIZATION AND RESPONSE UTILITIES
# ==========================================================

def make_json_safe(value):
    """
    Recursively convert MongoDB and Python values into
    JSON-safe values.

    ObjectId values become strings.
    Datetimes and dates become ISO timestamps.
    Dictionaries and collections are processed recursively.
    """

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Decimal128):
        return str(value.to_decimal())

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, dict):
        return {
            str(key): make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if hasattr(value, "isoformat") and callable(value.isoformat):
        try:
            return value.isoformat()
        except (ValueError, TypeError):
            pass

    # Avoid returning an unsupported object to the JSON encoder.
    return str(value)


def json_response(payload, status_code=200):
    """
    Return a JSON-safe dictionary and HTTP status code.

    IMPORTANT:
    Do not use jsonify() here. Flask-RESTful automatically
    serializes dictionaries returned by Resource methods.

    Returning a Flask Response from jsonify() here would cause
    Flask-RESTful to attempt to serialize the Response object.
    """

    safe_payload = make_json_safe(payload)

    return safe_payload, status_code


def error_response(message, status_code=400, errors=None):
    """Return a consistent JSON error response."""

    payload = {
        "success": False,
        "message": message,
    }

    if errors is not None:
        payload["errors"] = errors

    return json_response(payload, status_code)


def safe_send_email(method, *args):
    """
    Attempt an email operation without allowing an unexpected
    email-provider exception to invalidate a completed database
    operation.
    """

    try:
        return bool(method(*args))
    except Exception:
        logger.exception("Email operation failed.")
        return False


# ==========================================================
# GENERAL STUDENT UTILITIES
# ==========================================================

def hash_password(password):
    """Hash a password using bcrypt."""

    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def check_password(password, password_hash):
    """Verify a password against its bcrypt hash."""

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


def normalize_reg_no(reg_no):
    """Normalize a student registration number."""

    if not isinstance(reg_no, str):
        return ""

    return reg_no.strip().upper()


def validate_password(password):
    """Require a password of at least eight characters."""

    return isinstance(password, str) and len(password) >= 8


def validate_student_identity(data):
    """Validate required student registration information."""

    required_fields = [
        "surname",
        "first_name",
        "email",
        "reg_no",
        "department",
        "faculty",
        "phone_number",
        "gender",
        "admission_year",
        "password",
    ]

    missing_fields = [
        field
        for field in required_fields
        if data.get(field) is None
        or (
            isinstance(data.get(field), str)
            and not data[field].strip()
        )
    ]

    if missing_fields:
        return False, "Some required fields are missing.", {
            "missing_fields": missing_fields
        }

    if not is_valid_email(data.get("email", "")):
        return False, "Please provide a valid email address.", None

    if str(data["gender"]).strip().lower() not in {"male", "female"}:
        return False, "Gender must be male or female.", None

    if not validate_password(data["password"]):
        return False, "Password must contain at least 8 characters.", None

    try:
        admission_year = int(data["admission_year"])
    except (TypeError, ValueError):
        return False, "Admission year must be a valid year.", None

    if admission_year < 1900 or admission_year > get_utc_now().year:
        return False, "Admission year is invalid or in the future.", None

    for field in ("surname", "first_name", "department", "faculty"):
        if not isinstance(data.get(field), str):
            return (
                False,
                f"{field.replace('_', ' ').title()} must be text.",
                None,
            )

    if not isinstance(data.get("phone_number"), str):
        return False, "Phone number must be supplied as text.", None

    return True, None, None


def get_request_reg_no(data):
    """Read and normalize reg_no from a JSON request."""

    if not isinstance(data, dict):
        return ""

    return normalize_reg_no(data.get("reg_no", ""))


def get_stage_document_list(clearance, stage):
    """Return a stage's documents as a list."""

    stage_data = clearance.get("stages", {}).get(stage, {})

    if not isinstance(stage_data, dict):
        return []

    documents = stage_data.get("documents", [])

    return documents if isinstance(documents, list) else []


def validate_clearance_workflow(clearance):
    """
    Validate the overall clearance record before accepting a document upload.

    The current stage must be part of the configured workflow, previous stages
    must be approved, and the stage records must agree with current_stage and
    the overall clearance status. This protects against inconsistent records
    allowing an upload to skip a required stage.

    Returns:
        (True, current_stage, None) when the workflow is valid.
        (False, None, error_message) when it is invalid.
    """

    if not isinstance(clearance, dict):
        return False, None, "Clearance record is invalid."

    stages = clearance.get("stages")

    if not isinstance(stages, dict):
        return False, None, "Clearance stage data is invalid."

    stored_current_stage = clearance.get("current_stage", "")
    current_stage = normalize_clearance_stage(stored_current_stage)

    if not current_stage or current_stage not in CLEARANCE_STAGES:
        return False, None, "The current clearance stage is invalid."

    # Database records should store canonical stage names such as
    # student_affairs, not display labels or differently-cased values.
    if stored_current_stage != current_stage:
        return (
            False,
            None,
            "The clearance record contains a non-standard current stage. "
            "Please contact the clearance administrator.",
        )

    # Every configured stage must have a valid stage record.
    for configured_stage in CLEARANCE_STAGES:
        record = stages.get(configured_stage)

        if not isinstance(record, dict):
            return (
                False,
                None,
                "The clearance record is missing valid data for the "
                f"{configured_stage.replace('_', ' ')} stage.",
            )

    try:
        # Confirm that current_stage, stage statuses, and overall status
        # are consistent with the official clearance order.
        if not is_clearance_stage_consistent(clearance):
            return (
                False,
                None,
                "The clearance record does not follow the required stage order. "
                "Please contact the clearance administrator before uploading.",
            )

        # Explicitly verify that all previous stages have been approved.
        if not are_previous_stages_approved(clearance, current_stage):
            return (
                False,
                None,
                "Previous clearance stages have not all been approved. "
                "You cannot submit documents for this stage yet.",
            )

    except Exception:
        logger.exception("Clearance workflow consistency check failed.")

        return (
            False,
            None,
            "Unable to validate the clearance workflow. Please try again or "
            "contact the clearance administrator.",
        )

    return True, current_stage, None


def document_public_data(document):
    """Return document metadata without internal storage details."""

    return make_json_safe({
        "document_id": str(document.get("document_id", "")),
        "document_name": document.get("document_name", ""),
        "file_name": document.get("file_name", ""),
        "original_filename": document.get("original_filename", ""),
        "content_type": document.get("content_type", ""),
        "file_size": document.get("file_size", 0),
        "stage": document.get("stage", ""),
        "status": document.get("status", "under_review"),
        "uploaded_at": document.get("uploaded_at"),
        "rejection_comment": document.get("rejection_comment", ""),
    })


def find_document_in_clearance(reg_no, document_id):
    """Find document metadata across a student's clearance stages."""

    clearance = get_clearance_by_reg_no(reg_no)

    if not clearance:
        return None, None

    stages = clearance.get("stages", {})

    if not isinstance(stages, dict):
        return None, None

    for stage_name, stage_data in stages.items():
        if not isinstance(stage_data, dict):
            continue

        documents = stage_data.get("documents", [])

        if not isinstance(documents, list):
            continue

        for document in documents:
            if (
                isinstance(document, dict)
                and str(document.get("document_id")) == str(document_id)
            ):
                return stage_name, document

    return None, None


def allowed_file_extension(filename):
    """Check whether a filename has an allowed extension."""

    if not isinstance(filename, str) or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_DOCUMENT_EXTENSIONS


def get_document_content_type(filename):
    """Determine a document's MIME content type."""

    extension = filename.rsplit(".", 1)[-1].lower()

    content_types = {
        "pdf": "application/pdf",
        "doc": "application/msword",
        "docx": (
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
        ),
    }

    return content_types.get(
        extension,
        mimetypes.guess_type(filename)[0]
        or "application/octet-stream",
    )


def student_is_active(student):
    """Check whether a student account is active."""

    return str(
        student.get("account_status", "active")
    ).lower() == "active"


def get_json_body():
    """Read a JSON request body safely."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


def public_student_data(student):
    """
    Remove credentials, reset OTPs and internal timestamps
    from student information returned to API clients.
    """

    private_fields = {
        "password",
        "reset_otp",
        "reset_otp_expiry",
        "reset_otp_created_at",
        "otp",
        "otp_expiry",
        "created_at",
        "updated_at",
    }

    public_data = {
        key: value
        for key, value in student.items()
        if key not in private_fields
    }

    return make_json_safe(public_data)


# ==========================================================
# 1. STUDENT REGISTRATION
# ==========================================================

class RegisterStudent(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        valid, message, errors = validate_student_identity(data)

        if not valid:
            return error_response(message, 400, errors)

        reg_no = normalize_reg_no(data["reg_no"])
        email = data["email"].strip().lower()
        other_names = data.get("other_names") or ""

        if not isinstance(other_names, str):
            return error_response("Other names must be text.", 400)

        try:
            existing = mongo.db.students.find_one({
                "$or": [
                    {"reg_no": reg_no},
                    {"email": email},
                ]
            })

        except PyMongoError:
            logger.exception("Student registration lookup failed.")

            return error_response(
                "Unable to check registration details at this time.",
                503,
            )

        if existing:
            if normalize_reg_no(existing.get("reg_no", "")) == reg_no:
                return error_response(
                    "A student with this registration number already exists.",
                    409,
                )

            return error_response(
                "This email address is already registered.",
                409,
            )

        admission_year = int(data["admission_year"])
        current_year = get_utc_now().year

        try:
            study_duration = calculate_study_duration(
                admission_year,
                current_year,
            )

            student_status = determine_student_status(
                admission_year,
                current_year,
            )

            now = get_utc_now()

            student = {
                "surname": data["surname"].strip(),
                "first_name": data["first_name"].strip(),
                "other_names": other_names.strip(),
                "email": email,
                "reg_no": reg_no,
                "department": data["department"].strip(),
                "faculty": data["faculty"].strip(),
                "phone_number": data["phone_number"].strip(),
                "gender": data["gender"].strip().lower(),
                "admission_year": admission_year,
                "study_duration": study_duration,
                "student_status": student_status,
                "role": "student",
                "account_status": "active",
                "password": hash_password(data["password"]),
                "created_at": now,
                "updated_at": now,
            }

            result = mongo.db.students.insert_one(student)
            student["_id"] = result.inserted_id

        except DuplicateKeyError:
            return error_response(
                "This email address or registration number is already registered.",
                409,
            )

        except PyMongoError:
            logger.exception(
                "Student registration database operation failed."
            )

            return error_response(
                "Student registration could not be completed. Please try again.",
                503,
            )

        except Exception:
            logger.exception("Unexpected student registration error.")

            return error_response(
                "Student registration could not be completed.",
                500,
            )

        email_sent = safe_send_email(
            EmailSender.send_student_registration_email,
            email,
            get_student_full_name(student),
            reg_no,
            None,
        )

        return json_response({
            "success": True,
            "message": "Student registered successfully.",
            "email_sent": email_sent,
            "data": public_student_data(student),
        }, 201)


# ==========================================================
# 2. STUDENT LOGIN
# ==========================================================

class LoginStudent(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)
        password = data.get("password")

        if not reg_no or not isinstance(password, str) or not password:
            return error_response(
                "Registration number and password are required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Student login lookup failed.")

            return error_response(
                "Unable to process login at this time.",
                503,
            )

        if not student or not check_password(
            password,
            student.get("password", ""),
        ):
            return error_response(
                "Invalid registration number or password.",
                401,
            )

        if not student_is_active(student):
            return error_response(
                "Your student account is not active.",
                403,
            )

        return json_response({
            "success": True,
            "message": "Student login successful.",
            "data": public_student_data(student),
        }, 200)


# ==========================================================
# 3. STUDENT FORGOT PASSWORD
# ==========================================================

class ForgotPassword(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)

        if not reg_no:
            return error_response(
                "Registration number is required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Forgot-password lookup failed.")

            return error_response(
                "Unable to process your request at this time.",
                503,
            )

        # Do not reveal whether a student account exists.
        if not student:
            return json_response({
                "success": True,
                "message": (
                    "If the account exists, password-reset instructions "
                    "will be sent."
                ),
            }, 200)

        if not student_is_active(student):
            return error_response(
                "Your student account is not active.",
                403,
            )

        otp = generate_otp()
        now = get_utc_now()
        expiry = now + timedelta(minutes=10)

        try:
            result = mongo.db.students.update_one(
                {"_id": student["_id"]},
                {
                    "$set": {
                        "reset_otp": otp,
                        "reset_otp_expiry": expiry,
                        "reset_otp_created_at": now,
                        "updated_at": now,
                    }
                },
            )

            if result.matched_count != 1:
                return error_response(
                    "Unable to prepare password reset. Please try again.",
                    503,
                )

        except PyMongoError:
            logger.exception("Could not save password-reset OTP.")

            return error_response(
                "Unable to prepare password reset.",
                503,
            )

        email_sent = safe_send_email(
            EmailSender.send_student_forgot_password_email,
            student.get("email"),
            get_student_full_name(student),
            otp,
        )

        if not email_sent:
            try:
                mongo.db.students.update_one(
                    {
                        "_id": student["_id"],
                        "reset_otp": otp,
                    },
                    {
                        "$unset": {
                            "reset_otp": "",
                            "reset_otp_expiry": "",
                            "reset_otp_created_at": "",
                        }
                    },
                )

            except PyMongoError:
                logger.exception(
                    "Failed to clear unsent password-reset OTP."
                )

            return error_response(
                "Unable to send the password-reset email. Please try again later.",
                503,
            )

        return json_response({
            "success": True,
            "message": "Password-reset OTP sent to your email.",
            "otp_expiry_minutes": 10,
        }, 200)


# ==========================================================
# 4. STUDENT RESET PASSWORD WITH OTP
# ==========================================================

class OTPResetStudentPassword(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)
        otp = data.get("otp")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if (
            not reg_no
            or not isinstance(otp, (str, int))
            or isinstance(otp, bool)
            or not str(otp).strip()
            or not isinstance(new_password, str)
            or not new_password
        ):
            return error_response(
                "Registration number, OTP and new password are required.",
                400,
            )

        otp = str(otp).strip()

        if confirm_password is not None and confirm_password != new_password:
            return error_response("Passwords do not match.", 400)

        if not validate_password(new_password):
            return error_response(
                "Password must contain at least 8 characters.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Password-reset lookup failed.")

            return error_response(
                "Unable to process password reset.",
                503,
            )

        if not student:
            return error_response(
                "Invalid registration number or OTP.",
                400,
            )

        stored_otp = student.get("reset_otp")
        expiry = student.get("reset_otp_expiry")
        now = get_utc_now()

        if (
            stored_otp is None
            or not secrets.compare_digest(str(stored_otp), otp)
        ):
            return error_response(
                "Invalid registration number or OTP.",
                400,
            )

        if not isinstance(expiry, datetime):
            return error_response(
                "OTP has expired. Request a new OTP.",
                400,
            )

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=now.tzinfo)

        if now >= expiry:
            try:
                mongo.db.students.update_one(
                    {
                        "_id": student["_id"],
                        "reset_otp": stored_otp,
                    },
                    {
                        "$unset": {
                            "reset_otp": "",
                            "reset_otp_expiry": "",
                            "reset_otp_created_at": "",
                        }
                    },
                )

            except PyMongoError:
                logger.exception("Failed to clear expired OTP.")

            return error_response(
                "OTP has expired. Request a new OTP.",
                400,
            )

        try:
            result = mongo.db.students.update_one(
                {
                    "_id": student["_id"],
                    "reset_otp": stored_otp,
                    "reset_otp_expiry": student["reset_otp_expiry"],
                },
                {
                    "$set": {
                        "password": hash_password(new_password),
                        "updated_at": now,
                    },
                    "$unset": {
                        "reset_otp": "",
                        "reset_otp_expiry": "",
                        "reset_otp_created_at": "",
                    },
                },
            )

        except PyMongoError:
            logger.exception(
                "Password-reset database update failed."
            )

            return error_response(
                "Unable to reset password at this time.",
                503,
            )

        if result.modified_count != 1:
            return error_response(
                "The password could not be reset. Request a new OTP and try again.",
                409,
            )

        email_sent = safe_send_email(
            EmailSender.send_student_password_changed_email,
            student.get("email"),
            get_student_full_name(student),
        )

        return json_response({
            "success": True,
            "message": "Password reset successfully.",
            "email_sent": email_sent,
        }, 200)


# ==========================================================
# 5. STUDENT CHANGE PASSWORD
# ==========================================================

class ChangeStudentPassword(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if (
            not reg_no
            or not isinstance(current_password, str)
            or not current_password
            or not isinstance(new_password, str)
            or not new_password
        ):
            return error_response(
                "Registration number, current password and new password are required.",
                400,
            )

        if confirm_password is not None and confirm_password != new_password:
            return error_response("Passwords do not match.", 400)

        if not validate_password(new_password):
            return error_response(
                "Password must contain at least 8 characters.",
                400,
            )

        if current_password == new_password:
            return error_response(
                "Your new password must differ from your current password.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Change-password lookup failed.")

            return error_response(
                "Unable to process password change.",
                503,
            )

        if not student or not check_password(
            current_password,
            student.get("password", ""),
        ):
            return error_response(
                "Invalid registration number or password.",
                401,
            )

        if not student_is_active(student):
            return error_response(
                "Your student account is not active.",
                403,
            )

        try:
            result = mongo.db.students.update_one(
                {
                    "_id": student["_id"],
                    "password": student["password"],
                },
                {
                    "$set": {
                        "password": hash_password(new_password),
                        "updated_at": get_utc_now(),
                    }
                },
            )

        except PyMongoError:
            logger.exception(
                "Change-password database update failed."
            )

            return error_response(
                "Unable to change password at this time.",
                503,
            )

        if result.modified_count != 1:
            return error_response(
                "Unable to change the password. Please try again.",
                409,
            )

        email_sent = safe_send_email(
            EmailSender.send_student_password_changed_email,
            student.get("email"),
            get_student_full_name(student),
        )

        return json_response({
            "success": True,
            "message": "Password changed successfully.",
            "email_sent": email_sent,
        }, 200)


# ==========================================================
# 6. CREATE CLEARANCE
# ==========================================================

class CreateClearance(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)

        if not reg_no:
            return error_response(
                "Registration number is required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Clearance student lookup failed.")

            return error_response(
                "Unable to retrieve student details.",
                503,
            )

        if not student:
            return error_response("Student is not registered.", 404)

        if not student_is_active(student):
            return error_response(
                "Your student account is not active.",
                403,
            )

        if student.get("student_status") not in {"regular", "external"}:
            return error_response("Student status is invalid.", 400)

        try:
            existing = get_clearance_by_reg_no(reg_no)

        except Exception:
            logger.exception("Existing clearance lookup failed.")

            return error_response(
                "Unable to check clearance record.",
                503,
            )

        if existing:
            return json_response({
                "success": False,
                "message": "A clearance record already exists.",
                "data": serialize_document(existing),
            }, 409)

        now = get_utc_now()
        stages = {}

        for stage in CLEARANCE_STAGES:
            stages[stage] = {
                "status": "pending",
                "documents": [],
                "rejection_comment": "",
                "reviewed_by": None,
                "reviewed_at": None,
            }

        first_stage = CLEARANCE_STAGES[0]
        stages[first_stage]["status"] = "awaiting_submission"

        clearance = {
            "reg_no": reg_no,
            "student_name": get_student_full_name(student),
            "department": student.get("department"),
            "faculty": student.get("faculty"),
            "student_status": student.get("student_status"),
            "stages": stages,
            "current_stage": first_stage,
            "status": "in_progress",
            "created_at": now,
            "updated_at": now,
        }

        try:
            result = mongo.db.clearances.insert_one(clearance)
            clearance["_id"] = result.inserted_id

        except DuplicateKeyError:
            return error_response(
                "A clearance record already exists.",
                409,
            )

        except PyMongoError:
            logger.exception(
                "Clearance creation database operation failed."
            )

            return error_response(
                "Unable to create the clearance record. Please try again.",
                503,
            )

        return json_response({
            "success": True,
            "message": "Clearance record created successfully.",
            "data": clearance,
        }, 201)


# ==========================================================
# 7. VIEW CLEARANCE
# ==========================================================

class ViewClearance(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)

        if not reg_no:
            return error_response(
                "Registration number is required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

            if not student:
                return error_response("Student not found.", 404)

            clearance = get_clearance_by_reg_no(reg_no)

        except Exception:
            logger.exception("Clearance retrieval failed.")

            return error_response(
                "Unable to retrieve clearance record.",
                503,
            )

        if not clearance:
            return error_response(
                "Clearance record not found.",
                404,
            )

        return json_response({
            "success": True,
            "message": (
                "Your final-year clearance has been completed successfully."
                if clearance.get("status") == "completed"
                else "Clearance record retrieved successfully."
            ),
            "clearance_status": clearance.get("status", "in_progress"),
            "clearance_completed": clearance.get("status") == "completed",
            "current_stage": clearance.get("current_stage"),
            "data": clearance,
        }, 200)


# ==========================================================
# 8. UPLOAD CLEARANCE DOCUMENT
# ==========================================================

class UploadDocument(Resource):
    """
    Multipart form fields:
        reg_no         Student registration number
        stage          Optional requested stage; if supplied, it must match
                       the student's current clearance stage
        document_name  Human-readable document name
        document       PDF, DOC or DOCX file
    """

    def post(self):
        reg_no = normalize_reg_no(
            request.form.get("reg_no", "")
        )

        document_name = request.form.get(
            "document_name", ""
        ).strip()

        uploaded_file = request.files.get("document")

        if not reg_no or not document_name or not uploaded_file:
            return error_response(
                "Registration number, document name and document file are required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

        except Exception:
            logger.exception("Upload student lookup failed.")

            return error_response(
                "Unable to retrieve student details.",
                503,
            )

        if not student:
            return error_response(
                "Student is not registered.",
                404,
            )

        if not student_is_active(student):
            return error_response(
                "Your student account is not active.",
                403,
            )

        try:
            clearance = get_clearance_by_reg_no(reg_no)

        except Exception:
            logger.exception("Upload clearance lookup failed.")

            return error_response(
                "Unable to retrieve clearance record.",
                503,
            )

        if not clearance:
            return error_response(
                "Create your clearance record before uploading documents.",
                404,
            )

        # A completed clearance is terminal: no more document uploads are allowed.
        if clearance.get("status") == "completed":
            return json_response({
                "success": False,
                "message": (
                    "Your final-year clearance is already completed. "
                    "No further documents can be submitted."
                ),
                "clearance_status": "completed",
                "clearance_completed": True,
            }, 409)

        # Validate stage order before accepting the upload. This checks that
        # current_stage is configured, every preceding stage is approved, and
        # the stage records agree with the overall clearance status.
        workflow_valid, current_stage, workflow_error = validate_clearance_workflow(
            clearance
        )

        if not workflow_valid:
            return error_response(workflow_error, 409)

        # The stage field is optional for backward compatibility with existing
        # frontend clients. If supplied, it is treated as the student's explicit
        # requested stage and must equal the stage currently open for submission.
        requested_stage_raw = request.form.get("stage", "").strip()

        if requested_stage_raw:
            requested_stage = normalize_clearance_stage(requested_stage_raw)

            if not requested_stage or requested_stage not in CLEARANCE_STAGES:
                return json_response({
                    "success": False,
                    "message": "The requested clearance stage is invalid.",
                    "requested_stage": requested_stage_raw,
                    "current_stage": current_stage,
                    "allowed_stages": CLEARANCE_STAGES,
                }, 400)

            if requested_stage != current_stage:
                requested_index = CLEARANCE_STAGES.index(requested_stage)
                current_index = CLEARANCE_STAGES.index(current_stage)

                direction = (
                    "earlier"
                    if requested_index < current_index
                    else "later"
                )

                return json_response({
                    "success": False,
                    "message": (
                        f"You cannot upload a document for the "
                        f"{requested_stage.replace('_', ' ')} stage because "
                        f"your current clearance stage is "
                        f"{current_stage.replace('_', ' ')}. The requested "
                        f"stage is a {direction} stage in the clearance "
                        "workflow. Upload the document only for your "
                        "current stage."
                    ),
                    "requested_stage": requested_stage,
                    "current_stage": current_stage,
                    "stage_direction": direction,
                    "stage_status": clearance.get("stages", {}).get(
                        current_stage, {}
                    ).get("status"),
                }, 409)

        stages = clearance.get("stages", {})
        stage_data = stages.get(current_stage, {})
        stage_status = stage_data.get("status")

        if stage_status not in {
            "awaiting_submission",
            "pending",
            "rejected",
        }:
            return json_response({
                "success": False,
                "message": (
                    "You cannot upload a document for this stage "
                    "in its current status."
                ),
                "stage": current_stage,
                "stage_status": stage_status,
            }, 409)

        if not uploaded_file.filename:
            return error_response(
                "Please select a document file.",
                400,
            )

        if not allowed_file_extension(uploaded_file.filename):
            return error_response(
                "Only PDF, DOC and DOCX files are allowed.",
                415,
            )

        original_filename = secure_filename(
            uploaded_file.filename
        )

        if not original_filename or "." not in original_filename:
            return error_response(
                "The uploaded filename is invalid.",
                400,
            )

        try:
            file_bytes = uploaded_file.stream.read(
                MAX_DOCUMENT_SIZE + 1
            )

        except Exception:
            logger.exception("Failed to read uploaded file.")

            return error_response(
                "Unable to read the uploaded file.",
                400,
            )

        if not file_bytes:
            return error_response(
                "The uploaded file is empty.",
                400,
            )

        if len(file_bytes) > MAX_DOCUMENT_SIZE:
            return error_response(
                "Maximum document size is 10 MB.",
                413,
            )

        extension = original_filename.rsplit(".", 1)[1].lower()
        content_type = get_document_content_type(original_filename)

        display_filename = (
            f"{secure_filename(document_name) or 'document'}."
            f"{extension}"
        )

        now = get_utc_now()
        document_id = ObjectId()
        grid_file_id = None

        try:
            grid_file_id = get_grid_fs().put(
                file_bytes,
                filename=display_filename,
                content_type=content_type,
                metadata={
                    "reg_no": reg_no,
                    "stage": current_stage,
                    "document_id": str(document_id),
                    "uploaded_at": now.isoformat(),
                },
            )

            document_record = {
                "document_id": str(document_id),
                "grid_file_id": grid_file_id,
                "document_name": document_name,
                "file_name": display_filename,
                "original_filename": original_filename,
                "content_type": content_type,
                "file_size": len(file_bytes),
                "stage": current_stage,
                "status": "under_review",
                "uploaded_at": now,
                "rejection_comment": "",
            }

            result = mongo.db.clearances.update_one(
                {
                    "_id": clearance["_id"],
                    "current_stage": current_stage,
                    "status": {"$ne": "completed"},
                    f"stages.{current_stage}.status": {
                        "$in": [
                            "awaiting_submission",
                            "pending",
                            "rejected",
                        ]
                    },
                },
                {
                    "$push": {
                        f"stages.{current_stage}.documents": (
                            document_record
                        ),
                    },
                    "$set": {
                        f"stages.{current_stage}.status": "under_review",
                        f"stages.{current_stage}.rejection_comment": "",
                        "updated_at": now,
                    },
                },
            )

            if result.modified_count != 1:
                try:
                    get_grid_fs().delete(grid_file_id)

                except Exception:
                    logger.exception(
                        "Failed to remove orphaned GridFS file."
                    )

                return error_response(
                    "The clearance stage changed during upload. Refresh and try again.",
                    409,
                )

        except PyMongoError:
            logger.exception("Document storage operation failed.")

            if grid_file_id is not None:
                try:
                    get_grid_fs().delete(grid_file_id)

                except Exception:
                    logger.exception(
                        "Failed to clean up GridFS upload."
                    )

            return error_response(
                "The document could not be saved. Please try again.",
                503,
            )

        except Exception:
            logger.exception("Unexpected document upload error.")

            if grid_file_id is not None:
                try:
                    get_grid_fs().delete(grid_file_id)

                except Exception:
                    logger.exception(
                        "Failed to clean up GridFS upload."
                    )

            return error_response(
                "The document could not be saved. Please try again.",
                500,
            )

        return json_response({
            "success": True,
            "message": "Document uploaded successfully and is under review.",
            "data": document_public_data(document_record),
        }, 201)


# ==========================================================
# 9. VIEW UPLOADED DOCUMENTS
# ==========================================================

class ViewUploadedDocuments(Resource):

    def post(self):
        data = get_json_body()

        if data is None:
            return error_response(
                "Request body must be valid JSON.",
                400,
            )

        reg_no = get_request_reg_no(data)

        if not reg_no:
            return error_response(
                "Registration number is required.",
                400,
            )

        try:
            student = get_student_by_reg_no(reg_no)

            if not student:
                return error_response(
                    "Student not found.",
                    404,
                )

            clearance = get_clearance_by_reg_no(reg_no)

        except Exception:
            logger.exception("Uploaded-document lookup failed.")

            return error_response(
                "Unable to retrieve uploaded documents.",
                503,
            )

        if not clearance:
            return error_response(
                "Clearance record not found.",
                404,
            )

        documents = []

        for stage in CLEARANCE_STAGES:
            stage_data = clearance.get("stages", {}).get(stage, {})

            if not isinstance(stage_data, dict):
                continue

            stage_documents = stage_data.get("documents", [])

            if not isinstance(stage_documents, list):
                continue

            for document in stage_documents:
                if isinstance(document, dict):
                    documents.append(
                        document_public_data(document)
                    )

        return json_response({
            "success": True,
            "message": "Uploaded documents retrieved successfully.",
            "clearance_status": clearance.get("status", "in_progress"),
            "clearance_completed": clearance.get("status") == "completed",
            "data": {
                "reg_no": reg_no,
                "current_stage": clearance.get("current_stage"),
                "clearance_status": clearance.get("status", "in_progress"),
                "clearance_completed": clearance.get("status") == "completed",
                "documents": documents,
                "total_documents": len(documents),
            },
        }, 200)


# ==========================================================
# SHARED DOCUMENT STREAMING FUNCTION
# ==========================================================

def stream_clearance_document(document_id, download=False):
    """Validate and stream a GridFS document."""

    reg_no = normalize_reg_no(
        request.args.get("reg_no", "")
    )

    if not reg_no:
        return error_response(
            "Registration number is required.",
            400,
        )

    try:
        ObjectId(document_id)

    except (TypeError, ValueError):
        return error_response(
            "Invalid document ID.",
            400,
        )

    try:
        student = get_student_by_reg_no(reg_no)

        if not student:
            return error_response(
                "Student not found.",
                404,
            )

        stage, document = find_document_in_clearance(
            reg_no,
            document_id,
        )

    except Exception:
        logger.exception("Document metadata lookup failed.")

        return error_response(
            "Unable to retrieve document details.",
            503,
        )

    if not document:
        return error_response(
            "Document not found for this student.",
            404,
        )

    grid_file_id = document.get("grid_file_id")

    if not grid_file_id:
        return error_response(
            "Document storage information is missing.",
            404,
        )

    try:
        stored_file = get_grid_fs().get(grid_file_id)
        file_bytes = stored_file.read()

    except NoFile:
        return error_response(
            "The stored document could not be found.",
            404,
        )

    except PyMongoError:
        logger.exception("GridFS document retrieval failed.")

        return error_response(
            "Unable to retrieve the stored document.",
            503,
        )

    except Exception:
        logger.exception("Unexpected document streaming error.")

        return error_response(
            "Unable to retrieve the stored document.",
            500,
        )

    filename = document.get("file_name") or "document"

    try:
        response = send_file(
            BytesIO(file_bytes),
            mimetype=document.get(
                "content_type",
                "application/octet-stream",
            ),
            as_attachment=download,
            download_name=filename,
        )

        response.headers["X-Content-Type-Options"] = "nosniff"

        return response

    except Exception:
        logger.exception("Failed to prepare document response.")

        return error_response(
            "Unable to prepare the document response.",
            500,
        )


# ==========================================================
# 10. VIEW DOCUMENT
# ==========================================================

class ViewClearanceDocument(Resource):

    def get(self, document_id):
        return stream_clearance_document(
            document_id,
            download=False,
        )


# ==========================================================
# 11. DOWNLOAD DOCUMENT
# ==========================================================

class DownloadClearanceDocument(Resource):

    def get(self, document_id):
        return stream_clearance_document(
            document_id,
            download=True,
        )


# ==========================================================
# REGISTER STUDENT API ROUTES
# ==========================================================

api.add_resource(
    RegisterStudent,
    "/api/v1/clearance/register/student",
)

api.add_resource(
    LoginStudent,
    "/api/v1/clearance/login/student",
)

api.add_resource(
    ForgotPassword,
    "/api/v1/clearance/forgot-password/student",
)

api.add_resource(
    OTPResetStudentPassword,
    "/api/v1/clearance/otp-reset-password/student",
)

api.add_resource(
    ChangeStudentPassword,
    "/api/v1/clearance/change-password/student",
)

api.add_resource(
    CreateClearance,
    "/api/v1/clearance/create",
)

api.add_resource(
    ViewClearance,
    "/api/v1/clearance/view",
)

api.add_resource(
    UploadDocument,
    "/api/v1/clearance/upload-document",
)

api.add_resource(
    ViewUploadedDocuments,
    "/api/v1/clearance/documents",
)

api.add_resource(
    ViewClearanceDocument,
    "/api/v1/clearance/document/view/<string:document_id>",
)

api.add_resource(
    DownloadClearanceDocument,
    "/api/v1/clearance/document/download/<string:document_id>",
)