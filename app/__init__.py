# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/__init__.py
#
# PURPOSE:
# 1. Initialize the Flask application.
# 2. Load application configuration.
# 3. Initialize MongoDB.
# 4. Configure Cross-Origin Resource Sharing (CORS).
# 5. Initialize Flask-RESTful with safe JSON serialization.
# 6. Register student and staff API resources.
# 7. Provide application and database health checks.
# 8. Support local Windows development and Vercel deployment.
#
# IMPORTANT:
# The MongoDB connection string must be configured through
# the MONGO_URI environment variable.
#
# Student and staff modules are imported at the bottom of
# this file, after the Flask app, MongoDB and API objects
# have been initialized. This helps avoid circular imports.
# ==========================================================


# ==========================================================
# IMPORTS
# ==========================================================

import json
import logging

from datetime import date, datetime
from decimal import Decimal

from bson import ObjectId
from bson.decimal128 import Decimal128

from flask import Flask, jsonify, Response, make_response
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_restful import Api

from config import Config


# ==========================================================
# LOGGING
# ==========================================================

logger = logging.getLogger(__name__)


# ==========================================================
# 1. JSON-SAFE VALUE CONVERSION
# ==========================================================

def make_json_safe(value):
    """
    Convert common Python and MongoDB values into JSON-safe
    values before Flask-RESTful serializes the response.
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
        return [
            make_json_safe(item)
            for item in value
        ]

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if value is None or isinstance(
        value, (str, int, float, bool)
    ):
        return value

    # Handle other values that are not directly JSON serializable.
    return str(value)


# ==========================================================
# 2. INITIALIZE THE FLASK APPLICATION
# ==========================================================

app = Flask(__name__)

# Load settings from config.py.
app.config.from_object(Config)


# ==========================================================
# 3. CONFIGURE CROSS-ORIGIN RESOURCE SHARING (CORS)
# ==========================================================

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    },
    supports_credentials=False
)


# ==========================================================
# 4. INITIALIZE MONGODB
# ==========================================================

mongo = PyMongo()

if app.config.get("MONGO_URI"):
    mongo.init_app(app)

else:
    print(
        "WARNING: MONGO_URI is not configured. "
        "Set MONGO_URI in your .env file locally and "
        "configure it as an environment variable on Vercel."
    )


# ==========================================================
# 5. INITIALIZE FLASK-RESTFUL
# ==========================================================

# Create only one API instance.
api = Api(app)


# ==========================================================
# 6. SAFE FLASK-RESTFUL JSON REPRESENTATION
# ==========================================================

@api.representation("application/json")
def safe_json_output(data, code, headers=None):
    """
    Handle Flask-RESTful JSON responses safely.

    This representation:
    1. Returns an existing Flask Response without attempting
       to JSON-encode the Response object.
    2. Converts MongoDB ObjectId and common Python values.
    3. Serializes ordinary dictionaries and lists as JSON.
    4. Preserves response headers and appropriate status codes.
    """

    # IMPORTANT:
    # A Flask Response is already an HTTP response.
    # It must not be passed to json.dumps().
    if isinstance(data, Response):
        response = data

        # If the Response has its default status and the resource
        # explicitly supplied another status, use that status.
        if response.status_code == 200 and code != 200:
            response.status_code = code

        if headers:
            response.headers.extend(headers)

        return response

    # Convert ObjectId, datetime, Decimal and other values
    # before JSON serialization.
    safe_data = make_json_safe(data)

    try:
        serialized_data = json.dumps(safe_data)

    except (TypeError, ValueError, OverflowError):
        logger.exception(
            "UniClear API response JSON serialization failed."
        )

        serialized_data = json.dumps({
            "success": False,
            "message": (
                "The server could not serialize the API response."
            )
        })

        code = 500

    response = make_response(serialized_data, code)

    response.headers["Content-Type"] = "application/json"

    if headers:
        response.headers.extend(headers)

    return response


# ==========================================================
# 7. HOME ENDPOINT
# ==========================================================

@app.route("/", methods=["GET"])
def home():
    """
    Confirm that the UniClear application is running.

    Endpoint:
    GET /

    This endpoint does not guarantee that MongoDB is available.
    """

    return jsonify({
        "success": True,
        "message": (
            "Welcome to UniClear - Student Clearance Platform"
        ),
        "status": "running"
    }), 200


# ==========================================================
# 8. DATABASE-AWARE HEALTH CHECK
# ==========================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Check the application and MongoDB connection.

    HTTP 200:
    The application is running and MongoDB responds to ping.

    HTTP 503:
    MongoDB is not configured or cannot be reached.
    """

    if not app.config.get("MONGO_URI"):
        return jsonify({
            "success": False,
            "application": "UniClear",
            "status": "degraded",
            "database": "not_configured",
            "message": (
                "MongoDB is not configured. "
                "Set the MONGO_URI environment variable."
            )
        }), 503

    try:
        mongo.cx.admin.command("ping")

        return jsonify({
            "success": True,
            "application": "UniClear",
            "status": "healthy",
            "database": "connected"
        }), 200

    except Exception:
        logger.exception(
            "UniClear health check could not reach MongoDB."
        )

        return jsonify({
            "success": False,
            "application": "UniClear",
            "status": "degraded",
            "database": "unavailable",
            "message": (
                "The application is running, but the "
                "database connection could not be verified."
            )
        }), 503


# ==========================================================
# 9. REGISTER STUDENT AND STAFF RESOURCES
# ==========================================================

# Import resources only after app, mongo and api are initialized.
#
# student.py and staff.py register their routes using
# api.add_resource(...).
#
# Do not register these resources a second time here.

from app.code import student as student_resources
from app.code import staff as staff_resources


# ==========================================================
# APPLICATION INITIALIZATION COMPLETE
# ==========================================================

# app   - Flask application
# mongo - PyMongo database extension
# api   - Flask-RESTful API
#
# Student and staff routes are registered when their modules
# are imported above.
# ==========================================================