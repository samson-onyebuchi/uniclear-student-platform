# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: config.py
#
# PURPOSE:
# 1. Load environment variables.
# 2. Configure MongoDB Atlas.
# 3. Configure email and SMTP settings.
# 4. Configure student and staff image URLs.
# 5. Support local development and Vercel deployment.
# ==========================================================

import os
from pathlib import Path

from dotenv import load_dotenv


# ==========================================================
# PROJECT DIRECTORY
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent


# ==========================================================
# ENVIRONMENT VARIABLES
# ==========================================================

# Load the local .env file when available.
# Existing deployment environment variables take priority.
load_dotenv(BASE_DIR / ".env", override=False)


# ==========================================================
# APPLICATION CONFIGURATION
# ==========================================================

class Config:
    """
    Central configuration for the UniClear application.
    """

    # ------------------------------------------------------
    # APPLICATION
    # ------------------------------------------------------

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-only-change-this-secret"
    )

    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    # ------------------------------------------------------
    # MONGODB ATLAS
    # ------------------------------------------------------

    MONGO_URI = os.getenv("MONGO_URI", "").strip()

    # ------------------------------------------------------
    # EMAIL ACCOUNT
    # ------------------------------------------------------

    EMAIL_USERNAME = os.getenv("EMAIL_USERNAME", "").strip()

    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "").strip()

    # ------------------------------------------------------
    # SMTP CONFIGURATION
    # ------------------------------------------------------

    SMTP_SERVER = os.getenv("SMTP_SERVER", "").strip()

    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

    # ------------------------------------------------------
    # IMAGE URLS
    # ------------------------------------------------------

    IMAGE_URL = os.getenv("IMAGE_URL", "").strip()

    LECTURER_IMAGE_URL = os.getenv(
        "LECTURER_IMAGE_URL",
        ""
    ).strip()