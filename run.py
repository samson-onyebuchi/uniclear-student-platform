# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: run.py
#
# PURPOSE:
# 1. Provide the main entry point for the Flask application.
# 2. Support running the backend locally on a development
#    computer.
# 3. Expose the Flask application object for deployment
#    platforms such as Vercel.
# 4. Read the port from the environment when one is provided.
# 5. Use the DEBUG setting configured by the application.
#
# LOCAL DEVELOPMENT:
# Run with:
#     python run.py
#
# DEPLOYMENT:
# The Flask application object is exposed as `app`.
# Deployment configuration must point to this entry point
# using the format supported by the selected platform.
# ==========================================================

import os

from app import app


# ==========================================================
# LOCAL DEVELOPMENT SERVER
# ==========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=app.config.get("DEBUG", False)
    )