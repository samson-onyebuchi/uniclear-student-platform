# UniClear — Student Clearance Platform

UniClear is a web-based student clearance management system built with Flask and MongoDB. It is designed to help final-year students complete their clearance requirements through the appropriate university departments.

## Features

### Student Features

- Student registration and login.
- Password reset using email OTP.
- Change password.
- Create and view final-year clearance records.
- Upload clearance documents in PDF, DOC, and DOCX formats.
- View uploaded documents and their review statuses.
- View and download uploaded documents.
- Track clearance progress across the required stages.

### Staff Features

- Staff onboarding.
- Staff login.
- Password reset and password change.
- Review clearance documents.
- Approve or reject clearance stages.
- Require comments when rejecting a stage.
- Generate and verify OTPs for progression to the next stage.

### Clearance Stages

1. Finance
2. Department
3. Faculty
4. Library
5. Health
6. Student Affairs
7. Final Clearance

### Student Classification

Student study duration is calculated using the current year minus the admission year.

- Students with a study duration greater than six years are classified as external.
- Students with a study duration of six years or less are classified as regular.

## Technology Stack

- Python
- Flask
- Flask-RESTful
- MongoDB Atlas
- PyMongo
- GridFS for uploaded documents
- Bcrypt for password hashing
- SMTP email delivery
- Vercel for deployment

## Project Structure

```text
uniclear-student-platform/
├── app/
│   ├── __init__.py
│   ├── code/
│   │   ├── __init__.py
│   │   ├── student.py
│   │   ├── staff.py
│   │   └── general_function.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py
│   └── email_util.py
├── config.py
├── .env
├── .env.example
├── .gitignore
├── requirements.txt
├── pyproject.toml
├── README.md
├── run.py
└── vercel.json
```
