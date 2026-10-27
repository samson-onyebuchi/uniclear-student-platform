# ==========================================================
# UNICLEAR - STUDENT CLEARANCE PLATFORM
# FILE: app/email_util.py
#
# PURPOSE:
# 1. Configure email delivery through SMTP.
# 2. Send student registration notifications.
# 3. Send student and staff password-reset OTPs.
# 4. Notify staff of successful onboarding.
# 5. Send password-change notifications.
# 6. Notify students about clearance approvals.
# 7. Notify students about clearance rejections.
# 8. Notify students after stage OTP verification.
# 9. Send a dedicated final-clearance congratulatory email.
# 10. Support local development and Vercel deployment.
# ==========================================================

import html
import logging
import smtplib
import ssl

from email.message import EmailMessage

from config import Config
from app.utils import format_stage_name


logger = logging.getLogger(__name__)


class EmailSender:
    """
    Central email utility for the UniClear platform.

    SMTP credentials are loaded from config.py, which reads
    the environment variables defined in the .env file locally
    or in the deployment environment.
    """

    @staticmethod
    def _send_html_email(receiver_email, subject, html_body):
        """
        Send an HTML email using the configured SMTP server.

        Returns:
            bool: True if the email was sent successfully,
                  otherwise False.
        """

        if not receiver_email or not isinstance(receiver_email, str):
            logger.error("Email delivery failed: recipient is missing.")
            return False

        smtp_server = Config.SMTP_SERVER
        smtp_port = Config.SMTP_PORT
        email_username = Config.EMAIL_USERNAME
        email_password = Config.EMAIL_PASSWORD

        if not all(
            [
                smtp_server,
                smtp_port,
                email_username,
                email_password,
            ]
        ):
            logger.error(
                "Email delivery unavailable. Check SMTP_SERVER, "
                "SMTP_PORT, EMAIL_USERNAME and EMAIL_PASSWORD."
            )
            return False

        try:
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = email_username
            message["To"] = receiver_email

            message.set_content(
                "This message contains HTML content. "
                "Please open it with an email application "
                "that supports HTML messages."
            )

            message.add_alternative(html_body, subtype="html")

            context = ssl.create_default_context()

            if int(smtp_port) == 465:
                with smtplib.SMTP_SSL(
                    smtp_server,
                    int(smtp_port),
                    context=context,
                    timeout=30,
                ) as server:
                    server.login(email_username, email_password)
                    server.send_message(message)
            else:
                with smtplib.SMTP(
                    smtp_server,
                    int(smtp_port),
                    timeout=30,
                ) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(email_username, email_password)
                    server.send_message(message)

            logger.info(
                "Email sent successfully to %s",
                receiver_email,
            )
            return True

        except (smtplib.SMTPException, OSError, ValueError) as exc:
            logger.exception(
                "Failed to send email to %s: %s",
                receiver_email,
                exc,
            )
            return False

    @staticmethod
    def _build_email(title, greeting, content):
        """
        Build a reusable, responsive HTML email template.
        """

        safe_title = html.escape(str(title))
        safe_greeting = html.escape(str(greeting))

        image_url = (
            Config.IMAGE_URL
            or Config.LECTURER_IMAGE_URL
            or ""
        ).strip()

        logo_html = ""

        if image_url.startswith(("https://", "http://")):
            safe_image_url = html.escape(image_url, quote=True)

            logo_html = f"""
                <div style="text-align:center;margin-bottom:20px;">
                    <img
                        src="{safe_image_url}"
                        alt="UniClear"
                        style="max-width:140px;max-height:100px;"
                    >
                </div>
            """

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">
            <title>{safe_title}</title>
        </head>
        <body style="
            margin:0;
            padding:20px;
            background-color:#f3f6fb;
            font-family:Arial,Helvetica,sans-serif;
            color:#263247;
        ">
            <div style="
                max-width:620px;
                margin:0 auto;
                background-color:#ffffff;
                border:1px solid #e2e8f0;
                border-radius:10px;
                overflow:hidden;
            ">
                <div style="
                    background-color:#102a43;
                    padding:25px 20px;
                    text-align:center;
                ">
                    <h1 style="
                        margin:0;
                        color:#ffffff;
                        font-size:25px;
                    ">UniClear</h1>

                    <p style="
                        margin:8px 0 0;
                        color:#d9e7f5;
                        font-size:13px;
                    ">Student Clearance Platform</p>
                </div>

                <div style="padding:30px 25px;">
                    {logo_html}

                    <h2 style="
                        color:#102a43;
                        font-size:21px;
                        margin-top:0;
                    ">{safe_greeting}</h2>

                    {content}

                    <p style="
                        margin-top:30px;
                        color:#64748b;
                        font-size:13px;
                    ">
                        This is an automated message from UniClear.
                        If you did not initiate the relevant request,
                        please contact your university's clearance
                        administrator.
                    </p>
                </div>

                <div style="
                    padding:18px;
                    background-color:#f8fafc;
                    border-top:1px solid #e2e8f0;
                    text-align:center;
                    color:#64748b;
                    font-size:12px;
                ">
                    &copy; UniClear Student Clearance Platform
                </div>
            </div>
        </body>
        </html>
        """

    @staticmethod
    def _paragraph(message):
        """Return an escaped HTML paragraph."""

        return (
            '<p style="font-size:15px;line-height:1.7;">'
            f"{html.escape(str(message))}"
            "</p>"
        )

    @staticmethod
    def _button(label, value):
        """Return a styled information box."""

        safe_label = html.escape(str(label))
        safe_value = html.escape(str(value))

        return f"""
        <div style="
            margin:20px 0;
            padding:18px;
            border-radius:8px;
            background-color:#edf4ff;
            border:1px solid #c9dcff;
            text-align:center;
        ">
            <div style="
                color:#52657a;
                font-size:13px;
                margin-bottom:8px;
            ">{safe_label}</div>

            <div style="
                color:#102a43;
                font-size:25px;
                font-weight:bold;
                letter-spacing:2px;
                overflow-wrap:anywhere;
            ">{safe_value}</div>
        </div>
        """

    @staticmethod
    def _safe_stage(stage):
        """Convert a stage identifier into readable text."""

        return format_stage_name(stage) or "Unknown Stage"

    @staticmethod
    def send_student_registration_email(
        receiver_email,
        student_name,
        reg_no,
        password,
    ):
        """
        Send student registration confirmation.

        Note:
            This method follows the legacy project interface.
            Avoid passing a student's permanent password to email
            in a production deployment.
        """

        safe_reg_no = html.escape(str(reg_no))

        content = (
            EmailSender._paragraph(
                "Your UniClear student account has been created."
            )
            + EmailSender._button("Registration Number", reg_no)
            + EmailSender._paragraph(
                "You can now sign in to access the student clearance "
                "platform. Keep your account credentials private."
            )
        )

        body = EmailSender._build_email(
            "Student Registration",
            f"Welcome, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Student Registration",
            body,
        )

    @staticmethod
    def send_student_forgot_password_email(
        receiver_email,
        student_name,
        otp,
    ):
        """Send a student password-reset OTP."""

        content = (
            EmailSender._paragraph(
                "A request was made to reset your UniClear password."
            )
            + EmailSender._button("Password Reset OTP", otp)
            + EmailSender._paragraph(
                "This OTP is valid for 10 minutes. Do not share it "
                "with anyone."
            )
        )

        body = EmailSender._build_email(
            "Password Reset",
            f"Hello, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Student Password Reset OTP",
            body,
        )

    @staticmethod
    def send_staff_forgot_password_email(
        receiver_email,
        staff_name,
        otp,
    ):
        """Send a staff password-reset OTP."""

        content = (
            EmailSender._paragraph(
                "A password-reset request was made for your "
                "UniClear staff account."
            )
            + EmailSender._button("Password Reset OTP", otp)
            + EmailSender._paragraph(
                "This OTP is valid for 10 minutes. Keep it private."
            )
        )

        body = EmailSender._build_email(
            "Staff Password Reset",
            f"Hello, {staff_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Staff Password Reset OTP",
            body,
        )

    @staticmethod
    def send_student_password_changed_email(
        receiver_email,
        student_name,
    ):
        """Notify a student that their password has changed."""

        content = EmailSender._paragraph(
            "Your UniClear account password has been changed. "
            "If you did not make this change, contact your "
            "university's clearance administrator immediately."
        )

        body = EmailSender._build_email(
            "Password Changed",
            f"Hello, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Student Password Changed",
            body,
        )

    @staticmethod
    def send_staff_onboarding_email(
        receiver_email,
        staff_name,
        staff_id,
        role,
        temporary_password=None,
    ):
        """
        Send staff onboarding confirmation.

        Staff members create their own passwords during onboarding,
        so no temporary password is sent by email.

        The temporary_password parameter is retained as optional
        for compatibility with existing calls from staff.py.
        Its value is intentionally not displayed or emailed.
        """

        content = (
            EmailSender._paragraph(
                "Your UniClear staff account has been created successfully."
            )
            + EmailSender._button("Staff ID", staff_id)
            + EmailSender._button("Assigned Role", role)
            + EmailSender._paragraph(
                "You can now sign in using your staff ID and the "
                "password you created during onboarding."
            )
            + EmailSender._paragraph(
                "Keep your login credentials private. If you did not "
                "register for this account, contact the system "
                "administrator."
            )
        )

        body = EmailSender._build_email(
            "Staff Account Created",
            f"Welcome, {staff_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Staff Account Onboarding",
            body,
        )

    @staticmethod
    def send_staff_password_changed_email(
        receiver_email,
        staff_name,
    ):
        """Notify a staff member that their password has changed."""

        content = EmailSender._paragraph(
            "Your UniClear staff account password has been changed. "
            "If you did not authorize this change, contact the "
            "system administrator."
        )

        body = EmailSender._build_email(
            "Password Changed",
            f"Hello, {staff_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Staff Password Changed",
            body,
        )

    @staticmethod
    def send_student_clearance_stage_approved_email(
        receiver_email,
        student_name,
        reg_no,
        stage,
        next_stage=None,
        otp=None,
        otp_expiry_minutes=None,
    ):
        """
        Notify a student of stage approval.

        For non-final stages, include the OTP for the next stage.
        For final-stage approval, send a completion notification.
        """

        stage_name = EmailSender._safe_stage(stage)

        content = (
            EmailSender._paragraph(
                f"Your {stage_name} clearance stage has been approved."
            )
            + EmailSender._button("Registration Number", reg_no)
        )

        if next_stage:
            next_stage_name = EmailSender._safe_stage(next_stage)

            content += EmailSender._paragraph(
                f"Your next clearance stage is {next_stage_name}."
            )

            if otp is not None:
                content += EmailSender._button(
                    f"{next_stage_name} Stage OTP",
                    otp,
                )

                if otp_expiry_minutes is None:
                    content += EmailSender._paragraph(
                        "This stage OTP has no time-based expiry. "
                        "It remains valid until used or invalidated."
                    )
                else:
                    content += EmailSender._paragraph(
                        "This stage OTP is valid for "
                        f"{otp_expiry_minutes} minutes."
                    )
        else:
            content += EmailSender._paragraph(
                "Congratulations! Your final clearance stage has "
                "been approved, and your clearance is complete."
            )

        body = EmailSender._build_email(
            "Clearance Stage Approved",
            f"Congratulations, {student_name}",
            content,
        )

        subject = (
            "UniClear Final Clearance Completed"
            if not next_stage
            else f"UniClear {stage_name} Stage Approved"
        )

        return EmailSender._send_html_email(
            receiver_email,
            subject,
            body,
        )

    # ======================================================
    # NEW FUNCTION: FINAL-YEAR CLEARANCE COMPLETION EMAIL
    # ======================================================

    @staticmethod
    def send_student_clearance_completed_email(
        receiver_email,
        student_name,
        reg_no,
    ):
        """
        Send a dedicated congratulatory email after the student
        has successfully completed all final-year clearance stages.

        This email is intended to be called only after the backend
        has successfully marked the student's clearance as completed.

        The message is formal and university-appropriate, with tasteful
        celebratory emojis and the student's registration number.

        No OTP is generated or included because this is the final
        completion of the student's clearance process.
        """

        content = (
            """
            <div style="
                margin:0 0 24px;
                padding:24px 18px;
                text-align:center;
                background-color:#f0fdf4;
                border:1px solid #bbf7d0;
                border-radius:10px;
            ">
                <div style="
                    font-size:38px;
                    line-height:1.4;
                    margin-bottom:10px;
                ">🎓</div>

                <h2 style="
                    margin:0 0 12px;
                    color:#166534;
                    font-size:23px;
                    line-height:1.4;
                ">Congratulations!</h2>

                <p style="
                    margin:0;
                    color:#166534;
                    font-size:16px;
                    line-height:1.7;
                    font-weight:600;
                ">
                    Your final-year clearance process has been
                    successfully completed.
                </p>

                <div style="
                    margin-top:16px;
                    font-size:24px;
                ">✅ 🎉</div>
            </div>
            """
            + EmailSender._paragraph(
                "We are pleased to inform you that you have successfully "
                "completed all the required stages of your final-year "
                "clearance through the UniClear Student Clearance Platform."
            )
            + EmailSender._button(
                "Registration Number",
                reg_no,
            )
            + """
            <div style="
                margin:22px 0;
                padding:18px;
                border-left:4px solid #16a34a;
                background-color:#f8fafc;
                border-radius:4px;
            ">
                <p style="
                    margin:0 0 8px;
                    font-size:15px;
                    font-weight:bold;
                    color:#102a43;
                ">
                    Clearance Status: COMPLETED
                </p>

                <p style="
                    margin:0;
                    font-size:14px;
                    line-height:1.7;
                    color:#475569;
                ">
                    All required clearance stages have been approved.
                    No further clearance stage or stage-verification
                    OTP is required for this completed clearance process.
                </p>
            </div>
            """
            + EmailSender._paragraph(
                "Thank you for completing your clearance through UniClear. "
                "Please retain this email for your personal records and "
                "refer to your student dashboard for your clearance status."
            )
            + EmailSender._paragraph(
                "On behalf of the university clearance administration, "
                "we congratulate you on reaching this important milestone "
                "and wish you success in your future endeavours."
            )
            + """
            <p style="
                margin:24px 0 0;
                text-align:center;
                color:#102a43;
                font-size:16px;
                line-height:1.7;
                font-weight:bold;
            ">
                🎓 Congratulations on completing your final-year clearance!
            </p>
            """
        )

        body = EmailSender._build_email(
            "Final-Year Clearance Successfully Completed",
            f"Congratulations, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "🎓 Congratulations! Your Final-Year Clearance Is Complete",
            body,
        )

    @staticmethod
    def send_student_clearance_stage_rejected_email(
        receiver_email,
        student_name,
        reg_no,
        stage,
        rejection_comment,
    ):
        """Notify a student of stage rejection and its reason."""

        stage_name = EmailSender._safe_stage(stage)

        content = (
            EmailSender._paragraph(
                f"Your {stage_name} clearance submission has been "
                "rejected. Please review the reason below."
            )
            + EmailSender._button("Registration Number", reg_no)
            + EmailSender._paragraph(
                f"Rejection reason: {rejection_comment}"
            )
            + EmailSender._paragraph(
                "Correct the issue and upload the required document "
                "again for review."
            )
        )

        body = EmailSender._build_email(
            "Clearance Stage Rejected",
            f"Hello, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            f"UniClear {stage_name} Stage Rejected",
            body,
        )

    @staticmethod
    def send_student_clearance_stage_otp_verified_email(
        receiver_email,
        student_name,
        reg_no,
        previous_stage,
        current_stage,
    ):
        """Notify a student that their next-stage OTP was verified."""

        previous_stage_name = EmailSender._safe_stage(previous_stage)
        current_stage_name = EmailSender._safe_stage(current_stage)

        content = (
            EmailSender._paragraph(
                f"Your OTP verification following the "
                f"{previous_stage_name} stage was successful."
            )
            + EmailSender._button("Registration Number", reg_no)
            + EmailSender._paragraph(
                f"Your current clearance stage is now "
                f"{current_stage_name}."
            )
            + EmailSender._paragraph(
                "You may proceed with the requirements for your "
                "current stage."
            )
        )

        body = EmailSender._build_email(
            "Stage OTP Verified",
            f"Hello, {student_name}",
            content,
        )

        return EmailSender._send_html_email(
            receiver_email,
            "UniClear Clearance OTP Verified",
            body,
        )