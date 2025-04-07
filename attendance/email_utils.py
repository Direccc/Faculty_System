import os
import base64
import random
import datetime
import pytz
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .models import AttendanceLog 
from django.utils import timezone


LOCAL_TZ = pytz.timezone("Asia/Manila")

TIME_IN_MESSAGES = [
    "Keep up the good work!",
    "Have a productive day!",
    "Stay safe and take care!",
    "Make today great!",
    "Welcome to campus!",
]

TIME_OUT_MESSAGES = [
    "Rest well and recharge!",
    "Have a great evening!",
    "See you tomorrow!",
    "Hope you had a great day!",
    "Take care on your way home!",
]


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Path to your credentials.json file
CREDENTIALS_PATH = os.path.join(BASE_DIR, "token.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.json")


def generate_otp():
    """Generate a random 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(user_email, otp_code):
    """Send OTP email via Gmail API."""
    try:
        if not os.path.exists(CREDENTIALS_PATH):
            return False

        creds = Credentials.from_authorized_user_file(CREDENTIALS_PATH)
        service = build("gmail", "v1", credentials=creds)

        subject = "Your OTP Verification Code"
        body = f"""
Hello,

Your One-Time Password (OTP) for verification is: {otp_code}

This code is valid for 3 minutes. Do not share this with anyone.

If you did not request this, please ignore this email.

Best regards,
ICT.helpdesk@sscr.edu
"""
        message = MIMEText(body)
        message["to"] = user_email
        message["subject"] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        print(f"✅ OTP email sent to {user_email} successfully!")
        return True

    except Exception as e:
        print(f"🚨 Error sending OTP email: {e}")
        return False

def send_email(user, is_time_out=False, scan_time=None):
    """Send an email notification via Gmail API."""
    try:
        if not os.path.exists(TOKEN_PATH):
            return False

        creds = Credentials.from_authorized_user_file(TOKEN_PATH)
        service = build("gmail", "v1", credentials=creds)

        # Convert scan_time to local timezone before formatting
        if scan_time:
            scan_time = scan_time.astimezone(LOCAL_TZ)
            formatted_time = scan_time.strftime("%I:%M %p")  # Convert to 12-hour format with AM/PM
        else:
            formatted_time = "Unknown Time"

        # Select a random message
        random_message = random.choice(TIME_OUT_MESSAGES if is_time_out else TIME_IN_MESSAGES)

        # **Fetch the latest attendance record**
        latest_log = AttendanceLog.objects.filter(user=user).order_by("-time_in").first()

        # **Determine Time In & Time Out display**
        time_in_str = latest_log.time_in.astimezone(LOCAL_TZ).strftime("%I:%M %p") if latest_log else "N/A"
        time_out_str = (
            latest_log.time_out.astimezone(LOCAL_TZ).strftime("%I:%M %p") if latest_log and latest_log.time_out else "None"
        )

        subject = f"Gate Entry Log for: {user.last_name.upper()}, {user.first_name.upper()}"
        body = f"""
Gate Entry Log for: {user.last_name.upper()}, {user.first_name.upper()}
Role: {user.role.capitalize()}
User ID (RFID ID): {user.rfid_code}

Time In: {time_in_str} | Time Out: {time_out_str}

{random_message}

This is a system-generated message. If you received this email in error, please notify us immediately by sending an e-mail to ICT.helpdesk@sscr.edu or by calling us at (046)431-9405 loc 760.
"""

        message = MIMEText(body)
        message["to"] = user.email
        message["subject"] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        print(f"✅ Email sent to {user.email} successfully!")
        return True

    except Exception as e:
        print(f"🚨 Error sending email: {e}")
        return False