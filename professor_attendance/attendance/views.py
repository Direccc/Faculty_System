import os
import datetime
import random
import base64
import pytz
import hashlib
import binascii  

from .models import RFIDLog, User
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from django.http import HttpResponse
from google_auth_oauthlib.flow import InstalledAppFlow  
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account  
from google_auth_oauthlib.flow import Flow
from email.mime.text import MIMEText
from django.contrib import messages
from .forms import RegisterForm
from .forms import HashForm
from .models import RFIDLog, AttendanceLog
from .models import OTPVerification
from datetime import timedelta
from .email_utils import send_otp_email, generate_otp, send_email # Import email functions
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth import get_user_model



# Set your local timezone (e.g., "Asia/Manila" for the Philippines)
LOCAL_TZ = pytz.timezone("Asia/Manila")


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CREDENTIALS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "credentials.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.json")
User = get_user_model()

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

def gmail_auth(request):
    """Redirect user to Google's OAuth 2.0 authorization page."""
    if not os.path.exists(CREDENTIALS_PATH):
        return HttpResponse("Error: credentials.json file not found!", status=500)

    flow = Flow.from_client_secrets_file(
        CREDENTIALS_PATH, scopes=SCOPES, redirect_uri="http://127.0.0.1:8000/oauth2callback/"
    )
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")

    return HttpResponse(f'<a href="{auth_url}">Click here to authorize Gmail access</a>')

def gmail_auth_callback(request):
    """Handle OAuth callback and save access token."""
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_PATH, scopes=SCOPES, redirect_uri="http://127.0.0.1:8000/oauth2callback/"
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())

    creds = flow.credentials
    with open(os.path.join(BASE_DIR, "token.json"), "w") as token:
        token.write(creds.to_json())

    return HttpResponse("Authentication successful! Gmail API is now authorized.")

def studybit(request):
    return render(request, 'studybit.html') 

def login_view(request):
    return render(request, 'login.html')  

def register(request):
    return render(request, 'register.html')

def verify(request):
    return render(request, 'verify.html')  

def scan(request):
    return render(request, 'scan.html')


@login_required
def dashboard(request):
    return render(request, "dashboard.html")  

def user_logout(request):
    logout(request)
    return redirect("login") 


def scan_page(request):
    if request.method == "POST":
        rfid_code = request.POST.get("rfid_code")

        if rfid_code:
            user = User.objects.filter(rfid_code=rfid_code).first()

            if user:
                # Get current time and convert to local timezone
                scan_time_utc = timezone.now()  # Get UTC time
                scan_time = scan_time_utc.astimezone(LOCAL_TZ)  # Convert to local timezone

                today_logs = AttendanceLog.objects.filter(
                    user=user, time_in__date=scan_time.date()
                ).order_by("-time_in")

                if today_logs.exists():
                    last_log = today_logs.first()

                    if not last_log.time_out:
                        # Log Time Out
                        last_log.time_out = scan_time
                        last_log.save()
                        print(f"🕒 Logged OUT: {user.username} at {scan_time}")
                        send_email(user, is_time_out=True, scan_time=scan_time)  # ✅ Pass scan_time
                    else:
                        # Create a new Time In entry
                        AttendanceLog.objects.create(user=user, time_in=scan_time)
                        print(f"🕒 New Time IN: {user.username} at {scan_time}")
                        send_email(user, is_time_out=False, scan_time=scan_time)  # ✅ Pass scan_time
                else:
                    # ✅ First scan of the day (Time In)
                    AttendanceLog.objects.create(user=user, time_in=scan_time)
                    print(f"🕒 First Time IN: {user.username} at {scan_time}")
                    send_email(user, is_time_out=False, scan_time=scan_time)  # ✅ Pass scan_time

                # ✅ Save scan log for record-keeping
                RFIDLog.objects.create(user=user, scanned_rfid=rfid_code, scan_time=scan_time)

    return render(request, "scan.html")


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  # Don't save yet
            user.is_active = False  # ❌ Make user inactive until verification
            user.save()

            # Generate OTP
            otp_code = generate_otp()
            otp_expiry = now() + timedelta(minutes=3)  # 3-minute expiry
            
            # Save OTP
            OTPVerification.objects.create(user=user, otp=otp_code, expires_at=otp_expiry)

            # Send OTP via email
            send_otp_email(user.email, otp_code)

            # Store user ID in session
            request.session["pending_user_id"] = user.id

            # Redirect to verification page
            return redirect("verify_otp")  # Redirect to verify.html

        else:
            messages.error(request, "Registration failed. Please check the form.")

    else:
        form = RegisterForm()

    return render(request, "register.html", {"form": form})

def verify_otp(request):
    user_id = request.session.get("pending_user_id")
    if not user_id:
        messages.error(request, "Session expired. Please register again.")
        return redirect("register")

    user = User.objects.get(id=user_id)

    if request.method == "POST":
        otp_code = request.POST.get("code")

        try:
            otp_record = OTPVerification.objects.get(user=user, otp=otp_code)
            if otp_record.created_at + timedelta(minutes=3) < now():
                messages.error(request, "OTP expired! Please request a new one.")
                return redirect("verify_otp")
            
            # ✅ Activate user & log them in
            user.is_active = True
            user.save()
            otp_record.delete()  # Delete OTP record after successful verification
            login(request, user)  # Log the user in

            messages.success(request, "✅ Account verified successfully!")
            return redirect("dashboard")  # Redirect to dashboard.html

        except OTPVerification.DoesNotExist:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, "verify.html")

def resend_otp(request):
    user_id = request.session.get("pending_user_id")
    if not user_id:
        messages.error(request, "Session expired. Please register again.")
        return redirect("register")

    user = User.objects.get(id=user_id)

    # Generate new OTP
    new_otp = generate_otp()
    otp_record, created = OTPVerification.objects.update_or_create(
        user=user,
        defaults={"otp": new_otp, "created_at": now()},
    )

    # Send new OTP email
    print(f"Generated OTP: {new_otp} for user: {user.email}")
    send_otp_email(user.email, new_otp)
    messages.success(request, "🔄 A new OTP has been sent to your email.")

    return redirect("verify_otp")

def process_scan(user):
    """Handles RFID scans and determines Time In / Time Out logic."""
    now_time = timezone.now()

    # Check if user already has a scan for today
    today_entry = AttendanceLog.objects.filter(
        user=user,
        scan_time__date=now_time.date()
    ).order_by("scan_time").first()  # Get the earliest scan

    if today_entry and today_entry.time_out is None:
        # If the user has a time-in record but no time-out, log them out
        today_entry.time_out = now_time
        today_entry.save()
        log_type = "Time Out"
    else:
        # Otherwise, log a new time-in entry
        AttendanceLog.objects.create(user=user, time_in=now_time)
        log_type = "Time In"

    send_email(user, log_type, now_time)

def hash_demo_view(request):
    result = None
    salt = None
    iterations = 100000  
    error = None

    if request.method == 'POST':
        form = HashForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['message']

            if 'encrypt' in request.POST:
                salt = os.urandom(16)  # generate random 16-byte salt
                hash_bytes = hashlib.pbkdf2_hmac(
                    'sha256',
                    text.encode('utf-8'),
                    salt,
                    iterations
                )
                result = binascii.hexlify(hash_bytes).decode('utf-8')
                salt = binascii.hexlify(salt).decode('utf-8')

            elif 'decrypt' in request.POST:
                error = "Hashing is one-way. Decryption not possible."

    else:
        form = HashForm()

    return render(request, 'hash_demo.html', {
        'form': form,
        'result': result,
        'salt': salt,
        'iterations': iterations,
        'error': error,
    })
