import os
import datetime
import random
import base64
import pytz
import hashlib
import binascii  
import json

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
from django.contrib.auth import authenticate
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from django.contrib.auth import update_session_auth_hash
from datetime import datetime, timedelta, time
from .models import WorkSchedule, AttendanceRecord
from collections import defaultdict
from datetime import date
from dateutil.relativedelta import relativedelta
from django.shortcuts import render, get_object_or_404, redirect
from .models import AttendanceRecord, AttendanceCorrection
from .forms import AttendanceCorrectionForm


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

def landing(request):
    latest_time_in = AttendanceLog.objects.filter(time_in__isnull=False).order_by('-time_in').first()
    latest_time_out = AttendanceLog.objects.filter(time_out__isnull=False).order_by('-time_out').first()

    context = {
        'latest_time_in': latest_time_in,
        'latest_time_out': latest_time_out,
    }
    return render(request, 'Timein_Timeout.html', context)

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')  # from the form
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')  # make sure this matches your URL name
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')

def register(request):
    return render(request, 'register.html')

def verify(request):
    return render(request, 'verify.html')  

def scan(request):
    return render(request, 'scan.html')

def forgot_password(request):
    return render(request, 'forgot_password.html')


@login_required(login_url='login')
def dashboard(request):
    user = request.user

    # Get attendance summary and daily logs
    attendance_info = get_monthly_attendance(user)

    # Get attendance chart data for last 3 months
    attendance_chart_data = get_monthly_grouped_attendance(user)

    context = {
        'status_counts': attendance_info['summary'],
        'daily_logs': attendance_info['daily_logs'],
        'attendance_chart_data': json.dumps(attendance_chart_data),
    }

    return render(request, 'dashboard.html', context)


def user_logout(request):
    logout(request)
    return redirect("login") 


def scan_page(request):
    if request.method == "POST":
        rfid_code = request.POST.get("rfid_code")

        if rfid_code:
            user = User.objects.filter(rfid_code=rfid_code).first()

            if user:
                scan_time_utc = timezone.now()
                scan_time = scan_time_utc.astimezone(LOCAL_TZ)

                print(f"Scan Time (UTC): {scan_time_utc}")
                print(f"Scan Time (Local): {scan_time}")

                # Get logs for today
                today_logs = AttendanceLog.objects.filter(
                    user=user, time_in__date=scan_time.date()
                ).order_by("-time_in")

                if today_logs.exists():
                    last_log = today_logs.first()

                    if not last_log.time_out:  # User hasn't logged out yet
                        # Set the current scan as the time_out
                        last_log.time_out = scan_time
                        last_log.save()
                        print(f"🕒 Logged OUT: {user.username} at {scan_time}")
                        send_email(user, is_time_out=True, scan_time=scan_time)
                        handle_scan(user, scan_time)  # Passing scan_time here

                    else:  # A time_out exists, create a new time_in
                        AttendanceLog.objects.create(user=user, time_in=scan_time)
                        print(f"🕒 New Time IN: {user.username} at {scan_time}")
                        send_email(user, is_time_out=False, scan_time=scan_time)
                        handle_scan(user, scan_time)  # Pass scan_time here

                else:  # No log for today, create a new time_in entry
                    AttendanceLog.objects.create(user=user, time_in=scan_time)
                    print(f"🕒 First Time IN: {user.username} at {scan_time}")
                    send_email(user, is_time_out=False, scan_time=scan_time)
                    handle_scan(user, scan_time)  # Pass scan_time here

                # Log the RFID scan event
                RFIDLog.objects.create(user=user, scanned_rfid=rfid_code, scan_time=scan_time)

    latest_time_in = AttendanceLog.objects.filter(time_in__isnull=False).order_by('-time_in').first()
    latest_time_out = AttendanceLog.objects.filter(time_out__isnull=False).order_by('-time_out').first()

    context = {
        'latest_time_in': latest_time_in,
        'latest_time_out': latest_time_out,
    }
    return render(request, "TimeIn_TimeOut.html", context)



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
            print("Form errors:", form.errors)
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


def send_verification_code(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if email:
            User = get_user_model()
            try:
                user = User.objects.get(email=email)

                # Generate OTP using your function
                otp_code = generate_otp()

                # Save to session
                request.session['reset_email'] = email
                request.session['verification_code'] = otp_code

                # Send OTP email using your function
                success = send_otp_email(user_email=email, otp_code=otp_code)

                if success:
                    messages.success(request, 'Verification code sent! Please check your email.')
                    return redirect('verify_pass')  # Go to verify page
                else:
                    messages.error(request, 'Failed to send email. Please try again later.')
                    return redirect('forgot_password')

            except User.DoesNotExist:
                messages.error(request, 'Email not registered!')
                return redirect('forgot_password')
        else:
            messages.error(request, 'Please enter your email.')
            return redirect('forgot_password')
    else:
        return redirect('forgot_password')
    

def verify_pass(request):
    if request.method == 'POST':
        user_input_code = request.POST.get('code')
        session_code = request.session.get('verification_code')

        if not session_code:
            messages.error(request, 'Session expired. Please request a new code.')
            return redirect('forgot_password')

        if user_input_code == session_code:
            messages.success(request, 'Verification successful! You can now update your password.')
            return redirect('update_password')
        else:
            messages.error(request, 'Incorrect code. Please try again.')
            return redirect('verify_pass')
    else:
        return render(request, 'verifypass.html')  # Ensure this template exists


def update_password(request):
    email = request.session.get('reset_email')

    # Check if there's no reset email in session or session expired
    if not email:
        messages.error(request, 'Unauthorized access or session expired. Please start the password reset process again.')
        return redirect('forgot_password')

    # Process POST request for password change
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Password validation
        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('update_password')  # Redirect to the same page for the user to try again

        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return redirect('update_password')

        try:
            # Get the user from the database using the email stored in the session
            user = get_user_model().objects.get(email=email)
            
            # Update the password
            user.set_password(new_password)
            user.save()

            # Log the user in immediately after updating the password
            update_session_auth_hash(request, user)

            # Clear the session data after the password update
            del request.session['reset_email']
            del request.session['verification_code']

            messages.success(request, 'Password updated successfully! Please log in with your new password.')
            return redirect('login')  # Redirect the user to the login page after success

        except get_user_model().DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('login')  # If user not found, redirect to login

    return render(request, 'UpdatePassword.html', {'email': email})  # Render the page with the email

def handle_scan(user, scan_time):

    if scan_time.tzinfo is None:
        scan_time = timezone.make_aware(scan_time, timezone.get_current_timezone())  # Convert to aware time
        
    current_time = scan_time.time()
    current_day = scan_time.strftime('%A')
    today = scan_time.date()
    NOON = time(12, 0)

    try:
        schedule = WorkSchedule.objects.get(role=user.role, day_of_week=current_day)
    except WorkSchedule.DoesNotExist:
        print(f"No schedule found for {user.role} on {current_day}")
        return

    grace_limit = (datetime.combine(today, schedule.start_time) + timedelta(minutes=schedule.grace_period)).time()

    record, created = AttendanceRecord.objects.get_or_create(user=user, attendance_date=today)

    if not record.time_in:
        record.time_in = current_time

        if current_time <= grace_limit:
            record.status = 'present'
        elif current_time <= NOON:
            record.status = 'late'
        elif NOON < current_time <= schedule.end_time:
            record.status = 'halfday'
        elif current_time > schedule.end_time:
            record.status = 'overtime'
        else:
            record.status = 'absent'

    elif not record.time_out:
        record.time_out = current_time

    record.save()

def get_monthly_attendance(user):
    today = timezone.now()
    first_day = today.replace(day=1)
    last_day = (today.replace(day=28) + timezone.timedelta(days=4)).replace(day=1) - timezone.timedelta(days=1)

    # Get attendance records for the current month
    records = AttendanceRecord.objects.filter(
        user=user,
        attendance_date__range=(first_day, last_day)
    ).order_by('attendance_date')

    # Status summary counts
    status_counts = defaultdict(int)
    for record in records:
        status_counts[record.status] += 1

    total_records = sum(status_counts.values())

    # Convert to percentage
    status_percentages = {}
    for status, count in status_counts.items():
        if total_records > 0:
            status_percentages[status] = round((count / total_records) * 100, 1)
        else:
            status_percentages[status] = 0

    # Build daily status table with the record's id
    daily_logs = []
    for record in records:
        daily_logs.append({
            'id': record.id,  # Add the ID of the attendance record
            'date': record.attendance_date.strftime('%b %d, %Y (%A)'),
            'status': record.get_status_display(),
            'time_in': record.time_in.strftime('%I:%M %p') if record.time_in else '—',
            'time_out': record.time_out.strftime('%I:%M %p') if record.time_out else '—'
        })

    return {
        'summary': status_percentages,  # now contains percentage values
        'daily_logs': daily_logs
    }


def get_monthly_grouped_attendance(user):
    today = date.today()
    data = defaultdict(lambda: {status: 0 for status, _ in AttendanceRecord.STATUS_CHOICES})
    
    for i in range(3):
        target_month = (today - relativedelta(months=i)).replace(day=1)
        records = AttendanceRecord.objects.filter(
            user=user,
            attendance_date__year=target_month.year,
            attendance_date__month=target_month.month
        )
        month_label = target_month.strftime('%B %Y')
        for record in records:
            if record.status in data[month_label]:
                data[month_label][record.status] += 1
            else:
                # Optional: handle unknown status values
                print(f"Warning: Unknown status '{record.status}' for record on {record.attendance_date}")
    
    return data


@login_required
def submit_appeal(request, record_id):
    record = get_object_or_404(AttendanceRecord, id=record_id, user=request.user)

    # Prevent duplicate appeal submissions for the same record
    if AttendanceCorrection.objects.filter(attendance_record=record).exists():
        messages.warning(request, "You have already submitted an appeal for this record.")
        return redirect('dashboard')  # or wherever the user comes from

    if request.method == 'POST':
        form = AttendanceCorrectionForm(request.POST)
        if form.is_valid():
            appeal = form.save(commit=False)
            appeal.attendance_record = record
            appeal.user = request.user
            appeal.save()
            messages.success(request, "Your appeal has been submitted.")
            return redirect('dashboard')
        else:
            # Optionally, you could display form errors here
            messages.error(request, "Please fix the errors below.")
    else:
        form = AttendanceCorrectionForm()

    return render(request, 'submit_appeal.html', {'form': form, 'record': record})

@login_required
def approve_appeal(request, appeal_id):
    appeal = get_object_or_404(AttendanceCorrection, id=appeal_id)

    # Check if the current user is authorized to approve the appeal (e.g., admin or reviewer)
    if not request.user.is_staff:  # or any other condition based on your requirements
        messages.error(request, "You do not have permission to approve this appeal.")
        return redirect('dashboard')

    if appeal.status == 'pending':
        appeal.status = 'approved'
        appeal.reviewed_by = request.user
        appeal.reviewed_at = timezone.now()
        appeal.save()

        # Update the AttendanceRecord with the approved times and status
        appeal.approve_appeal()

        messages.success(request, "The appeal has been approved and attendance record updated.")
    else:
        messages.warning(request, "This appeal has already been processed.")

    return redirect('dashboard')

@login_required
def reject_appeal(request, appeal_id):
    appeal = get_object_or_404(AttendanceCorrection, id=appeal_id)

    if not request.user.is_staff:
        messages.error(request, "You do not have permission to reject this appeal.")
        return redirect('dashboard')

    if appeal.status == 'pending':
        appeal.status = 'rejected'
        appeal.reviewed_by = request.user
        appeal.reviewed_at = timezone.now()
        appeal.save()

        # You can update the attendance record status to "rejected" or leave it as is.
        appeal.reject_appeal()

        messages.success(request, "The appeal has been rejected.")
    else:
        messages.warning(request, "This appeal has already been processed.")

    return redirect('dashboard')