from datetime import datetime, timedelta
from django.utils.timezone import make_aware, is_aware, get_current_timezone
from django.apps import apps
from django.contrib.auth import get_user_model
from django.utils import timezone

def process_attendance(user):
    """Check the latest RFID scan and determine attendance status."""
    RFIDLog = apps.get_model('attendance', 'RFIDLog')
    WorkSchedule = apps.get_model('attendance', 'WorkSchedule')
    AttendanceRecord = apps.get_model('attendance', 'AttendanceRecord')

    # Get latest scan
    latest_scan = RFIDLog.objects.filter(user=user).order_by('-scan_time').first()
    if not latest_scan:
        return "No scan recorded"

    scan_time = latest_scan.scan_time
    print(f"Original scan_time: {scan_time}, Timezone aware: {is_aware(scan_time)}")

    # Ensure scan_time is timezone-aware
    if not is_aware(scan_time):
        scan_time = make_aware(scan_time)
    print(f"After make_aware scan_time: {scan_time}, Timezone aware: {is_aware(scan_time)}")

    today = scan_time.date()
    today_name = today.strftime('%A')

    # Ensure user has a valid role before querying WorkSchedule
    if not hasattr(user, 'role') or user.role is None:
        return "User role not found"

    # Get today's schedule based on the user's role
    schedule = WorkSchedule.objects.filter(role=user.role, day_of_week=today_name).first()
    if not schedule:
        return "No schedule for today"

    # Convert schedule start_time to timezone-aware datetime
    tz = get_current_timezone()
    expected_datetime = datetime.combine(today, schedule.start_time)

    print(f"Original expected_datetime: {expected_datetime}, Timezone aware: {is_aware(expected_datetime)}")

    expected_datetime = make_aware(expected_datetime, timezone=tz)  # Ensure timezone-aware
    print(f"After make_aware expected_datetime: {expected_datetime}, Timezone aware: {is_aware(expected_datetime)}")

    # Compute grace period deadline
    deadline = expected_datetime + timedelta(minutes=schedule.grace_period)
    print(f"Deadline: {deadline}, Timezone aware: {is_aware(deadline)}")

    # Determine status
    status = "On-Time" if scan_time <= deadline else "Late"

    # Create or update attendance record
    attendance, created = AttendanceRecord.objects.get_or_create(
        user=user,
        attendance_date=today,  # ✅ Use the correct field name
        defaults={'status': status, 'time_in': scan_time}
    )


    if not created and not attendance.time_in:
        attendance.status = status
        attendance.time_in = scan_time
        attendance.save()

    return status

def mark_absent_users_for_today():
    from .models import AttendanceRecord  # Move the import inside the function
    User = get_user_model()
    today = timezone.localdate()  # Get today's date

    # Get all users who have an attendance record for today
    users_with_attendance = AttendanceRecord.objects.filter(attendance_date=today).values_list('user_id', flat=True)

    # Get all users who don't have attendance yet for today
    absent_users = User.objects.exclude(id__in=users_with_attendance)

    # Create attendance records for absent users
    for user in absent_users:
        AttendanceRecord.objects.create(
            user=user,
            attendance_date=today,
            status='absent'
        )
        print(f"Marked absent: {user.username}")

