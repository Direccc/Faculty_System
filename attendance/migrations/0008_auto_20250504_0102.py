from django.db import migrations
from datetime import datetime, timedelta

def populate_attendance_data(apps, schema_editor):
    User = apps.get_model('attendance', 'User')
    AttendanceRecord = apps.get_model('attendance', 'AttendanceRecord')
    
    # Get the user we created earlier
    user = User.objects.get(username="Jiyan")
    
    # Create attendance records for Jiyan

    # On Time Attendance (Present)
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 4).date(),  # May 4, 2025
        time_in=datetime(2025, 5, 4, 8, 0, 0).time(),  # 8:00 AM
        time_out=datetime(2025, 5, 4, 16, 0, 0).time(),  # 4:00 PM
        status="present"
    )
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 5).date(),  # May 5, 2025
        time_in=datetime(2025, 5, 5, 8, 0, 0).time(),  # 8:00 AM
        time_out=datetime(2025, 5, 5, 16, 0, 0).time(),  # 4:00 PM
        status="present"
    )

    # Late Attendance (After Grace Period)
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 6).date(),  # May 6, 2025
        time_in=datetime(2025, 5, 6, 8, 30, 0).time(),  # 8:30 AM (30 minutes late)
        time_out=datetime(2025, 5, 6, 16, 0, 0).time(),  # 4:00 PM
        status="late"
    )
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 7).date(),  # May 7, 2025
        time_in=datetime(2025, 5, 7, 8, 30, 0).time(),  # 8:30 AM
        time_out=datetime(2025, 5, 7, 16, 0, 0).time(),  # 4:00 PM
        status="late"
    )

    # Halfday Attendance (PM Arrival)
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 8).date(),  # May 8, 2025
        time_in=datetime(2025, 5, 8, 12, 0, 0).time(),  # 12:00 PM (half day)
        time_out=datetime(2025, 5, 8, 16, 0, 0).time(),  # 4:00 PM
        status="halfday"
    )
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 9).date(),  # May 9, 2025
        time_in=datetime(2025, 5, 9, 12, 0, 0).time(),  # 12:00 PM
        time_out=datetime(2025, 5, 9, 16, 0, 0).time(),  # 4:00 PM
        status="halfday"
    )

    # Overtime (After End Time)
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 10).date(),  # May 10, 2025
        time_in=datetime(2025, 5, 10, 8, 0, 0).time(),  # 8:00 AM
        time_out=datetime(2025, 5, 10, 17, 0, 0).time(),  # 5:00 PM (1 hour overtime)
        status="overtime"
    )
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 11).date(),  # May 11, 2025
        time_in=datetime(2025, 5, 11, 8, 0, 0).time(),  # 8:00 AM
        time_out=datetime(2025, 5, 11, 18, 0, 0).time(),  # 6:00 PM (2 hours overtime)
        status="overtime"
    )

    # Absent (No Scan)
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 12).date(),  # May 12, 2025
        time_in=None,  # No time in
        time_out=None,  # No time out
        status="absent"
    )
    AttendanceRecord.objects.create(
        user=user,
        attendance_date=datetime(2025, 5, 13).date(),  # May 13, 2025
        time_in=None,  # No time in
        time_out=None,  # No time out
        status="absent"
    )

class Migration(migrations.Migration):

    dependencies = [
        ('attendance', '0007_alter_attendancerecord_status'),  # Replace with actual previous migration
    ]

    operations = [
        migrations.RunPython(populate_attendance_data),
    ]
