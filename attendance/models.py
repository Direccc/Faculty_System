import logging

from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from django.utils.timezone import now
from attendance.utils import process_attendance
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from django.utils import timezone



logger = logging.getLogger('attendance')


class User(AbstractUser):
    ROLE_CHOICES = [
        ('professor', 'Professor'),
        ('faculty_staff', 'Faculty Staff'),
        ('admin', 'Admin'),
        ('it_support', 'IT Support'),
        ('security', 'Security'),
        ('janitorial', 'Janitorial'),
        ('maintenance', 'Maintenance'),
        ('librarian', 'Librarian'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    rfid_code = models.CharField(max_length=50, unique=True, null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  # <-- Add this line
    created_at = models.DateTimeField(auto_now_add=True)
    groups = models.ManyToManyField(Group, related_name="custom_user_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_permissions", blank=True)

    def __str__(self):
        return self.username


class WorkSchedule(models.Model):
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES)
    day_of_week = models.CharField(max_length=10, choices=[
        ('Monday', 'Monday'),
        ('Tuesday', 'Tuesday'),
        ('Wednesday', 'Wednesday'),
        ('Thursday', 'Thursday'),
        ('Friday', 'Friday'),
        ('Saturday', 'Saturday'),
        ('Sunday', 'Sunday'),
    ])
    start_time = models.TimeField()
    end_time = models.TimeField()
    grace_period = models.IntegerField(default=15)  # 15 minutes

    def __str__(self):
        return f"{self.role} - {self.day_of_week}"


class AttendanceRecord(models.Model):
    STATUS_CHOICES = [
        ('present', 'Present (On Time)'),
        ('late', 'Late (After Grace Period)'),
        ('halfday', 'Halfday (PM Arrival)'),
        ('overtime', 'Overtime (After End Time)'),
        ('absent', 'Absent (No Scan)'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    attendance_date = models.DateField()
    time_in = models.TimeField(null=True, blank=True)
    time_out = models.TimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='absent')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        day_of_week = self.attendance_date.strftime('%A')
        date_str = self.attendance_date.strftime('%B %d, %Y')  # Example: May 04, 2025
        return f"{self.user.username} - {day_of_week} - {date_str}"

class RFIDLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_time = models.DateTimeField(auto_now_add=True)
    device_location = models.CharField(max_length=255, null=True, blank=True)
    scanned_rfid = models.CharField(max_length=50, default="UNKNOWN")  # Set a default

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        process_attendance(self.user)

class LateNotification(models.Model):
    attendance_record = models.ForeignKey(AttendanceRecord, on_delete=models.CASCADE)
    notification_message = models.TextField()
    notification_time = models.DateTimeField(auto_now_add=True)

class AttendanceCorrection(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    attendance_record = models.ForeignKey(AttendanceRecord, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    requested_time_in = models.TimeField(null=True, blank=True)
    requested_time_out = models.TimeField(null=True, blank=True)
    reason = models.TextField()  # The reason for the appeal
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewer')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Appeal by {self.user.username} for {self.attendance_record.attendance_date}"

    def approve_appeal(self, reviewer=None):
        self.status = 'approved'
        self.reviewed_by = reviewer or self.reviewed_by
        self.reviewed_at = timezone.now()
        self.save()

        logger.info(f"✅ Approved appeal for {self.user.username}, Correction ID: {self.id}")

        if self.attendance_record:
            record = self.attendance_record
            record.time_in = self.requested_time_in
            record.time_out = self.requested_time_out
            record.status = 'present'
            record.save()

            logger.info(
                f"✅ Updated AttendanceRecord for {record.user.username}, "
                f"Record ID: {record.id}, Time In: {record.time_in}, "
                f"Time Out: {record.time_out}, Status: {record.status}"
            )

    def reject_appeal(self, reviewer=None):
        self.status = 'rejected'
        self.reviewed_by = reviewer or self.reviewed_by
        self.reviewed_at = timezone.now()
        self.save()

        logger.info(f"❌ Rejected appeal for {self.user.username}, Correction ID: {self.id}")

    def save(self, *args, **kwargs):
        """Override save method to automatically update the reviewed_at field when status changes."""
        if self.status in ['approved', 'rejected'] and not self.reviewed_at:
            self.reviewed_at = timezone.now()
        elif self.pk and self.status != AttendanceCorrection.objects.get(pk=self.pk).status:
            # Ensure reviewed_at is updated only when status changes
            self.reviewed_at = timezone.now()
        super().save(*args, **kwargs)

class OTPVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # ✅ Add expiry time

    def is_expired(self):
        """Check if the OTP has expired."""
        return datetime.now() >= self.expires_at  # Compare current time with expiry

    def __str__(self):
        return f'OTP for {self.user.username}: {self.otp}'
    
class AttendanceLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    time_in = models.DateTimeField()
    time_out = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.time_in.strftime('%Y-%m-%d %I:%M %p')}"
    
