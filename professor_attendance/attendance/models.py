from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from django.utils.timezone import now
from attendance.utils import process_attendance
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model



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
    created_at = models.DateTimeField(auto_now_add=True)
    rfid_code = models.CharField(max_length=50, unique=True, null=True, blank=True)  
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

class AttendanceRecord(models.Model):
    STATUS_CHOICES = [
        ('present', 'Present'),
        ('late', 'Late'),
        ('absent', 'Absent'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    attendance_date = models.DateField()
    time_in = models.TimeField(null=True, blank=True)
    time_out = models.TimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='absent')
    created_at = models.DateTimeField(auto_now_add=True)

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
    reason = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewer')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

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