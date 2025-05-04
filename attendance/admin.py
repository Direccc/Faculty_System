import logging

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, AttendanceRecord, LateNotification, RFIDLog, WorkSchedule, AttendanceCorrection
from django.utils import timezone

logger = logging.getLogger('attendance')
logger.info("✅ Logger test: This should appear in the console.")

# Custom User Admin
class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('username', 'email', 'role', 'rfid_code', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'role', 'rfid_code', 'profile_picture')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'rfid_code', 'profile_picture', 'is_staff', 'is_active'),
        }),
    )
    search_fields = ('email', 'username', 'rfid_code')
    ordering = ('username',)


class RFIDAdmin(admin.ModelAdmin):
    list_display = ('user', 'scanned_rfid', 'scan_time', 'device_location')
    ordering = ('-scan_time',)


@admin.register(AttendanceCorrection)
class AttendanceCorrectionAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'attendance_record', 'requested_time_in', 'requested_time_out',
        'status', 'created_at', 'reviewed_by', 'reviewed_at'
    )
    list_filter = ('status', 'reviewed_by', 'created_at')
    search_fields = ('user__username', 'attendance_record__attendance_date')
    actions = ['approve_appeals', 'reject_appeals']

    def approve_appeals(self, request, queryset):
        updated_count = 0
        for correction in queryset:
            if correction.status != 'approved':
                correction.approve_appeal(reviewer=request.user)
                updated_count += 1
        self.message_user(request, f"{updated_count} appeal(s) approved.")

    def reject_appeals(self, request, queryset):
        updated_count = 0
        for correction in queryset:
            if correction.status != 'rejected':
                correction.reject_appeal(reviewer=request.user)
                updated_count += 1
        self.message_user(request, f"{updated_count} appeal(s) rejected.")

    def save_model(self, request, obj, form, change):
        logger = logging.getLogger('attendance')

        if obj.status == 'approved' and not obj.reviewed_at:
            obj.approve_appeal(reviewer=request.user)
            logger.info(f"✅ save_model: Approved via form for correction {obj.id}")
        elif obj.status == 'rejected' and not obj.reviewed_at:
            obj.reject_appeal(reviewer=request.user)
            logger.info(f"❌ save_model: Rejected via form for correction {obj.id}")
        else:
            logger.info(f"ℹ️ save_model: No action taken for correction {obj.id}")
        super().save_model(request, obj, form, change)

    approve_appeals.short_description = "Approve selected appeals"
    reject_appeals.short_description = "Reject selected appeals"
    
# Register models in the Django admin panel
admin.site.register(User, CustomUserAdmin)
admin.site.register(AttendanceRecord)
admin.site.register(LateNotification)
admin.site.register(RFIDLog, RFIDAdmin)
admin.site.register(WorkSchedule)
