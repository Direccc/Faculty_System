from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, AttendanceRecord, LateNotification, RFIDLog, WorkSchedule, AttendanceCorrection
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


# Register models in the Django admin panel
admin.site.register(User, CustomUserAdmin)
admin.site.register(AttendanceRecord)
admin.site.register(LateNotification)
admin.site.register(RFIDLog, RFIDAdmin)
admin.site.register(WorkSchedule)
admin.site.register(AttendanceCorrection)

