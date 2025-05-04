import re

from django import forms
from django.contrib.auth import get_user_model
from .models import AttendanceCorrection

User = get_user_model()

class RegisterForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'role']
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')

        # Password rules
        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", password):
            raise forms.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise forms.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            raise forms.ValidationError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise forms.ValidationError("Password must contain at least one special character.")

        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match.")
        return password2
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.is_active = False  # User will be activated after OTP verification
        if commit:
            user.save()
        return user

class HashForm(forms.Form):
    message = forms.CharField(label='Enter text', max_length=255)

class AttendanceCorrectionForm(forms.ModelForm):
    class Meta:
        model = AttendanceCorrection
        fields = ['requested_time_in', 'requested_time_out', 'reason']
        widgets = {
            'reason': forms.Textarea(attrs={'rows': 3}),
        }
