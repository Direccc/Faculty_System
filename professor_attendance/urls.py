"""
URL configuration for professor_attendance project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.shortcuts import render
from attendance import views
from django.conf import settings
from django.conf.urls.static import static

def landing_page(request):
    return render(request, 'Timein_Timeout.html')  # No need to specify "templates/"

urlpatterns = [
    path('', views.landing, name='TimeIn_TimeOut'),
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),  
    path('register/', views.register, name='register'),  
    path('verify/', views.verify_otp, name='verify_otp'),  
    path('scan/', views.scan_page, name='scan'),  
    path("gmail_auth/", views.gmail_auth, name="gmail_auth"),
    path("oauth2callback/", views.gmail_auth_callback, name="gmail_auth_callback"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.user_logout, name="logout"),
    path('resend_otp/', views.resend_otp, name='resend_otp'),
    path('hash-demo/', views.hash_demo_view, name='hash_demo'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-pass/', views.verify_pass, name='verify_pass'),  # Updated this line
    path('update-password/', views.update_password, name='update_password'),
    path('send-verification-code/', views.send_verification_code, name='send_verification_code'),
    path('appeal/<int:record_id>/', views.submit_appeal, name='submit_appeal'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)