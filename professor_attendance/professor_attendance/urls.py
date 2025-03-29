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
from attendance.views import login_view  # Import your views

def landing_page(request):
    return render(request, 'studybit.html')  # No need to specify "templates/"

urlpatterns = [
    path('', views.studybit, name='studybit'),
    path('admin/', admin.site.urls),
    path('login/', login_view, name='login'),  
    path('register/', views.register, name='register'),  
    path('verify/', views.verify_otp, name='verify_otp'),  
    path('scan/', views.scan_page, name='scan'),  
    path("gmail_auth/", views.gmail_auth, name="gmail_auth"),
    path("oauth2callback/", views.gmail_auth_callback, name="gmail_auth_callback"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.user_logout, name="logout"),
    path('resend_otp/', views.resend_otp, name='resend_otp'),
]
