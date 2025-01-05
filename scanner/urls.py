from django.urls import path
from .views import logout_view, login_view, malware_analysis, phishing_detection, register_view, dashboard, port_scan, user_profile
from django.contrib.auth import views as auth_views

from scanner import views


urlpatterns = [
    path('', views.dashboard, name='home'),
    path('login/', login_view, name='login'),
     path('logout/', views.logout_view, name='logout'),
    path('register/', register_view, name='register'),
    path('dashboard/', dashboard, name='dashboard'),
    path('port-scan/', port_scan, name='port_scan'),
    path('malware-analysis/', malware_analysis, name='malware_analysis'),
    path('profile/', user_profile, name='profile'),
    path('phishing-detection/', phishing_detection, name='phishing_detection'),

]
