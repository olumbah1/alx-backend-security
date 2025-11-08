from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    # Authentication endpoints with rate limiting
    path('login/', views.login_view, name='login'),
    
    # API endpoints
    path('api/', views.api_endpoint, name='api'),
    path('api/sensitive/', views.sensitive_endpoint, name='sensitive'),
    
    # Authenticated actions
    path('action/', views.authenticated_action, name='action'),
    
    # Admin dashboard (requires staff permissions)
    path('dashboard/', views.ip_dashboard, name='dashboard'),
]