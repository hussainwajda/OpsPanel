from django.urls import path, re_path
from . import views

urlpatterns = [
    # Health check
    path('health/', views.health_check, name='health_check'),
    
    # Authentication endpoints
    path('auth/', views.auth_view, name='auth'),
    path('validate-auth/', views.validate_auth_view, name='validate_auth'),
    path('profile/', views.user_profile_view, name='user_profile'),
    path('logout/', views.logout_view, name='logout'),
    
    # User management endpoints
    path('users/', views.get_all_users_view, name='get_all_users'),
    path('users/delete/', views.delete_user_view, name='delete_user'),

    # SSH connection endpoint
    re_path(r'^connect/?$', views.ConnectAPIView.as_view(), name='connect'),
    
    # Application installation endpoints
    path('check-installed', views.check_installed_view, name='check_installed'),
    path('install', views.install_view, name='install'),

    # Verify SSH connection
    path('verify-connection', views.verify_connection_view, name='verify_connection'),
]
