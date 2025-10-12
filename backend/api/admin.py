from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Admin configuration for CustomUser model
    """
    list_display = ('username', 'email', 'login_ip', 'last_login_time', 'created_at', 'is_active')
    list_filter = ('is_active', 'is_staff', 'created_at', 'last_login_time')
    search_fields = ('username', 'email')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Device Info', {'fields': ('device_token', 'login_ip', 'last_login_time')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'device_token'),
        }),
    )
    
    readonly_fields = ('created_at', 'last_login_time')
