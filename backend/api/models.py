from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.validators import RegexValidator

# Create your models here.

class CustomUser(AbstractUser):
    """
    Custom User model extending Django's AbstractUser
    Based on the Node.js backend User schema
    """
    device_token = models.CharField(
        max_length=500,
        help_text="Device token for authentication"
    )
    login_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address of the last login"
    )
    last_login_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last login timestamp"
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="Account creation timestamp"
    )
    
    # Override username field to match Node.js requirements
    username = models.CharField(
        max_length=50,
        unique=True,
        validators=[RegexValidator(
            regex=r'^[a-zA-Z0-9_]+$',
            message='Username can only contain letters, numbers, and underscores'
        )],
        help_text="Required. 3-50 characters. Letters, numbers and underscores only."
    )
    
    # Override email field to be required
    email = models.EmailField(
        unique=True,
        help_text="Required. Enter a valid email address."
    )
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        db_table = 'custom_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def get_formatted_date(self):
        """Format date like Node.js backend"""
        from django.utils import timezone
        return timezone.now().strftime('%d-%b-%Y %H:%M:%S')


class ServerConnectionHistory(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    server_ip = models.GenericIPAddressField()
    server_port = models.IntegerField(default=22)
    server_username = models.CharField(max_length=50)
    server_password = models.TextField(blank=True, null=True, help_text="Encrypted password")
    server_key = models.TextField(blank=True, null=True, help_text="Encrypted key file content")
    server_key_name = models.CharField(max_length=255, blank=True, null=True)
    server_key_type = models.CharField(max_length=50, blank=True, null=True, help_text="password or key")
    server_key_path = models.CharField(max_length=255, blank=True, null=True)
    server_key_content = models.TextField(blank=True, null=True, help_text="Encrypted key content")
    last_connected = models.DateTimeField(default=timezone.now, help_text="Last connection timestamp")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Record creation timestamp")
    
    class Meta:
        db_table = 'server_connection_history'
        verbose_name = 'Server Connection History'
        verbose_name_plural = 'Server Connection Histories'
        ordering = ['-last_connected']
        indexes = [
            models.Index(fields=['user', '-last_connected']),
            models.Index(fields=['-last_connected']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.server_username}@{self.server_ip}:{self.server_port}"
    
    def is_expired(self):
        """Check if connection history is older than 7 days"""
        from datetime import timedelta
        return timezone.now() - self.last_connected > timedelta(days=7)