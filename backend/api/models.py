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
