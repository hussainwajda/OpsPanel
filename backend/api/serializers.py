from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
from .models import CustomUser
import re
from Crypto.Cipher import AES
import base64
import hashlib

def decrypt_password(encrypted_password):
    """
    Decrypt password using AES decryption
    Compatible with CryptoJS.AES.encrypt from frontend
    """
    try:
        # Get the AES key from settings
        key = settings.AES_AUTH_PASSWORD_KEY
        
        # Decode the base64 encrypted password
        encrypted_data = base64.b64decode(encrypted_password)
        
        # CryptoJS format: "Salted__" + salt + encrypted_data
        if encrypted_data[:8] != b'Salted__':
            raise ValidationError("Invalid encrypted password format")
        
        # Extract salt and encrypted content
        salt = encrypted_data[8:16]  # Salt is 8 bytes
        encrypted_content = encrypted_data[16:]  # Rest is encrypted content
        
        # Derive key and IV from password and salt using MD5 (CryptoJS default)
        def evp_bytestokey(password, salt, key_len, iv_len):
            d = d_i = b''
            while len(d) < key_len + iv_len:
                d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
                d += d_i
            return d[:key_len], d[key_len:key_len+iv_len]
        
        derived_key, iv = evp_bytestokey(key, salt, 32, 16)
        
        # Decrypt
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_content)
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        decrypted = decrypted[:-padding_length]
        
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValidationError(f"Password decryption failed: {str(e)}")

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(write_only=True, min_length=6)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password_confirm', 'device_token')
        extra_kwargs = {
            'username': {'min_length': 3, 'max_length': 50},
            'email': {'required': True},
            'device_token': {'required': True}
        }
    
    def validate_username(self, value):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                'Username can only contain letters, numbers, and underscores'
            )
        return value.lower()
    
    def validate_email(self, value):
        """Validate email format"""
        return value.lower()
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Validate password strength
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        
        return attrs
    
    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        # Check if password is encrypted (starts with CryptoJS format)
        if password.startswith('U2FsdGVkX1'):
            # Decrypt the password before storing
            decrypted_password = decrypt_password(password)
        else:
            # Use plain password
            decrypted_password = password
        
        user = CustomUser.objects.create_user(
            password=decrypted_password,
            **validated_data
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    device_token = serializers.CharField()
    
    def validate_email(self, value):
        """Normalize email"""
        return value.lower()
    
    def validate(self, attrs):
        """Validate credentials"""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Check if password is encrypted (starts with CryptoJS format)
            if password.startswith('U2FsdGVkX1'):
                # Decrypt the password before authentication
                decrypted_password = decrypt_password(password)
            else:
                # Use plain password
                decrypted_password = password
            
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=decrypted_password
            )
            
            if not user:
                raise serializers.ValidationError(
                    'Invalid credentials',
                    code='invalid_credentials'
                )
            
            if not user.is_active:
                raise serializers.ValidationError(
                    'User account is disabled',
                    code='account_disabled'
                )
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError(
                'Must include email and password',
                code='missing_credentials'
            )

class UserValidationSerializer(serializers.Serializer):
    """
    Serializer for authentication validation
    """
    email = serializers.EmailField()
    username = serializers.CharField()
    device_token = serializers.CharField()
    
    def validate_email(self, value):
        """Normalize email"""
        return value.lower()

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user data (read-only)
    """
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'login_ip', 'last_login_time', 'created_at')
        read_only_fields = ('id', 'created_at')

