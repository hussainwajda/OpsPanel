from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import login
from django.utils import timezone
from django.core.cache import cache
from django.db import IntegrityError
from django.core.exceptions import ValidationError
import logging
from django.views.decorators.csrf import csrf_exempt
from .authentication import CsrfExemptSessionAuthentication
from .models import CustomUser
from .serializers import (
    UserRegistrationSerializer, 
    UserLoginSerializer, 
    UserValidationSerializer,
    UserSerializer
)
from .utils import (
    decrypt_ssh_password,
    create_ssh_config,
    get_ssh_connection,
    cleanup_ssh_connections,
    get_connection_key
)
import paramiko

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Simple health check endpoint
    """
    return Response({
        'status': 'ok',
        'message': 'Django backend is running',
        'timestamp': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)

@api_view(['POST', 'OPTIONS'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def auth_view(request):
    """
    Combined authentication endpoint for signup and signin
    Based on Node.js backend /api/auth endpoint
    """
    logger.info(f"Auth request received: {request.method} {request.path}")
    logger.info(f"Request headers: {dict(request.headers)}")
    logger.info(f"Request data: {request.data}")

    if request.method == 'OPTIONS':
        return Response(status=status.HTTP_200_OK)
    
    try:
        auth_type = request.data.get('auth')
        email = request.data.get('email')
        password = request.data.get('password')
        username = request.data.get('username')
        device_token = request.headers.get('X-Device-Token')
        public_ip = request.headers.get('X-Public-IP', 'Unknown')
        
        # Validate required fields
        if not auth_type or not email or not password:
            return Response({
                'message': 'Missing required authentication fields'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not device_token:
            return Response({
                'message': 'Device token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if auth_type == 'signup':
            if not username:
                return Response({
                    'message': 'Username is required for signup'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user already exists
            if CustomUser.objects.filter(email=email.lower()).exists():
                return Response({
                    'message': 'Email already exists'
                }, status=status.HTTP_409_CONFLICT)
            
            if CustomUser.objects.filter(username=username).exists():
                return Response({
                    'message': 'Username already exists'
                }, status=status.HTTP_409_CONFLICT)
            
            # Create new user
            serializer = UserRegistrationSerializer(data={
                'username': username,
                'email': email,
                'password': password,
                'password_confirm': password,
                'device_token': device_token
            })
            
            if serializer.is_valid():
                user = serializer.save()
                user.login_ip = public_ip
                user.save()
                
                logger.info(f"User {username} registered successfully")
                
                return Response({
                    'message': 'User registered successfully',
                    'username': user.username,
                    'email': user.email
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'message': 'Validation failed',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        
        elif auth_type == 'signin':
            print(f"Signin request received: {email}, {password}, {device_token}, {public_ip}")
            serializer = UserLoginSerializer(data={
                'email': email,
                'password': password,
                'device_token': device_token
            }, context={'request': request})
            
            if serializer.is_valid():
                user = serializer.validated_data['user']
                
                # Update user login info
                user.device_token = device_token
                user.login_ip = public_ip
                user.last_login_time = timezone.now()
                user.save()
                
                # Create or get token
                token, created = Token.objects.get_or_create(user=user)
                
                logger.info(f"User {user.username} logged in successfully")
                
                return Response({
                    'message': 'Login successful',
                    'username': user.username,
                    'email': user.email,
                    'token': token.key
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Invalid credentials',
                    'errors': serializer.errors
                }, status=status.HTTP_401_UNAUTHORIZED)
        
        else:
            return Response({
                'message': 'Invalid authentication type'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return Response({
            'message': 'Server error during authentication',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def validate_auth_view(request):
    """
    Authentication validation endpoint
    Based on Node.js backend /api/validate-auth endpoint
    """
    try:
        email = request.data.get('email')
        username = request.data.get('username')
        device_token = request.headers.get('X-Device-Token')
        
        # Check cache first
        cache_key = f"auth_validation_{email}_{username}_{device_token[:10] if device_token else 'none'}"
        cached_result = cache.get(cache_key)
        
        if cached_result:
            return Response(cached_result, status=status.HTTP_200_OK)
        
        if not email or not username or not device_token:
            return Response({
                'message': 'Missing required authentication fields',
                'valid': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user
        try:
            user = CustomUser.objects.get(email=email.lower(), username=username)
        except CustomUser.DoesNotExist:
            return Response({
                'message': 'User not found',
                'valid': False
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Update device token and last login time
        user.device_token = device_token
        user.last_login_time = timezone.now()
        user.save()
        
        response_data = {
            'message': 'Authentication validated successfully',
            'valid': True
        }
        
        # Cache the result for 30 seconds
        cache.set(cache_key, response_data, 30)
        
        logger.info(f"Authentication validated for user {username}")
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Authentication validation error: {str(e)}")
        return Response({
            'message': 'Server error during authentication validation',
            'error': str(e),
            'valid': False
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def user_profile_view(request):
    """
    Get current user profile
    """
    try:
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"User profile error: {str(e)}")
        return Response({
            'message': 'Error retrieving user profile',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def logout_view(request):
    """
    Logout user by deleting token
    """
    try:
        # Delete the token
        request.user.auth_token.delete()
        
        logger.info(f"User {request.user.username} logged out")
        
        return Response({
            'message': 'Logged out successfully'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return Response({
            'message': 'Error during logout',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_all_users_view(request):
    """
    Get all users details
    """
    try:
        users = CustomUser.objects.all().order_by('-created_at')
        serializer = UserSerializer(users, many=True)
        
        logger.info(f"Retrieved {len(users)} users")
        
        return Response({
            'message': 'Users retrieved successfully',
            'count': len(users),
            'users': serializer.data
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Get all users error: {str(e)}")
        return Response({
            'message': 'Error retrieving users',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ConnectAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication]

    def post(self, request, *args, **kwargs):
        start_time = timezone.now()
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')

        if not all([username, ip_address, auth_method]):
            return Response({
                'success': False,
                'message': 'Missing SSH connection details'
            }, status=status.HTTP_400_BAD_REQUEST)

        if auth_method not in ['password', 'key']:
            return Response({
                'success': False,
                'message': 'Invalid authentication method'
            }, status=status.HTTP_400_BAD_REQUEST)

        if auth_method == 'password' and not password:
            return Response({
                'success': False,
                'message': 'Password is required for password authentication'
            }, status=status.HTTP_400_BAD_REQUEST)

        if auth_method == 'key' and not key_file_content:
            return Response({
                'success': False,
                'message': 'Key file content is required for key authentication'
            }, status=status.HTTP_400_BAD_REQUEST)

        decrypted_password = None
        decrypted_key_content = None

        if auth_method == 'password':
            decrypted_password = decrypt_ssh_password(password)
            if not decrypted_password:
                return Response({'success': False, 'message': 'Failed to decrypt SSH password'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            decrypted_key_content = decrypt_ssh_password(key_file_content)
            if not decrypted_key_content:
                return Response({'success': False, 'message': 'Failed to decrypt SSH key file'}, status=status.HTTP_400_BAD_REQUEST)

        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )

        conn = None
        try:
            conn = get_ssh_connection(connection_config)
            
            os_type_command = "cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d'=' -f2 | tr -d '\"'"
            stdin, stdout, stderr = conn.exec_command(os_type_command)
            os_type = stdout.read().decode().strip()
            
            logger.info(f"SSH connect completed in {(timezone.now() - start_time).total_seconds()}s")
            
            return Response({
                'success': True,
                'osType': os_type
            }, status=status.HTTP_200_OK)

        except paramiko.AuthenticationException:
            return Response({'success': False, 'message': 'Authentication failed. Please check your credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        except paramiko.SSHException as e:
            return Response({'success': False, 'message': f'SSH connection error: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"SSH connect error after {(timezone.now() - start_time).total_seconds()}s: {e}")
            return Response({'success': False, 'message': 'Failed to connect to server', 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # The connection is kept in the pool, so we don't close it here.
            # cleanup_ssh_connections() will handle idle connections.
            pass

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_user_view(request):
    """
    Delete user by email
    """
    try:
        email = request.data.get('email')
        
        if not email:
            return Response({
                'message': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user by email
        try:
            user = CustomUser.objects.get(email=email.lower())
        except CustomUser.DoesNotExist:
            return Response({
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Store user info before deletion
        username = user.username
        user_email = user.email
        
        # Delete the user
        user.delete()
        
        logger.info(f"User {username} ({user_email}) deleted successfully")
        
        return Response({
            'message': 'User deleted successfully',
            'username': username,
            'email': user_email
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return Response({
            'message': 'Error deleting user',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
