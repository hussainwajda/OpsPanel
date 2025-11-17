from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import login
from django.utils import timezone
from django.core.cache import cache
from django.db import IntegrityError
from django.core.exceptions import ValidationError
import logging
from django.views.decorators.csrf import csrf_exempt
from .authentication import CsrfExemptSessionAuthentication
from .models import CustomUser, ServerConnectionHistory
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
    get_connection_key,
    execute_ssh_command,
    upload_and_execute_script,
    ssh_connection_pool
)
import paramiko
import time

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
    authentication_classes = [CsrfExemptSessionAuthentication, TokenAuthentication]

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
            
            # Save connection history if user is authenticated
            logger.info(f"User authentication status: is_authenticated={request.user.is_authenticated}, user={request.user if hasattr(request.user, 'username') else 'Anonymous'}")
            if request.user.is_authenticated:
                try:
                    logger.info(f"Attempting to save connection history for authenticated user {request.user.username}")
                    save_connection_history_internal(
                        user=request.user,
                        ip_address=ip_address,
                        port=22,
                        username=username,
                        auth_method=auth_method,
                        encrypted_password=password if auth_method == 'password' else None,
                        encrypted_key_content=key_file_content if auth_method == 'key' else None,
                        key_file_name=key_file_name if auth_method == 'key' else None
                    )
                    logger.info(f"Connection history saved successfully for user {request.user.username} - {username}@{ip_address}")
                except Exception as history_error:
                    logger.error(f"Failed to save connection history: {str(history_error)}", exc_info=True)
                    # Don't fail the connection if history save fails
            else:
                logger.warning(f"User not authenticated - connection history will not be saved for {username}@{ip_address}")
            
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

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def check_installed_view(request):
    start_time = timezone.now()
    conn = None
    
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        connection_key = get_connection_key(username, ip_address, auth_method)
        
        if not username or not ip_address:
            return Response({
                'success': False,
                'message': 'Missing SSH connection details (username or IP address)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not auth_method or auth_method not in ['password', 'key']:
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
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH password'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            decrypted_key_content = decrypt_ssh_password(key_file_content)
            if not decrypted_key_content:
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH key file'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )
        
        conn = get_ssh_connection(connection_config)
        
        # Check version commands for each application
        check_version_commands = {
            'docker': "docker --version 2>/dev/null || echo 'Not installed'",
            'nginx': "nginx -v 2>&1 || echo 'Not installed'",
            'caddy': "caddy version 2>/dev/null || echo 'Not installed'",
            'apache2': "(apache2 -v 2>/dev/null || httpd -v 2>/dev/null) || echo 'Not installed'",
            'awsCli': "aws --version 2>/dev/null || echo 'Not installed'"
        }
        
        installed_status = {}
        
        for app, cmd in check_version_commands.items():
            try:
                result = execute_ssh_command(
                    conn, cmd, 
                    decrypted_password=decrypted_password, 
                    auth_method=auth_method,
                    return_code=True,
                    ignore_error=True
                )
                
                installed_status[app] = {
                    'installed': 'Not installed' not in result['output'] and result['code'] == 0,
                    'version': result['output'].strip() if result['output'].strip() else 'Error checking version'
                }
            except Exception as e:
                logger.error(f"Error checking {app}: {str(e)}")
                installed_status[app] = {
                    'installed': False,
                    'version': 'Error checking version'
                }
        
        logger.info(f"SSH check installed completed in {(timezone.now() - start_time).total_seconds()}s")
        
        return Response({
            'success': True,
            'installed': installed_status
        }, status=status.HTTP_200_OK)
    
    except paramiko.AuthenticationException:
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except paramiko.SSHException as e:
        return Response({
            'success': False,
            'message': f'SSH connection error: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.error(f"SSH check installed error after {(timezone.now() - start_time).total_seconds()}s: {e}")
        return Response({
            'success': False,
            'message': 'Failed to check installed applications',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def install_view(request):
    import os
    start_time = timezone.now()
    conn = None
    
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        applications = request.data.get('applications', [])
        connection_key = get_connection_key(username, ip_address, auth_method)
        
        if not username or not ip_address or not applications or not isinstance(applications, list) or len(applications) == 0:
            return Response({
                'success': False,
                'message': 'Missing required fields (username, IP address, or applications array)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        supported_apps = ['docker', 'nginx', 'caddy', 'apache2', 'awsCli']
        invalid_apps = [app for app in applications if app not in supported_apps]
        if invalid_apps:
            return Response({
                'success': False,
                'message': f'Unsupported application(s): {", ".join(invalid_apps)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not auth_method or auth_method not in ['password', 'key']:
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
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH password'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            decrypted_key_content = decrypt_ssh_password(key_file_content)
            if not decrypted_key_content:
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH key file'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )
        
        conn = get_ssh_connection(connection_config)
        
        # Get the scripts directory path
        scripts_dir = os.path.join(os.path.dirname(__file__), 'scripts')
        
        results = []
        
        for application in applications:
            try:
                script_path = os.path.join(scripts_dir, f'{application}.sh')
                
                if not os.path.exists(script_path):
                    results.append({
                        'application': application,
                        'success': False,
                        'message': f'Installation script for {application} not found or cannot be read'
                    })
                    continue
                
                # Read script content
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                # Upload and execute the script
                try:
                    output = upload_and_execute_script(
                        conn, script_content,
                        use_sudo=True,
                        decrypted_password=decrypted_password,
                        auth_method=auth_method
                    )
                    
                    results.append({
                        'application': application,
                        'success': True,
                        'message': f'{application} has been successfully installed'
                    })
                except Exception as install_error:
                    results.append({
                        'application': application,
                        'success': False,
                        'message': str(install_error) or f'Failed to install {application}'
                    })
                    
            except Exception as app_error:
                logger.error(f"Error installing {application}: {str(app_error)}")
                results.append({
                    'application': application,
                    'success': False,
                    'message': str(app_error) or f'Failed to install {application}'
                })
        
        overall_success = any(result['success'] for result in results)
        
        logger.info(f"SSH install apps completed in {(timezone.now() - start_time).total_seconds()}s")
        
        return Response({
            'success': overall_success,
            'results': results
        }, status=status.HTTP_200_OK if overall_success else status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    except paramiko.AuthenticationException:
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except paramiko.SSHException as e:
        return Response({
            'success': False,
            'message': f'SSH connection error: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.error(f"SSH install apps error after {(timezone.now() - start_time).total_seconds()}s: {e}")
        return Response({
            'success': False,
            'message': 'Failed to install applications',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def verify_connection_view(request):
    """
    Connection verification endpoint
    Replicates Node.js /api/verify-connection behavior
    """
    start_time = timezone.now()
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        verify_only = bool(request.data.get('verifyOnly'))

        # Simple cache when verify_only is true
        cache_key = f"verify_{username}@{ip_address}_{auth_method}"
        if verify_only:
            cached = cache.get(cache_key)
            if cached:
                return Response(cached, status=status.HTTP_200_OK)

        if not username or not ip_address:
            return Response({
                'success': False,
                'message': 'Missing SSH connection details (username or IP address)'
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
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH password'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            decrypted_key_content = decrypt_ssh_password(key_file_content)
            if not decrypted_key_content:
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH key file'
                }, status=status.HTTP_400_BAD_REQUEST)

        # For verification we create a fresh connection and close it right away
        connection_config = {
            'hostname': ip_address,
            'port': 22,
            'username': username,
            'timeout': 10,
            'auth_timeout': 10,
        }
        if auth_method == 'password':
            connection_config['password'] = decrypted_password
        else:
            # Parse private key using the same helper as create_ssh_config
            # but inline to avoid touching connection pool
            from io import StringIO
            key_obj = StringIO(decrypted_key_content)
            pkey = None
            key_classes = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
            for key_class in key_classes:
                try:
                    key_obj.seek(0)
                    pkey = key_class.from_private_key(key_obj)
                    break
                except paramiko.SSHException:
                    continue
                except Exception:
                    continue
            if pkey is None:
                return Response({
                    'success': False,
                    'message': 'Failed to parse private key. The format may be unsupported.'
                }, status=status.HTTP_400_BAD_REQUEST)
            connection_config['pkey'] = pkey

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(**connection_config)
        finally:
            try:
                client.close()
            except Exception:
                pass

        response_data = {
            'success': True,
            'message': 'SSH connection verified successfully'
        }

        if verify_only:
            cache.set(cache_key, response_data, 30)

        logger.info(f"SSH verify completed in {(timezone.now() - start_time).total_seconds()}s")
        return Response(response_data, status=status.HTTP_200_OK)

    except paramiko.AuthenticationException:
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({
            'success': False,
            'message': 'Failed to verify connection to server',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def save_connection_history_internal(user, ip_address, port, username, auth_method, encrypted_password=None, encrypted_key_content=None, key_file_name=None):
    """
    Internal function to save or update connection history
    Stores encrypted credentials and updates last_connected timestamp
    """
    try:
        # Check if connection history already exists for this user, IP, and username
        existing_history = ServerConnectionHistory.objects.filter(
            user=user,
            server_ip=ip_address,
            server_username=username
        ).first()
        
        if existing_history:
            # Update existing record
            existing_history.last_connected = timezone.now()
            existing_history.server_port = port
            existing_history.server_key_type = auth_method
            
            if auth_method == 'password' and encrypted_password:
                existing_history.server_password = encrypted_password
                existing_history.server_key = None
                existing_history.server_key_name = None
                existing_history.server_key_content = None
            elif auth_method == 'key' and encrypted_key_content:
                existing_history.server_key = encrypted_key_content
                existing_history.server_key_content = encrypted_key_content
                existing_history.server_key_name = key_file_name or ''
                existing_history.server_password = None
            
            existing_history.save()
            logger.info(f"Updated connection history for user {user.username} - {username}@{ip_address}")
        else:
            # Create new record
            history_data = {
                'user': user,
                'server_ip': ip_address,
                'server_port': port,
                'server_username': username,
                'server_key_type': auth_method,
                'last_connected': timezone.now(),
            }
            
            if auth_method == 'password' and encrypted_password:
                history_data['server_password'] = encrypted_password
            elif auth_method == 'key' and encrypted_key_content:
                history_data['server_key'] = encrypted_key_content
                history_data['server_key_content'] = encrypted_key_content
                history_data['server_key_name'] = key_file_name or ''
            
            ServerConnectionHistory.objects.create(**history_data)
            logger.info(f"Created new connection history for user {user.username} - {username}@{ip_address}")
        
        return True
    except Exception as e:
        logger.error(f"Error saving connection history: {str(e)}")
        raise e


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def connect_from_history_view(request, history_id):
    """
    Connect to server using stored connection history credentials
    Updates last_connected timestamp on successful connection
    """
    try:
        if not request.user.is_authenticated:
            logger.warning("Unauthenticated user attempted to connect from history")
            return Response({
                'success': False,
                'message': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            connection_history = ServerConnectionHistory.objects.get(
                id=history_id,
                user=request.user
            )
        except ServerConnectionHistory.DoesNotExist:
            logger.warning(f"Connection history {history_id} not found for user {request.user.username}")
            return Response({
                'success': False,
                'message': 'Connection history not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check if connection is expired
        if connection_history.is_expired():
            logger.info(f"Connection history {history_id} is expired, deleting it")
            connection_history.delete()
            return Response({
                'success': False,
                'message': 'Connection history has expired (older than 7 days)'
            }, status=status.HTTP_410_GONE)
        
        # Decrypt stored credentials
        decrypted_password = None
        decrypted_key_content = None
        
        if connection_history.server_key_type == 'password' and connection_history.server_password:
            decrypted_password = decrypt_ssh_password(connection_history.server_password)
            if not decrypted_password:
                logger.error(f"Failed to decrypt password for connection history {history_id}")
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt stored credentials'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        elif connection_history.server_key_type == 'key' and connection_history.server_key_content:
            decrypted_key_content = decrypt_ssh_password(connection_history.server_key_content)
            if not decrypted_key_content:
                logger.error(f"Failed to decrypt key for connection history {history_id}")
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt stored credentials'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.error(f"No valid credentials found for connection history {history_id}")
            return Response({
                'success': False,
                'message': 'No valid credentials found in connection history'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create connection config
        connection_config = create_ssh_config(
            connection_history.server_username,
            str(connection_history.server_ip),
            connection_history.server_key_type or 'password',
            decrypted_password,
            decrypted_key_content,
            connection_history.server_key_name
        )
        
        # Attempt connection
        start_time = timezone.now()
        conn = None
        try:
            conn = get_ssh_connection(connection_config)
            
            # Get OS type
            os_type_command = "cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d'=' -f2 | tr -d '\"'"
            stdin, stdout, stderr = conn.exec_command(os_type_command)
            os_type = stdout.read().decode().strip()
            
            # Update last_connected timestamp
            connection_history.last_connected = timezone.now()
            connection_history.save()
            
            logger.info(f"Connected from history {history_id} in {(timezone.now() - start_time).total_seconds()}s for user {request.user.username}")
            
            return Response({
                'success': True,
                'osType': os_type,
                'message': 'Connected successfully using stored credentials'
            }, status=status.HTTP_200_OK)
        
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for connection history {history_id}")
            return Response({
                'success': False,
                'message': 'Authentication failed. Stored credentials may be invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for history {history_id}: {str(e)}")
            return Response({
                'success': False,
                'message': f'SSH connection error: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Connection error for history {history_id}: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to connect to server',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    except Exception as e:
        logger.error(f"Error connecting from history: {str(e)}")
        return Response({
            'success': False,
            'message': 'Failed to connect from history',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_connection_history_view(request):
    """
    Get connection history for authenticated user
    Returns list of connections with last_connected time
    """
    try:
        if not request.user.is_authenticated:
            logger.warning("Unauthenticated user attempted to access connection history")
            return Response({
                'success': False,
                'message': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Clean up expired connections first
        cleanup_expired_connections(request.user)
        
        # Get all non-expired connections for the user
        connections = ServerConnectionHistory.objects.filter(
            user=request.user
        ).order_by('-last_connected')
        
        # Filter out expired connections
        from datetime import timedelta
        seven_days_ago = timezone.now() - timedelta(days=7)
        connections = connections.filter(last_connected__gte=seven_days_ago)
        
        history_list = []
        for conn in connections:
            history_list.append({
                'id': conn.id,
                'server_ip': str(conn.server_ip),
                'server_port': conn.server_port,
                'server_username': conn.server_username,
                'auth_method': conn.server_key_type or 'password',
                'last_connected': conn.last_connected.isoformat(),
                'created_at': conn.created_at.isoformat(),
            })
        
        logger.info(f"Retrieved {len(history_list)} connection history records for user {request.user.username}")
        
        return Response({
            'success': True,
            'count': len(history_list),
            'connections': history_list
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving connection history: {str(e)}")
        return Response({
            'success': False,
            'message': 'Failed to retrieve connection history',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_connection_history_view(request, history_id):
    """
    Delete a specific connection history by ID
    Also deletes associated SSH key file if it exists
    """
    try:
        if not request.user.is_authenticated:
            logger.warning("Unauthenticated user attempted to delete connection history")
            return Response({
                'success': False,
                'message': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            connection_history = ServerConnectionHistory.objects.get(
                id=history_id,
                user=request.user
            )
        except ServerConnectionHistory.DoesNotExist:
            logger.warning(f"Connection history {history_id} not found for user {request.user.username}")
            return Response({
                'success': False,
                'message': 'Connection history not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Store info for logging before deletion
        server_info = f"{connection_history.server_username}@{connection_history.server_ip}"
        
        # Delete associated key file if it exists
        if connection_history.server_key_path:
            try:
                import os
                if os.path.exists(connection_history.server_key_path):
                    os.remove(connection_history.server_key_path)
                    logger.info(f"Deleted SSH key file: {connection_history.server_key_path}")
            except Exception as key_error:
                logger.warning(f"Failed to delete key file {connection_history.server_key_path}: {str(key_error)}")
        
        # Delete the history record
        connection_history.delete()
        
        logger.info(f"Deleted connection history {history_id} ({server_info}) for user {request.user.username}")
        
        return Response({
            'success': True,
            'message': 'Connection history deleted successfully'
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error deleting connection history: {str(e)}")
        return Response({
            'success': False,
            'message': 'Failed to delete connection history',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def execute_command_view(request):
    """
    Command execution endpoint
    """
    start_time = timezone.now()
    conn = None
    connection_key = None
    
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        command = request.data.get('command')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        use_sudo = request.data.get('useSudo', False)
        connection_key = get_connection_key(username, ip_address, auth_method)
        
        if not username or not ip_address or not command:
            return Response({
                'success': False,
                'message': 'Missing required fields (username, IP address, or command)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not auth_method or auth_method not in ['password', 'key']:
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
        
        try:
            if auth_method == 'password':
                decrypted_password = decrypt_ssh_password(password)
                if not decrypted_password:
                    raise Exception('Failed to decrypt SSH password')
            else:
                decrypted_key_content = decrypt_ssh_password(key_file_content)
                if not decrypted_key_content:
                    raise Exception('Failed to decrypt SSH key file')
        except Exception as decrypt_error:
            return Response({
                'success': False,
                'message': str(decrypt_error)
            }, status=status.HTTP_400_BAD_REQUEST)
        
        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )
        
        conn = get_ssh_connection(connection_config)
        
        output = execute_ssh_command(
            conn, command,
            use_sudo=use_sudo,
            decrypted_password=decrypted_password,
            auth_method=auth_method
        )
        
        # Update connection pool last_used time
        if connection_key in ssh_connection_pool:
            ssh_connection_pool[connection_key]['last_used'] = time.time()
        
        logger.info(f"SSH execute command completed in {(timezone.now() - start_time).total_seconds()}s")
        
        return Response({
            'success': True,
            'output': output
        }, status=status.HTTP_200_OK)
    
    except paramiko.AuthenticationException:
        # Clean up connection on authentication failure
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except paramiko.SSHException as e:
        # Clean up connection on SSH error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        if 'ETIMEDOUT' in str(e) or 'ECONNREFUSED' in str(e):
            return Response({
                'success': False,
                'message': 'Connection timed out. Please verify the server address and try again.'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        return Response({
            'success': False,
            'message': f'SSH connection error: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.error(f"SSH execute command error after {(timezone.now() - start_time).total_seconds()}s: {e}")
        
        # Clean up connection on error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        error_message = str(e)
        if 'sudo' in error_message.lower():
            return Response({
                'success': False,
                'message': 'Sudo access denied. Ensure you have the necessary privileges.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        return Response({
            'success': False,
            'message': error_message or 'Failed to execute command',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def execute_script_view(request):
    """
    Script execution endpoint
    """
    start_time = timezone.now()
    conn = None
    connection_key = None
    
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        script_content = request.data.get('scriptContent')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        use_sudo = request.data.get('useSudo', False)
        connection_key = get_connection_key(username, ip_address, auth_method)
        
        if not username or not ip_address or not script_content:
            return Response({
                'success': False,
                'message': 'Missing required fields (username, IP address, or script content)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not auth_method or auth_method not in ['password', 'key']:
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
        
        try:
            if auth_method == 'password':
                decrypted_password = decrypt_ssh_password(password)
                if not decrypted_password:
                    raise Exception('Failed to decrypt SSH password')
            else:
                decrypted_key_content = decrypt_ssh_password(key_file_content)
                if not decrypted_key_content:
                    raise Exception('Failed to decrypt SSH key file')
        except Exception as decrypt_error:
            return Response({
                'success': False,
                'message': str(decrypt_error)
            }, status=status.HTTP_400_BAD_REQUEST)
        
        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )
        
        conn = get_ssh_connection(connection_config)
        
        output = upload_and_execute_script(
            conn, script_content,
            use_sudo=use_sudo,
            decrypted_password=decrypted_password,
            auth_method=auth_method
        )
        
        # Update connection pool last_used time
        if connection_key in ssh_connection_pool:
            ssh_connection_pool[connection_key]['last_used'] = time.time()
        
        logger.info(f"SSH execute script completed in {(timezone.now() - start_time).total_seconds()}s")
        
        return Response({
            'success': True,
            'output': output
        }, status=status.HTTP_200_OK)
    
    except paramiko.AuthenticationException:
        # Clean up connection on authentication failure
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except paramiko.SSHException as e:
        # Clean up connection on SSH error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        if 'ETIMEDOUT' in str(e) or 'ECONNREFUSED' in str(e):
            return Response({
                'success': False,
                'message': 'Connection timed out. Please verify the server address and try again.'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        return Response({
            'success': False,
            'message': f'SSH connection error: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.error(f"SSH execute script error after {(timezone.now() - start_time).total_seconds()}s: {e}")
        
        # Clean up connection on error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        error_message = str(e)
        if 'sudo' in error_message.lower():
            return Response({
                'success': False,
                'message': 'Sudo access denied. Ensure you have the necessary privileges.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        return Response({
            'success': False,
            'message': error_message or 'Failed to execute script',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([CsrfExemptSessionAuthentication])
def monitor_view(request):
    """
    SSH monitoring endpoint
    """
    start_time = timezone.now()
    conn = None
    connection_key = None
    
    try:
        username = request.data.get('username')
        ip_address = request.data.get('ipAddress')
        auth_method = request.data.get('authMethod')
        password = request.data.get('password')
        key_file_content = request.data.get('keyFileContent')
        key_file_name = request.data.get('keyFileName')
        connection_key = get_connection_key(username, ip_address, auth_method)
        
        if not username or not ip_address:
            return Response({
                'success': False,
                'message': 'Missing SSH connection details (username or IP address)'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not auth_method or auth_method not in ['password', 'key']:
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
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH password'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            decrypted_key_content = decrypt_ssh_password(key_file_content)
            if not decrypted_key_content:
                return Response({
                    'success': False,
                    'message': 'Failed to decrypt SSH key file'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        connection_config = create_ssh_config(
            username, ip_address, auth_method, decrypted_password, decrypted_key_content, key_file_name
        )
        
        conn = get_ssh_connection(connection_config)
        
        # Define monitoring commands
        cpu_info_command = "cat /proc/cpuinfo | grep 'model name' | head -1 && top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'"
        memory_info_command = "free -h | grep 'Mem:' | awk '{print $2, $3}'"
        processes_command = "ps aux | awk '{print $2, $1, $3, $4, $11}'"
        load_command = "uptime | awk -F'load average:' '{print $2}'"
        
        # Execute commands in parallel using ThreadPoolExecutor
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def execute_command(cmd):
            try:
                return execute_ssh_command(
                    conn, cmd,
                    decrypted_password=decrypted_password,
                    auth_method=auth_method,
                    ignore_error=True
                )
            except Exception as e:
                logger.error(f"Error executing command '{cmd}': {str(e)}")
                return ""
        
        # Execute all commands in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_command = {
                executor.submit(execute_command, cpu_info_command): 'cpu',
                executor.submit(execute_command, memory_info_command): 'memory',
                executor.submit(execute_command, processes_command): 'processes',
                executor.submit(execute_command, load_command): 'load'
            }
            
            results = {}
            for future in as_completed(future_to_command):
                command_type = future_to_command[future]
                try:
                    results[command_type] = future.result()
                except Exception as e:
                    logger.error(f"Error getting result for {command_type}: {str(e)}")
                    results[command_type] = ""
        
        # Parse CPU info
        cpu_info = results.get('cpu', '').strip()
        cpu_lines = [line.strip() for line in cpu_info.split('\n') if line.strip()]
        
        # Extract CPU model (first line that contains 'model name' or first line)
        cpu_model = ''
        for line in cpu_lines:
            if 'model name' in line.lower():
                cpu_model = line.replace('model name\t: ', '').replace('model name : ', '').strip()
                break
        
        # If no model found, use first line
        if not cpu_model and cpu_lines:
            cpu_model = cpu_lines[0]
        
        # Extract CPU usage (last numeric line, or line that looks like a percentage)
        cpu_usage = 0.0
        for line in reversed(cpu_lines):
            # Try to parse as float
            try:
                # Remove any % signs or other characters
                cleaned = line.replace('%', '').strip()
                cpu_usage = float(cleaned)
                break
            except (ValueError, TypeError):
                continue
        
        # Parse memory info
        memory_info = results.get('memory', '').strip()
        memory_parts = memory_info.split()
        total_memory = memory_parts[0] if len(memory_parts) > 0 else '0'
        used_memory = memory_parts[1] if len(memory_parts) > 1 else '0'
        
        # Parse processes
        processes_output = results.get('processes', '').strip()
        processes = []
        process_lines = processes_output.split('\n')
        for line in process_lines[1:]:  # Skip header line
            parts = line.split(None, 4)  # Split into max 5 parts
            if len(parts) >= 5:
                processes.append({
                    'pid': parts[0],
                    'user': parts[1],
                    'cpu': parts[2],
                    'memory': parts[3],
                    'command': parts[4]
                })
        
        # Parse system load
        system_load = results.get('load', '').strip()
        load_parts = [part.strip() for part in system_load.split(',')]
        load_1m = load_parts[0] if len(load_parts) > 0 else '0.00'
        load_5m = load_parts[1] if len(load_parts) > 1 else '0.00'
        load_15m = load_parts[2] if len(load_parts) > 2 else '0.00'
        
        # Update connection pool last_used time
        if connection_key in ssh_connection_pool:
            ssh_connection_pool[connection_key]['last_used'] = time.time()
        
        logger.info(f"SSH monitoring completed in {(timezone.now() - start_time).total_seconds()}s")
        
        return Response({
            'success': True,
            'cpuInfo': {
                'model': cpu_model,
                'usage': f"{cpu_usage:.2f}"
            },
            'memoryInfo': {
                'total': total_memory,
                'used': used_memory
            },
            'processes': processes,
            'systemLoad': {
                '1m': load_1m,
                '5m': load_5m,
                '15m': load_15m
            }
        }, status=status.HTTP_200_OK)
    
    except paramiko.AuthenticationException:
        # Clean up connection on authentication failure
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        return Response({
            'success': False,
            'message': 'Authentication failed. Please check your credentials.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except paramiko.SSHException as e:
        # Clean up connection on SSH error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        error_str = str(e)
        if 'ETIMEDOUT' in error_str or 'ECONNREFUSED' in error_str:
            return Response({
                'success': False,
                'message': 'Connection timed out. Please verify the server address and try again.'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        return Response({
            'success': False,
            'message': 'Failed to retrieve monitoring data',
            'error': error_str
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.error(f"SSH monitoring error after {(timezone.now() - start_time).total_seconds()}s: {e}")
        
        # Clean up connection on error
        if connection_key and connection_key in ssh_connection_pool:
            try:
                ssh_connection_pool[connection_key]['client'].close()
            except:
                pass
            del ssh_connection_pool[connection_key]
        
        return Response({
            'success': False,
            'message': 'Failed to retrieve monitoring data',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def cleanup_expired_connections(user=None):
    """
    Clean up connection history older than 7 days
    Can be called for a specific user or all users
    """
    try:
        from datetime import timedelta
        seven_days_ago = timezone.now() - timedelta(days=7)
        
        if user:
            expired_connections = ServerConnectionHistory.objects.filter(
                user=user,
                last_connected__lt=seven_days_ago
            )
        else:
            expired_connections = ServerConnectionHistory.objects.filter(
                last_connected__lt=seven_days_ago
            )
        
        deleted_count = 0
        for conn in expired_connections:
            # Delete associated key file if it exists
            if conn.server_key_path:
                try:
                    import os
                    if os.path.exists(conn.server_key_path):
                        os.remove(conn.server_key_path)
                        logger.info(f"Deleted expired SSH key file: {conn.server_key_path}")
                except Exception as key_error:
                    logger.warning(f"Failed to delete key file {conn.server_key_path}: {str(key_error)}")
            
            conn.delete()
            deleted_count += 1
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} expired connection history records")
        
        return deleted_count
    
    except Exception as e:
        logger.error(f"Error cleaning up expired connections: {str(e)}")
        return 0