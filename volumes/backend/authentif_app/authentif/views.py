import os, json, requests, logging
from django.http import JsonResponse
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import activate, gettext as _
from .forms import SignUpForm, LogInForm, EditProfileForm
from .models import User
from .authmiddleware import login_required, JWTAuthenticationMiddleware, generate_jwt_token
import pyotp, qrcode, base64
from io import BytesIO
from django.core.cache import cache
import prettyprinter
prettyprinter.set_default_config(depth=None, width=80, ribbon_width=80)

logger = logging.getLogger(__name__)


def api_get_user_info(request, user_id):
    logger.debug("api_get_user_info")
    try:
        users = User.objects.all()
        users_id = [user.id for user in users]
        user = User.objects.get(id=user_id)
        if user:
            username = user.username
            avatar_url = user.avatar.url if user.avatar else None
            return JsonResponse({
                  'status': 'success',
                  'message': 'User found',
                  'username': username,
                  'usernames': [user.username for user in users],
                  'users_id': users_id,
                  'avatar_url': avatar_url
                })
        else:
            return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
        
@login_required
def api_logout(request):
    """Logs out the user by blacklisting their JWT token and sending a guest token."""
    token = request.COOKIES.get('jwt_token')
    refresh_token = request.COOKIES.get('refresh_jwt_token')

    if token:
        # Blacklist the current JWT token
        JWTAuthenticationMiddleware.blacklist_token(token)
        JWTAuthenticationMiddleware.blacklist_token(refresh_token)

        # Generate a new guest token
        guest_token = ""

        # Create a response indicating logout success
        response = JsonResponse({
              'status': 'success',
              'type': 'logout_successful',
              'message': _('Logged out successfully')
            })

        # Set the new guest JWT token as a cookie in the response
        response.set_cookie('jwt_token', guest_token, httponly=True, secure=True, samesite='Lax')
        response.set_cookie('refresh_jwt_token', guest_token, httponly=True, secure=True, samesite='Lax')

        return response
    else:
        return JsonResponse({'error': _('No active session found')}, status=400)
    
def api_login(request):
    logger.debug("api_login")
    # logger.debug(f"api_login > request.headers: {pformat(request.headers)}")
    language = request.headers.get('X-Language', 'en')
    activate(language)
    try:
        if request.method == 'POST':
            try:
                data = json.loads(request.body)
                form = LogInForm(request, data=data)
                try:
                    if form.is_valid():
                        user = form.get_user()
                        try:
                            login(request, user)
                        except Exception as e:
                            logger.error(f'api_login > Failed to log in user: {e}')
                            return JsonResponse({'status': 'error', 'message': _('Wrong credentials')}, status=401)
                        
                        logger.debug(f"api_login > User.id: {user.id}")

                        if user.two_factor_token:
                            auth_header = request.META.get('HTTP_AUTHORIZATION')

                            if auth_header and auth_header.startswith('Bearer '):
                                token = auth_header.split(' ')[1]  # Get the token part after 'Bearer '
                                
                                # Set the token in the cache
                                cache_key = f"2fa_user_{user.id}"
                                cache.set(cache_key, token, timeout=60*5)  # Cache for 5 minutes
                            return JsonResponse({'status': 'success', 'message': _('2FA required'), 'user_id': user.id, 'type': '2FA'}, status=200)

                        # Generate a JWT token for the authenticated user
                        jwt_token, refresh_jwt_token = generate_jwt_token(user)
                        logger.debug(f"token >>>>>>>>>>>: {jwt_token}")

                        # Create response object
                        response = JsonResponse({
                            'status': 'success',
                            'type': 'login_successful',
                            'message': _('Login successful'),
                            'token': jwt_token,
                            'user_id': user.id
                        })

                        # Set the JWT token in the headers and a secure cookie
                        response['Authorization'] = f'Bearer {jwt_token}'
                        response.set_cookie(
                            key='jwt_token',
                            value=jwt_token,
                            httponly=True,
                            secure=True,
                            samesite='Lax',
                            max_age=60 * 60 * 24 * 7,
                        )
                        response.set_cookie(
                            key='refresh_jwt_token',
                            value=refresh_jwt_token,
                            httponly=True,
                            secure=True,
                            samesite='Lax',
                            max_age=60 * 60 * 24 * 7,
                        )
                        
                        return response

                    else:
                        logger.debug('api_login > Invalid username or password')
                        return JsonResponse({'status': 'error', 'message': _('Invalid username or password')}, status=401)
                except:
                    logger.debug(f'Password validation error: {e.messages}')
                    return JsonResponse({'status': 'error', 'message': _('Wrong credentials')}, status=401)
            except json.JSONDecodeError:
                logger.debug('api_login > Invalid JSON')
                return JsonResponse({'status': 'error', 'message': _('Invalid JSON')}, status=400)
    except:
        logger.debug('api_login > Wrong or invalid password')
        return JsonResponse({'status': 'error', 'message': _('Wrong or invalid password')}, status=400)
    logger.debug('api_login > Method not allowed')
    return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)

# Create a profile linked to user through call to profileapi service
def createProfile(username, user_id, csrf_token, id_42, lang):
    profileapi_url = 'https://profileapi:9002/api/signup/'
    if id_42:
        profile_data = { 'user_id': user_id, 'username': username, 'id_42': id_42 }
    else:
        profile_data = { 'user_id': user_id, 'username': username }
    
    headers = {
        'X-CSRFToken': csrf_token,
        'X-Language': lang,
        'Cookie': f'csrftoken={csrf_token}',
        'Content-Type': 'application/json',
        'HTTP_HOST': 'profileapi',
        'Referer': 'https://authentif:9001',
    }

    cookies = {
    'csrftoken': f'{csrf_token}',
    }

    try:
        response = requests.post(profileapi_url, json=profile_data, headers=headers, cookies=cookies, verify=os.getenv("CERTFILE"))
        logger.debug(f'api_signup > createProfile > Response: {response}')
        logger.debug(f'api_signup > createProfile > Response status code: {response.status_code}')
        
        response.raise_for_status()
        if response.status_code == 201:
            logger.debug('api_signup > createProfile > Profile created in profile service')
            return True
        else:
            logger.error(f'api_signup > createProfile > Unexpected status code: {response.status_code}')
            return False
    except requests.RequestException as e:
        logger.error(f'api_signup > createProfile > Failed to create profile: {e}')
        return False


def api_signup(request):
    logger.debug("api_signup")
    language = request.headers.get('X-Language', 'en')
    activate(language)
    if request.method == 'POST':
        try:
          data = json.loads(request.body)
          # logger.debug(f'Received data: {data}')
          form = SignUpForm(data=data)
          if form.is_valid():
                user = form.save(commit=False)

                # Password validation
                password = data.get('password') # clear text password
                
                # Ensure the password meets the minimum requirements
                try:
                  validate_password(password)
                except DjangoValidationError as e:
                  return JsonResponse({'status': 'error', 'message': _('Not a valid password')}, status=400)
                
                user.password = make_password(data['password']) # hashed password
                user = form.save()
                username = data.get('username')
                logger.info(f'api_signup > User.username: {user.username}, hased pwd {user.password}')

                user_obj = User.objects.get(username=username)

                # Check if the user is active
                if not user_obj.is_active:
                    logger.debug('api_signup > User is inactive')
                    user.delete()
                    return JsonResponse({
                        'status': 'error', 
                        'message': _('User is inactive')
                    }, status=400)
                
                csrf_token = request.COOKIES.get('csrftoken')
                # Create a profile through call to profileapi service
                if not createProfile(username, user.id, csrf_token, False, language):
                        user.delete()
                        return JsonResponse({
                            'status': 'error', 
                            'message': _('Failed to create profile')
                        }, status=500)

                jwt_token, refresh_jwt_token = generate_jwt_token(user)
        
                # Create response object
                response = JsonResponse({
                    'status': 'success',
                    'type': 'login_successful',
                    'message': _('Login successful'),
                    'token': jwt_token,
                    'user_id': user.id
                })

                # Set the JWT token in the headers and a secure cookie
                response['Authorization'] = f'Bearer {jwt_token}'
                response.set_cookie(
                    key='jwt_token',
                    value=jwt_token,
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age=60 * 60 * 24 * 7,
                )
                response.set_cookie(
                    key='refresh_jwt_token',
                    value=refresh_jwt_token,
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age=60 * 60 * 24 * 7,
                )       
                return response
              
          else:
              logger.debug('api_signup > Invalid form')
              errors = json.loads(form.errors.as_json())
              logger.debug(f'Errors: {errors}')
              # message = errors.get('username')[0].get('message')
              message = None
              if errors:
                message = next((error['message'] for field_errors in errors.values() for error in field_errors), None)
              logger.debug(f'message: {message}')
              return JsonResponse({'status': 'error', 'message': message}, status=400)
        except json.JSONDecodeError:
            logger.debug('api_signup > Invalid JSON')
            return JsonResponse({'status': 'error', 'message': _('Invalid JSON')}, status=400)
        except DjangoValidationError as e:
                  logger.debug(f'Password validation error: {e.messages}')
                  return JsonResponse({'status': 'error', 'message': _('Not a valid password')}, status=400)
        except Exception as e:
            logger.error(f'api_signup > Unexpected error: {e}')
            return JsonResponse({'status': 'error','message': _('An unexpected error occurred')}, status=500)
    logger.debug('api_signup > Method not allowed')
    return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)

def api_check_username_exists(request):
    logger.debug("api_check_exists")
    language = request.headers.get('X-Language', 'en')
    activate(language)
    if request.method == 'POST':
        try:
          data = json.loads(request.body)
          username = data.get('username')
          if User.objects.filter(username=username).exists():
              logger.debug('api_check_exists > User exists')
              return JsonResponse({'status': 'success', 'message': _('User exists')})
          else:
              logger.debug('api_check_exists > User does not exist')
              return JsonResponse({'status': 'failure', 'message': _('User does not exist')}, status=404)
        except json.JSONDecodeError:
            logger.debug('api_check_exists > Invalid JSON')
            return JsonResponse({'status': 'error', 'message': _('Invalid JSON')}, status=400)
    logger.debug('api_check_exists > Method not allowed')
    return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)


def api_edit_profile(request):
  logger.debug("api_edit_profile")
  language = request.headers.get('X-Language', 'en')
  activate(language)
  if request.method == 'POST':
    try:
      data = json.loads(request.body)
      logger.debug(f'data: {data}')

      # Check the user id changed is the same as the user id in the token

      user_id = data.get('user_id')
      user_obj = User.objects.get(id=user_id)
      #user_obj = User.objects.filter(id=user_id).first()
      logger.debug(f'user_obj username: {user_obj.username}, user_obj id: {user_obj.id}')

      # Password validation
      if not request.user.id_42 and data.get('avatar') is None:
        new_password = data.get('new_password')
        try:
          validate_password(new_password)
        except DjangoValidationError as e:
          return JsonResponse({'status': 'error', 'message': _('Not a valid password')}, status=400)
      
      if request.user.id_42 and request.headers.get('sudo') != "add" :
        return JsonResponse({'status': 'error', 'message': _('Unauthorized')}, status=401)
    
      form = EditProfileForm(data, instance=user_obj)
      # logger.debug(f'form: {form}')
      
      if form.is_valid():
        logger.debug('api_edit_profile > Form is valid')
        form.save()
        return JsonResponse({
              'status': 'success',
              'type': 'profile_updated',
              'message': _('Profile updated'),
              'status': 200
            })
      else:
        errors = json.loads(form.errors.as_json())
        if errors:
          message = next((error['message'] for field_errors in errors.values() for error in field_errors), None)
        else:
          message = _('Invalid profile update')
        return JsonResponse({'status': 'error', 'message':message}, status=400)
    except json.JSONDecodeError:
      logger.debug('api_edit_profile > Invalid JSON')
      return JsonResponse({'status': 'error', 'message': _('Invalid JSON')}, status=400)    
    except User.DoesNotExist:
      logger.debug('api_edit_profile > User not found')
      return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except DjangoValidationError as e:
          return JsonResponse({'status': 'error', 'message': _('Not a valid password')}, status=400)
  else:
    logger.debug('api_edit_profile > Method not allowed')
    return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)


@login_required
def enable2FA(request):
    language = request.headers.get('X-Language', 'en')
    activate(language)
    logger.debug("enable2FA")
    logger.debug(f"request.method: {request.method}")

    if request.method != 'POST':
        return JsonResponse({"status": 'error', 'message': _('Invalid request method. Use POST.')}, status=405)
    
    if request.user.id_42:
        return JsonResponse({"status": 'error', 'message': _('Unauthorized')}, status=401)
    
    if request.user.id is None or request.user.id == 0:
        return JsonResponse({"status": 'error', 'message': _('Unauthorized'), 'qr_code': "", 'two_fa_enabled': False}, status=401)
    
    user = User.objects.get(pk=request.user.id)

    if user.two_factor_token:
        # 2FA is already enabled for the user
        return JsonResponse({'status': 'error', 'message': _('2FA is already enabled'), 'qr_code': "", 'two_fa_enabled': True}, status=200)

    # Generate a new TOTP secret and QR code
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret

    # Store the secret temporarily in the cache with a short expiration time
    cache_key = f"2fa_setup_{user.id}"
    cache.set(cache_key, secret, timeout=300)  # Cache for 5 minutes

    # Generate QR code for authenticator app
    qr = qrcode.make(totp.provisioning_uri(name=str(user.username), issuer_name="Pongscendence"))
    qr_io = BytesIO()
    qr.save(qr_io, format="PNG")
    qr_io.seek(0)

    # Encode QR code in base64
    qr_code_base64 = base64.b64encode(qr_io.getvalue()).decode('utf-8')
    qr_code_url = f"data:image/png;base64,{qr_code_base64}"
    
    return JsonResponse({
        'status': 'success',
        'message': _('Scan the QR code, then enter the OTP below to confirm'),
        'qr_code': qr_code_url,
        'two_fa_enabled': False
    }, status=200)

@login_required
def confirmEnable2FA(request):
    language = request.headers.get('X-Language', 'en')
    activate(language)
    # Check if the request is a POST request
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": _("Invalid request method. Use POST.")}, status=405)

    if request.user.id_42:
        return JsonResponse({"status": "error", "message": _("Unauthorized")}, status=401)


    if request.user.id is None or request.user.id == 0:
        return JsonResponse({"status": "error", "message": _("Unauthorized")}, status=401)

    # Get OTP code from request body
    try:
        body = json.loads(request.body)
        otp_code = body.get("otp_code")
        if not otp_code:
            return JsonResponse({"status": "error", "message": _("OTP code is required")}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": _("Invalid JSON format")}, status=400)

    # Retrieve temporary TOTP secret from cache
    cache_key = f"2fa_setup_{request.user.id}"
    temp_secret = cache.get(cache_key)
    if not temp_secret:
        return JsonResponse({"status": "error", "message": _("No 2FA setup in progress or setup expired")}, status=400)

    # Verify OTP using the TOTP secret
    totp = pyotp.TOTP(temp_secret)
    if totp.verify(otp_code):
        # OTP is correct, enable 2FA by saving the token to the user's profile
        user = request.user
        user.two_factor_token = temp_secret
        user.save()

        # Remove the temporary token from cache
        cache.delete(cache_key)

        return JsonResponse({
            "status": "success",
            "message": _("2FA is now enabled"),
            "two_fa_enabled": True
        }, status=200)
    else:
        return JsonResponse({"status": "error", "message": _("Invalid OTP code")}, status=400)

@login_required
def disable2FA(request):
    language = request.headers.get('X-Language', 'en')
    activate(language)
    if request.method == 'POST':
        if request.user.id_42:
            return JsonResponse({"status": "error", "message": _("Unauthorized")}, status=401)

        user = User.objects.get(pk=request.user.id)
        if user.two_factor_token:
            user.two_factor_token = None
            user.save()
            return JsonResponse({"status": "success", "message": _("2FA disabled successfully")})
        else:
            return JsonResponse({"status": "error", "message": _("2FA is not enabled")}, status=400)
    return JsonResponse({"status": "error", "message": _("Invalid request")}, status=400)


def verify2FA(request, user_id):
    language = request.headers.get('X-Language', 'en')
    activate(language)
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": _("Invalid request method. Use POST.")}, status=405)

    # Ensure user_id is provided
    if not user_id:
        return JsonResponse({"status": "error", "message": _("User ID is required")}, status=400)

    # Attempt to retrieve the user and check if they have 2FA enabled
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return JsonResponse({"status": "error", "message": _("User not found")}, status=404)

    if not user.two_factor_token:
        return JsonResponse({"status": "error", "message": _("2FA is not enabled for this user")}, status=400)

    # Retrieve and verify the OTP code
    payload = json.loads(request.body)  # Decode the JSON request body
    otp_code = payload.get('otp_code')  # Extract the otp_code

    if not otp_code:
        return JsonResponse({"status": "error", "message": _("OTP code is required")}, status=400)

    # Use pyotp to verify the provided OTP code
    totp = pyotp.TOTP(user.two_factor_token)
    if totp.verify(otp_code):
        new_token, refresh_jwt_token = generate_jwt_token(user)

        # Respond with success and set the new JWT as a secure cookie
        response = JsonResponse({"status": "success", 'type': 'login_successful', "message": _("Login successful"), "token": new_token})
        response.set_cookie('jwt_token', new_token, httponly=True, secure=True, samesite='Lax')
        response.set_cookie('refresh_jwt_token', refresh_jwt_token, httponly=True, secure=True, samesite='Lax')

        return response
    else:
        return JsonResponse({"status": "error", "message": _("Invalid OTP code")}, status=400)