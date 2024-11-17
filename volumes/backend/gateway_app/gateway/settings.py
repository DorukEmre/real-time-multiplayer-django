"""
Django settings for transcendence project.

Generated by 'django-admin startproject' using Django 4.2.16.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
import logging

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

APPEND_SLASH = True

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Redirects to his address when using @login_required
LOGIN_URL = '/login/'

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

TIME_ZONE = 'UTC'
USE_TZ = True
USE_I18N = True
USE_L10N = True
# Path to the translation files
LOCALE_PATHS = [
    BASE_DIR /'translations/',
]

# Define the languages that the application will support
LANGUAGES = [
    ('en', 'English'),
    ('es', 'Spanish'),
    ('fr', 'French'),
]


# Application definition

INSTALLED_APPS = [
    
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'authentif',
    'channels',
    'uvicorn',
]

AUTH_USER_MODEL = 'authentif.User'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'gateway.authmiddleware.JWTAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'gateway.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'gateway', 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],     
            'libraries':{
                'custom_filters': 'gateway.templatetags.custom_filters',
                }
        },     
    },
]

WSGI_APPLICATION = 'gateway.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB"),
        "USER": os.getenv("POSTGRES_USER"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD"),
        "HOST": "postgres", # Name of the docker-compose service
        "PORT": 5432,
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Logging

class IgnoreMtimeFilter(logging.Filter):
    def filter(self, record):
        return 'first seen with mtime' not in record.getMessage()

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'ignore_mtime': {
            '()': IgnoreMtimeFilter,
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'filters': ['ignore_mtime'],
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',  # Set to INFO to reduce verbosity
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'WARNING',  # Set to WARNING to suppress SQL query logs
            'propagate': False,
        },
    },
}

# MIGRATION_MODULES = {
#     'django_app': 'django_app.migrations',  # Default location
# }



# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'

# For production, directory where Django collects static files into when running the collectstatic management command.
STATIC_ROOT = '/usr/src/frontend/'

# For development
STATICFILES_DIRS = [BASE_DIR / "static_dev"]

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Setting to handle media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Channels

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# SSL - HTTPS - Security

# Defines a set of host/domain names that Django will accept requests from
#ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'calcgame', 'gateway', 'authentif', 'profileapi', 'play']
ALLOWED_HOSTS = [ 'localhost', '127.0.0.1', f'{os.getenv("ACTUALHOSTNAME")}', 'gateway', 'authentif', 'profileapi', 'play', 'calcgame'] # Removing the containers names from host breaks communication between containers

# Redirect all HTTP traffic to HTTPS
SECURE_SSL_REDIRECT = True

# Set the header that tells the browser to use HTTPS
# Use the X-Forwarded-Proto header to determine whether the request is secure
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')  

# Tells browser to strictly follow the Content-Type headers provided by the server.
SECURE_CONTENT_TYPE_NOSNIFF = True
# Instructs browsers to activate their built-in XSS filtering mechanisms by adding X-XSS-Protection HTTP header
SECURE_BROWSER_XSS_FILTER = True

# Session cookie only transmitted over HTTPS secure connections
SESSION_COOKIE_SECURE = True
# Mitigates the risk of cross-site scripting (XSS) - document.cookie not accessible in the browser.
SESSION_COOKIE_HTTPONLY = True

CORS_ALLOWED_ORIGINS = [ '"https://localhost:8443", "https://localhost:8000"',
  f'https://{os.getenv("ACTUALHOSTNAME")}:8000' ]

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [
  'https://localhost:8000',
  'https://nginx:8000',
  'https://gateway:8443',
  'https://authentif:9001',
  'https://profileapi:9002',
  'https://play:9003',
  'https://calcgame:9004',
  f'https://{os.getenv("ACTUALHOSTNAME")}:8000', 
]
