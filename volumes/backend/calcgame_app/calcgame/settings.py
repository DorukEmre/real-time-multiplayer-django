"""
Django settings for profileapi project.

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


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

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
	'calcgame',
    'channels',
    'uvicorn',
    'authentif',
]

AUTH_USER_MODEL = 'authentif.User'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'calcgame.authmiddleware.JWTAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'calcgame.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'calcgame.wsgi.application'


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


LOG_DIR = '/usr/src/app/logs/'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'uvicorn': {  # Formatter for Uvicorn logs
            'format': '{asctime} {levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/usr/src/app/logs/django-calcgame.log',
            'formatter': 'standard',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'uvicorn_file': {  # Separate file handler for Uvicorn logs
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/usr/src/app/logs/uvicorn-calcgame.log',
            'formatter': 'uvicorn',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'uvicorn': {  # Base logger for Uvicorn
            'handlers': ['uvicorn_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'uvicorn.access': {  # Uvicorn access logs (HTTP requests)
            'handlers': ['uvicorn_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'uvicorn.error': {  # Uvicorn error logs
            'handlers': ['uvicorn_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = '/usr/src/frontend/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Channels

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# SSL - HTTPS - Security

# Defines a set of host/domain names that Django will accept requests from
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'calcgame', 'gateway', 'authentif', 'profileapi', 'play']


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

CORS_ALLOWED_ORIGINS = [ "https://localhost:8443" ]

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [
    'https://localhost:8888',
    'https://nginx:8888',
    'https://gateway:8443',
    'https://authentif:9001',
    'https://profileapi:9002',
    'https://play:9003',
    'https://calcgame:9004',
    ]



ASGI_APPLICATION = 'calcgame.asgi.application'
