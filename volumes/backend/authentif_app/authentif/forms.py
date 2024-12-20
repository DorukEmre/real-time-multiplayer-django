from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm
from .models import User
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import logging
logger = logging.getLogger(__name__)


class SignUpForm(forms.ModelForm):
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = User
        fields = ['username', 'password', 'id_42']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        id_42 = cleaned_data.get("id_42")

        # If id_42 is provided, no need for password
        if not id_42:
            if not password or not confirm_password:
                raise forms.ValidationError(_("Password and confirmation are required"))
            if password != confirm_password:
                raise forms.ValidationError(_("Passwords do not match"))
            # Check if password has one uppercase, one lowercase, one digit
            if not any(char.isupper() for char in password):
                raise ValidationError(_("Password must contain at least one uppercase letter"))
            if not any(char.islower() for char in password):
                raise ValidationError(_("Password must contain at least one lowercase letter"))
            if not any(char.isdigit() for char in password):
                raise ValidationError(_("Password must contain at least one digit"))
            if len(password) < 8:
                raise ValidationError(_("Password must be at least 8 characters long"))

        # If id_42 is set, we don't need a password, vice versa
        if id_42 and password:
            raise forms.ValidationError(_("Cannot set both password and id_42"))

        return cleaned_data



class LogInForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control', 'id': 'loginUsername'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'id': 'loginPassword'
    }))

class LogInForm42(AuthenticationForm):
    id = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control', 'id': 'loginId'
    }))

class EditProfileForm(UserChangeForm):

    new_username = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control', 'id': 'newUsername'
    }), label=_('New Username'), required=False)

    new_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'id': 'newPassword'
    }), label=_('New Password'), required=False)

    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'id': 'signupConfirmPassword'
    }), label=_('Confirm Password'), required=False)

    avatar = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control', 'id': 'avatar'
    }), label=_('Avatar'), required=False) 

    def __init__(self, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        del self.fields['password']

    class Meta:
        model = User
        fields = ('username', 'avatar')



    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        new_username = cleaned_data.get('username')
        avatar = cleaned_data.get('avatar')

        # Change avatar
        if avatar:
            self.instance.avatar = avatar

        # Validate current password
        if new_password or confirm_password:
            if new_password != confirm_password:
                raise ValidationError(_("Passwords do not match"))
            # Check if password has one uppercase, one lowercase, one digit
            if not any(char.isupper() for char in new_password):
                raise ValidationError(_("Password must contain at least one uppercase letter"))
            if not any(char.islower() for char in new_password):
                raise ValidationError(_("Password must contain at least one lowercase letter"))
            if not any(char.isdigit() for char in new_password):
                raise ValidationError(_("Password must contain at least one digit"))
            if len(new_password) < 8:
                raise ValidationError(_("Password must be at least 8 characters long"))
            else:
              self.instance.set_password(new_password)
              if new_username:
                self.instance.username = new_username
        return cleaned_data
