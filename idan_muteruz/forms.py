from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm

from .models import Profile


User = get_user_model()


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text='Required. Enter a valid email address.')
    first_name = forms.CharField(required=False, max_length=30, help_text='Optional.')
    last_name = forms.CharField(required=False, max_length=30, help_text='Optional.')

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'first_name',
            'last_name',
            'password1',
            'password2',
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('A user with that email already exists.')
        return email


class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and self.user and User.objects.exclude(pk=self.user.pk).filter(email__iexact=email).exists():
            raise forms.ValidationError('This email address is already in use.')
        return email


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['display_name', 'bio']
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4}),
        }


class CustomPasswordChangeForm(PasswordChangeForm):
    pass


class AssignRoleForm(forms.Form):
    """
    Single-field form that replaces all of a user's groups with one chosen group.
    Rendered once per user row inside the admin panel's User Management table.
    """

    group = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        empty_label=None,
        label='Role',
        widget=forms.Select(attrs={'class': 'role-select'}),
    )

    def __init__(self, *args, **kwargs):
        from django.contrib.auth.models import Group
        super().__init__(*args, **kwargs)
        self.fields['group'].queryset = Group.objects.order_by('name')
