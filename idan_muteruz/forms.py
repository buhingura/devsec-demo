from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.utils.html import strip_tags

from .models import Profile


def validate_no_html(value: str) -> None:
    """
    Reject input that contains HTML markup.

    Uses Django's ``strip_tags`` to detect any HTML tags in the value.
    If stripping tags changes the string, HTML was present and the value
    is rejected.

    Why form-level, not just template auto-escaping:
    · Template auto-escaping is the primary defence, but defence-in-depth
      means not relying on a single control.  A future template change that
      inadvertently adds ``|safe``, ``|linebreaks``, or ``{% autoescape off %}``
      would activate any stored payload.  Rejecting HTML at write time ensures
      the database never contains executable markup.
    · Clear user feedback: the submitter sees an explicit error rather than
      silently discovering their content looks wrong when rendered.

    Note on ``strip_tags`` behaviour:
    · Strips complete tags: ``<script>alert(1)</script>`` → ``alert(1)``
    · Strips partial tags: ``<b`` → ``""``
    · Does NOT strip HTML entities (``&lt;``, ``&amp;``).  Entities are
      harmless in plain-text fields because the template will double-encode
      them on output.

    The minor trade-off is that patterns such as ``<3`` (a common emoticon)
    are also rejected because the HTML parser treats ``<`` followed by a
    digit as a malformed tag.  This is an acceptable limitation for fields
    where no markup is ever intended.
    """
    if strip_tags(value) != value:
        raise forms.ValidationError(
            'HTML tags are not permitted. Please use plain text only.'
        )


User = get_user_model()


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text='Required. Enter a valid email address.')
    first_name = forms.CharField(
        required=False, max_length=30, help_text='Optional.',
        validators=[validate_no_html],
    )
    last_name = forms.CharField(
        required=False, max_length=30, help_text='Optional.',
        validators=[validate_no_html],
    )

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
    first_name = forms.CharField(
        required=False, max_length=150,
        validators=[validate_no_html],
    )
    last_name = forms.CharField(
        required=False, max_length=150,
        validators=[validate_no_html],
    )

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Apply the no-HTML validator to both user-controlled text fields.
        # display_name and bio are rendered in dashboard.html and
        # admin_panel.html; rejecting markup here ensures the database never
        # stores executable content regardless of future template changes.
        self.fields['display_name'].validators.append(validate_no_html)
        self.fields['bio'].validators.append(validate_no_html)


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
