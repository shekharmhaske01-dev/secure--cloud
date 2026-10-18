"""WTForms definitions for authentication and file operations."""
from __future__ import annotations

import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
RESERVED_USERNAMES = {"admin", "administrator", "root", "system", "securecloud", "support", "null", "none"}


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Please choose a username."),
            Length(min=3, max=32, message="Username must be 3-32 characters long."),
            Regexp(
                USERNAME_RE,
                message="Use only letters, numbers, dots, dashes and underscores.",
            ),
        ],
        render_kw={"autocomplete": "username", "autocapitalize": "none", "spellcheck": "false"},
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Please enter your email address."),
            Length(max=255),
            Email(message="Please enter a valid email address."),
        ],
        render_kw={"autocomplete": "email", "autocapitalize": "none", "spellcheck": "false"},
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Please choose a password."),
            Length(min=10, max=128, message="Password must be at least 10 characters long."),
        ],
        render_kw={"autocomplete": "new-password"},
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(message="Please repeat the password."),
            EqualTo("password", message="The passwords do not match."),
        ],
        render_kw={"autocomplete": "new-password"},
    )
    accept_terms = BooleanField(
        "I understand that SecureCloud stores only encrypted blocks and that a lost "
        "key-encryption key makes stored files unrecoverable.",
        validators=[DataRequired(message="Please acknowledge the key-management notice.")],
    )
    submit = SubmitField("Create account")

    def validate_username(self, field):  # noqa: ANN001
        value = (field.data or "").strip()
        if value.lower() in RESERVED_USERNAMES:
            raise ValidationError("That username is reserved. Please choose another one.")

    def validate_email(self, field):  # noqa: ANN001
        value = (field.data or "").strip().lower()
        if len(value) > 255:
            raise ValidationError("Please enter a shorter email address.")

    def validate_password(self, field):  # noqa: ANN001
        value = field.data or ""
        if value.strip() != value:
            raise ValidationError("Password must not start or end with spaces.")
        if value.isdigit() or value.isalpha():
            raise ValidationError("Use a mix of letters, numbers and symbols for a stronger password.")


class LoginForm(FlaskForm):
    username = StringField(
        "Username or email",
        validators=[DataRequired(message="Enter your username or email."), Length(max=255)],
        render_kw={"autocomplete": "username", "autocapitalize": "none", "spellcheck": "false"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Enter your password.")],
        render_kw={"autocomplete": "current-password"},
    )
    remember = BooleanField("Keep me signed in on this device")
    submit = SubmitField("Sign in")


class UploadForm(FlaskForm):
    file = FileField(
        "Select a file",
        validators=[
            FileRequired(message="Choose a file to upload."),
            FileAllowed(
                ["txt", "pdf", "png", "jpg", "jpeg", "gif", "webp", "zip", "csv", "json",
                 "doc", "docx", "xls", "xlsx", "ppt", "pptx", "md", "log", "bin", "tar", "gz"],
                message="That file type is not permitted.",
            ),
        ],
    )
    submit = SubmitField("Upload and encrypt")


class DeleteFileForm(FlaskForm):
    """CSRF-only form for destructive actions triggered from the file list."""

    confirm_name = StringField("Type the filename to confirm")
    submit = SubmitField("Delete file")


class EmptyForm(FlaskForm):
    """CSRF-only form (delete / maintenance buttons)."""

    submit = SubmitField("Confirm")
