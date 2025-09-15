import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone

from .models import (
    EmailVerificationToken, PasswordResetToken, Notification, NotificationPreference, Session
)


def _generate_token() -> str:
    return secrets.token_urlsafe(48)


def create_email_verification_token(user):
    token = _generate_token()
    expires = timezone.now() + timedelta(hours=24)
    EmailVerificationToken.objects.create(user=user, token=token, expires_at=expires)
    return token


def send_verification_email(request, user, token):
    base = f"{request.scheme}://{request.get_host()}"
    url = f"{base}{reverse('api:verify-email')}?token={token}"
    subject = "Verify your email"
    message = f"Welcome! Please verify your email by visiting: {url}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)


def create_password_reset_token(user):
    token = _generate_token()
    expires = timezone.now() + timedelta(hours=1)
    PasswordResetToken.objects.create(user=user, token=token, expires_at=expires)
    return token


def send_password_reset_email(request, user, token):
    base = f"{request.scheme}://{request.get_host()}"
    url = f"{base}{reverse('api:password-reset-confirm')}?token={token}"
    subject = "Password Reset Request"
    message = f"Reset your password using the following link (valid 1 hour): {url}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)


def create_session(user) -> Session:
    token = _generate_token()
    session = Session.objects.create(
        user=user,
        token=token,
        expires_at=timezone.now() + timedelta(minutes=getattr(settings, "SESSION_EXP_MINUTES", 30)),
    )
    return session


def revoke_session(session: Session):
    session.revoked = True
    session.save(update_fields=["revoked"])


def notify_inapp(user, type_, content):
    pref, _ = NotificationPreference.objects.get_or_create(user=user)
    if pref.inapp_enabled:
        Notification.objects.create(user=user, type=type_, content=content)


def notify_email(user, subject, message):
    pref, _ = NotificationPreference.objects.get_or_create(user=user)
    if pref.email_enabled:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)


def summarize_analytics():
    from .models import User, Question, Answer
    return {
        "total_questions": Question.objects.filter(status="published").count(),
        "total_answers": Answer.objects.filter(status="published").count(),
        "active_users": User.objects.filter(is_active=True, is_verified=True).count(),
    }
