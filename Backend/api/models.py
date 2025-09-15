from __future__ import annotations

from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom user manager using email as unique identifier."""

    use_in_migrations = True

    def _create_user(self, email, username, password, **extra_fields):
        if not email:
            raise ValueError("Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        if password:
            user.set_password(password)
        else:
            raise ValueError("Password must be set")
        user.save(using=self._db)
        return user

    def create_user(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        # New users are inactive until email verified
        extra_fields.setdefault("is_active", False)
        return self._create_user(email=email, username=username, password=password, **extra_fields)

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")
        return self._create_user(email=email, username=username, password=password, **extra_fields)


class User(AbstractUser):
    """Custom user with profile and reputation fields."""
    email = models.EmailField(unique=True)
    # Username remains from AbstractUser and unique
    display_name = models.CharField(max_length=64, blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True, validators=[MaxLengthValidator(512)])
    reputation = models.IntegerField(default=0)
    is_verified = models.BooleanField(default=False)

    # Privacy controls
    show_email = models.BooleanField(default=False)
    show_activity = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    REQUIRED_FIELDS = ["username"]
    USERNAME_FIELD = "email"

    class Meta:
        permissions = [
            ("can_moderate", "Can moderate questions and answers"),
            ("can_view_analytics", "Can view analytics dashboards"),
        ]

    def __str__(self):
        return self.email or self.username


class Role(models.Model):
    """Role for RBAC beyond Django groups/permissions."""
    name = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.name


class UserRole(models.Model):
    """Map users to roles."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "role")


class Session(models.Model):
    """Session store for issued tokens with revocation."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    revoked = models.BooleanField(default=False)

    def is_active(self):
        return not self.revoked and self.expires_at > timezone.now()


class Tag(models.Model):
    name = models.CharField(max_length=32, unique=True, validators=[MinLengthValidator(1)])
    description = models.CharField(max_length=256, blank=True, null=True)

    def __str__(self):
        return self.name


class Question(models.Model):
    STATUS_CHOICES = (
        ("draft", "Draft"),
        ("published", "Published"),
        ("deleted", "Deleted"),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="questions")
    title = models.CharField(max_length=256, validators=[MinLengthValidator(3)])
    body = models.TextField(validators=[MinLengthValidator(5)])
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    tags = models.ManyToManyField(Tag, through="QuestionTag", related_name="questions")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    def soft_delete(self, actor: User):
        self.status = "deleted"
        self.deleted_at = timezone.now()
        self.save(update_fields=["status", "deleted_at", "updated_at"])
        AuditLog.log(actor, "delete", "Question", self.pk, {"soft": True})

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"


class QuestionTag(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("question", "tag")


class Answer(models.Model):
    STATUS_CHOICES = (
        ("draft", "Draft"),
        ("published", "Published"),
        ("deleted", "Deleted"),
    )
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="answers")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="answers")
    body = models.TextField(validators=[MinLengthValidator(1)])
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    def soft_delete(self, actor: User):
        self.status = "deleted"
        self.deleted_at = timezone.now()
        self.save(update_fields=["status", "deleted_at", "updated_at"])
        AuditLog.log(actor, "delete", "Answer", self.pk, {"soft": True})


class EditHistory(models.Model):
    """Track edit history for questions/answers."""
    entity_type = models.CharField(max_length=16, choices=(("Question", "Question"), ("Answer", "Answer")))
    entity_id = models.IntegerField()
    editor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    previous_body = models.TextField()
    new_body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class AuditLog(models.Model):
    """Audit log for critical actions."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=64)
    entity_type = models.CharField(max_length=64)
    entity_id = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(blank=True, null=True)

    @classmethod
    def log(cls, user: User | None, action: str, entity_type: str, entity_id: int, details: dict | None = None):
        cls.objects.create(user=user, action=action, entity_type=entity_type, entity_id=entity_id, details=details or {})


class Notification(models.Model):
    """In-app notifications."""
    TYPES = (
        ("answer_created", "Answer Created"),
        ("answer_updated", "Answer Updated"),
        ("question_updated", "Question Updated"),
        ("moderation", "Moderation"),
        ("system", "System"),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    type = models.CharField(max_length=64, choices=TYPES)
    content = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class NotificationPreference(models.Model):
    """User notification preferences."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_pref")
    email_enabled = models.BooleanField(default=True)
    inapp_enabled = models.BooleanField(default=True)
    answers_email = models.BooleanField(default=True)
    moderation_email = models.BooleanField(default=True)
    digest_frequency = models.CharField(
        max_length=16,
        choices=(("immediate", "Immediate"), ("daily", "Daily"), ("weekly", "Weekly")),
        default="immediate",
    )


class EmailVerificationToken(models.Model):
    """Token for email verification"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return (not self.used) and self.expires_at > timezone.now()


class PasswordResetToken(models.Model):
    """Token for password reset workflow."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return (not self.used) and self.expires_at > timezone.now()
