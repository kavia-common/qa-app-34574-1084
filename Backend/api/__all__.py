# Explicit re-exports for clarity and lint compliance
from .models import (
    User, Role, UserRole, Session, Tag, Question, QuestionTag, Answer,
    EditHistory, AuditLog, Notification, NotificationPreference,
    EmailVerificationToken, PasswordResetToken
)
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer, PasswordChangeSerializer,
    PasswordResetRequestSerializer, PasswordResetSerializer, TagSerializer,
    QuestionSerializer, AnswerSerializer, NotificationSerializer,
    NotificationPreferenceSerializer
)
from .permissions import IsVerifiedAndAuthenticated, IsOwnerOrModerator

__all__ = [
    # models
    "User", "Role", "UserRole", "Session", "Tag", "Question", "QuestionTag", "Answer",
    "EditHistory", "AuditLog", "Notification", "NotificationPreference",
    "EmailVerificationToken", "PasswordResetToken",
    # serializers
    "UserSerializer", "RegisterSerializer", "LoginSerializer", "PasswordChangeSerializer",
    "PasswordResetRequestSerializer", "PasswordResetSerializer", "TagSerializer",
    "QuestionSerializer", "AnswerSerializer", "NotificationSerializer",
    "NotificationPreferenceSerializer",
    # permissions
    "IsVerifiedAndAuthenticated", "IsOwnerOrModerator",
]
