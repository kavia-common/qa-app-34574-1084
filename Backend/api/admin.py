from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    User, Role, UserRole, Session, Tag, Question, QuestionTag, Answer,
    EditHistory, AuditLog, Notification, NotificationPreference,
    EmailVerificationToken, PasswordResetToken
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("id", "email", "username", "is_verified", "is_active", "reputation", "created_at")
    search_fields = ("email", "username")
    ordering = ("-created_at",)
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Profile", {"fields": ("display_name", "avatar_url", "bio", "reputation", "is_verified", "show_email", "show_activity")}),
    )


admin.site.register(Role)
admin.site.register(UserRole)
admin.site.register(Session)
admin.site.register(Tag)
admin.site.register(Question)
admin.site.register(QuestionTag)
admin.site.register(Answer)
admin.site.register(EditHistory)
admin.site.register(AuditLog)
admin.site.register(Notification)
admin.site.register(NotificationPreference)
admin.site.register(EmailVerificationToken)
admin.site.register(PasswordResetToken)
