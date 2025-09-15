from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsVerifiedAndAuthenticated(BasePermission):
    """Allow only authenticated and verified users."""

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "is_verified", False))


class IsOwnerOrModerator(BasePermission):
    """Allow resource owner or users with moderation permission."""

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if getattr(obj, "user_id", None) == user.id:
            return True
        return user.has_perm("api.can_moderate") or user.is_staff
