from __future__ import annotations

from django.contrib.auth import authenticate, password_validation
from rest_framework import serializers

from .models import (
    User, Tag, Question, Answer, Notification, NotificationPreference,
)


# PUBLIC_INTERFACE
class UserSerializer(serializers.ModelSerializer):
    """User serializer for public exposure (hide sensitive fields)."""

    class Meta:
        model = User
        fields = ["id", "username", "email", "display_name", "avatar_url", "bio", "reputation", "is_verified", "created_at"]
        read_only_fields = ["id", "reputation", "is_verified", "created_at"]
        extra_kwargs = {"email": {"write_only": False}}


# PUBLIC_INTERFACE
class RegisterSerializer(serializers.Serializer):
    """Serializer to register a new user with email verification."""
    username = serializers.CharField(min_length=3, max_length=32)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    display_name = serializers.CharField(required=False, allow_blank=True, max_length=64)
    bio = serializers.CharField(required=False, allow_blank=True, max_length=512)
    avatar_url = serializers.URLField(required=False, allow_blank=True)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(
            email=validated_data["email"],
            username=validated_data["username"],
            password=password,
            display_name=validated_data.get("display_name", ""),
            bio=validated_data.get("bio", ""),
            avatar_url=validated_data.get("avatar_url", ""),
        )
        return user


# PUBLIC_INTERFACE
class LoginSerializer(serializers.Serializer):
    """Authenticate with email and password."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = authenticate(email=attrs["email"], password=attrs["password"])
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        if not user.is_active or not user.is_verified:
            raise serializers.ValidationError("Account is inactive or not verified")
        attrs["user"] = user
        return attrs


# PUBLIC_INTERFACE
class PasswordChangeSerializer(serializers.Serializer):
    """Change password while authenticated."""
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value

    def validate(self, attrs):
        user: User = self.context["request"].user
        if not user.check_password(attrs["current_password"]):
            raise serializers.ValidationError("Current password is incorrect")
        return attrs


# PUBLIC_INTERFACE
class PasswordResetRequestSerializer(serializers.Serializer):
    """Request password reset."""
    email = serializers.EmailField()


# PUBLIC_INTERFACE
class PasswordResetSerializer(serializers.Serializer):
    """Reset password using token."""
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value


# PUBLIC_INTERFACE
class TagSerializer(serializers.ModelSerializer):
    """Tag model serializer."""

    class Meta:
        model = Tag
        fields = ["id", "name", "description"]


# PUBLIC_INTERFACE
class QuestionSerializer(serializers.ModelSerializer):
    """Question model serializer with tags."""
    tags = TagSerializer(many=True, required=False)
    author_id = serializers.IntegerField(source="user_id", read_only=True)

    class Meta:
        model = Question
        fields = ["id", "title", "body", "author_id", "status", "created_at", "updated_at", "tags"]
        read_only_fields = ["id", "author_id", "status", "created_at", "updated_at"]

    def create(self, validated_data):
        tags_data = validated_data.pop("tags", [])
        question = Question.objects.create(**validated_data)
        if tags_data:
            tag_objs = []
            for t in tags_data:
                tag, _ = Tag.objects.get_or_create(name=t["name"], defaults={"description": t.get("description", "")})
                tag_objs.append(tag)
            question.tags.set(tag_objs)
        return question

    def update(self, instance, validated_data):
        tags_data = validated_data.pop("tags", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if tags_data is not None:
            tag_objs = []
            for t in tags_data:
                tag, _ = Tag.objects.get_or_create(name=t["name"], defaults={"description": t.get("description", "")})
                tag_objs.append(tag)
            instance.tags.set(tag_objs)
        return instance


# PUBLIC_INTERFACE
class AnswerSerializer(serializers.ModelSerializer):
    """Answer model serializer."""
    author_id = serializers.IntegerField(source="user_id", read_only=True)
    question_id = serializers.IntegerField()

    class Meta:
        model = Answer
        fields = ["id", "question_id", "body", "author_id", "status", "created_at", "updated_at"]
        read_only_fields = ["id", "author_id", "status", "created_at", "updated_at"]

    def create(self, validated_data):
        return Answer.objects.create(**validated_data)


# PUBLIC_INTERFACE
class NotificationSerializer(serializers.ModelSerializer):
    """Notification serializer."""

    class Meta:
        model = Notification
        fields = ["id", "type", "content", "is_read", "created_at"]


# PUBLIC_INTERFACE
class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """Notification preference serializer."""

    class Meta:
        model = NotificationPreference
        fields = ["email_enabled", "inapp_enabled", "answers_email", "moderation_email", "digest_frequency"]
