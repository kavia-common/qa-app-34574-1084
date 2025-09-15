from __future__ import annotations

from django.contrib.auth import login as django_login, logout as django_logout, get_user_model
from rest_framework import status, viewsets
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Question, Answer, AuditLog, EmailVerificationToken, PasswordResetToken, Session
from .permissions import IsVerifiedAndAuthenticated, IsOwnerOrModerator
from .serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer, PasswordChangeSerializer,
    PasswordResetRequestSerializer, PasswordResetSerializer, QuestionSerializer,
    AnswerSerializer
)
from .utils import (
    create_email_verification_token, send_verification_email, create_password_reset_token,
    send_password_reset_email, create_session, revoke_session, notify_inapp, summarize_analytics
)

User = get_user_model()


@api_view(['GET'])
def health(request):
    """
    PUBLIC_INTERFACE
    Health check endpoint.
    Returns a simple JSON indicating the server is up.
    """
    return Response({"message": "Server is up!"})


class RegisterView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Register a new user with email verification
      description: Accepts username, email, password and optional profile fields; sends verification email.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = create_email_verification_token(user)
            send_verification_email(request, user, token)
            AuditLog.log(user, "register", "User", user.id, {"email": user.email})
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response({"error_code": "VALIDATION_ERROR", "message": "Invalid input", "details": serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """
    PUBLIC_INTERFACE
    get:
      summary: Verify email
      description: Verifies email using token sent to user.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get("token")
        if not token:
            return Response({"error_code": "BAD_REQUEST", "message": "Token required"}, status=400)
        try:
            ev = EmailVerificationToken.objects.select_related("user").get(token=token)
        except EmailVerificationToken.DoesNotExist:
            return Response({"error_code": "INVALID_TOKEN", "message": "Invalid token"}, status=400)
        if not ev.is_valid():
            return Response({"error_code": "TOKEN_EXPIRED", "message": "Token invalid or expired"}, status=400)
        ev.used = True
        ev.save(update_fields=["used"])
        user = ev.user
        user.is_active = True
        user.is_verified = True
        user.save(update_fields=["is_active", "is_verified"])
        AuditLog.log(user, "verify_email", "User", user.id, {})
        return Response({"message": "Email verified"})


class LoginView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Authenticate user and issue a session token
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error_code": "AUTH_FAILED", "message": "Invalid credentials"}, status=401)
        user = serializer.validated_data["user"]
        # create server-side session token (HttpOnly cookie compatible if used by frontend)
        session = create_session(user)
        django_login(request, user)
        AuditLog.log(user, "login", "User", user.id, {})
        return Response({"token": session.token})


class LogoutView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Logout current session
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            try:
                sess = Session.objects.get(token=token, user=request.user, revoked=False)
                revoke_session(sess)
            except Session.DoesNotExist:
                pass
        django_logout(request)
        AuditLog.log(request.user, "logout", "User", request.user.id, {})
        return Response({"message": "Logged out"})


class PasswordChangeView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Change password when logged in
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data["new_password"])
            user.save(update_fields=["password"])
            AuditLog.log(user, "password_change", "User", user.id, {})
            return Response({"message": "Password changed"})
        return Response({"error_code": "VALIDATION_ERROR", "message": "Invalid input", "details": serializer.errors},
                        status=400)


class PasswordResetRequestView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Request password reset
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Do not reveal existence
            return Response({"message": "If an account exists, a reset email has been sent"})
        token = create_password_reset_token(user)
        send_password_reset_email(request, user, token)
        AuditLog.log(user, "password_reset_request", "User", user.id, {})
        return Response({"message": "If an account exists, a reset email has been sent"})


class PasswordResetConfirmView(APIView):
    """
    PUBLIC_INTERFACE
    post:
      summary: Confirm password reset using token
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        try:
            pr = PasswordResetToken.objects.select_related("user").get(token=token)
        except PasswordResetToken.DoesNotExist:
            return Response({"error_code": "INVALID_TOKEN", "message": "Invalid token"}, status=400)
        if not pr.is_valid():
            return Response({"error_code": "TOKEN_EXPIRED", "message": "Token invalid or expired"}, status=400)
        user = pr.user
        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        pr.used = True
        pr.save(update_fields=["used"])
        AuditLog.log(user, "password_reset", "User", user.id, {})
        return Response({"message": "Password has been reset"})


class QuestionViewSet(viewsets.ModelViewSet):
    """
    PUBLIC_INTERFACE
    CRUD for questions with filtering by status and pagination.
    """
    serializer_class = QuestionSerializer
    permission_classes = [IsVerifiedAndAuthenticated & IsOwnerOrModerator]

    def get_queryset(self):
        qs = Question.objects.all()
        status_param = self.request.query_params.get("status")
        if status_param:
            if status_param in ("open", "answered", "closed"):
                # map to underlying published state for MVP
                qs = qs.filter(status="published")
        # Hide deleted from normal views
        qs = qs.exclude(status="deleted")
        return qs.order_by("-created_at")

    def perform_create(self, serializer):
        question = serializer.save(user=self.request.user, status="published")
        AuditLog.log(self.request.user, "create", "Question", question.id, {})
        notify_inapp(self.request.user, "question_updated", f"Question '{question.title}' created")

    def perform_update(self, serializer):
        instance: Question = self.get_object()
        old_body = instance.body
        question = serializer.save()
        AuditLog.log(self.request.user, "update", "Question", question.id, {})
        if old_body != question.body:
            from .models import EditHistory
            EditHistory.objects.create(
                entity_type="Question",
                entity_id=question.id,
                editor=self.request.user,
                previous_body=old_body,
                new_body=question.body,
            )
        notify_inapp(self.request.user, "question_updated", f"Question '{question.title}' updated")

    def perform_destroy(self, instance):
        instance.soft_delete(self.request.user)


class AnswerViewSet(viewsets.ModelViewSet):
    """
    PUBLIC_INTERFACE
    Create/Edit/Delete answers. Only owner or moderator can modify.
    """
    serializer_class = AnswerSerializer
    permission_classes = [IsVerifiedAndAuthenticated & IsOwnerOrModerator]

    def get_queryset(self):
        qs = Answer.objects.exclude(status="deleted").order_by("-created_at")
        qid = self.request.query_params.get("question_id")
        if qid:
            qs = qs.filter(question_id=qid)
        return qs

    def perform_create(self, serializer):
        answer = serializer.save(user=self.request.user, status="published")
        AuditLog.log(self.request.user, "create", "Answer", answer.id, {"question_id": answer.question_id})
        # Notify question owner if different
        if answer.question.user_id != self.request.user.id:
            notify_inapp(answer.question.user, "answer_created", f"New answer on your question '{answer.question.title}'")

    def perform_update(self, serializer):
        instance: Answer = self.get_object()
        old_body = instance.body
        answer = serializer.save()
        AuditLog.log(self.request.user, "update", "Answer", answer.id, {})
        if old_body != answer.body:
            from .models import EditHistory
            EditHistory.objects.create(
                entity_type="Answer",
                entity_id=answer.id,
                editor=self.request.user,
                previous_body=old_body,
                new_body=answer.body,
            )
        # Notify question owner
        if answer.question.user_id != self.request.user.id:
            notify_inapp(answer.question.user, "answer_updated", f"An answer was updated on '{answer.question.title}'")

    def perform_destroy(self, instance):
        instance.soft_delete(self.request.user)


class AnalyticsView(APIView):
    """
    PUBLIC_INTERFACE
    get:
      summary: Retrieve analytics data
      description: Returns basic totals for questions, answers, and active users.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not (request.user.has_perm("api.can_view_analytics") or request.user.is_staff):
            return Response({"error_code": "FORBIDDEN", "message": "Not authorized"}, status=403)
        return Response(summarize_analytics())
