from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    health, RegisterView, VerifyEmailView, LoginView, LogoutView,
    PasswordChangeView, PasswordResetRequestView, PasswordResetConfirmView,
    QuestionViewSet, AnswerViewSet, AnalyticsView
)

app_name = "api"

router = DefaultRouter()
router.register(r'questions', QuestionViewSet, basename='questions')
router.register(r'answers', AnswerViewSet, basename='answers')

urlpatterns = [
    path('health/', health, name='Health'),
    path('register', RegisterView.as_view(), name='register'),
    path('verify-email', VerifyEmailView.as_view(), name='verify-email'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('password/change', PasswordChangeView.as_view(), name='password-change'),
    path('password/reset', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password/reset/confirm', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('', include(router.urls)),
    path('analytics', AnalyticsView.as_view(), name='analytics'),
]
