from typing import Tuple, Optional

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .models import Session

User = get_user_model()


class BearerSessionAuthentication(BaseAuthentication):
    """Authenticate with Bearer <token> header against Session model."""

    def authenticate(self, request) -> Optional[Tuple[User, None]]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b"bearer":
            return None
        if len(auth) == 1:
            raise AuthenticationFailed("Invalid auth header")
        token = auth[1].decode("utf-8")
        try:
            sess = Session.objects.select_related("user").get(token=token, revoked=False)
        except Session.DoesNotExist:
            raise AuthenticationFailed("Invalid token")
        if not sess.is_active():
            raise AuthenticationFailed("Token expired or revoked")
        return sess.user, None
