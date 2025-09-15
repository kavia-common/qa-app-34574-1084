Q&A Backend Service (Django)
- Features: Registration with email verification, login/logout with bearer session token, password reset/change, RBAC via permissions, questions/answers CRUD with drafts (MVP published/soft-delete), tags, notifications (in-app), analytics summary, and audit logs.
- API Docs: /docs (Swagger UI), /redoc
- Base API: /api

Environment variables (set these in .env and map to Django settings):
- DJANGO_SECRET_KEY
- DJANGO_DEBUG (true/false)
- EMAIL_BACKEND (e.g., django.core.mail.backends.console.EmailBackend)
- DEFAULT_FROM_EMAIL
- SESSION_EXP_MINUTES (e.g., 30)

Migrations:
- python manage.py makemigrations
- python manage.py migrate

Admin:
- python manage.py createsuperuser

Security:
- Password hashing by Django
- Tokens stored server-side in Session model; Bearer header supported
- CSRF: DRF SessionAuthentication protected; Bearer endpoints stateless

Testing:
- python manage.py test
