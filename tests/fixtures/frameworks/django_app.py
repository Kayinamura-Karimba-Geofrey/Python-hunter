"""Django Application Settings & Views Test Fixture."""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import jwt

DEBUG = True
SECRET_KEY = "django-insecure-secret"

@csrf_exempt
def vulnerable_view(request):
    token = request.GET.get("token")
    decoded = jwt.decode(token, options={"verify_signature": False})
    return HttpResponse("OK")
