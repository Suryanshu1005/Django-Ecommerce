from django.views import View
from django_six import force_text

from .utils import generate_token
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.conf import settings


def signup(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        cnf_password = request.POST.get('password2')

        if not email or not password or not cnf_password:
            messages.warning(request, 'Please fill in all the required field')
            return render(request, 'authentication/signup.html')

        if password != cnf_password:
            messages.warning(request, 'Password Does Not Match')
            return render(request, 'authentication/signup.html')
        try:
            if User.objects.get(username=email):
                messages.info(request, 'User already exists')
                return render(request, 'authentication/signup.html')
        except User.DoesNotExist:
            user = User.objects.create_user(email, email, password)
            user.save()
            user.is_active = False
            email_subject = "Please activate your account"
            message = render_to_string('activate.html', {
                'user': user,
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user)
            })
            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            email_message.send()
            message.success(request, "Please click the mail sent to your gmail account to activate your account")
            return redirect('auth/login/')
            return render(request, "authentication/signup.html")

    return render(request, 'authentication/signup.html')


def login(request):
    if request.method == "POST":
        email = request.POST.get('email')
    return render(request, 'authentication/login.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account Activated Successfully")
            return redirect('auth/login')
