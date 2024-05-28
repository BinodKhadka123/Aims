from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_mail(data):
        EMAIL_FROM = 'sunitabuddhathoki3@gmail.com'  # Define the sender email address here
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=EMAIL_FROM,
            to=[data['to_email']]
        )
        email.send()
