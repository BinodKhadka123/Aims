from django.db import models
from rest_framework import serializers
from django.core.validators import RegexValidator
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.auth.hashers import make_password


class Subject(models.Model):
    subjectName = models.CharField(max_length=100)
    subjectCode = models.CharField(max_length=30,unique=True)
    number_of_classes = models.IntegerField()

    def __str__(self):
        return self.subjectName
class Teacher(models.Model):
    password_validator = RegexValidator(
        regex='^(?=.*[!@#$%^&*()_+}{":;\'?\/.,`~])(?=.*[a-zA-Z])(?=.*\d).{8,}$',
        message='Password must contain at least one special character, one letter, one digit, and be at least 8 characters long.',
        code='invalid_password'
    )
    phone_number_validator = RegexValidator(
        regex=r'^\d{10}$',
        message='Phone number must be 10 digits long.',
        code='invalid_phone_number'
    )
    fullname=models.CharField(max_length=100)
    email =models.EmailField()
    password = models.CharField(max_length=50, validators=[password_validator])
    phone_number = models.CharField(max_length=10, validators=[phone_number_validator])
    profile_pic=models.ImageField()
class UserManager(BaseUserManager):
    def create_user(self, email, fullname, phone_number, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        
        # Use default password if not provided
        if not password:
            password = "password@123"
        
        # Hash the password
        hashed_password = make_password(password)
        
        user = self.model(email=email, fullname=fullname, phone_number=phone_number, password=hashed_password, **extra_fields)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, fullname, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')

        return self.create_user(email, fullname, phone_number, password, **extra_fields)


class User(AbstractBaseUser):
    ROLE_CHOICES = (
        ('teacher', 'Teacher'),
        ('admin', 'Admin'),
    )
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
        help_text="Enter your Email"
    )
    fullname = models.CharField(max_length=200, blank=False, null=False, help_text="Enter your full name")
    password = models.CharField(max_length=200, blank=False, null=False, help_text="Enter your password")
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    phone_number = models.CharField(max_length=10, unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["fullname","phone_number"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin