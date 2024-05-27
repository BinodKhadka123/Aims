from django.db import models
from rest_framework import serializers
from django.core.validators import RegexValidator
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


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
    def create_user(self, email, name,tc, password=None,password2=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, tc, password=None,pasword2=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            tc=tc,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user    
class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    tc=models.BooleanField()
    is_admin = models.BooleanField(default=False)
    created_at=models.DateTimeField( auto_now_add=True)
    updated_at=models.DateTimeField( auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name","tc"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin