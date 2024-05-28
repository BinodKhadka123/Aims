# Generated by Django 5.0.1 on 2024-05-28 09:00

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(help_text='Enter your Email', max_length=255, unique=True, verbose_name='Email')),
                ('fullname', models.CharField(help_text='Enter your full name', max_length=200)),
                ('password', models.CharField(help_text='Enter your password', max_length=200)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('phone_number', models.CharField(max_length=10, unique=True)),
                ('role', models.CharField(choices=[('teacher', 'Teacher'), ('admin', 'Admin')], max_length=20)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Subject',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subjectName', models.CharField(max_length=100)),
                ('subjectCode', models.CharField(max_length=30, unique=True)),
                ('number_of_classes', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Teacher',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fullname', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=50, validators=[django.core.validators.RegexValidator(code='invalid_password', message='Password must contain at least one special character, one letter, one digit, and be at least 8 characters long.', regex='^(?=.*[!@#$%^&*()_+}{":;\'?\\/.,`~])(?=.*[a-zA-Z])(?=.*\\d).{8,}$')])),
                ('phone_number', models.CharField(max_length=10, validators=[django.core.validators.RegexValidator(code='invalid_phone_number', message='Phone number must be 10 digits long.', regex='^\\d{10}$')])),
                ('profile_pic', models.ImageField(upload_to='')),
            ],
        ),
    ]
