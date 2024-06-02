# Generated by Django 5.0.1 on 2024-05-31 06:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('attendence', '0003_remove_student_attendance_delete_attendance'),
    ]

    operations = [
        migrations.CreateModel(
            name='Group',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('student_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='attendence.student')),
                ('subject_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='attendence.subject')),
                ('teacher_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]