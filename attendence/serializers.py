from nbformat import ValidationError
from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from attendence.utils import Util
from .models import *
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.core.mail import send_mail
def validate_number_of_classes(value):
    if not isinstance(value, int):
        raise ValidationError('Number of classes must be an integer.')
    if value < 5 or value > 500:
        raise ValidationError('Number of classes must be between 5 and 500.')
    if value < 0:
        raise ValidationError('Number of classes cannot be negative.')
    if value != int(value):
        raise ValidationError('Number of classes cannot be a decimal value.')
class SubjectSerializer(serializers.ModelSerializer):
    number_of_classes = serializers.IntegerField(validators=[validate_number_of_classes])
    class Meta:
        model = Subject
        fields = [ 'subjectName', 'subjectCode','number_of_classes']
        

def validate_fullname(value):
    parts = value.split()
    if len(parts) < 2 or len(parts) > 3:
        raise ValidationError('Fullname must consist of three parts separated by spaces.')
    for part in parts:
        if not part.isalpha():
            raise ValidationError('Each part of the fullname must contain only letters.')
def validate_phone_number(value):
    if not str(value).startswith('9') or len(str(value))!=10 or not str(value).isdigit():
        raise ValidationError('Phone number must be a 10-digit number starting with 9.')
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fullname', 'email', 'phone_number']
class UserRegistrationSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(validators=[validate_fullname])
    password = serializers.CharField(write_only=True, required=False, default="password@123")
    phone_number = serializers.CharField(validators=[validate_phone_number])

    class Meta:
        model = User
        fields = ['email', 'fullname', 'phone_number', 'role', 'password']

    def create(self, validated_data):
        # Extract and hash the password
        email = validated_data.get('email')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data, password=password)
        
        # Send email with password
        body = f'Your password for {email} is: {password}'  # Compose email body
        data = {
            'subject': 'Welcome to YourApp - Your Password',
            'body': body,
            'to_email': email,
            'from_email': 'yourapp@example.com'  # Update with your email
        }
        Util.send_mail(data)  # Use your email sending utility
        
        return user
    
    
    
   
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email',  'password']
        
class UserProfileSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = User
        fields = ['id','email',  'fullname']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    
    def validate(self, attrs):
        password = attrs.get('password')
        
        user = self.context.get('user')
        if not password.strip():
            raise serializers.ValidationError("Password should not be blank")
        user.set_password(password)
        user.save()
        return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'http://127.0.0.1:8000/reset/'+uid+'/'+token
            print('Encoded id:', uid)
            print('Password reset token:', token)
            print('Password reset link:', link)
            #send email
            body='click the following link to reset password'+link
            data={
                'subject':'password reset link',
                'body':body,
                'to_email':user.email,
                'from_email':'nikesh.rokka@deerwalk.edu.np>'
                
                
            }
            Util.send_mail(data)
            return attrs
        else:
            raise serializers.ValidationError("You are not a registered user")
                

class UserPasswordRestSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
   
    def validate(self, attrs):
        password = attrs.get('password')
        
        if not password.strip():
            raise serializers.ValidationError("Password should not be blank")
        
        uid = self.context.get('uid')
        token = self.context.get('token')

        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Token is not valid or expired")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is not valid or expired")

        # Set the new password
        user.set_password(password)
        user.save()
        return attrs


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'fullname', 'phone_number', 'role', 'password']



class StudentSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Student
        fields = ['email', 'fullname', 'phone_number']


class GroupSerializer(serializers.ModelSerializer):
    student_name = StudentSerializer(write_only=True)
    subject_name = SubjectSerializer()  
    teacher_name = UserSerializer()

    class Meta:
        model = Group
        fields = ['name', 'student_name', 'subject_name', 'teacher_name']
    def create(self, validated_data):
        # Extract the nested data
        student_data = validated_data.pop('student_name')
        subject_data = validated_data.pop('subject_name')
        teacher_data = validated_data.pop('teacher_name')

        # Create related objects
        student = Student.objects.create(**student_data)
        subject = Subject.objects.create(**subject_data)
        teacher = User.objects.create(**teacher_data)

        # Create Group object
        group = Group.objects.create(
            student_name=student,
            subject_name=subject,
            teacher_name=teacher,
            **validated_data
        )

        return group

class GroupSerializer(serializers.ModelSerializer):    

    class Meta:
        model = Group
        fields = ['name', 'student_name', 'subject_name', 'teacher_name']

    def create(self, validated_data):
        # Extract the nested data
        student_data = validated_data.pop('student_name')
        subject_data = validated_data.pop('subject_name')
        teacher_data = validated_data.pop('teacher_name')

        # Create related objects
        student = Student.objects.create(**student_data)
        subject = Subject.objects.create(**subject_data)
        teacher = User.objects.create(**teacher_data)

        # Create Group object
        group = Group.objects.create(
            student_name=student,
            subject_name=subject,
            teacher_name=teacher,
            **validated_data
        )

        return group