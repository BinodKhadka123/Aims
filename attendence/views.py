from rest_framework.generics import (
    ListAPIView, RetrieveAPIView, CreateAPIView,
    UpdateAPIView, DestroyAPIView
)
from rest_framework.mixins import (
    ListModelMixin, RetrieveModelMixin,
    CreateModelMixin, UpdateModelMixin, DestroyModelMixin
)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Subject
from .serializers import *
from django.contrib.auth import authenticate
from .renders import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
       

class SubjectListCreateView(ListAPIView, CreateAPIView, ListModelMixin, CreateModelMixin):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            if serializer.is_valid():
                self.perform_create(serializer)
                subject_data = serializer.data
                success_message = "Subject created successfully."
                response_data = {
                    'success': True,
                    'message': success_message,
                    'data': subject_data,
                    
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                error_message = "Failed to create subject."  # Modify the error message for failure
                return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:           
            return Response({'error_message': str(e)}, 
                                status=status.HTTP_404_NOT_FOUND)

class SubjectDetailView(RetrieveAPIView, UpdateAPIView, DestroyAPIView, RetrieveModelMixin, UpdateModelMixin, DestroyModelMixin):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            success_message = "Subject updated successfully."
            return Response({'success': True, 'message': success_message}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        success_message = "Subject deleted successfully."
        response_data = {
            'success': True,
            'message': success_message
        }
        return Response(response_data, status=status.HTTP_204_NO_CONTENT)
class UserRegistrationAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        try:
            if serializer.is_valid(raise_exception=True):
                user=serializer.save()
                token=get_tokens_for_user(user)
                return Response({'token':token,'msg':'Registration Sucessfully'},status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:           
            return Response({'error_message': str(e)}, 
                                status=status.HTTP_404_NOT_FOUND)
        
class UserLogin(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, format=None):
        try:
            serializer = UserLoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data.get('email')
                password = serializer.validated_data.get('password')
                user = authenticate(request, email=email,password=password)
                if user is not None:
                    token=get_tokens_for_user(user)
                    return Response({'token':token,'msg': 'Login Successfully'}, status=status.HTTP_200_OK)
                else:
                    return Response({'errors': {'non_field_errors': ['Email or Password is not valid']}}, 
                                    status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:           
            return Response({'error_message': str(e)}, 
                                status=status.HTTP_404_NOT_FOUND)

class UserProfile(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]  # Note: Use a list, not a dictionary

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)  # Use request.user to get the user object
        return Response(serializer.data, status=status.HTTP_200_OK)
        
class UserChangePassword(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated] 
    def post(self, request, format=None):
        serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password changed Successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, 
                                status=status.HTTP_404_NOT_FOUND)

class SendpasswordResetEmail(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset link sent. Please change your password'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)

class UserPasswordReset(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request,uid,token, format=None):
        serializer=UserPasswordRestSerializer(data=request.data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password  Successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, 
                                status=status.HTTP_404_NOT_FOUND)
    
    
            
    


                

     
        