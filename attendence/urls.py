from django.urls import path
from .views import *
from .views import *

urlpatterns = [
    path('subjects/', SubjectListCreateView.as_view(), name='subject-list-create'),
    path('subjects/<int:pk>/', SubjectDetailView.as_view(), name='subject-detail'),
    path('register',UserRegistration.as_view(),name='user_registration'),
    path('login/',UserLogin.as_view(),name='user_login'),
     path('profile',UserProfile.as_view(),name='user_profile'),
      path('change_password',UserChangePassword.as_view(),name='change_password'),
      path('password_reset',SendpasswordResetEmail.as_view(),name='password_reset'),
      path('reset_password/<uid>/<token>/',UserPasswordReset.as_view(),name='reset'),


]
