# urls.py

from django.urls import path, include
from rest_framework import routers
from .views import SubjectListCreateView, SubjectDetailView,GroupCreateView, UserRegistrationAPIView, UserLogin, UserProfile, UserChangePassword, SendpasswordResetEmail, UserPasswordReset, UserList, Userdetail, UserDelete, AddStudent, StudentDetail, GroupViewSet

router = routers.DefaultRouter()
router.register(r'groups', GroupViewSet, basename='group')

urlpatterns = [
    path('', include(router.urls)),
    path('subjects/', SubjectListCreateView.as_view(), name='subject-list-create'),
    path('subjects/<int:pk>/', SubjectDetailView.as_view(), name='subject-detail'),
    path('register',UserRegistrationAPIView.as_view(),name='user_registration'),
    path('login/',UserLogin.as_view(),name='user_login'),
    path('profile',UserProfile.as_view(),name='user_profile'),
    path('change_password',UserChangePassword.as_view(),name='change_password'),
    path('password_reset',SendpasswordResetEmail.as_view(),name='password_reset'),
    path('reset_password/<uid>/<token>/',UserPasswordReset.as_view(),name='reset'),
    path('list/',UserList.as_view(),name='user_list'),
    path('users/<int:pk>/', Userdetail.as_view(), name='user-detail'),
    path('delete/<int:pk>/', UserDelete.as_view(), name='user-delete'),
    path('student/', AddStudent.as_view(), name='add_subject_create'),
    path('student/<int:pk>/', StudentDetail.as_view(), name='student-detail'),
     path('Group_create/', GroupCreateView.as_view(), name='student-detail'),
]
