
from api.views import UserRegistrationView , UserLoginView ,UserProfileView, UserChangePassword , SendPasswordResetEmailView, UserPasswordResetView
from django.urls import path

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePassword.as_view(), name='changepassword'),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view(), name='send_reset_password_email'),
    path('reset_password/<uid>/<token>/',UserPasswordResetView .as_view(), name='UserPasswordResetView'),
]
