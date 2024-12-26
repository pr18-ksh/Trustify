from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
from .views import *

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/', CustomObtainAuthToken.as_view(), name='api_token_auth'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/',AuthUserView.as_view(), name='register'),
    path('login/', AuthUserView.as_view(), name='login'),
    path('logout/', AuthUserView.as_view(), name='logout'),
    path('change_password/',AuthUserView.as_view(), name='change_password'),
    path('home/',AuthUserView.as_view(), name='home'),
    path('profile/create/', create_or_update_profile, name='profile_create_or_update'),
    path('profile/view/', view_profile, name='profile_view'),
    path('profile/update/',create_or_update_profile, name='profile_update'),
    path('profile/delete/',delete_profile, name='profile_delete'),
    path('profile/manage/', profile_manage, name='profile_manage'),
    path('profile/edit/', profile_edit, name='profile_edit'),
    path('profile/change_picture/', change_profile_picture, name='change_profile_picture'),
    path('profile/delete_picture/', delete_profile_picture, name='delete_profile_picture'),
    path('profile/', profile_dashboard, name='profile_dashboard'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)





