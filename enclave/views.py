from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from .serializers import LogoutSerializer, UserProfileForm, UserProfileSerializer, UserRegistrationSerializer, UserLoginSerializer, PasswordChangeSerializer
from django.contrib import messages
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed
from .models import CustomUser, UserProfile
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view
from drf_yasg.utils import swagger_auto_schema  # Import the decorator
from drf_yasg import openapi
import logging
logger = logging.getLogger(__name__)

# Helper function to generate token
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class AuthUserView(APIView):

    @swagger_auto_schema(
        operation_description="Handles user registration, login, logout, password change, and home actions.",
        responses={ 200: openapi.Response(description="Action performed successfully") },
        manual_parameters=[
            openapi.Parameter('action', openapi.IN_QUERY, description="Action to be performed", type=openapi.TYPE_STRING, enum=['register', 'login', 'change_password', 'logout', 'home'])
        ]
    )

    # Handle GET requests
    def get(self, request):
        action = request.GET.get('action')  # Use GET for GET requests

        if action == 'register':
            return render(request, 'register.html')

        elif action == 'login':
            return render(request, 'login.html')

        elif action == 'logout':
            logout(request)
            return redirect('/api/login/?action=login')

        elif action == 'change_password':
            return render(request, 'change_password.html')
        
        elif action == 'home':
            return render(request,'home.html')
        
        
        return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Handles user registration, login, logout, password change, and home actions.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'action': openapi.Schema(type=openapi.TYPE_STRING, enum=['register', 'login', 'change_password', 'logout', 'home']),
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['action']
        ),
        responses={200: openapi.Response(description="Action performed successfully")},
        manual_parameters=[
            openapi.Parameter('action', openapi.IN_QUERY, description="Action to be performed", type=openapi.TYPE_STRING, enum=['register', 'login', 'change_password', 'logout', 'home'])
        ]
    )
    
    # Handle POST requests
    def post(self, request):
        action = request.data.get('action')  # Use data for POST requests

        if action == 'register':
            return self.register_user(request)

        elif action == 'login':
            return self.login_user(request)

        elif action == 'change_password':
            return self.change_password(request)

        elif action == 'logout':
            return self.logout_user(request)
        
        elif action == 'home':
            return self.home_view(request)
    

        return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        operation_description="Register a new user.",
        request_body=UserRegistrationSerializer,
        responses={200: openapi.Response("User registered successfully", UserRegistrationSerializer)},
    )
    # Register a new user
    def register_user(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            messages.info(request, "Account created successfully.")
            return redirect('/api/login/?action=login')  
        return render(request, 'register.html', {'errors': serializer.errors})

    @swagger_auto_schema(
        operation_description="Login an existing user.",
        request_body=UserLoginSerializer,
        responses={200: openapi.Response("Login successful", schema=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "message": openapi.Schema(type=openapi.TYPE_STRING),
                "user": openapi.Schema(type=openapi.TYPE_OBJECT, additional_properties=openapi.Schema(type=openapi.TYPE_STRING)),
                "token": openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                    "access": openapi.Schema(type=openapi.TYPE_STRING),
                    "refresh": openapi.Schema(type=openapi.TYPE_STRING),
                }),
            }
        ))},
    )
    # Login user
    def login_user(self, request):
        login_serializer = UserLoginSerializer(data=request.data)
        if login_serializer.is_valid():
                validated_data = login_serializer.validated_data
                username = validated_data.get('username')

                logger.debug(f"Authenticating user: {username}")

                user = get_object_or_404(CustomUser, username=validated_data['username'])
    
                if user is None:
                    return render(request, 'login.html', {'errors': ["Invalid username or password."]})

                login(request, user)
    
                return render(request, 'home.html', {'message': "Login successful"})
        else:
            
            return render(request, 'login.html', {'errors': ["Invalid username or password."]})

    @swagger_auto_schema(
        operation_description="Log out the user and invalidate the refresh token.",
        request_body=LogoutSerializer,
        responses={200: openapi.Response("Logout successful")},
    )
    def logout_user(self, request):
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                return Response({"error": "Invalid refresh token!"}, status=status.HTTP_400_BAD_REQUEST)

        logout(request)  # End session
        return redirect('/api/login/?action=login')

    @swagger_auto_schema(
        operation_description="Change the user's password.",
        request_body=PasswordChangeSerializer,
        responses={200: openapi.Response("Password changed successfully")},
    )
    def change_password(self, request):
        if not request.user.is_authenticated:
            return redirect('/api/login/?action=login')
        
        changepassword_serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if changepassword_serializer.is_valid():
            
            old_password = changepassword_serializer.validated_data['old_password']
            new_password = changepassword_serializer.validated_data['new_password']
            user = request.user

            if not user.check_password(old_password):
                return render(request, 'change_password.html', {'errors': ['Old password is incorrect']})

            user.set_password(new_password)
            user.save()

            logout(request)

            user = authenticate(username=user.username, password=new_password)
            if user is not None:
                    login(request,user)
                    refresh = RefreshToken.for_user(user)
                    access_token = refresh.access_token
    
                    messages.success(request, 'Your password has been changed successfully.')
                    return render(request, 'home.html', {
                    'message': 'Password changed successfully!',
                    'token': {
                               "refresh": str(refresh),
                               "access": str(access_token),
                            },
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'mobile_number': user.mobile_number,
                    }
                })
            return render(request, 'change_password.html', {'errors': ['Authentication failed after password change.']})

        return render(request, 'change_password.html', {'errors': changepassword_serializer.errors})

    @swagger_auto_schema(
        operation_description="Returns the home page view, accessible only for authenticated users.",
        responses={200: openapi.Response(description="Home page view")},
        manual_parameters=[
            openapi.Parameter('auth_token', openapi.IN_HEADER, description="JWT Token for authentication", type=openapi.TYPE_STRING)
        ]
    ) 
    @login_required
    def home_view(request):
        permission_classes = [IsAuthenticated]
        return render(request, 'home.html', {'message': "Welcome to the Home Page!"})

class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        # Call the parent post method to validate credentials and generate the token
        response = super().post(request, *args, **kwargs)

        # Retrieve the user object using the username and password
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if not user:
            raise AuthenticationFailed("Invalid username or password")

        # Optionally, you can generate a JWT instead of the default token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        # Modify the response to include extra user information
        data = {
            "token": response.data["token"],  # original token
            "access": str(access_token),       # add access token (JWT)
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }

        return Response(data, status=status.HTTP_200_OK)
    


@login_required
def create_or_update_profile(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        print("Debugging user_profile.bio:", user_profile.bio if user_profile else "No user_profile")
    except UserProfile.DoesNotExist:
        user_profile = None
    
    if request.method == 'POST':
        # Using the form with the serializer
        form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
        
        if form.is_valid():
            # Serialize and save profile data
            serializer = UserProfileSerializer(user_profile, data=form.cleaned_data,partial=True)
            if serializer.is_valid():
                serializer.save(user=request.user)  # Update the user profile
                messages.success(request, "Profile saved successfully.")
                return redirect('profile_view')  # Redirect to profile view after save
            else:
                messages.error(request, "Error saving profile.")
        else:
            messages.error(request, "Form data is not valid.")
    else:
        form = UserProfileForm(instance=user_profile)

    return render(request, 'profile_form.html', {'form': form,'user_profile': user_profile})

@login_required
def view_profile(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        user_profile = None

    # Serialize the user profile data
    if user_profile:
        serializer = UserProfileSerializer(user_profile)
        user_profile_data = serializer.data
    else:
        user_profile_data = None

    return render(request, 'profile_view.html', {'user_profile': user_profile_data})

@login_required
def delete_profile(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        user_profile.delete()
        messages.success(request,"Profile deleted successfully.")
        return redirect('profile_create_or_update')  # Redirect after delete
    except UserProfile.DoesNotExist:
        messages.error(request, "Profile not found.")
        return redirect('profile_create_or_update')

def profile_manage(request):
    return render(request, 'profile_manage.html')

@login_required
def profile_edit(request):
    # Retrieve the user's profile or create one if it doesn't exist
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        user_profile = UserProfile.objects.create(user=request.user)  # Create profile

    errors = None  # Initialize errors as None

    if request.method == 'POST':
        # Make a mutable copy of request.POST and pass request.FILES as well for file uploads
        data = request.POST.copy()  # Make the QueryDict mutable
        data.update(request.FILES)  # Add the files to the data (for profile picture)

        # Use `request.FILES` for handling file uploads like profile_picture
        serializer = UserProfileSerializer(user_profile, data= data, partial=True)
        if 'profile_picture' in request.FILES:
            serializer.initial_data['profile_picture'] = request.FILES['profile_picture']
        
        if serializer.is_valid():
            serializer.save()  # Save the updated profile
            messages.success(request, "Profile updated successfully.")
            return redirect('profile_view')  # Redirect to the profile view (update with your URL name)
        else:
            # Add an error message if the serializer is not valid
            messages.error(request, "Error updating profile. Please correct the errors below.")
            errors = serializer.errors  # Access errors only after `.is_valid()` call
    
    # For GET requests or invalid POST, render the form with the serializer
    serializer = UserProfileSerializer(user_profile)
    return render(request, 'profile_edit.html', {
        'serializer': serializer,
        'user_profile': user_profile,
        'errors': errors,  # Pass the errors to the template for display
    })

@login_required
def change_profile_picture(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        messages.error(request, "Profile not found.")
        return redirect('profile_edit')

    if request.method == 'POST' and request.FILES.get('profile_picture'):
        data = {'profile_picture': request.FILES['profile_picture']}
        serializer = UserProfileSerializer(user_profile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            messages.success(request, "Profile picture updated successfully.")
            return redirect('profile_view')
        else:
            messages.error(request, "Error updating profile picture.")

    return render(request, 'change_profile_picture.html', {'user_profile': user_profile})

@login_required
def delete_profile_picture(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        messages.error(request, "Profile not found.")
        return redirect('profile_edit')

    if request.method == 'POST':
        data = {'profile_picture': None}
        serializer = UserProfileSerializer(user_profile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            messages.success(request, "Profile picture deleted successfully.")
            return redirect('profile_view')
        else:
            messages.error(request, "Error deleting profile picture.")

    return render(request, 'delete_profile_picture.html', {'user_profile': user_profile})

@login_required
def profile_dashboard(request):
        """Display user profile details and management options."""
        user = request.user
        token = get_tokens_for_user(user)
        return render(request, 'profile_dashboard.html', {
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'mobile_number': user.mobile_number,
        },'token': token
    })



