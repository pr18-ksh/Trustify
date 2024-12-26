from django.http import HttpResponse
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from .serializers import *
from rest_framework import status


# Utility function to generate tokens for a user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class AuthUserView(APIView):
    # permission_classes = [IsAuthenticated]
    
    def post(self, request):
        action = request.data.get('action')
        
        if action == 'register':
            return self.register_user(request)
        elif action == 'login':
            return self.login_user(request)
        elif action == 'logout':
            return self.logout_user(request)
        elif action == 'change_password':
            return self.change_password(request)
        else:
            return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    # Register user and return JWT tokens
    def register_user(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token': token, 'message': "User created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Handle user login and return JWT tokens
    @login_required
    def login_user(self, request):
        login_serializer = UserLoginSerializer(data=request.data)
        if login_serializer.is_valid():
                # You don't need login(request, user) as we're using JWT
                validated_data = login_serializer.validated_data
                token = get_tokens_for_user(CustomUser.objects.get(username=validated_data['username']))
                return Response({'message': "Login successfully",'user': validated_data, 'token': token}, status=status.HTTP_200_OK)  
        return Response(login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def logout_user(self, request):
        # Validate the input
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
               try:
                    # Accessing 'refresh_token' correctly
                    refresh_token = serializer.validated_data.get('refresh_token')
            
                    if not refresh_token:
                       return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token to invalidate it
                    token = RefreshToken(refresh_token)
                    token.blacklist()  # This will blacklist the refresh token so it can't be used again

                    return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

               except Exception as e:
                     return Response({"error": "Invalid token or token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Change user password
    def change_password(self, request):
         
        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        
        changepassword_serializer = PasswordChangeSerializer(data=request.data,context={'request': request})
        
        if changepassword_serializer.is_valid():
            user = request.user
            old_password = changepassword_serializer.validated_data['old_password']
            new_password = changepassword_serializer.validated_data['new_password']
            
            if not user.check_password(old_password):
                return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(new_password)
            user.save()

            # After changing the password, you must log the user back in
            login(request, user)

            # Delete old tokens if needed (optional)
            # Token.objects.filter(user=user).delete()  # This line should be avoided since JWT is stateless

            # Return new token pair
            token = get_tokens_for_user(user)
            return Response({'message': 'Password changed successfully', 'token': token}, status=status.HTTP_200_OK)

        return Response(changepassword_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@method_decorator(login_required, name='dispatch')
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request, pk=None):
        """Handle profile view based on action."""
        action = request.query_params.get("action")
        try:
            if action == "view_profile":
                if pk:
                    profile = UserProfile.objects.get(id=pk)
                else:
                    profile = UserProfile.objects.get(user=request.user)
                return render(request, "view_profile.html", {"profile": profile})

            return HttpResponse("Invalid action specified.", status=400)

        except UserProfile.DoesNotExist:
            return HttpResponse("Profile not found.", status=404)

    def post(self, request):
        """Handle profile creation."""
        action = request.query_params.get("action")
        if action == "create_profile":
            serializer = UserProfileSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save(user=request.user)
                return redirect("view_profile")  # Redirect to profile view page
            return render(request, "create_profile.html", {"errors": serializer.errors})
        
        return HttpResponse("Invalid action specified.", status=400)

    def put(self, request, pk=None):
        """Handle profile updates."""
        try:
            profile = UserProfile.objects.get(id=pk) if pk else UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(profile, data=request.data, partial=True, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                return redirect("view_profile", pk=profile.id)  # Redirect to updated profile
            return render(request, "update_profile.html", {"profile": profile, "errors": serializer.errors})
        
        except UserProfile.DoesNotExist:
            return HttpResponse("Profile not found.", status=404)

    def delete(self, request, pk=None):
        """Handle profile deletion."""
        try:
            profile = UserProfile.objects.get(id=pk) if pk else UserProfile.objects.get(user=request.user)
            profile.delete()
            return redirect("create_profile")  # Redirect to create profile page
        
        except UserProfile.DoesNotExist:
            return HttpResponse("Profile not found.", status=404)
        
class UserProfileView(APIView):
    # authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # To support file uploads

    # @swagger_auto_schema(
    #     operation_description="Retrieve the user's profile or a specific profile by ID.",
    #     responses={200: UserProfileSerializer()},
    #     manual_parameters=[
    #         openapi.Parameter(
    #             'Authorization',
    #             openapi.IN_HEADER,
    #             description="JWT token for authorization",
    #             type=openapi.TYPE_STRING
    #         ),
    #         openapi.Parameter('pk',openapi.IN_PATH,description="Profile ID (optional)",type=openapi.TYPE_INTEGER),
    #     ],)
    def get(self, request, pk=None):
        """Retrieve the user's profile or a specific profile by ID."""
        if pk:
            try:
                profile = UserProfile.objects.get(id=pk)
            except UserProfile.DoesNotExist:
                return Response({"error": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            profile, created = UserProfile.objects.get_or_create(user=request.user)

        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)

    # @swagger_auto_schema(
    #     operation_description="Create a new profile with optional profile picture upload.",
    #     request_body=UserProfileSerializer,
    #     responses={201: UserProfileSerializer(), 400: "Bad Request"},
    #     manual_parameters=[
    #          openapi.Parameter('Authorization', openapi.IN_HEADER, description="JWT token for authorization", type=openapi.TYPE_STRING)
    #     ]
    # )
    def post(self, request):
        """Create a new profile for the user."""

        serializer = UserProfileSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @swagger_auto_schema(
    #     operation_description="Update the user's profile or a specific profile by ID.",
    #     request_body=UserProfileSerializer,
    #     responses={200: UserProfileSerializer(), 400: "Bad Request"},
    # )
    def put(self, request, pk=None):
        """Update the user's profile or a specific profile by ID."""
        try:
            profile = UserProfile.objects.get(id=pk) if pk else UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @swagger_auto_schema(
    #     operation_description="Delete the user's profile or a specific profile by ID.",
    #     responses={204: "Profile deleted successfully", 404: "Profile not found"},
    #     manual_parameters=[
    #         openapi.Parameter('Authorization',openapi.IN_HEADER,description="JWT token for authorization",type=openapi.TYPE_STRING),
    #         openapi.Parameter('pk',openapi.IN_PATH, description="Profile ID (optional)",type=openapi.TYPE_INTEGER),
    #     ],
    # )
    def delete(self, request, pk=None):
        """Delete the user's profile or a specific profile by ID."""
        try:
            profile = UserProfile.objects.get(id=pk) if pk else UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

        profile.delete()
        return Response({"message": "Profile deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    
#  {% extends 'base.html' %} {% block start %}
# <div class="container mt-5">
#     <div class="card shadow-lg p-4">
#         <h2 class="text-center">Welcome, {{ user.username }}!</h2>
#         <p class="text-center">You are successfully logged in.</p>
#         <hr>
#         <div class="row">
#             <div class="col-md-6">
#                 <h4>User Information</h4>
#                 <ul class="list-group">
#                     <li class="list-group-item"><strong>First Name:</strong>{{ user.first_name }}</li>
#                     <li class="list-group-item"><strong>Last Name:</strong>{{ user.last_name }}</li>
#                     <li class="list-group-item"><strong>Username:</strong>{{ user.username }}</li>
#                     <li class="list-group-item"><strong>Email:</strong>{{ user.email }}</li>
#                     <li class="list-group-item"><strong>Mobile Number:</strong>{{ user.mobile_number }}</li>
#                 </ul>
#             </div>
#             <div class="col-md-6">
#                 <h4>Quick Actions</h4>
#                 <ul class="list-group">
#                     <li class="list-group-item">
#                         <a href="/api/change_password/?action=change_password" class="btn btn-warning w-100">Change Password</a>
#                     </li>
#                     <li class="list-group-item">
#                         <a href="/api/logout/?action=logout" class="btn btn-danger w-100">Logout</a>
#                     </li>
#                     <li class="list-group-item">
#                         <a href="{% url 'profile_create_or_update' %}" class="btn btn-success w-100">Create Profile</a>
#                     </li>
#                     <li class="list-group-item">
#                         <a href="{% url 'profile_view' %}" class="btn btn-success w-100">View Profile</a>
#                     </li>
#                     <li class="list-group-item">
#                         <a href="{% url 'profile_update' %}" class="btn btn-primary w-100">Update Profile</a>
#                     </li>
#                     <li class="list-group-item">
#                         <a href="{% url 'profile_delete' %}" class="btn btn-danger w-100">Delete Profile</a>
#                     </li>
#                 </ul>
#             </div>

#             <div class="col-md-12 mt-4">
#                 <h4>Profile Details</h4>
#                 <form method="POST" action="{% url 'profile_create_or_update' %}" enctype="multipart/form-data">
#                     {% csrf_token %}
#                     <div class="form-group">
#                         <label for="bio">Bio</label>
#                         <textarea class="form-control" id="bio" name="bio" rows="3">{{ userprofile.bio }}</textarea>

#                     </div>
#                     <div class="form-group">
#                         <label for="profile_picture">Profile Picture</label>
#                         <input type="file" class="form-control" id="profile_picture" name="profile_picture">
#                     </div>
#                     <div class="form-group">
#                         <label for="date_of_birth">Date of Birth</label>
#                         <input type="date" class="form-control" id="date_of_birth" name="date_of_birth" value="{{ userprofile.date_of_birth }}">
#                     </div>
#                     <button type="submit" class="btn btn-success w-100">Save Profile</button>
#                 </form>
#             </div>
#             <div class="mb-3">
#                 <label for="userToken">Access Token:</label>
#                 <textarea class="form-control" id="userToken" rows="3" disabled>{{ token.access }}</textarea>
#             </div>
#             <div class="mb-3">
#                 <label for="userRefreshToken">Refresh Token:</label>
#                 <textarea class="form-control" id="userRefreshToken" rows="3" disabled>{{ token.refresh }}</textarea>
#             </div>
#         </div>
#     </div>
# </div>
# {% endblock %} 

#  def register_user(self, request):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             # token = get_tokens_for_user(user)
#             messages.info(request, "Account created successfully.")
#             return redirect('/api/login/?action=login')  
#             # After successful registration, render home.html with the user's details and token
#             # return render(request, 'home.html', {'message': 'User registered successfully!','user': {
#             #     'first_name': user.first_name,
#             #     'last_name': user.last_name,
#             #     'username': user.username,
#             #     'email': user.email,
#             #     'mobile_number': user.mobile_number,
#             # }, 'token': token})
#         return render(request, 'register.html', {'errors': serializer.errors})
#     from pyexpat.errors import messages
# from django.shortcuts import redirect, render
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.models import User
# from django.utils.decorators import method_decorator
# from django.contrib.auth.decorators import login_required

# def get_tokens_for_user(user):
#     refresh = RefreshToken.for_user(user)
#     return {
#         'refresh': str(refresh),
#         'access': str(refresh.access_token),
#     }


# class AuthUserView(APIView):

#     # Handle GET requests for rendering appropriate HTML templates based on the action
#     def get(self, request):
#         action = request.GET.get('action')
#         if action == 'register':
#             return render(request, 'register.html')
#         elif action == 'login':
#             return render(request, 'login.html')
#         elif action == 'change_password':
#             return render(request, 'change_password.html')
        
#         return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

#     # Handle POST requests for registration, login, change password, and logout
#     def post(self, request):
#         action = request.data.get('action')
        
#         if action == 'register':
#             return self.register_user(request)
        
#         elif action == 'login':
#             return self.login_user(request)
        
#         elif action == 'change_password':
#             return self.change_password(request)
        
#         elif action == 'logout':
#             return self.logout_user(request)
        
#         return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

#     # Helper function for registering a user
#     def register_user(self, request):
#         firstname = request.data.get('first_name')
#         lastname = request.data.get('last_name')
#         username = request.data.get('username')
#         password = request.data.get('password')

#         if User.objects.filter(username=username).exists():
#             return Response({"error": "Username already exists!"}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.create_user(
#             first_name=firstname, last_name=lastname, username=username, password=password
#         )
#         tokens = get_tokens_for_user(user)
#         messages.info(request, "Account created successfully.")
#         return Response({
#             "message": "Registration successful!",
#             "tokens": tokens,
#         }, status=status.HTTP_201_CREATED)
       
#     # Helper function for logging in a user
#     def login_user(self, request):
#         username = request.data.get('username')
#         password = request.data.get('password')

#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             tokens = get_tokens_for_user(user)
#             return Response({
#                 "message": "Login successful!",
#                 "tokens": tokens,
#             }, status=status.HTTP_200_OK)
#         else:
#             return Response({"error": "Invalid credentials!"}, status=status.HTTP_401_UNAUTHORIZED)

#     # Helper function for changing a user's password
#     @method_decorator(login_required)
#     def change_password(self, request):
#         old_password = request.data.get('old_password')
#         new_password = request.data.get('new_password')
#         confirm_password = request.data.get('confirm_password')

#         if not request.user.check_password(old_password):
#             return Response({"error": "Old password is incorrect!"}, status=status.HTTP_400_BAD_REQUEST)

#         if new_password != confirm_password:
#             return Response({"error": "New passwords do not match!"}, status=status.HTTP_400_BAD_REQUEST)

#         request.user.set_password(new_password)
#         request.user.save()
#         return Response({"message": "Password changed successfully!"}, status=status.HTTP_200_OK)

#     # Helper function for logging out a user
#     def logout_user(self, request):
#         refresh_token = request.data.get('refresh_token')
#         try:
#             token = RefreshToken(refresh_token)
#             token.blacklist()
#             logout(request)
#             return Response({"message": "Logout successful!"}, status=status.HTTP_200_OK)
#         except Exception:
#             return Response({"error": "Invalid refresh token!"}, status=status.HTTP_400_BAD_REQUEST)

