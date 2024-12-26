from django import forms
from django.forms import ValidationError
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser, UserProfile
from django.core.validators import RegexValidator


class UserRegistrationSerializer(serializers.ModelSerializer):
    
    first_name = serializers.CharField(required=True,validators=[RegexValidator(regex="^[a-zA-Z]+$",
            message="Firstname should only contain alphabets.")])
    last_name = serializers.CharField(required=True,validators=[RegexValidator(regex="^[a-zA-Z]+$",
                message="Lastname should only contain alphabets.")])
    username = serializers.CharField(required=True,min_length=5,
        error_messages={
            'min_length': 'Username must be at least 5 characters long.'
        }
    )
    email = serializers.EmailField(required=True
    )
    password = serializers.CharField(write_only=True,validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    mobile_number = serializers.CharField(required=True,validators=[RegexValidator(regex="^\d{10}$",
            message="Mobile number must contain exactly 10 digits.")])
    
    class Meta:
        model = CustomUser
        fields = ['id','first_name', 'last_name', 'username', 'email', 'password','password_confirm','mobile_number']
    
    def validate_first_name(self, value):
        if CustomUser.objects.filter(first_name=value).exists():
            raise serializers.ValidationError("Firstname is already taken.")
        return value

    def validate_last_name(self, value):
        if CustomUser.objects.filter(last_name=value).exists():
            raise serializers.ValidationError("Lastname is already taken.")
        return value
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def validate_username(self, value):
        # Ensure Username is Unique
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username is already taken.")
        return value

    def validate_email(self, value):
        # Ensure Email is Unique
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already registered.")
        return value

    def validate_mobile_number(self, value):
        # Ensure Mobile Number is Unique
        if CustomUser.objects.filter(mobile_number=value).exists():
            raise serializers.ValidationError("Mobile number is already registered.")
        return value

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = CustomUser.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            mobile_number=validated_data.get('mobile_number'),
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255,required=True)
    password = serializers.CharField(max_length=255,required=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid username or password.")
        return {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'username': user.username,
                'email': user.email,
                'mobile_number': user.mobile_number,
                # 'password':user.password,
        }

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        if not attrs.get("refresh_token"):
            raise serializers.ValidationError({"refresh_token": "This field is required."})
        return attrs

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({"old_password": "Old password is not correct."})
        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance


class UserProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'bio', 'profile_picture', 'date_of_birth']
        read_only_fields = ['user']
 
        def validate_profile_picture(self, value):
         if value.size > 5 * 1024 * 1024:  # Limit to 5MB
            raise serializers.ValidationError("File size must not exceed 5MB.")
         if not value.name.endswith(('jpg', 'jpeg', 'png')):
            raise serializers.ValidationError("Only .jpg, .jpeg, or .png files are allowed.")
         return value

class UserProfileForm(forms.ModelForm):
    
    class Meta:
        model = UserProfile
        fields = ['bio', 'profile_picture', 'date_of_birth']
     
    def clean_profile_picture(self):
        profile_picture = self.cleaned_data.get('profile_picture')

        if profile_picture:
            # Validate the file size (limit to 5MB)
            if profile_picture.size > 5 * 1024 * 1024:
                raise forms.ValidationError("File size must not exceed 5MB.")
            
            # Validate the file type (only .jpg, .jpeg, or .png)
            if not profile_picture.name.endswith(('jpg', 'jpeg', 'png')):
                raise forms.ValidationError("Only .jpg, .jpeg, or .png files are allowed.")
        
        return profile_picture
    
    