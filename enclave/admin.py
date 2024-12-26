from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import CustomUser, UserProfile

admin.site.register(CustomUser)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'bio', 'date_of_birth', 'profile_picture_preview']
    search_fields = ['user__username', 'bio']
    list_filter = ['date_of_birth']

    def profile_picture_preview(self, obj):
        if obj.profile_picture:
            return f'<img src="{obj.profile_picture.url}" width="50" height="50" />'
        return "No Image"
    profile_picture_preview.allow_tags = True
    profile_picture_preview.short_description = "Profile Picture"
    
# Customizing the UserAdmin for CustomUser
# @admin.register(CustomUser)
# class CustomUserAdmin(UserAdmin):
#     # Define the fields to display in the admin list view
#     list_display = ("username", "email", "mobile_number", "is_staff", "is_active")
#     search_fields = ("username", "email", "mobile_number")
#     ordering = ("username",)
    
#     # Add 'mobile_number' to the fieldsets for editing user details
#     fieldsets = (
#         (None, {"fields": ("username", "password")}),
#         (_("Personal info"), {"fields": ("first_name", "last_name", "email", "mobile_number")}),
#         (_("Permissions"), {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
#         (_("Important dates"), {"fields": ("last_login", "date_joined")}),
#     )
    
#     # Fields to display when creating a new user
#     add_fieldsets = (
#         (None, {
#             "classes": ("wide",),
#             "fields": ("username", "email", "mobile_number", "password1", "password2", "is_staff", "is_active"),
#         }),
#     )
