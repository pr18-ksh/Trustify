from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.contrib.auth import get_user_model

class CustomUser(AbstractUser):
    # Adding a mobile_number field
    mobile_number = models.CharField(max_length=15,null=True, blank=True)
   
   

    # Customizing groups relationship
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",  # Changed related_name for clarity
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups",
    )
    # Customizing user_permissions relationship
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_set",  # Changed related_name for clarity
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
    )

    def __str__(self):
        return self.username

class UserProfile(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE) 
    bio = models.TextField(blank=True,null=True,db_index=True)
    profile_picture = models.ImageField(upload_to='Photos/profile_pics/', blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    