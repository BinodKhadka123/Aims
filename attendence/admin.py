from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
admin.site.register(Subject)
admin.site.register(Group)
admin.site.register(Student)
class UserModelAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ["id", "email", "fullname","phone_number","role","password", "is_admin"]  # Assuming "name" maps to "fullname" in your model
    list_filter = ["is_admin"]
    fieldsets = [
        ("User Credentials", {"fields": ["fullname","email", "password","role"]}),
        ("Personal info", {"fields": ["phone_number"]}),  # Assuming you have a "phone" field in your model
        ("Permissions", {"fields": ["is_admin"]}),
    ]
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "fullname","phone_number", "password1", "password2"],
            },
        ),
    ]
    search_fields = ["email"]
    ordering = ["email", "id"]
    filter_horizontal = []

# Register the new UserAdmin...
admin.site.register(User, UserModelAdmin)
# Register your models here.
