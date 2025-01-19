from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Department, CustomUser, DailyActivityReport

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'department', 'is_staff', 'is_admin', 'can_edit', 'can_delete', 'can_add_admin']
    search_fields = ['username', 'email']
    ordering = ['username']
    
    # Include email in fieldsets for both add and edit user views
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('email', 'department', 'can_edit', 'can_delete', 'can_add_admin')}),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('email', 'department', 'can_edit', 'can_delete', 'can_add_admin')}),
    )


admin.site.register(Department)
admin.site.register(CustomUser)
admin.site.register(DailyActivityReport)
