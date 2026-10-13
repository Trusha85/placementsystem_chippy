from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.shortcuts import redirect
from django.urls import reverse

from . import audit
from .models import (Attendance, AuditLog, Company, Drive, Offer, PolicyConfig, Student, User)


def _admin_login(request, extra_context=None):
    """Route admin-console logins through the app's login (lockout + MFA)."""
    return redirect("%s?next=%s" % (reverse("login"), request.path))


admin.site.login = _admin_login
admin.site.site_header = "NFSU Placement - Administration"


class AuditedAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        audit.log(request.user, "ADMIN_CHANGE" if change else "ADMIN_CREATE", obj, request=request,
                  after={"fields_changed": form.changed_data})

    def delete_model(self, request, obj):
        audit.log(request.user, "ADMIN_DELETE", obj, request=request)
        super().delete_model(request, obj)


@admin.register(User)
class AppUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (("Placement access", {"fields": ("role", "course", "company", "student")}),)
    add_fieldsets = UserAdmin.add_fieldsets + ((None, {"fields": ("role", "course", "company", "student")}),)
    list_display = ("username", "role", "course", "company", "mfa_enabled", "is_active")
    readonly_fields = ("totp_secret",)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        audit.log(request.user, "ADMIN_USER_CHANGE" if change else "ADMIN_USER_CREATE", obj, request=request,
                  after={"role": obj.role, "fields_changed": form.changed_data})


@admin.register(Company)
class CompanyAdmin(AuditedAdmin):
    list_display = ("name", "category", "response_hours")


@admin.register(PolicyConfig)
class PolicyAdmin(AuditedAdmin):
    def has_add_permission(self, request):
        return not PolicyConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "timestamp", "actor_name", "action", "object_type", "object_id")
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
