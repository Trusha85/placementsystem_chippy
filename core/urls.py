from django.contrib.auth import views as auth_views
from django.urls import path
from django.urls import reverse_lazy

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("security/", views.security_settings, name="security_settings"),
    path("password/", auth_views.PasswordChangeView.as_view(
        template_name="password_change.html", success_url=reverse_lazy("home")), name="password_change"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("recruiter/", views.recruiter_home, name="recruiter_home"),
    path("students/", views.student_list, name="student_list"),
    path("students/new/", views.student_create, name="student_create"),
    path("students/import/", views.student_import, name="student_import"),
    path("students/<int:pk>/", views.student_detail, name="student_detail"),
    path("students/<int:pk>/edit/", views.student_edit, name="student_edit"),
    path("students/<int:pk>/archive/", views.student_archive, name="student_archive"),
    path("students/<int:pk>/delete/", views.student_delete, name="student_delete"),
    path("students/<int:pk>/offers/new/", views.offer_create, name="offer_create"),
    path("offers/", views.offer_list, name="offer_list"),
    path("offers/<int:pk>/edit/", views.offer_update, name="offer_update"),
    path("drives/", views.drive_list, name="drive_list"),
    path("drives/new/", views.drive_create, name="drive_create"),
    path("drives/<int:pk>/", views.drive_detail, name="drive_detail"),
    path("drives/<int:pk>/attendance/", views.drive_attendance, name="drive_attendance"),
    path("export/", views.export_page, name="export"),
    path("audit/", views.audit_list, name="audit_list"),
    path("audit/verify/", views.audit_verify, name="audit_verify"),
]
