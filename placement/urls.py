from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin-console/", admin.site.urls),
    path("", include("core.urls")),
]
