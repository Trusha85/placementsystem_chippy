"""Server-side authorization. Every view is wrapped; every queryset is scoped by role."""
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from . import audit
from .models import Offer, Student, User

R = User.Role


def role_required(*roles):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapper(request, *args, **kwargs):
            if request.user.role not in roles:
                audit.log(request.user, "ACCESS_DENIED", request=request,
                          note="%s %s" % (request.method, request.path))
                return render(request, "403.html", status=403)
            return view(request, *args, **kwargs)
        return wrapper
    return deco


def students_for(user):
    qs = Student.objects.all()
    if user.role in (R.ADMIN, R.OFFICER):
        return qs
    if user.role == R.COORDINATOR:
        return qs.filter(course=user.course) if user.course else qs.none()
    if user.role == R.STUDENT:
        return qs.filter(pk=user.student_id) if user.student_id else qs.none()
    if user.role == R.RECRUITER:
        return qs.filter(offers__company_id=user.company_id).distinct() if user.company_id else qs.none()
    return qs.none()


def offers_for(user):
    qs = Offer.objects.select_related("student", "company")
    if user.role in (R.ADMIN, R.OFFICER):
        return qs
    if user.role == R.COORDINATOR:
        return qs.filter(student__course=user.course) if user.course else qs.none()
    if user.role == R.STUDENT:
        return qs.filter(student_id=user.student_id) if user.student_id else qs.none()
    if user.role == R.RECRUITER:
        return qs.filter(company_id=user.company_id) if user.company_id else qs.none()
    return qs.none()


def can_see_contact(user):
    return user.role in (R.ADMIN, R.OFFICER, R.STUDENT)  # students: their own (scoped) record only


def can_see_compensation(user):
    return user.role != R.COORDINATOR
