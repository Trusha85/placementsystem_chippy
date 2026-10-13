import csv
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Prefetch, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import audit, policy, reports
from .forms import (CSVUploadForm, DriveForm, OfferForm, OfferStatusForm, OtpForm, StudentForm, parse_csv)
from .models import (COURSE_LABEL, COURSES, Attendance, AuditLog, Drive, Offer, PolicyConfig, Student, User,
                     expire_overdue_offers)
from .permissions import (R, can_see_compensation, can_see_contact, offers_for, role_required, students_for)
from .security import (client_ip, clear_failures, csv_safe, is_locked, mask_mobile, new_totp_secret,
                       register_failure, verify_totp)

ADMIN_OFFICER = (R.ADMIN, R.OFFICER)


def _qs(request):
    q = request.GET.copy()
    q.pop("page", None)
    return q.urlencode()


# ------------------------------------------------------------------ auth
def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")
    error = None
    if request.method == "POST":
        username = request.POST.get("username", "").strip()[:150]
        password = request.POST.get("password", "")
        otp = request.POST.get("otp", "")
        ip = client_ip(request)
        if is_locked(username, ip):
            audit.log(None, "LOGIN_LOCKED", request=request, actor_name=username or "?",
                      note="Too many failed attempts")
            error = "Too many failed attempts. Try again in 15 minutes."
        else:
            user = authenticate(request, username=username, password=password)
            ok = user is not None and user.is_active
            if ok and user.mfa_enabled and not verify_totp(user.totp_secret, otp):
                ok = False
            if ok:
                clear_failures(username, ip)
                login(request, user)  # rotates the session key (anti session-fixation)
                audit.log(user, "LOGIN_SUCCESS", request=request)
                nxt = request.POST.get("next", "")
                if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}, request.is_secure()):
                    return redirect(nxt)
                return redirect("home")
            register_failure(username, ip)
            audit.log(None, "LOGIN_FAILED", request=request, actor_name=username or "?")
            error = "Invalid credentials or verification code."
    return render(request, "login.html", {"error": error, "next": request.GET.get("next", "")})


@require_POST
@login_required
def logout_view(request):
    audit.log(request.user, "LOGOUT", request=request)
    logout(request)
    return redirect("login")


@login_required
def home(request):
    u = request.user
    if u.role == R.STUDENT:
        if u.student_id:
            return redirect("student_detail", pk=u.student_id)
        return render(request, "no_record.html")
    if u.role == R.RECRUITER:
        return redirect("recruiter_home")
    return redirect("dashboard")


@login_required
def security_settings(request):
    user = request.user
    ctx = {}
    if request.method == "POST":
        action = request.POST.get("action")
        form = OtpForm(request.POST)
        if action == "enable" and form.is_valid() and not user.mfa_enabled:
            secret = request.session.get("pending_totp", "")
            if verify_totp(secret, form.cleaned_data["code"]):
                user.totp_secret, user.mfa_enabled = secret, True
                user.save(update_fields=["totp_secret", "mfa_enabled"])
                request.session.pop("pending_totp", None)
                audit.log(user, "MFA_ENABLED", user, request=request)
                messages.success(request, "Multi-factor authentication enabled.")
                return redirect("security_settings")
            messages.error(request, "That code did not match. Try again.")
        elif action == "disable" and user.mfa_enabled:
            if user.check_password(request.POST.get("password", "")) and form.is_valid() \
                    and verify_totp(user.totp_secret, form.cleaned_data["code"]):
                user.totp_secret, user.mfa_enabled = "", False
                user.save(update_fields=["totp_secret", "mfa_enabled"])
                audit.log(user, "MFA_DISABLED", user, request=request)
                messages.success(request, "Multi-factor authentication disabled.")
                return redirect("security_settings")
            messages.error(request, "Password or code incorrect.")
    if not user.mfa_enabled:
        secret = request.session.setdefault("pending_totp", new_totp_secret())
        ctx["secret"] = secret
        ctx["uri"] = "otpauth://totp/NFSU-Placement:%s?secret=%s&issuer=NFSU-Placement" % (user.username, secret)
    return render(request, "security_settings.html", ctx)


# ------------------------------------------------------------- dashboards
@role_required(R.ADMIN, R.OFFICER, R.COORDINATOR)
def dashboard(request):
    expire_overdue_offers()
    u = request.user
    stats = reports.compute(students_for(u), offers_for(u), with_comp=can_see_compensation(u))
    return render(request, "dashboard.html", {"s": stats, "show_comp": can_see_compensation(u)})


@role_required(R.RECRUITER)
def recruiter_home(request):
    expire_overdue_offers()
    offers = offers_for(request.user)
    drives = Drive.objects.filter(company_id=request.user.company_id).select_related("company")
    return render(request, "recruiter_home.html", {"offers": offers, "drives": drives})


# ---------------------------------------------------------------- students
@role_required(R.ADMIN, R.OFFICER, R.COORDINATOR)
def student_list(request):
    qs = students_for(request.user).prefetch_related(
        Prefetch("offers", queryset=Offer.objects.select_related("company")))
    q = request.GET.get("q", "").strip()[:80]
    course = request.GET.get("course", "")
    batch = request.GET.get("batch", "").strip()[:9]
    status = request.GET.get("status", "")
    archived = request.GET.get("archived") == "1"
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(placement_id__icontains=q) | Q(email__icontains=q))
    if course in COURSE_LABEL:
        qs = qs.filter(course=course)
    if batch:
        qs = qs.filter(batch=batch)
    qs = qs.filter(is_archived=archived)
    rows = list(qs)
    if status in ("Unplaced", "Internship only", "FTE only", "Internship + PPO/FTE"):
        rows = [s for s in rows if s.placement_status == status]
    page = Paginator(rows, 25).get_page(request.GET.get("page"))
    return render(request, "student_list.html", {
        "page": page, "qs": _qs(request), "q": q, "course": course, "batch": batch, "status": status, "archived": archived,
        "courses": COURSES, "show_contact": can_see_contact(request.user),
        "statuses": ["Unplaced", "Internship only", "FTE only", "Internship + PPO/FTE"]})


@login_required
def student_detail(request, pk):
    user = request.user
    student = get_object_or_404(students_for(user), pk=pk)   # IDOR-safe: scoped queryset
    expire_overdue_offers()
    offers = offers_for(user).filter(student=student)
    show_contact = can_see_contact(user)
    audit.log(user, "VIEW_STUDENT", student, request=request,
              note="contact visible" if show_contact else "contact hidden")
    ctx = {
        "st": student, "offers": offers, "show_contact": show_contact,
        "mobile": student.mobile if show_contact else mask_mobile(student.mobile),
        "show_comp": can_see_compensation(user),
        "attendance": student.attendance.select_related("drive") if user.role != R.RECRUITER else [],
        "placement_status": Student.objects.prefetch_related("offers").get(pk=student.pk).placement_status,
        "history": AuditLog.objects.filter(object_type="Student", object_id=str(student.pk))[:15]
        if user.role in ADMIN_OFFICER else [],
        "can_edit": user.role in ADMIN_OFFICER,
    }
    if user.role == R.RECRUITER:   # recruiters never see other companies' offers
        ctx["placement_status"] = "Hidden"
    return render(request, "student_detail.html", ctx)


@role_required(*ADMIN_OFFICER)
def student_create(request):
    form = StudentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                s = form.save()
        except IntegrityError:
            form.add_error("placement_id", "This Placement ID already exists.")
        else:
            audit.log(request.user, "STUDENT_CREATE", s, after=audit.snapshot(s, Student.AUDIT_FIELDS), request=request)
            messages.success(request, "Student %s created." % s.placement_id)
            return redirect("student_detail", pk=s.pk)
    return render(request, "student_form.html", {"form": form, "title": "Add student"})


@role_required(*ADMIN_OFFICER)
def student_edit(request, pk):
    s = get_object_or_404(students_for(request.user), pk=pk)
    before = audit.snapshot(s, Student.AUDIT_FIELDS)
    form = StudentForm(request.POST or None, instance=s)
    if request.method == "POST" and form.is_valid():
        s = form.save()
        audit.log(request.user, "STUDENT_UPDATE", s, before, audit.snapshot(s, Student.AUDIT_FIELDS), request=request)
        messages.success(request, "Student updated.")
        return redirect("student_detail", pk=s.pk)
    return render(request, "student_form.html", {"form": form, "title": "Edit %s" % s.placement_id})


@require_POST
@role_required(*ADMIN_OFFICER)
def student_archive(request, pk):
    s = get_object_or_404(students_for(request.user), pk=pk)
    before = audit.snapshot(s, Student.AUDIT_FIELDS)
    s.is_archived = not s.is_archived
    s.save(update_fields=["is_archived", "updated_at"])
    audit.log(request.user, "STUDENT_ARCHIVE" if s.is_archived else "STUDENT_RESTORE", s, before,
              audit.snapshot(s, Student.AUDIT_FIELDS), request=request)
    messages.success(request, "Student archived." if s.is_archived else "Student restored.")
    return redirect("student_list")


@require_POST
@role_required(R.ADMIN)
def student_delete(request, pk):
    s = get_object_or_404(Student, pk=pk)
    if s.offers.exists():
        messages.error(request, "Cannot delete: placement history exists. Archive the record instead.")
        return redirect("student_detail", pk=pk)
    before = audit.snapshot(s, Student.AUDIT_FIELDS)
    pid = s.placement_id
    s.delete()
    audit.log(request.user, "STUDENT_DELETE", before=before, request=request, object_type="Student", object_id=pid)
    messages.success(request, "Student %s deleted." % pid)
    return redirect("student_list")


@role_required(*ADMIN_OFFICER)
def student_import(request):
    form = CSVUploadForm(request.POST or None, request.FILES or None)
    result = None
    if request.method == "POST" and form.is_valid():
        try:
            rows = parse_csv(form.cleaned_data["file"])
        except Exception as exc:  # decoding / size problems
            form.add_error("file", "Could not read the file: %s" % (exc if len(str(exc)) < 150 else "invalid format"))
            rows = None
        if rows is not None:
            created, errors = [], []
            for i, row in enumerate(rows, start=2):
                data = {k: (row.get(k) or "").strip() for k in
                        ["placement_id", "name", "mobile", "email", "course", "batch",
                         "registration_status", "eligibility_status", "remarks"]}
                f = StudentForm(data)
                if f.is_valid():
                    try:
                        with transaction.atomic():
                            s = f.save()
                        created.append(s.placement_id)
                    except IntegrityError:
                        errors.append((i, data["placement_id"], "Duplicate Placement ID"))
                else:
                    msg = "; ".join("%s: %s" % (k, " ".join(v)) for k, v in f.errors.items())
                    errors.append((i, data["placement_id"][:20], msg[:200]))
            audit.log(request.user, "STUDENT_IMPORT", request=request, object_type="Student",
                      after={"created": created[:200], "created_count": len(created), "rejected_count": len(errors)})
            result = {"created": len(created), "errors": errors}
    return render(request, "student_import.html", {"form": form, "result": result})


@role_required(*ADMIN_OFFICER)
def export_page(request):
    if request.method == "POST":
        kind = request.POST.get("kind")
        sensitive = request.user.is_admin and request.POST.get("sensitive") == "1"
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="%s_export.csv"' % ("offers" if kind == "offers" else "students")
        w = csv.writer(resp)
        if kind == "offers":
            hdr = ["Placement ID", "Student", "Course", "Company", "Category", "Offer type", "Acceptance",
                   "Joining", "PPO", "Off-campus"] + (["FTE CTC (LPA)", "Stipend (INR)", "Stipend period"] if sensitive else [])
            w.writerow(hdr)
            qs = Offer.objects.select_related("student", "company")
            for o in qs:
                row = [o.student.placement_id, o.student.name, o.student.course_label, o.company.name, o.category,
                       o.get_offer_type_display(), o.get_acceptance_status_display(),
                       o.get_joining_status_display(), o.get_ppo_status_display(), "Yes" if o.off_campus else "No"]
                if sensitive:
                    row += [o.ctc_lpa, o.stipend_amount, o.stipend_period]
                w.writerow([csv_safe(c) for c in row])
            count = qs.count()
        else:
            kind = "students"
            hdr = ["Placement ID", "Name", "Email", "Course", "Batch", "Registration", "Eligibility",
                   "Placement status"] + (["Mobile"] if sensitive else [])
            w.writerow(hdr)
            qs = Student.objects.filter(is_archived=False).prefetch_related("offers")
            count = 0
            for s in qs:
                row = [s.placement_id, s.name, s.email, s.course_label, s.batch,
                       s.get_registration_status_display(), s.get_eligibility_status_display(), s.placement_status]
                if sensitive:
                    row.append(s.mobile)
                w.writerow([csv_safe(c) for c in row])
                count += 1
        audit.log(request.user, "EXPORT_CSV", request=request, object_type=kind,
                  after={"rows": count, "sensitive_columns": sensitive})
        return resp
    return render(request, "export.html")


# ------------------------------------------------------------------ offers
def _drive_context():
    return list(Drive.objects.select_related("company"))


@role_required(*ADMIN_OFFICER)
def offer_create(request, pk):
    student = get_object_or_404(students_for(request.user), pk=pk)
    cfg = PolicyConfig.get()
    form = OfferForm(request.POST or None)
    decision = None
    if request.method == "POST" and form.is_valid():
        o = form.save(commit=False)
        o.student, o.created_by = student, request.user
        o.category = policy.category_for(o.ctc_lpa, o.company.category, cfg)
        if o.drive and o.drive.company_id != o.company_id:
            form.add_error("drive", "This drive belongs to a different company.")
        elif o.drive and o.drive.offer_type != o.offer_type:
            form.add_error("drive", "Offer type does not match the drive's offer type.")
        else:
            drives = _drive_context()
            absences = list(student.attendance.filter(status="ABSENT"))
            opp = policy.Opportunity(o.offer_type, o.category, o.ctc_lpa, o.drive_id,
                                     o.drive.course_list if o.drive else None, label="this offer")
            decision = policy.evaluate(student, opp, cfg, student.active_offers(), absences, drives)
            o.policy_outcome, o.policy_reasons = decision.outcome, decision.text
            o.acceptance_deadline = o.offered_at + timedelta(
                hours=min(cfg.acceptance_hours, o.company.response_hours))
            admin_override = (request.user.is_admin and request.POST.get("override") == "1"
                              and len(request.POST.get("override_reason", "").strip()) >= 10)
            if decision.outcome == policy.BLOCK and not o.off_campus and not admin_override:
                audit.log(request.user, "OFFER_BLOCKED", student, after={
                    "company": str(o.company), "type": o.offer_type, "reasons": decision.reasons}, request=request)
                return render(request, "offer_form.html", {"form": form, "st": student, "decision": decision,
                                                           "blocked": True})
            if decision.outcome != policy.ALLOW:
                o.needs_review = True
            action = "OFFER_CREATE"
            if decision.outcome == policy.BLOCK and admin_override:
                o.override_reason = request.POST.get("override_reason", "").strip()[:300]
                action = "OFFER_OVERRIDE"
            elif decision.outcome == policy.BLOCK and o.off_campus:
                action = "OFFER_OFFCAMPUS_FLAGGED"
            o.save()
            audit.log(request.user, action, o, after=audit.snapshot(o, Offer.AUDIT_FIELDS), request=request)
            if o.needs_review:
                messages.warning(request, "Offer recorded and flagged for Placement Cell review.")
            else:
                messages.success(request, "Offer recorded - policy check passed.")
            return redirect("student_detail", pk=student.pk)
    return render(request, "offer_form.html", {"form": form, "st": student, "decision": decision})


@role_required(*ADMIN_OFFICER)
def offer_update(request, pk):
    o = get_object_or_404(offers_for(request.user), pk=pk)
    before = audit.snapshot(o, Offer.AUDIT_FIELDS)
    form = OfferStatusForm(request.POST or None, instance=o)
    if request.method == "POST" and form.is_valid():
        if (before["acceptance_status"] == "EXPIRED" and form.cleaned_data["acceptance_status"] == "ACCEPTED"
                and not request.user.is_admin):
            form.add_error("acceptance_status", "Offer has expired; only an administrator can reinstate it.")
        else:
            o = form.save()
            audit.log(request.user, "OFFER_UPDATE", o, before, audit.snapshot(o, Offer.AUDIT_FIELDS), request=request)
            messages.success(request, "Offer updated.")
            return redirect("student_detail", pk=o.student_id)
    return render(request, "offer_status_form.html", {"form": form, "o": o})


@role_required(*ADMIN_OFFICER, R.COORDINATOR)
def offer_list(request):
    expire_overdue_offers()
    qs = offers_for(request.user)
    f = request.GET.get("f", "")
    if f == "pending":
        qs = qs.filter(acceptance_status="PENDING")
    elif f == "joining":
        qs = qs.filter(acceptance_status="ACCEPTED", joining_status="PENDING")
    elif f == "review":
        qs = qs.filter(needs_review=True)
    q = request.GET.get("q", "").strip()[:80]
    if q:
        qs = qs.filter(Q(company__name__icontains=q) | Q(student__name__icontains=q) | Q(student__placement_id__icontains=q))
    page = Paginator(qs, 30).get_page(request.GET.get("page"))
    return render(request, "offer_list.html", {"page": page, "qs": _qs(request), "f": f, "q": q,
                                               "show_comp": can_see_compensation(request.user)})


# ------------------------------------------------------------------ drives
@role_required(*ADMIN_OFFICER, R.COORDINATOR)
def drive_list(request):
    return render(request, "drive_list.html", {"drives": Drive.objects.select_related("company")})


@role_required(*ADMIN_OFFICER)
def drive_create(request):
    form = DriveForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        d = form.save()
        audit.log(request.user, "DRIVE_CREATE", d, after={"company": str(d.company), "title": d.title,
                                                          "date": d.date, "type": d.offer_type, "ctc": d.ctc_lpa}, request=request)
        messages.success(request, "Drive created.")
        return redirect("drive_detail", pk=d.pk)
    return render(request, "drive_form.html", {"form": form})


@role_required(*ADMIN_OFFICER, R.COORDINATOR)
def drive_detail(request, pk):
    drive = get_object_or_404(Drive.objects.select_related("company"), pk=pk)
    cfg = PolicyConfig.get()
    drives = list(Drive.objects.all())
    students = students_for(request.user).filter(is_archived=False, registration_status="REGISTERED").prefetch_related(
        Prefetch("offers", queryset=Offer.objects.select_related("company")),
        Prefetch("attendance", queryset=Attendance.objects.all()))
    opp = policy.Opportunity(drive.offer_type, drive.category, drive.ctc_lpa, drive.id, drive.course_list,
                             label="this drive")
    rows, counts = [], {policy.ALLOW: 0, policy.REVIEW: 0, policy.BLOCK: 0}
    att = {a.student_id: a for a in drive.attendance.all()}
    for s in students:
        absences = [a for a in s.attendance.all() if a.status == "ABSENT"]
        d = policy.evaluate(s, opp, cfg, s.active_offers(), absences, drives)
        counts[d.outcome] += 1
        rows.append({"s": s, "d": d, "att": att.get(s.pk)})
    rows.sort(key=lambda r: ({"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[r["d"].outcome], r["s"].placement_id))
    return render(request, "drive_detail.html", {
        "drive": drive, "rows": rows, "counts": counts, "show_comp": can_see_compensation(request.user),
        "can_edit": request.user.role in ADMIN_OFFICER, "att_choices": Attendance.Status.choices})


@require_POST
@role_required(*ADMIN_OFFICER)
def drive_attendance(request, pk):
    drive = get_object_or_404(Drive, pk=pk)
    valid = dict(Attendance.Status.choices)
    changed = 0
    for s in students_for(request.user).filter(is_archived=False, course__in=drive.course_list):
        val = request.POST.get("att_%d" % s.pk, "")
        if val not in valid:
            continue
        existing = Attendance.objects.filter(student=s, drive=drive).first()
        if existing and existing.status == val:
            continue
        Attendance.objects.update_or_create(student=s, drive=drive,
                                            defaults={"status": val, "recorded_by": request.user})
        audit.log(request.user, "ATTENDANCE_SET", s, {"status": existing.status if existing else None},
                  {"status": val, "drive": drive.title}, request=request)
        changed += 1
    messages.success(request, "Attendance saved (%d changes)." % changed)
    return redirect("drive_detail", pk=pk)


# ------------------------------------------------------------------- audit
@role_required(R.ADMIN)
def audit_list(request):
    qs = AuditLog.objects.all()
    action = request.GET.get("action", "").strip()[:60]
    actor = request.GET.get("actor", "").strip()[:150]
    if action:
        qs = qs.filter(action__icontains=action)
    if actor:
        qs = qs.filter(actor_name__icontains=actor)
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    return render(request, "audit_list.html", {"page": page, "qs": _qs(request), "action": action, "actor": actor})


@role_required(R.ADMIN)
def audit_verify(request):
    ok, bad_id, count = audit.verify_chain()
    audit.log(request.user, "AUDIT_VERIFY", request=request, note="ok" if ok else "TAMPERING at id %s" % bad_id)
    return render(request, "audit_verify.html", {"ok": ok, "bad_id": bad_id, "count": count})


def csrf_failure(request, reason=""):
    return render(request, "403.html", {"csrf": True}, status=403)
