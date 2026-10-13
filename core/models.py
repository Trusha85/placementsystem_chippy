from decimal import Decimal

from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone

from .security import EncryptedTextField

COURSES = [
    ("MTECH_CS", "M.Tech. CS"),
    ("MTECH_AIDS", "M.Tech. AIDS"),
    ("BTECH_MTECH_CS", "B.Tech.-M.Tech. CSE"),
    ("MSC_CS", "M.Sc. CS"),
    ("MSC_DFIS", "M.Sc. DFIS"),
]
COURSE_LABEL = dict(COURSES)
CATEGORIES = [("A+", "A+"), ("A", "A"), ("B", "B"), ("C", "C")]


class Company(models.Model):
    name = models.CharField(max_length=120, unique=True)
    category = models.CharField(max_length=2, choices=CATEGORIES, default="C",
                                help_text="Default category (used for internship-only offers).")
    response_hours = models.PositiveIntegerField(
        default=24, validators=[MinValueValidator(1), MaxValueValidator(24)],
        help_text="Company's stated acceptance timeline in hours (policy cap: 24).")

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "companies"

    def __str__(self):
        return self.name


class Student(models.Model):
    class Registration(models.TextChoices):
        REGISTERED = "REGISTERED", "Registered"
        DEREGISTERED = "DEREGISTERED", "Deregistered"
        NOT_REGISTERED = "NOT_REGISTERED", "Not registered"

    class Eligibility(models.TextChoices):
        ELIGIBLE = "ELIGIBLE", "Eligible"
        INELIGIBLE = "INELIGIBLE", "Ineligible"
        PENDING = "PENDING", "Pending verification"

    placement_id = models.CharField(
        max_length=20, unique=True,
        validators=[RegexValidator(r"^[A-Z0-9\-]{4,20}$", "4-20 chars: capital letters, digits, hyphen.")])
    name = models.CharField(
        max_length=100,
        validators=[RegexValidator(r"^[A-Za-z][A-Za-z .'\-]{1,99}$", "Letters, spaces, . ' - only.")])
    mobile = EncryptedTextField(
        validators=[RegexValidator(r"^[6-9]\d{9}$", "Enter a valid 10-digit Indian mobile number.")])
    email = models.EmailField()
    course = models.CharField(max_length=20, choices=COURSES)
    batch = models.CharField(max_length=9, validators=[RegexValidator(r"^\d{4}-\d{2}$", "Format: 2025-27")])
    registration_status = models.CharField(max_length=20, choices=Registration.choices,
                                           default=Registration.NOT_REGISTERED)
    eligibility_status = models.CharField(max_length=20, choices=Eligibility.choices,
                                          default=Eligibility.PENDING)
    remarks = models.CharField(max_length=500, blank=True)
    is_archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    AUDIT_FIELDS = ["placement_id", "name", "mobile", "email", "course", "batch",
                    "registration_status", "eligibility_status", "remarks", "is_archived"]

    class Meta:
        ordering = ["placement_id"]

    def __str__(self):
        return "%s - %s" % (self.placement_id, self.name)

    # Placement status is DERIVED from offer history - never typed in or editable,
    # so a student/clerk cannot "set" themselves as placed/unplaced.
    def active_offers(self):
        return [o for o in self.offers.all() if o.is_active]

    @property
    def placement_status(self):
        types = {o.offer_type for o in self.active_offers()}
        if not types:
            return "Unplaced"
        if "IF" in types or {"I", "F"} <= types:
            return "Internship + PPO/FTE"
        return "Internship only" if types == {"I"} else "FTE only"

    @property
    def course_label(self):
        return COURSE_LABEL.get(self.course, self.course)


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Placement Administrator"
        OFFICER = "OFFICER", "Placement Officer"
        COORDINATOR = "COORDINATOR", "Course Coordinator"
        RECRUITER = "RECRUITER", "Company / Recruiter"
        STUDENT = "STUDENT", "Student (read-only)"

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.STUDENT)
    course = models.CharField(max_length=20, choices=COURSES, blank=True,
                              help_text="Coordinators: the one course they may see.")
    company = models.ForeignKey(Company, null=True, blank=True, on_delete=models.SET_NULL,
                                help_text="Recruiters: the one company they may see.")
    student = models.OneToOneField(Student, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="login", help_text="Students: their own record.")
    totp_secret = models.CharField(max_length=64, blank=True)
    mfa_enabled = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # Role is the single source of truth for privileges (no stray staff/superuser flags).
        if self.is_superuser:
            self.role = self.Role.ADMIN
        self.is_staff = self.is_superuser = (self.role == self.Role.ADMIN)
        super().save(*args, **kwargs)

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def is_staff_member(self):  # admin or officer
        return self.role in (self.Role.ADMIN, self.Role.OFFICER)


class PolicyConfig(models.Model):
    """Single-row, admin-editable policy parameters (configurable rules)."""
    a_plus_min = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal("16"))
    a_min = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal("10"))
    b_min = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal("6"))
    b_switch_multiplier = models.DecimalField(max_digits=4, decimal_places=2, default=Decimal("1.5"))
    absence_exclusion_drives = models.PositiveIntegerField(default=3)
    acceptance_hours = models.PositiveIntegerField(default=24)

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def __str__(self):
        return "Placement policy parameters"


class Drive(models.Model):
    class OfferType(models.TextChoices):
        I = "I", "Internship only (I)"
        F = "F", "FTE only (F)"
        IF = "IF", "Internship + PPO/FTE (I+F)"

    company = models.ForeignKey(Company, on_delete=models.PROTECT, related_name="drives")
    title = models.CharField(max_length=150)
    date = models.DateField()
    offer_type = models.CharField(max_length=2, choices=OfferType.choices)
    ctc_lpa = models.DecimalField("CTC (LPA)", max_digits=6, decimal_places=2, null=True, blank=True,
                                  validators=[MinValueValidator(Decimal("0.1")), MaxValueValidator(Decimal("500"))])
    eligible_courses = models.CharField(max_length=200, default=",".join(c for c, _ in COURSES))

    class Meta:
        ordering = ["date", "id"]

    def __str__(self):
        return "%s - %s (%s)" % (self.company, self.title, self.date)

    @property
    def course_list(self):
        return [c for c in self.eligible_courses.split(",") if c]

    @property
    def category(self):
        from .policy import category_for
        return category_for(self.ctc_lpa, self.company.category, PolicyConfig.get())


class Attendance(models.Model):
    class Status(models.TextChoices):
        PRESENT = "PRESENT", "Present"
        ABSENT = "ABSENT", "Absent"
        EXCUSED = "EXCUSED", "Absent - emergency exception"

    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name="attendance")
    drive = models.ForeignKey(Drive, on_delete=models.CASCADE, related_name="attendance")
    status = models.CharField(max_length=10, choices=Status.choices)
    note = models.CharField(max_length=200, blank=True)
    recorded_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)

    class Meta:
        unique_together = [("student", "drive")]


class Offer(models.Model):
    class Type(models.TextChoices):
        I = "I", "Internship only (I)"
        F = "F", "FTE only (F)"
        IF = "IF", "Internship + PPO/FTE (I+F)"

    class Acceptance(models.TextChoices):
        PENDING = "PENDING", "Pending"
        ACCEPTED = "ACCEPTED", "Accepted"
        DECLINED = "DECLINED", "Declined"
        EXPIRED = "EXPIRED", "Expired"

    class Joining(models.TextChoices):
        PENDING = "PENDING", "Pending"
        JOINED = "JOINED", "Joined"
        NOT_JOINED = "NOT_JOINED", "Not joined"

    class PPO(models.TextChoices):
        NA = "NA", "Not applicable"
        PENDING = "PENDING", "Pending"
        OFFERED = "OFFERED", "Offered"
        ACCEPTED = "ACCEPTED", "Accepted"
        DECLINED = "DECLINED", "Declined"

    class NOC(models.TextChoices):
        NA = "NA", "Not applicable"
        PENDING = "PENDING", "Pending"
        ISSUED = "ISSUED", "Issued"
        DENIED = "DENIED", "Denied"

    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="offers")
    company = models.ForeignKey(Company, on_delete=models.PROTECT, related_name="offers")
    drive = models.ForeignKey(Drive, null=True, blank=True, on_delete=models.SET_NULL, related_name="offers")
    offer_type = models.CharField(max_length=2, choices=Type.choices)
    category = models.CharField(max_length=2, choices=CATEGORIES)
    ctc_lpa = models.DecimalField("FTE CTC (LPA)", max_digits=6, decimal_places=2, null=True, blank=True,
                                  validators=[MinValueValidator(Decimal("0.1")), MaxValueValidator(Decimal("500"))])
    stipend_amount = models.DecimalField("Internship stipend (INR)", max_digits=9, decimal_places=2,
                                         null=True, blank=True, validators=[MinValueValidator(Decimal("0"))])
    stipend_period = models.CharField(max_length=10, blank=True,
                                      choices=[("MONTHLY", "Per month"), ("TOTAL", "Total / one-time")])
    offered_at = models.DateTimeField(default=timezone.now)
    acceptance_deadline = models.DateTimeField(null=True, blank=True)
    acceptance_status = models.CharField(max_length=10, choices=Acceptance.choices, default=Acceptance.PENDING)
    joining_status = models.CharField(max_length=12, choices=Joining.choices, default=Joining.PENDING)
    ppo_status = models.CharField(max_length=10, choices=PPO.choices, default=PPO.NA)
    off_campus = models.BooleanField(default=False)
    noc_status = models.CharField(max_length=10, choices=NOC.choices, default=NOC.NA)
    needs_review = models.BooleanField(default=False)
    policy_outcome = models.CharField(max_length=10, blank=True)
    policy_reasons = models.TextField(blank=True)
    override_reason = models.CharField(max_length=300, blank=True)
    remarks = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    AUDIT_FIELDS = ["student", "company", "offer_type", "category", "ctc_lpa", "stipend_amount",
                    "stipend_period", "acceptance_status", "joining_status", "ppo_status", "off_campus",
                    "noc_status", "needs_review", "policy_outcome", "override_reason", "remarks"]

    class Meta:
        ordering = ["-offered_at", "-id"]

    @property
    def is_active(self):
        return self.acceptance_status in (self.Acceptance.PENDING, self.Acceptance.ACCEPTED)

    @property
    def has_fte(self):
        return self.offer_type in ("F", "IF")

    def __str__(self):
        return "%s -> %s (%s)" % (self.student.placement_id, self.company, self.offer_type)


class AuditLog(models.Model):
    timestamp = models.DateTimeField()
    actor = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    actor_name = models.CharField(max_length=150)
    action = models.CharField(max_length=60, db_index=True)
    object_type = models.CharField(max_length=40, blank=True)
    object_id = models.CharField(max_length=40, blank=True)
    before = models.JSONField(default=dict)
    after = models.JSONField(default=dict)
    ip = models.CharField(max_length=45, blank=True)
    note = models.CharField(max_length=300, blank=True)
    prev_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64)

    class Meta:
        ordering = ["-id"]

    def save(self, *args, **kwargs):  # append-only
        if self.pk is not None and not kwargs.get("force_insert"):
            raise PermissionError("Audit records are immutable.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("Audit records cannot be deleted.")


def expire_overdue_offers():
    """Mark pending offers whose acceptance deadline has passed as EXPIRED (audited)."""
    from . import audit
    now = timezone.now()
    for o in Offer.objects.filter(acceptance_status=Offer.Acceptance.PENDING,
                                  acceptance_deadline__lt=now).select_related("student", "company"):
        before = audit.snapshot(o, Offer.AUDIT_FIELDS)
        o.acceptance_status = Offer.Acceptance.EXPIRED
        o.save(update_fields=["acceptance_status", "updated_at"])
        audit.log(None, "OFFER_AUTO_EXPIRED", o, before, audit.snapshot(o, Offer.AUDIT_FIELDS),
                  note="Acceptance deadline passed")
