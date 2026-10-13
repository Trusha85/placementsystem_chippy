import csv
import io

from datetime import timedelta

from django import forms
from django.conf import settings
from django.utils import timezone

from .models import COURSES, Attendance, Company, Drive, Offer, PolicyConfig, Student


class StudentForm(forms.ModelForm):
    """Whitelist of fields: placement status/offers can NEVER be set through this form."""

    class Meta:
        model = Student
        fields = ["placement_id", "name", "mobile", "email", "course", "batch",
                  "registration_status", "eligibility_status", "remarks"]
        widgets = {"remarks": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:       # placement ID is immutable once created
            self.fields["placement_id"].disabled = True

    def clean_placement_id(self):
        return (self.cleaned_data["placement_id"] or "").strip().upper()

    def clean_name(self):
        return " ".join(self.cleaned_data["name"].split())


class CSVUploadForm(forms.Form):
    file = forms.FileField(label="CSV file")

    def clean_file(self):
        f = self.cleaned_data["file"]
        if not f.name.lower().endswith(".csv"):
            raise forms.ValidationError("Only .csv files are accepted.")
        if f.size > 1024 * 1024:
            raise forms.ValidationError("File too large (max 1 MB).")
        return f


def parse_csv(upload):
    text = upload.read().decode("utf-8-sig", errors="strict")
    rows = list(csv.DictReader(io.StringIO(text)))
    if len(rows) > settings.IMPORT_MAX_ROWS:
        raise forms.ValidationError("Too many rows (max %d)." % settings.IMPORT_MAX_ROWS)
    return rows


class OfferForm(forms.ModelForm):
    override = forms.BooleanField(required=False, label="Administrator override of a policy block")
    override_reason = forms.CharField(required=False, max_length=300, label="Override justification")

    class Meta:
        model = Offer
        fields = ["company", "drive", "offer_type", "ctc_lpa", "stipend_amount", "stipend_period",
                  "offered_at", "ppo_status", "off_campus", "noc_status", "remarks"]
        widgets = {"offered_at": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M")}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["offered_at"].input_formats = ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"]
        self.fields["drive"].required = False

    def clean(self):
        d = super().clean()
        t, ctc, stipend = d.get("offer_type"), d.get("ctc_lpa"), d.get("stipend_amount")
        if t == "F" and ctc is None:
            self.add_error("ctc_lpa", "FTE-only offers need an annual CTC (LPA).")
        if t == "I" and stipend is None:
            self.add_error("stipend_amount", "Internship-only offers need a stipend amount.")
        if t == "I" and ctc is not None:
            self.add_error("ctc_lpa", "Internship-only offers have no FTE CTC; enter the stipend instead.")
        if t == "IF" and stipend is None:
            self.add_error("stipend_amount", "I+F offers need an internship stipend.")
        if stipend is not None and not d.get("stipend_period"):
            self.add_error("stipend_period", "Select the stipend payment period.")
        if d.get("offered_at") and d["offered_at"] > timezone.now() + timedelta(days=1):
            self.add_error("offered_at", "Offer date cannot be in the future.")
        return d


class OfferStatusForm(forms.ModelForm):
    """Only workflow-status fields are editable after creation - not package, type or category."""

    class Meta:
        model = Offer
        fields = ["acceptance_status", "joining_status", "ppo_status", "noc_status", "remarks"]


class DriveForm(forms.ModelForm):
    eligible = forms.MultipleChoiceField(choices=COURSES, widget=forms.CheckboxSelectMultiple,
                                         label="Eligible programmes", initial=[c for c, _ in COURSES])

    class Meta:
        model = Drive
        fields = ["company", "title", "date", "offer_type", "ctc_lpa"]
        widgets = {"date": forms.DateInput(attrs={"type": "date"})}

    def clean(self):
        d = super().clean()
        if d.get("offer_type") in ("F", "IF") and d.get("ctc_lpa") is None:
            self.add_error("ctc_lpa", "Provide the offered CTC (LPA) to categorise this drive.")
        return d

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.eligible_courses = ",".join(self.cleaned_data["eligible"])
        if commit:
            obj.save()
        return obj


class OtpForm(forms.Form):
    code = forms.CharField(max_length=6, min_length=6, label="6-digit code")
