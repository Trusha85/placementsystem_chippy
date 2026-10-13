"""Automated tests: policy enforcement, RBAC/IDOR, injection/XSS/CSRF, audit integrity.
Run:  python manage.py test -v 2
"""
import csv
import io
import time
from datetime import date, timedelta
from decimal import Decimal

from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from . import audit, policy
from .models import (Attendance, AuditLog, Company, Drive, Offer, PolicyConfig, Student, User)
from .security import csv_safe, totp


def mk_student(pid, course="MTECH_CS", **kw):
    d = dict(placement_id=pid, name="Test Student", mobile="9876543210", email=pid.lower() + "@x.in",
             course=course, batch="2025-27", registration_status="REGISTERED", eligibility_status="ELIGIBLE")
    d.update(kw)
    return Student.objects.create(**d)


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.cfg = PolicyConfig.get()
        self.co = {n: Company.objects.create(name=n, category=c) for n, c in
                   [("AP", "A+"), ("A1", "A"), ("B1", "B"), ("C1", "C"), ("B2", "B")]}
        self.admin = User.objects.create_user("adm", password="Str0ng#Pass123", role="ADMIN")
        self.officer = User.objects.create_user("off", password="Str0ng#Pass123", role="OFFICER")
        self.s1 = mk_student("TEST0001")
        self.s2 = mk_student("TEST0002", course="MSC_CS")
        self.coord = User.objects.create_user("co", password="Str0ng#Pass123", role="COORDINATOR", course="MTECH_CS")
        self.rec = User.objects.create_user("rec", password="Str0ng#Pass123", role="RECRUITER", company=self.co["B1"])
        self.stu1 = User.objects.create_user("st1", password="Str0ng#Pass123", role="STUDENT", student=self.s1)

    def offer(self, stu, co, t, ctc=None, stipend=None, acc="ACCEPTED", **kw):
        c = self.co[co]
        cat = policy.category_for(Decimal(ctc) if ctc else None, c.category, self.cfg)
        return Offer.objects.create(student=stu, company=c, offer_type=t, category=cat,
                                    ctc_lpa=Decimal(ctc) if ctc else None,
                                    stipend_amount=Decimal(stipend) if stipend else None,
                                    stipend_period="MONTHLY" if stipend else "", acceptance_status=acc,
                                    acceptance_deadline=timezone.now() + timedelta(hours=24), **kw)

    def check(self, stu, t, cat, ctc=None, **kw):
        stu = Student.objects.get(pk=stu.pk)
        return policy.evaluate(stu, policy.Opportunity(t, cat, Decimal(ctc) if ctc else None, **kw),
                               self.cfg, stu.active_offers(), kw.get("absences", ()), kw.get("drives", ()))


# ------------------------------------------------------------ policy engine
class PolicyEngineTests(Base):
    def test_category_thresholds(self):
        f = lambda x: policy.category_for(Decimal(x), "C", self.cfg)
        self.assertEqual([f("16"), f("15.99"), f("10"), f("9.99"), f("6"), f("5.99")], ["A+", "A", "A", "B", "B", "C"])

    def test_unplaced_student_allowed(self):
        self.assertEqual(self.check(self.s1, "F", "B", "8").outcome, policy.ALLOW)

    def test_A_plus_selected_is_out_of_process(self):
        self.offer(self.s1, "AP", "F", "18")
        for t in ("I", "F", "IF"):
            self.assertEqual(self.check(self.s1, t, "A+", "25").outcome, policy.BLOCK)

    def test_A_can_only_switch_to_A_plus(self):
        self.offer(self.s1, "A1", "F", "12")
        self.assertEqual(self.check(self.s1, "F", "A", "13").outcome, policy.BLOCK)
        self.assertEqual(self.check(self.s1, "F", "B", "8").outcome, policy.BLOCK)
        self.assertEqual(self.check(self.s1, "F", "A+", "20").outcome, policy.ALLOW)
        self.assertEqual(self.check(self.s1, "I", "B").outcome, policy.ALLOW)        # internships stay open (§5.2)

    def test_B_needs_1_5x_package(self):
        self.offer(self.s1, "B1", "F", "8")
        self.assertEqual(self.check(self.s1, "F", "A", None).outcome, policy.REVIEW)    # package unknown -> manual
        self.assertEqual(self.check(self.s1, "F", "A", "11.9").outcome, policy.BLOCK)   # 11.9 < 12
        self.assertEqual(self.check(self.s1, "F", "A", "12").outcome, policy.ALLOW)     # exactly 1.5x
        self.assertEqual(self.check(self.s1, "IF", "A", "12").outcome, policy.ALLOW)

    def test_C_only_higher_category(self):
        self.offer(self.s1, "C1", "F", "4")
        self.assertEqual(self.check(self.s1, "F", "C", "5").outcome, policy.BLOCK)
        self.assertEqual(self.check(self.s1, "F", "B", "7").outcome, policy.ALLOW)

    def test_internship_only_blocks_second_internship_but_allows_fte(self):
        self.offer(self.s1, "B1", "I", stipend="30000")
        self.assertEqual(self.check(self.s1, "I", "A+").outcome, policy.BLOCK)
        self.assertEqual(self.check(self.s1, "F", "C", "4").outcome, policy.ALLOW)
        self.assertEqual(self.check(self.s1, "IF", "B", "8").outcome, policy.ALLOW)

    def test_fte_only_blocks_plain_second_fte_but_allows_internship_and_valid_switch(self):
        self.offer(self.s1, "AP", "F", "10")  # category A (10 LPA)
        self.assertEqual(self.check(self.s1, "F", "A", "12").outcome, policy.BLOCK)
        self.assertEqual(self.check(self.s1, "I", "C").outcome, policy.ALLOW)
        self.assertEqual(self.check(self.s1, "IF", "A+", "20").outcome, policy.ALLOW)

    def test_IF_blocks_everything(self):
        self.offer(self.s1, "B1", "IF", "8", stipend="30000")
        for t in ("I", "F", "IF"):
            self.assertEqual(self.check(self.s1, t, "A+", "30").outcome, policy.BLOCK)

    def test_declined_or_expired_offer_does_not_restrict(self):
        self.offer(self.s1, "AP", "F", "18", acc="DECLINED")
        self.offer(self.s1, "AP", "F", "18", acc="EXPIRED")
        self.assertEqual(self.check(self.s1, "F", "C", "4").outcome, policy.ALLOW)
        self.assertEqual(Student.objects.get(pk=self.s1.pk).placement_status, "Unplaced")

    def test_registration_and_eligibility(self):
        self.s1.registration_status = "DEREGISTERED"; self.s1.save()
        self.assertEqual(self.check(self.s1, "F", "C", "3").outcome, policy.BLOCK)
        self.s1.registration_status = "REGISTERED"; self.s1.eligibility_status = "INELIGIBLE"; self.s1.save()
        self.assertEqual(self.check(self.s1, "F", "C", "3").outcome, policy.BLOCK)
        self.s1.eligibility_status = "PENDING"; self.s1.save()
        self.assertEqual(self.check(self.s1, "F", "C", "3").outcome, policy.REVIEW)

    def test_company_course_criteria(self):
        r = policy.evaluate(self.s2, policy.Opportunity("F", "B", Decimal(8), eligible_courses=["MTECH_CS"]),
                            self.cfg, [])
        self.assertEqual(r.outcome, policy.BLOCK)

    def test_absenteeism_flags_next_three_drives_only(self):
        ds = [Drive.objects.create(company=self.co["B1"], title="D%d" % i, date=date.today() + timedelta(days=i),
                                   offer_type="F", ctc_lpa=Decimal(8)) for i in range(5)]
        ab = Attendance.objects.create(student=self.s1, drive=ds[0], status="ABSENT")
        def ev(d):
            return policy.evaluate(self.s1, policy.Opportunity("F", "B", Decimal(8), drive_id=d.id), self.cfg, [], [ab], ds).outcome
        self.assertEqual([ev(d) for d in ds], [policy.ALLOW, policy.REVIEW, policy.REVIEW, policy.REVIEW, policy.ALLOW])
        ab.status = "EXCUSED"; ab.save()
        self.assertTrue(all(policy.evaluate(self.s1, policy.Opportunity("F", "B", Decimal(8), drive_id=d.id), self.cfg, [],
                                            list(Attendance.objects.filter(status="ABSENT")), ds).outcome == policy.ALLOW for d in ds))

    def test_reasons_explain_decision(self):
        self.offer(self.s1, "A1", "F", "12")
        d = self.check(self.s1, "F", "B", "8")
        self.assertTrue(any("§6.2" in r for r in d.reasons))

    def test_configurable_threshold(self):
        self.cfg.a_plus_min = Decimal("20"); self.cfg.save()
        self.assertEqual(policy.category_for(Decimal(18), "C", PolicyConfig.get()), "A")


# ---------------------------------------------------- offer workflow via UI
class OfferWorkflowTests(Base):
    def post_offer(self, user, stu, **data):
        c = Client(); c.force_login(user)
        base = {"company": self.co["B2"].pk, "offer_type": "F", "ctc_lpa": "8", "offered_at": timezone.now().strftime("%Y-%m-%dT%H:%M"),
                "ppo_status": "NA", "noc_status": "NA"}
        base.update(data)
        return c.post(reverse("offer_create", args=[stu.pk]), base)

    def test_policy_violation_cannot_be_saved_by_officer(self):
        self.offer(self.s1, "AP", "F", "18")
        r = self.post_offer(self.officer, self.s1)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "BLOCK")
        self.assertEqual(Offer.objects.filter(student=self.s1).count(), 1)
        self.assertTrue(AuditLog.objects.filter(action="OFFER_BLOCKED").exists())

    def test_officer_cannot_override_but_admin_can_with_reason(self):
        self.offer(self.s1, "AP", "F", "18")
        self.post_offer(self.officer, self.s1, override="1", override_reason="Approved by director verbally")
        self.assertEqual(Offer.objects.filter(student=self.s1).count(), 1)
        self.post_offer(self.admin, self.s1, override="1", override_reason="x")          # too short
        self.assertEqual(Offer.objects.filter(student=self.s1).count(), 1)
        self.post_offer(self.admin, self.s1, override="1", override_reason="Exception approved by committee 12/10")
        self.assertEqual(Offer.objects.filter(student=self.s1).count(), 2)
        o = Offer.objects.filter(student=self.s1).order_by("-id").first()
        self.assertTrue(o.needs_review)
        self.assertTrue(AuditLog.objects.filter(action="OFFER_OVERRIDE").exists())

    def test_allowed_offer_saved_with_deadline_min_24h(self):
        self.co["B2"].response_hours = 12; self.co["B2"].save()
        r = self.post_offer(self.officer, self.s1)
        self.assertEqual(r.status_code, 302)
        o = Offer.objects.get(student=self.s1)
        self.assertEqual(o.acceptance_deadline - o.offered_at, timedelta(hours=12))
        self.assertEqual(o.category, "B")

    def test_off_campus_violation_recorded_and_flagged(self):
        self.offer(self.s1, "AP", "F", "18")
        self.post_offer(self.officer, self.s1, off_campus="on")
        o = Offer.objects.filter(student=self.s1, off_campus=True).first()
        self.assertIsNotNone(o); self.assertTrue(o.needs_review)

    def test_fte_requires_ctc_and_internship_requires_stipend(self):
        r = self.post_offer(self.officer, self.s1, ctc_lpa="")
        self.assertContains(r, "need an annual CTC")
        r = self.post_offer(self.officer, self.s1, offer_type="I", ctc_lpa="", stipend_amount="")
        self.assertContains(r, "need a stipend")

    def test_pending_offer_expires(self):
        o = self.offer(self.s1, "B1", "F", "8", acc="PENDING")
        Offer.objects.filter(pk=o.pk).update(acceptance_deadline=timezone.now() - timedelta(hours=1))
        from .models import expire_overdue_offers
        expire_overdue_offers()
        o.refresh_from_db()
        self.assertEqual(o.acceptance_status, "EXPIRED")
        self.assertEqual(Student.objects.get(pk=self.s1.pk).placement_status, "Unplaced")

    def test_officer_cannot_reinstate_expired_offer(self):
        o = self.offer(self.s1, "B1", "F", "8", acc="EXPIRED")
        c = Client(); c.force_login(self.officer)
        c.post(reverse("offer_update", args=[o.pk]), {"acceptance_status": "ACCEPTED", "joining_status": "PENDING",
                                                      "ppo_status": "NA", "noc_status": "NA"})
        o.refresh_from_db(); self.assertEqual(o.acceptance_status, "EXPIRED")

    def test_offer_package_cannot_be_edited_after_creation(self):
        o = self.offer(self.s1, "B1", "F", "8")
        c = Client(); c.force_login(self.admin)
        c.post(reverse("offer_update", args=[o.pk]), {"acceptance_status": "ACCEPTED", "joining_status": "JOINED",
               "ppo_status": "NA", "noc_status": "NA", "ctc_lpa": "99", "category": "A+", "offer_type": "I"})
        o.refresh_from_db()
        self.assertEqual((o.ctc_lpa, o.category, o.offer_type, o.joining_status), (Decimal("8.00"), "B", "F", "JOINED"))


# --------------------------------------------------------- reports
class ReportTests(Base):
    def test_unique_students_vs_offers_and_separate_money(self):
        from . import reports
        self.offer(self.s1, "B1", "I", stipend="30000")
        self.offer(self.s1, "A1", "F", "12")
        self.offer(self.s2, "C1", "F", "4")
        st = reports.compute(Student.objects.all(), Offer.objects.all())
        self.assertEqual((st["placed"], st["total_offers"]), (2, 3))
        self.assertEqual(st["fte"]["highest"], Decimal("12.00"))
        self.assertEqual(st["fte"]["median"], Decimal("8"))      # per-student: 12 and 4
        self.assertEqual(st["stipend"]["highest"], Decimal("30000.00"))
        self.assertEqual(st["kinds"]["Internship + PPO/FTE"], 1)

    def test_coordinator_dashboard_hides_compensation(self):
        self.offer(self.s1, "A1", "F", "12")
        c = Client(); c.force_login(self.coord)
        r = c.get(reverse("dashboard"))
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "12.00"); self.assertNotContains(r, "Annual FTE CTC")


# ------------------------------------------- access control / IDOR / tampering
class AccessControlTests(Base):
    def test_anonymous_redirected_to_login(self):
        for name, args in [("dashboard", []), ("student_list", []), ("student_detail", [self.s1.pk]), ("audit_list", [])]:
            r = Client().get(reverse(name, args=args))
            self.assertEqual(r.status_code, 302); self.assertIn("/login/", r["Location"])

    def test_student_sees_own_record_not_others(self):
        c = Client(); c.force_login(self.stu1)
        self.assertEqual(c.get(reverse("student_detail", args=[self.s1.pk])).status_code, 200)
        self.assertEqual(c.get(reverse("student_detail", args=[self.s2.pk])).status_code, 404)   # IDOR blocked

    def test_student_cannot_modify_status_or_package(self):
        self.offer(self.s1, "B1", "F", "8")
        c = Client(); c.force_login(self.stu1)
        self.assertEqual(c.post(reverse("student_edit", args=[self.s1.pk]), {"name": "Hacker"}).status_code, 403)
        self.assertEqual(c.post(reverse("offer_create", args=[self.s1.pk]), {"offer_type": "F"}).status_code, 403)
        o = Offer.objects.get(student=self.s1)
        self.assertEqual(c.post(reverse("offer_update", args=[o.pk]), {"acceptance_status": "DECLINED"}).status_code, 403)
        self.assertEqual(c.get(reverse("student_list")).status_code, 403)
        self.assertEqual(c.post(reverse("student_archive", args=[self.s1.pk])).status_code, 403)
        self.assertEqual(c.get(reverse("export")).status_code, 403)
        self.s1.refresh_from_db(); o.refresh_from_db()
        self.assertEqual((self.s1.name, o.acceptance_status), ("Test Student", "ACCEPTED"))
        self.assertTrue(AuditLog.objects.filter(action="ACCESS_DENIED", actor=self.stu1).exists())

    def test_placement_status_not_settable_via_edit_form(self):
        c = Client(); c.force_login(self.officer)
        c.post(reverse("student_edit", args=[self.s1.pk]), {
            "placement_id": "HACKED99", "name": "Test Student", "mobile": "9876543210", "email": "a@b.in",
            "course": "MTECH_CS", "batch": "2025-27", "registration_status": "REGISTERED",
            "eligibility_status": "ELIGIBLE", "remarks": "", "placement_status": "FTE only", "is_archived": "on"})
        self.s1.refresh_from_db()
        self.assertEqual(self.s1.placement_id, "TEST0001")          # immutable
        self.assertFalse(self.s1.is_archived)                        # mass-assignment ignored
        self.assertEqual(Student.objects.get(pk=self.s1.pk).placement_status, "Unplaced")

    def test_coordinator_limited_to_own_course(self):
        c = Client(); c.force_login(self.coord)
        self.assertEqual(c.get(reverse("student_detail", args=[self.s1.pk])).status_code, 200)
        self.assertEqual(c.get(reverse("student_detail", args=[self.s2.pk])).status_code, 404)
        self.assertNotContains(c.get(reverse("student_list")), "TEST0002")
        r = c.get(reverse("student_detail", args=[self.s1.pk]))
        self.assertNotContains(r, "9876543210"); self.assertContains(r, "Restricted for your role")
        self.assertEqual(c.get(reverse("export")).status_code, 403)
        self.assertEqual(c.get(reverse("audit_list")).status_code, 403)

    def test_recruiter_sees_only_own_company_and_no_contacts(self):
        self.offer(self.s1, "B1", "F", "8"); self.offer(self.s2, "A1", "F", "12")
        c = Client(); c.force_login(self.rec)
        r = c.get(reverse("recruiter_home"))
        self.assertContains(r, "TEST0001"); self.assertNotContains(r, "TEST0002")
        self.assertEqual(c.get(reverse("student_detail", args=[self.s2.pk])).status_code, 404)
        d = c.get(reverse("student_detail", args=[self.s1.pk]))
        self.assertNotContains(d, "9876543210"); self.assertNotContains(d, "test0001@x.in")
        self.assertEqual(c.get(reverse("student_list")).status_code, 403)

    def test_recruiter_cannot_see_other_company_offers_on_shared_student(self):
        self.offer(self.s1, "B1", "F", "8"); self.offer(self.s1, "A1", "I", stipend="55555")
        c = Client(); c.force_login(self.rec)
        d = c.get(reverse("student_detail", args=[self.s1.pk]))
        self.assertNotContains(d, "55555"); self.assertNotContains(d, "A1")

    def test_only_admin_can_delete_and_only_without_history(self):
        o = Client(); o.force_login(self.officer)
        self.assertEqual(o.post(reverse("student_delete", args=[self.s2.pk])).status_code, 403)
        a = Client(); a.force_login(self.admin)
        self.offer(self.s1, "B1", "F", "8")
        a.post(reverse("student_delete", args=[self.s1.pk]))
        self.assertTrue(Student.objects.filter(pk=self.s1.pk).exists())     # history preserved
        a.post(reverse("student_delete", args=[self.s2.pk]))
        self.assertFalse(Student.objects.filter(pk=self.s2.pk).exists())

    def test_archive_preserves_history(self):
        self.offer(self.s1, "B1", "F", "8")
        c = Client(); c.force_login(self.officer)
        c.post(reverse("student_archive", args=[self.s1.pk]))
        self.s1.refresh_from_db(); self.assertTrue(self.s1.is_archived)
        self.assertEqual(Offer.objects.filter(student=self.s1).count(), 1)

    def test_role_cannot_be_escalated_by_flags(self):
        u = User.objects.create_user("x", password="Str0ng#Pass123", role="STUDENT", is_staff=True, is_superuser=True)
        self.assertEqual(u.role, "ADMIN")        # superuser flag maps to admin role, not the reverse
        u2 = User.objects.create_user("y", password="Str0ng#Pass123", role="OFFICER", is_staff=True)
        self.assertFalse(u2.is_staff)
        c = Client(); c.force_login(u2)
        self.assertEqual(c.get("/admin-console/").status_code, 302)


# ------------------------------------------- injection / XSS / CSRF / sessions
class WebAttackTests(Base):
    def test_sql_injection_in_search_and_filters(self):
        c = Client(); c.force_login(self.officer)
        for payload in ["' OR '1'='1", "'; DROP TABLE core_student; --", "\" UNION SELECT * FROM core_user --", "1' AND SLEEP(5)--"]:
            r = c.get(reverse("student_list"), {"q": payload, "course": payload, "batch": payload, "status": payload})
            self.assertEqual(r.status_code, 200)
            self.assertNotContains(r, "TEST0002")      # no "return everything" behaviour
        self.assertEqual(Student.objects.count(), 2)
        self.assertIn("core_student", connection.introspection.table_names())
        r = c.get(reverse("offer_list"), {"q": "' OR 1=1 --"}); self.assertEqual(r.status_code, 200)

    def test_sql_injection_in_login(self):
        r = Client().post(reverse("login"), {"username": "adm' OR '1'='1' --", "password": "x' OR '1'='1"})
        self.assertContains(r, "Invalid credentials")

    def test_stored_xss_is_escaped_and_names_validated(self):
        c = Client(); c.force_login(self.officer)
        s = mk_student("XSS00001", remarks="<script>alert(1)</script><img src=x onerror=alert(2)>")
        r = c.get(reverse("student_detail", args=[s.pk]))
        self.assertNotContains(r, "<script>alert(1)")
        self.assertContains(r, "&lt;script&gt;alert(1)&lt;/script&gt;")
        resp = c.post(reverse("student_create"), {
            "placement_id": "XSS00002", "name": "<script>alert(1)</script>", "mobile": "9876543210", "email": "a@b.in",
            "course": "MSC_CS", "batch": "2025-27", "registration_status": "REGISTERED", "eligibility_status": "ELIGIBLE"})
        self.assertEqual(resp.status_code, 200)          # re-rendered with validation error
        self.assertFalse(Student.objects.filter(placement_id="XSS00002").exists())

    def test_reflected_xss_in_search_box(self):
        c = Client(); c.force_login(self.officer)
        r = c.get(reverse("student_list"), {"q": '"><script>alert(1)</script>'})
        self.assertNotContains(r, "<script>alert(1)</script>")

    def test_csp_and_security_headers(self):
        c = Client(); c.force_login(self.officer)
        r = c.get(reverse("dashboard"))
        self.assertIn("script-src 'self'", r["Content-Security-Policy"])
        self.assertEqual(r["X-Frame-Options"], "DENY"); self.assertEqual(r["Cache-Control"], "no-store")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")

    def test_csrf_enforced_on_state_changing_requests(self):
        c = Client(enforce_csrf_checks=True); c.force_login(self.officer)
        r = c.post(reverse("student_archive", args=[self.s1.pk]))
        self.assertEqual(r.status_code, 403)
        self.s1.refresh_from_db(); self.assertFalse(self.s1.is_archived)
        self.assertEqual(c.post(reverse("logout")).status_code, 403)

    def test_state_change_requires_post(self):
        c = Client(); c.force_login(self.officer)
        self.assertEqual(c.get(reverse("student_archive", args=[self.s1.pk])).status_code, 405)
        self.assertEqual(c.get(reverse("logout")).status_code, 405)

    def test_duplicate_placement_id_rejected_ui_and_db(self):
        c = Client(); c.force_login(self.officer)
        r = c.post(reverse("student_create"), {
            "placement_id": "test0001", "name": "Dup", "mobile": "9876543210", "email": "a@b.in", "course": "MSC_CS",
            "batch": "2025-27", "registration_status": "REGISTERED", "eligibility_status": "ELIGIBLE"})
        self.assertContains(r, "already exists")
        self.assertEqual(Student.objects.filter(placement_id="TEST0001").count(), 1)

    def test_csv_import_validates_and_rejects_duplicates(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        data = ("placement_id,name,mobile,email,course,batch,registration_status,eligibility_status,remarks\n"
                "IMP00001,Good Row,9123456789,g@x.in,MSC_DFIS,2025-27,REGISTERED,ELIGIBLE,\n"
                "IMP00001,Duplicate,9123456789,g@x.in,MSC_DFIS,2025-27,REGISTERED,ELIGIBLE,\n"
                "TEST0001,Existing,9123456789,g@x.in,MSC_DFIS,2025-27,REGISTERED,ELIGIBLE,\n"
                "IMP00003,Bad Mobile,123,g@x.in,MSC_DFIS,2025-27,REGISTERED,ELIGIBLE,\n"
                "IMP00004,Bad Course,9123456789,g@x.in,PHD,2025-27,REGISTERED,ELIGIBLE,\n"
                "IMP00005,=cmd|' /C calc'!A0,9123456789,g@x.in,MSC_CS,2025-27,REGISTERED,ELIGIBLE,\n")
        c = Client(); c.force_login(self.officer)
        r = c.post(reverse("student_import"), {"file": SimpleUploadedFile("s.csv", data.encode(), "text/csv")})
        self.assertEqual(r.context["result"]["created"], 1)
        self.assertEqual(len(r.context["result"]["errors"]), 5)
        bad = c.post(reverse("student_import"), {"file": SimpleUploadedFile("evil.exe", b"MZ", "application/octet-stream")})
        self.assertContains(bad, "Only .csv")

    def test_export_restrictions_and_csv_injection_guard(self):
        self.offer(self.s1, "A1", "F", "12")
        o = Client(); o.force_login(self.officer)
        body = o.post(reverse("export"), {"kind": "students", "sensitive": "1"}).content.decode()
        self.assertNotIn("9876543210", body)                          # officer cannot export mobile
        body = o.post(reverse("export"), {"kind": "offers", "sensitive": "1"}).content.decode()
        self.assertNotIn("12.00", body)
        a = Client(); a.force_login(self.admin)
        body = a.post(reverse("export"), {"kind": "students", "sensitive": "1"}).content.decode()
        self.assertIn("9876543210", body)
        self.assertEqual(AuditLog.objects.filter(action="EXPORT_CSV").count(), 3)
        self.assertEqual([csv_safe(x) for x in ["=1+1", "+x", "-y", "@z", "ok"]], ["'=1+1", "'+x", "'-y", "'@z", "ok"])

    def test_open_redirect_blocked_on_login(self):
        r = Client().post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123", "next": "//evil.example/"})
        self.assertEqual(r.status_code, 302); self.assertNotIn("evil", r["Location"])

    def test_lockout_after_repeated_failures(self):
        c = Client()
        for _ in range(5):
            c.post(reverse("login"), {"username": "adm", "password": "wrong"})
        r = c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123"})
        self.assertContains(r, "Too many failed attempts")
        self.assertNotIn("_auth_user_id", c.session)

    def test_session_cookie_flags_and_logout(self):
        c = Client()
        r = c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123"})
        self.assertTrue(c.cookies["sessionid"]["httponly"])
        self.assertEqual(c.cookies["sessionid"]["samesite"], "Strict")
        old = c.cookies["sessionid"].value
        c.post(reverse("logout"))
        self.assertEqual(c.get(reverse("dashboard")).status_code, 302)
        from django.conf import settings
        self.assertEqual(settings.SESSION_COOKIE_AGE, 900)

    def test_session_key_rotates_on_login(self):
        c = Client(); c.get(reverse("login"))
        before = c.session.session_key
        c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123"})
        self.assertNotEqual(before, c.session.session_key)

    def test_mfa_required_when_enabled(self):
        secret = "JBSWY3DPEHPK3PXP"
        self.admin.totp_secret, self.admin.mfa_enabled = secret, True; self.admin.save()
        c = Client()
        r = c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123"})
        self.assertContains(r, "Invalid credentials")
        r = c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123", "otp": "000000"})
        self.assertContains(r, "Invalid credentials")
        r = c.post(reverse("login"), {"username": "adm", "password": "Str0ng#Pass123", "otp": totp(secret)})
        self.assertEqual(r.status_code, 302)

    def test_password_hashing_and_validators(self):
        self.assertTrue(self.admin.password.startswith(("argon2", "pbkdf2_sha256")))
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError
        for weak in ["password", "12345678901", "short"]:
            with self.assertRaises(ValidationError):
                validate_password(weak)

    def test_mobile_encrypted_at_rest(self):
        with connection.cursor() as cur:
            cur.execute("SELECT mobile FROM core_student WHERE placement_id=%s", ["TEST0001"])
            raw = cur.fetchone()[0]
        self.assertNotIn("9876543210", raw); self.assertTrue(raw.startswith("gAAAA"))
        self.assertEqual(Student.objects.get(placement_id="TEST0001").mobile, "9876543210")

    def test_audit_never_stores_full_mobile(self):
        c = Client(); c.force_login(self.officer)
        c.post(reverse("student_edit", args=[self.s1.pk]), {
            "name": "Test Student", "mobile": "9123456780", "email": "a@b.in", "course": "MTECH_CS", "batch": "2025-27",
            "registration_status": "REGISTERED", "eligibility_status": "ELIGIBLE", "remarks": ""})
        e = AuditLog.objects.filter(action="STUDENT_UPDATE").first()
        self.assertEqual(e.before["mobile"], "******3210"); self.assertEqual(e.after["mobile"], "******6780")


# ------------------------------------------------------------ audit integrity
class AuditIntegrityTests(Base):
    def test_chain_valid_then_detects_tampering(self):
        c = Client(); c.force_login(self.officer)
        c.post(reverse("student_archive", args=[self.s1.pk]))
        c.post(reverse("student_archive", args=[self.s1.pk]))
        ok, bad, n = audit.verify_chain()
        self.assertTrue(ok); self.assertGreaterEqual(n, 2)
        e = AuditLog.objects.filter(action="STUDENT_ARCHIVE").first()
        AuditLog.objects.filter(pk=e.pk).update(after={"is_archived": False})          # DB-level tampering
        ok, bad, _ = audit.verify_chain()
        self.assertFalse(ok); self.assertEqual(bad, e.pk)

    def test_deleting_a_record_is_detected(self):
        for i in range(3):
            audit.log(self.officer, "T%d" % i)
        mid = AuditLog.objects.get(action="T1")
        AuditLog.objects.filter(pk=mid.pk)._raw_delete(AuditLog.objects.db)
        self.assertFalse(audit.verify_chain()[0])

    def test_audit_rows_are_immutable_via_orm(self):
        e = audit.log(self.officer, "X")
        e.action = "Y"
        with self.assertRaises(PermissionError): e.save()
        with self.assertRaises(PermissionError): e.delete()

    def test_sensitive_actions_logged_with_actor_and_before_after(self):
        c = Client(); c.force_login(self.officer)
        c.post(reverse("student_edit", args=[self.s1.pk]), {
            "name": "Renamed Person", "mobile": "9876543210", "email": "a@b.in", "course": "MTECH_CS", "batch": "2025-27",
            "registration_status": "REGISTERED", "eligibility_status": "ELIGIBLE", "remarks": ""})
        e = AuditLog.objects.get(action="STUDENT_UPDATE")
        self.assertEqual((e.actor_name, e.before["name"], e.after["name"]), ("off", "Test Student", "Renamed Person"))
        c.get(reverse("student_detail", args=[self.s1.pk]))
        self.assertTrue(AuditLog.objects.filter(action="VIEW_STUDENT").exists())

    def test_audit_page_admin_only(self):
        c = Client(); c.force_login(self.officer)
        self.assertEqual(c.get(reverse("audit_list")).status_code, 403)
        a = Client(); a.force_login(self.admin)
        self.assertEqual(a.get(reverse("audit_list")).status_code, 200)
        self.assertContains(a.get(reverse("audit_verify")), "Intact")


# ----------------------------------------------------------- page smoke tests
class SmokeTests(Base):
    def test_all_pages_render_for_staff(self):
        self.offer(self.s1, "A1", "F", "12")
        d = Drive.objects.create(company=self.co["AP"], title="Drive", date=date.today(), offer_type="F", ctc_lpa=Decimal(18))
        c = Client(); c.force_login(self.admin)
        for name, args in [("dashboard", []), ("student_list", []), ("student_create", []), ("student_import", []),
                           ("student_detail", [self.s1.pk]), ("student_edit", [self.s1.pk]),
                           ("offer_create", [self.s1.pk]), ("offer_list", []), ("drive_list", []), ("drive_create", []),
                           ("drive_detail", [d.pk]), ("export", []), ("audit_list", []), ("security_settings", []),
                           ("password_change", [])]:
            self.assertEqual(c.get(reverse(name, args=args)).status_code, 200, name)

    def test_drive_page_explains_decisions_and_saves_attendance(self):
        self.offer(self.s1, "AP", "F", "18")
        d = Drive.objects.create(company=self.co["B1"], title="Drive", date=date.today(), offer_type="F", ctc_lpa=Decimal(8))
        c = Client(); c.force_login(self.officer)
        r = c.get(reverse("drive_detail", args=[d.pk]))
        self.assertContains(r, "§6.1"); self.assertEqual(r.context["counts"]["BLOCK"], 1)
        c.post(reverse("drive_attendance", args=[d.pk]), {"att_%d" % self.s2.pk: "ABSENT", "att_%d" % self.s1.pk: "bogus"})
        self.assertEqual(Attendance.objects.get(student=self.s2, drive=d).status, "ABSENT")
        self.assertFalse(Attendance.objects.filter(student=self.s1).exists())
