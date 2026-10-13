"""Create demo users, companies, drives, students and offers (fictional data)."""
import random
from datetime import date, timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.utils import timezone

from core import audit, policy
from core.models import (Attendance, Company, Drive, Offer, PolicyConfig, Student, User, COURSES)

PASSWORD = "Placement#2026Demo"
FIRST = ["Aarav", "Diya", "Ishaan", "Kavya", "Rohan", "Meera", "Vihaan", "Anaya", "Kabir", "Saanvi", "Arjun",
         "Tara", "Dev", "Riya", "Yash", "Nisha", "Karan", "Pooja", "Aditya", "Sneha", "Manav", "Ira", "Harsh",
         "Jiya", "Neel", "Sara", "Om", "Trisha", "Raj", "Anvi"]
LAST = ["Patel", "Shah", "Mehta", "Desai", "Joshi", "Trivedi", "Parmar", "Rana", "Modi", "Vyas"]


class Command(BaseCommand):
    help = "Seed demo data (fictional)."

    def handle(self, *args, **opts):
        random.seed(7)
        PolicyConfig.get()
        comps = {}
        for name, cat, hrs in [("Alpha Secure", "A+", 24), ("Beta Systems", "A", 24), ("Gamma Infotech", "B", 24),
                               ("Delta Services", "C", 12), ("Epsilon Labs", "B", 24), ("Zeta Cyber", "A", 24)]:
            comps[name], _ = Company.objects.get_or_create(name=name, defaults={"category": cat, "response_hours": hrs})
        today = date.today()
        specs = [("Alpha Secure", "Alpha - Security Engineer", -40, "F", "18"), ("Beta Systems", "Beta - Platform Engineer", -30, "F", "12"),
                 ("Gamma Infotech", "Gamma - Analyst", -20, "F", "7.5"), ("Delta Services", "Delta - Support Engineer", -12, "F", "4.5"),
                 ("Epsilon Labs", "Epsilon - Summer Intern", -6, "I", None), ("Zeta Cyber", "Zeta - Intern + PPO", 3, "IF", "11")]
        drives = []
        for co, title, off, t, ctc in specs:
            d, _ = Drive.objects.get_or_create(company=comps[co], title=title, defaults={
                "date": today + timedelta(days=off), "offer_type": t, "ctc_lpa": Decimal(ctc) if ctc else None})
            drives.append(d)

        students = []
        n = 0
        for ci, (code, label) in enumerate(COURSES):
            for k in range(6):
                n += 1
                pid = "NFSU%s%03d" % ("ABCDE"[ci], k + 1)
                s, _ = Student.objects.get_or_create(placement_id=pid, defaults={
                    "name": "%s %s" % (FIRST[n - 1], LAST[n % len(LAST)]),
                    "mobile": "9%09d" % (random.randint(10**8, 10**9 - 1)),
                    "email": "%s@nfsu.example" % pid.lower(), "course": code, "batch": "2025-27",
                    "registration_status": "REGISTERED", "eligibility_status": "ELIGIBLE"})
                students.append(s)
        # a few state oddities
        s = students[5]; s.eligibility_status = "INELIGIBLE"; s.remarks = "Backlog not cleared"; s.save()
        s = students[11]; s.registration_status = "DEREGISTERED"; s.save()
        s = students[17]; s.eligibility_status = "PENDING"; s.save()

        def offer(stu, co, t, ctc=None, stipend=None, acc="ACCEPTED", join="PENDING", drive=None, hours_ago=48, **kw):
            cfg = PolicyConfig.get()
            c = comps[co]
            cat = policy.category_for(Decimal(ctc) if ctc else None, c.category, cfg)
            when = timezone.now() - timedelta(hours=hours_ago)
            return Offer.objects.create(
                student=stu, company=c, drive=drive, offer_type=t, category=cat,
                ctc_lpa=Decimal(ctc) if ctc else None, stipend_amount=Decimal(stipend) if stipend else None,
                stipend_period="MONTHLY" if stipend else "", offered_at=when,
                acceptance_deadline=when + timedelta(hours=min(24, c.response_hours)),
                acceptance_status=acc, joining_status=join, policy_outcome="ALLOW",
                policy_reasons="[ALLOW] Seed data.", **kw)

        if not Offer.objects.exists():
            offer(students[0], "Alpha Secure", "F", "18", drive=drives[0], join="JOINED")          # A+ -> out of process
            offer(students[1], "Beta Systems", "F", "12", drive=drives[1])                         # A
            offer(students[2], "Gamma Infotech", "F", "7.5", drive=drives[2])                      # B
            offer(students[3], "Delta Services", "F", "4.5", drive=drives[3])                      # C
            offer(students[4], "Epsilon Labs", "I", stipend="35000", drive=drives[4], join="JOINED")  # I only
            offer(students[6], "Zeta Cyber", "IF", "11", stipend="40000", ppo_status="OFFERED")    # I+F
            offer(students[7], "Beta Systems", "F", "10.5")
            offer(students[8], "Gamma Infotech", "F", "9", hours_ago=2, acc="PENDING")             # pending acceptance
            offer(students[9], "Delta Services", "F", "5", acc="DECLINED")                         # declined: stays unplaced
            offer(students[10], "Gamma Infotech", "F", "6.5", acc="EXPIRED", hours_ago=90)         # expired
            offer(students[12], "Alpha Secure", "F", "20", join="JOINED")
            offer(students[13], "Epsilon Labs", "I", stipend="25000", drive=drives[4])
            offer(students[14], "Delta Services", "F", "4", off_campus=True, needs_review=True,
                  remarks="Off-campus offer reported by student")
            offer(students[15], "Beta Systems", "F", "11", join="NOT_JOINED")
        # absence at the first drive -> review flag for next 3 drives
        Attendance.objects.get_or_create(student=students[19], drive=drives[0], defaults={"status": "ABSENT"})
        Attendance.objects.get_or_create(student=students[20], drive=drives[0], defaults={"status": "EXCUSED", "note": "Medical emergency"})

        def user(name, role, **extra):
            u, created = User.objects.get_or_create(username=name, defaults={"role": role, **extra})
            if created:
                u.set_password(PASSWORD); u.save()
            return u
        user("admin", User.Role.ADMIN, first_name="Placement", last_name="Administrator")
        user("officer", User.Role.OFFICER, first_name="Placement", last_name="Officer")
        user("coord_cs", User.Role.COORDINATOR, course="MTECH_CS", first_name="Coordinator", last_name="M.Tech CS")
        user("recruiter_beta", User.Role.RECRUITER, company=comps["Beta Systems"], first_name="Beta", last_name="Recruiter")
        user("student1", User.Role.STUDENT, student=students[1])
        user("student2", User.Role.STUDENT, student=students[2])
        audit.log(None, "SEED_DEMO", note="Demo data created", actor_name="SYSTEM")
        self.stdout.write(self.style.SUCCESS("Demo data ready. Users: admin, officer, coord_cs, recruiter_beta, student1, student2"))
        self.stdout.write("Password for all demo users: %s  (change it before any real use)" % PASSWORD)
