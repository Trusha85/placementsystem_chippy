"""Placement policy rule engine (NFSU Student Placement Guidelines 2026-27).

evaluate() is a pure function: given a student, their active offers and a new
opportunity it returns ALLOW / BLOCK / REVIEW with human-readable reasons that
cite the guideline clause. Thresholds come from PolicyConfig (admin-editable).
"""
from dataclasses import dataclass, field
from decimal import Decimal
from typing import List, Optional, Tuple

RANK = {"C": 1, "B": 2, "A": 3, "A+": 4}
ALLOW, BLOCK, REVIEW = "ALLOW", "BLOCK", "REVIEW"
TYPE_NAME = {"I": "Internship-only (I)", "F": "FTE-only (F)", "IF": "Internship + PPO/FTE (I+F)"}


def category_for(ctc, fallback, cfg):
    """Company category from FTE package (clause 4); falls back to company default."""
    if ctc is None:
        return fallback
    ctc = Decimal(ctc)
    if ctc >= cfg.a_plus_min:
        return "A+"
    if ctc >= cfg.a_min:
        return "A"
    if ctc >= cfg.b_min:
        return "B"
    return "C"


@dataclass
class Opportunity:
    offer_type: str
    category: str
    ctc: Optional[Decimal] = None
    drive_id: Optional[int] = None
    eligible_courses: Optional[List[str]] = None
    label: str = "the opportunity"


@dataclass
class Decision:
    outcome: str
    items: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def reasons(self):
        return ["[%s] %s" % (lvl, txt) for lvl, txt in self.items]

    @property
    def text(self):
        return "\n".join(self.reasons)


def _fmt(o):
    pkg = ""
    if o.ctc_lpa is not None:
        pkg = ", %s LPA" % o.ctc_lpa
    return "%s (%s, category %s%s)" % (o.company.name, TYPE_NAME[o.offer_type], o.category, pkg)


def evaluate(student, opp, cfg, offers, absences=(), drives=()):
    """offers: the student's ACTIVE offers. absences: Attendance rows with status ABSENT.
    drives: all drives (any order) used to find the 'next N drives' after an absence."""
    items = []
    add = lambda lvl, txt: items.append((lvl, txt))

    # ---- clause 3: registration & eligibility
    if student.is_archived:
        add(BLOCK, "§3.1 Student record is archived.")
    if student.registration_status != "REGISTERED":
        add(BLOCK, "§3.1 Placement registration status is '%s'; only registered students may participate."
            % student.get_registration_status_display())
    if student.eligibility_status == "INELIGIBLE":
        add(BLOCK, "§3.2 Student is marked ineligible.")
    elif student.eligibility_status == "PENDING":
        add(REVIEW, "§3.2 Eligibility is pending verification; confirm before the student participates.")
    if opp.eligible_courses is not None and student.course not in opp.eligible_courses:
        add(BLOCK, "§3.3 Company criteria exclude the student's programme (%s)." % student.course_label)

    # ---- clause 7: absenteeism -> possible exclusion from next N drives
    n = cfg.absence_exclusion_drives
    if opp.drive_id:
        ordered = sorted(drives, key=lambda d: (d.date, d.id))
        for a in absences:
            ad = next((d for d in ordered if d.id == a.drive_id), None)
            if not ad:
                continue
            nxt = [d for d in ordered if (d.date, d.id) > (ad.date, ad.id)][:n]
            if opp.drive_id in {d.id for d in nxt}:
                add(REVIEW, "§7.2 Unexcused absence at '%s' - student may be excluded from the next %d drives. "
                    "Refer to Placement Cell (emergency exceptions possible)." % (ad.title, n))

    # ---- clauses 5 & 6: offer-type restrictions and switching
    for o in offers:
        ref = _fmt(o)
        if o.has_fte and o.category == "A+":
            add(BLOCK, "§6.1 Already selected in A+ category: %s. No switching - student is out of the "
                "placement process." % ref)
            continue
        if o.offer_type == "IF":
            add(BLOCK, "§5.3 Holds an I+F offer: %s. Cannot participate in other I, F or I+F roles." % ref)
            continue
        if o.offer_type == "I" and opp.offer_type == "I":
            add(BLOCK, "§5.1 Already holds an internship-only offer (%s); cannot take another internship-only role." % ref)
            continue
        if o.offer_type == "F" and opp.offer_type == "I":
            continue  # §5.2: an FTE-only holder may still apply for internship roles
        if o.offer_type == "F" and opp.offer_type in ("F", "IF"):
            # §5.2 + §6: a further FTE/I+F role after an FTE-only offer is possible only as a
            # permitted category switch. The category rules below decide.
            if o.category == "A":
                if opp.category != "A+":
                    add(BLOCK, "§5.2/§6.2 Holds category A offer (%s); switching allowed only to A+ companies "
                        "(this is category %s)." % (ref, opp.category))
            elif o.category == "B":
                if opp.ctc is None:
                    add(REVIEW, "§6.3 Holds category B offer (%s); new package unknown - cannot verify the "
                        "%sx rule." % (ref, cfg.b_switch_multiplier))
                else:
                    need = (o.ctc_lpa or Decimal(0)) * cfg.b_switch_multiplier
                    if Decimal(opp.ctc) < need:
                        add(BLOCK, "§5.2/§6.3 Holds category B offer (%s); new package %s LPA is below %sx existing "
                            "(needs >= %s LPA)." % (ref, opp.ctc, cfg.b_switch_multiplier, need.quantize(Decimal("0.01"))))
            elif o.category == "C":
                if RANK[opp.category] <= RANK["C"]:
                    add(BLOCK, "§5.2/§6.4 Holds category C offer (%s); only higher-category opportunities are allowed "
                        "(this is category %s)." % (ref, opp.category))
        # Existing internship-only offer: FTE and I+F roles stay open (§5.1); nothing further to check.

    levels = {lvl for lvl, _ in items}
    outcome = BLOCK if BLOCK in levels else (REVIEW if REVIEW in levels else ALLOW)
    if outcome == ALLOW:
        if offers:
            add(ALLOW, "Registered and eligible; existing offer(s) %s do not conflict with %s."
                % ("; ".join(_fmt(o) for o in offers), opp.label))
        else:
            add(ALLOW, "Registered and eligible; no existing offers. Student may participate.")
    return Decision(outcome, items)
