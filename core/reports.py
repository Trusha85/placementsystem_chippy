"""Dashboard statistics. Unique placed students are counted separately from offers;
internship stipends and annual FTE CTC are always reported separately."""
from decimal import Decimal
from statistics import mean, median

from django.db.models import Prefetch

from . import policy
from .models import COURSES, Offer, PolicyConfig


def _fte_ctc_per_student(students):
    vals = []
    for s in students:
        ctcs = [o.ctc_lpa for o in s.active_offers() if o.has_fte and o.ctc_lpa is not None]
        if ctcs:
            vals.append(max(ctcs))
    return vals


def compute(students_qs, offers_qs, with_comp=True, with_next=True):
    cfg = PolicyConfig.get()
    students = list(students_qs.filter(is_archived=False).prefetch_related(
        Prefetch("offers", queryset=Offer.objects.select_related("company"))))
    registered = [s for s in students if s.registration_status == "REGISTERED"]
    placed = [s for s in registered if s.active_offers()]
    out = {
        "total_students": len(students),
        "registered": len(registered),
        "eligible": sum(1 for s in students if s.eligibility_status == "ELIGIBLE"),
        "ineligible": sum(1 for s in students if s.eligibility_status == "INELIGIBLE"),
        "pending_verification": sum(1 for s in students if s.eligibility_status == "PENDING"),
        "placed": len(placed),
        "unplaced": len(registered) - len(placed),
    }
    kinds = {"Internship only": 0, "FTE only": 0, "Internship + PPO/FTE": 0}
    for s in registered:
        if s.placement_status in kinds:
            kinds[s.placement_status] += 1
    out["kinds"] = kinds

    rows = []
    for code, label in COURSES:
        cs = [s for s in registered if s.course == code]
        cp = [s for s in cs if s.active_offers()]
        batches = {}
        for s in cs:
            b = batches.setdefault(s.batch, [0, 0])
            b[0] += 1
            b[1] += 1 if s.active_offers() else 0
        rows.append({
            "label": label, "registered": len(cs), "placed": len(cp), "unplaced": len(cs) - len(cp),
            "rate": round(100 * len(cp) / len(cs), 1) if cs else 0,
            "i": sum(1 for s in cs if s.placement_status == "Internship only"),
            "f": sum(1 for s in cs if s.placement_status == "FTE only"),
            "if_": sum(1 for s in cs if s.placement_status == "Internship + PPO/FTE"),
            "batches": ", ".join("%s: %d/%d" % (b, v[1], v[0]) for b, v in sorted(batches.items())),
        })
    out["courses"] = rows

    offers = list(offers_qs)
    out["total_offers"] = len(offers)
    out["unique_students_with_offers"] = len({o.student_id for o in offers})
    out["pending_acceptance"] = sum(1 for o in offers if o.acceptance_status == "PENDING")
    out["pending_joining"] = sum(1 for o in offers if o.acceptance_status == "ACCEPTED" and o.joining_status == "PENDING")
    out["needs_review"] = sum(1 for o in offers if o.needs_review)

    companies = {}
    for o in offers:
        c = companies.setdefault(o.company.name, {"name": o.company.name, "category": o.category, "offers": 0,
                                                  "accepted": 0, "ctcs": [], "stipends": []})
        c["offers"] += 1
        c["accepted"] += 1 if o.acceptance_status == "ACCEPTED" else 0
        if o.has_fte and o.ctc_lpa is not None:
            c["ctcs"].append(o.ctc_lpa)
        if o.stipend_amount is not None and o.stipend_period == "MONTHLY":
            c["stipends"].append(o.stipend_amount)
    out["companies"] = [{
        "name": c["name"], "category": c["category"], "offers": c["offers"], "accepted": c["accepted"],
        "max_ctc": max(c["ctcs"]) if c["ctcs"] else None,
        "avg_ctc": round(mean(c["ctcs"]), 2) if c["ctcs"] else None,
        "avg_stipend": round(mean(c["stipends"]), 0) if c["stipends"] else None,
    } for c in sorted(companies.values(), key=lambda x: -x["offers"])]

    if with_comp:
        ctcs = _fte_ctc_per_student(registered)
        out["fte"] = {"count": len(ctcs), "highest": max(ctcs) if ctcs else None,
                      "average": round(mean(ctcs), 2) if ctcs else None,
                      "median": round(median(ctcs), 2) if ctcs else None}
        stip = [o.stipend_amount for o in offers
                if o.is_active and o.stipend_amount is not None and o.stipend_period == "MONTHLY"]
        out["stipend"] = {"count": len(stip), "highest": max(stip) if stip else None,
                          "average": round(mean(stip), 0) if stip else None,
                          "median": round(median(stip), 0) if stip else None}

    if with_next:
        hypo = [policy.Opportunity("I", "A+", None, label="a hypothetical A+ internship"),
                policy.Opportunity("F", "A+", Decimal("20"), label="a hypothetical A+ FTE"),
                policy.Opportunity("IF", "A+", Decimal("20"), label="a hypothetical A+ I+F")]
        still, out_of = [], []
        for s in placed:
            offs = s.active_offers()
            ok = any(policy.evaluate(s, h, cfg, offs).outcome != policy.BLOCK for h in hypo)
            (still if ok else out_of).append(s)
        out["still_eligible"] = still
        out["out_of_process"] = len(out_of)
    return out
