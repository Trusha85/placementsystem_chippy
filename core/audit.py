"""Tamper-evident audit logging (SHA-256 hash chain)."""
import hashlib
import json

from django.db import transaction
from django.utils import timezone

from .security import client_ip, mask_mobile


def _clean(value):
    return json.loads(json.dumps(value, default=str, sort_keys=True))


def compute_hash(prev_hash, timestamp, actor_name, action, object_type, object_id, before, after, ip, note):
    payload = json.dumps(
        [prev_hash, timestamp.isoformat(), actor_name, action, object_type, str(object_id),
         before, after, ip, note], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def snapshot(obj, fields):
    """Dict of field values for before/after records. Mobile numbers are masked."""
    data = {}
    for f in fields:
        value = getattr(obj, f, None)
        if f == "mobile":
            value = mask_mobile(value or "")
        elif hasattr(value, "pk"):
            value = str(value)
        data[f] = value
    return _clean(data)


def log(actor, action, obj=None, before=None, after=None, request=None,
        object_type="", object_id="", note="", actor_name=None):
    from .models import AuditLog
    if obj is not None:
        object_type = object_type or obj.__class__.__name__
        object_id = object_id or obj.pk
    actor_obj = actor if (actor is not None and getattr(actor, "is_authenticated", False)) else None
    actor_name = actor_name or (actor_obj.username if actor_obj else "SYSTEM")
    ip = client_ip(request) if request is not None else ""
    before, after = _clean(before or {}), _clean(after or {})
    with transaction.atomic():
        last = AuditLog.objects.order_by("-id").first()
        prev_hash = last.hash if last else "GENESIS"
        ts = timezone.now()
        ts = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)  # ms precision survives backup/restore
        entry = AuditLog(
            timestamp=ts, actor=actor_obj, actor_name=actor_name, action=action,
            object_type=object_type, object_id=str(object_id), before=before, after=after,
            ip=ip, note=note, prev_hash=prev_hash,
            hash=compute_hash(prev_hash, ts, actor_name, action, object_type, object_id,
                              before, after, ip, note))
        entry.save(force_insert=True)
    return entry


def verify_chain():
    """Return (ok, first_bad_id, checked_count)."""
    from .models import AuditLog
    prev = "GENESIS"
    count = 0
    for e in AuditLog.objects.order_by("id").iterator():
        expected = compute_hash(prev, e.timestamp, e.actor_name, e.action, e.object_type,
                                e.object_id, e.before, e.after, e.ip, e.note)
        if e.prev_hash != prev or e.hash != expected:
            return False, e.id, count
        prev = e.hash
        count += 1
    return True, None, count
