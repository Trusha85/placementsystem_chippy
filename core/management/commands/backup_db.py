"""Encrypted backup: dumpdata -> gzip -> Fernet encryption."""
import gzip
import io
from datetime import datetime

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand

from core.security import encrypt_bytes


class Command(BaseCommand):
    help = "Create an encrypted backup of all application data in BACKUP_DIR."

    def handle(self, *args, **opts):
        buf = io.StringIO()
        call_command("dumpdata", "core", "--natural-foreign", "--natural-primary", "--indent", "1", stdout=buf)
        raw = gzip.compress(buf.getvalue().encode())
        settings.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        path = settings.BACKUP_DIR / ("placement_%s.bak.enc" % datetime.now().strftime("%Y%m%d_%H%M%S"))
        path.write_bytes(encrypt_bytes(raw))
        self.stdout.write(self.style.SUCCESS("Encrypted backup written: %s" % path))
