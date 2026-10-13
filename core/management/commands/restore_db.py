"""Restore from an encrypted backup (replaces application data)."""
import gzip
import tempfile
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from core.security import decrypt_bytes


class Command(BaseCommand):
    help = "Restore application data from an encrypted backup file. Existing app data is flushed first."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument("--yes", action="store_true", help="Confirm that existing data will be replaced")

    def handle(self, *args, **opts):
        if not opts["yes"]:
            raise CommandError("Restoring replaces current data. Re-run with --yes to confirm.")
        try:
            raw = gzip.decompress(decrypt_bytes(Path(opts["path"]).read_bytes()))
        except Exception:
            raise CommandError("Backup could not be decrypted (wrong key or corrupted file).")
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(raw)
        call_command("flush", "--no-input")
        call_command("loaddata", fh.name)
        Path(fh.name).unlink(missing_ok=True)
        self.stdout.write(self.style.SUCCESS("Restore complete."))
