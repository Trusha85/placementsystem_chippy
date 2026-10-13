# NFSU Secure, Policy-Driven Student Placement System

Working prototype for Problem Statement 2. Django + SQLite, no build step.

## 1. Run it (5 minutes)
Requires Python 3.10+.

**Windows (PowerShell or CMD)**
```
cd placement_system
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```
**Linux / macOS**
```
cd placement_system
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```
Open http://127.0.0.1:8000/ and sign in.

## 2. Demo logins (password for all: `Placement#2026Demo`)
| User | Role | What to show |
|---|---|---|
| `admin` | Placement Administrator | everything, audit log, override, sensitive export, Django console `/admin-console/` |
| `officer` | Placement Officer | students, offers, drives, imports, dashboard |
| `coord_cs` | Course Coordinator (M.Tech CS) | own programme only, no contact or pay |
| `recruiter_beta` | Recruiter (Beta Systems) | only Beta's drives and offers |
| `student1`, `student2` | Student | own record only (try opening the other's URL: 404) |

## 3. Five-minute demo script
1. **Dashboard** (officer): unique placed students vs offers received; FTE CTC and stipend reported separately; "still eligible" list.
2. **Drives -> Beta Systems drive**: every student shows ALLOW / REVIEW / BLOCK with the guideline clause.
3. **Students -> NFSUA001 -> Record offer**: try an offer for an A+ student -> BLOCKED with reasons, nothing saved. Log in as `admin`, repeat, tick override with a justification -> saved and flagged.
4. **Import students**: upload `sample_data/students_sample.csv` -> 3 imported, 2 rejected (duplicate ID, bad mobile).
5. **Attack tests**: run `python manage.py test -v 2` (60 tests: SQLi, XSS, CSRF, IDOR, lockout, audit tampering).
6. **Audit log** (admin) -> *Verify integrity*; then tamper in the DB and verify again (shows detection).
7. **Security**: Two-step login (TOTP), encrypted mobile at rest, backup/restore commands below.

## 4. Useful commands
```
python manage.py test -v 2                      # all tests
python manage.py backup_db                      # encrypted backup into ./backups
python manage.py restore_db backups/<file> --yes  # restore
python manage.py createsuperuser                # real admin account
python manage.py seed_demo                      # (re)load demo data - run once only
```
Reset demo: delete `db.sqlite3`, then `migrate` and `seed_demo` again.

## 5. Before any real use
`DJANGO_DEBUG=0`, set `DJANGO_SECRET_KEY`, `FIELD_ENCRYPTION_KEY`, `DJANGO_ALLOWED_HOSTS`, serve over HTTPS, change all demo passwords or delete demo users, move to PostgreSQL.

## 6. Files
- `core/policy.py` rule engine, `core/permissions.py` RBAC, `core/audit.py` hash-chained log, `core/security.py` encryption/MFA/headers
- `core/views.py`, `core/forms.py`, `core/reports.py`, `core/models.py`, `templates/`, `static/`
- `docs/TECHNICAL.md` (schema, architecture, controls, limitations), `docs/PLACEMENT_GUIDELINES_2026-27.md` (draft guidelines), `docs/TEST_REPORT.md`
