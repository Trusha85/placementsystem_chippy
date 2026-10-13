# Technical Documentation - Secure, Policy-Driven Student Placement System

## 1. Architecture
Django 5 monolith (server-rendered, no external JS/CSS), SQLite for the prototype (PostgreSQL-ready: ORM only, no raw SQL).

```
Browser --HTTPS--> Django middleware (Security, Session, CSRF, Auth, CSP headers)
   -> views.py (role_required + role-scoped querysets)
        -> forms.py (server-side validation, whitelisted fields)
        -> policy.py (pure rule engine: ALLOW / BLOCK / REVIEW + reasons)
        -> reports.py (dashboard statistics)
        -> audit.py (hash-chained audit log, written on every sensitive action)
   -> models.py -> SQLite (mobile numbers encrypted with Fernet at field level)
```
Workflow (matches the problem statement): CSV import and validation -> eligibility verification -> drive and offer entry -> rule engine (checked before an offer is saved) -> dashboard, reports and audit.

## 2. Database schema
| Table | Key columns |
|---|---|
| `core_student` | placement_id **UNIQUE**, name, mobile (**encrypted**), email, course, batch, registration_status, eligibility_status, remarks, is_archived. *Placement status is derived from offers, not stored.* |
| `core_offer` | student FK (PROTECT), company FK, drive FK (optional), offer_type (I/F/IF), category, ctc_lpa, stipend_amount, stipend_period, offered_at, acceptance_deadline, acceptance_status, joining_status, ppo_status, off_campus, noc_status, needs_review, policy_outcome, policy_reasons, override_reason, remarks |
| `core_company` | name UNIQUE, category, response_hours |
| `core_drive` | company FK, title, date, offer_type, ctc_lpa, eligible_courses |
| `core_attendance` | student FK, drive FK, status (present / absent / excused), UNIQUE(student, drive) |
| `core_policyconfig` | single row: A+/A/B thresholds, B multiplier (1.5), absence exclusion drives (3), acceptance hours (24) |
| `core_user` | role, course (coordinator), company (recruiter), student (student login), TOTP secret, mfa_enabled |
| `core_auditlog` | timestamp, actor, action, object_type/id, before JSON, after JSON, ip, prev_hash, hash (append-only) |

Relationships: Student 1-N Offer (history preserved); Company 1-N Drive; Drive 1-N Attendance.
Reports count **unique placed students** (at least one active offer) separately from **offers received**. Stipend and CTC are separate fields, panels and statistics.

## 3. Policy rule engine (`core/policy.py`)
`evaluate(student, opportunity, config, active_offers, absences, drives) -> Decision(outcome, reasons[])`. Each reason cites the guideline clause.
Checks: registration, eligibility, company criteria, absenteeism (next 3 drives), A+ out of process, I+F blocks everything, I->I blocked, F->F/I+F only as a permitted category switch (A->A+, B->at least 1.5x, C->higher category), unknown package -> manual review.
Thresholds live in `PolicyConfig` (editable by the Administrator). The same engine powers offer entry, the per-drive eligibility table and the "still eligible for later drives" dashboard list.

## 4. Security controls (mapped to the problem statement)
| Area | Implementation |
|---|---|
| Authentication | Django auth; Argon2id password hashing (PBKDF2 fallback); 10-character minimum plus common/numeric/similarity validators; optional TOTP MFA (RFC 6238); generic login error; lockout after 5 failures per 15 min per user+IP; session key rotated at login; open-redirect check on `next`. |
| RBAC | Administrator, Officer, Coordinator, Recruiter (+ read-only Student). `role_required` on every view **and** role-scoped querysets (`students_for`, `offers_for`) so object access is enforced server-side (IDOR gives 404). Denied attempts are audited. Django admin is Administrator-only and routed through the app login/MFA. |
| Confidentiality | Mobile encrypted at rest (Fernet; key from `FIELD_ENCRYPTION_KEY`); masked in audit records; contact and compensation hidden from coordinators/recruiters; `Cache-Control: no-store`; secure cookies, HSTS and SSL redirect when `DJANGO_DEBUG=0`. |
| Input and query security | Django ORM only (parameterised queries); regex/length validation on every field; whitelisted ModelForm fields (no mass assignment); auto-escaped templates; strict CSP (`script-src 'self'`, no inline JS/CSS); CSV upload type/size/row limits. |
| Audit logging | Logins, failures, lockouts, record views, create/update/archive/delete, offer decisions, overrides, exports, imports, attendance, MFA changes, Django-admin changes. Entries hold actor, timestamp, IP and before/after values. |
| Integrity | Unique Placement ID (DB constraint + form check, upper-cased); Placement ID immutable; offers editable only in status fields; history never overwritten; placement status derived; SHA-256 **hash chain** over audit rows with a verify page; audit rows immutable through the ORM. |
| Session security | HttpOnly + SameSite=Strict cookies, 15-minute sliding idle timeout, expire at browser close, POST-only logout, CSRF tokens on all state changes, `X-Frame-Options: DENY`. |
| Backup and recovery | `python manage.py backup_db` writes a gzip + Fernet-encrypted file; `restore_db <file> --yes` restores it and the audit chain still verifies (tested). |
| Export security | Administrator/Officer only; sensitive columns (mobile, CTC, stipend) Administrator-only; spreadsheet formula-injection guard; every export audited with row count. |
| Privacy and retention | Only necessary fields collected; students see only their own record; retention rule in Guidelines §11; archive (soft delete) for records with history, hard delete only by Administrator when no offers exist. |

### Role matrix
| Capability | Admin | Officer | Coordinator | Recruiter | Student |
|---|---|---|---|---|---|
| View students | all | all | own programme (no contact/pay) | only students with their offers (no contact) | own record |
| Create/edit/archive students, import | yes | yes | no | no | no |
| Record offers / update status | yes | yes | no | no | no |
| Override a policy block | yes (reason required) | no | no | no | no |
| Dashboard | full | full | own programme, no pay | no | no |
| Export | yes (incl. sensitive) | yes (non-sensitive) | no | no | no |
| Audit log, users, policy parameters | yes | no | no | no | no |

## 5. Testing
`python manage.py test -v 2` runs 60 automated tests (see `TEST_REPORT.md`): every policy rule and boundary, offer workflow, reports, RBAC/IDOR, mass assignment, SQL injection, stored and reflected XSS, CSRF, security headers, lockout, MFA, session fixation, open redirect, import/export safety, encryption at rest and audit-chain tampering.

## 6. Assumptions and limitations
- The official guidelines were not supplied; `PLACEMENT_GUIDELINES_2026-27.md` is a working draft. Interpretations: an FTE-only holder may take a further FTE/I+F role only through a permitted category switch; internship-only offers use the company's category; package statistics use each placed student's highest active FTE CTC; stipend statistics use monthly stipends only.
- SQLite, `runserver` and the in-memory lockout cache are for demonstration. Production needs PostgreSQL (with disk/TDE encryption), a WSGI server behind TLS, a shared cache (Redis) and secrets from the environment. Only the mobile number is field-encrypted; compensation relies on database/disk encryption.
- The audit hash chain is tamper-*evident*, not tamper-*proof*: someone with full DB access could rewrite the whole chain. Mitigation: periodically store the latest hash outside the database.
- MFA secrets are stored unencrypted; there is no e-mail password-reset flow (administrators reset passwords), no student self-service and no e-mail reminders for acceptance deadlines.
- Absenteeism is flagged for review only; attendance is one record per drive.
