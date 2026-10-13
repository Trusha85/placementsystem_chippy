# Test Report

Command: `python manage.py test -v 2`  
Result: **60 tests, all passing**.

## Access control, IDOR, tampering (10)
| Test | Result |
|---|---|
| anonymous redirected to login | OK |
| archive preserves history | OK |
| coordinator limited to own course | OK |
| only admin can delete and only without history | OK |
| placement status not settable via edit form | OK |
| recruiter cannot see other company offers on shared student | OK |
| recruiter sees only own company and no contacts | OK |
| role cannot be escalated by flags | OK |
| student cannot modify status or package | OK |
| student sees own record not others | OK |

## Audit logging and integrity (5)
| Test | Result |
|---|---|
| audit page admin only | OK |
| audit rows are immutable via orm | OK |
| chain valid then detects tampering | OK |
| deleting a record is detected | OK |
| sensitive actions logged with actor and before after | OK |

## Offer and recruitment workflow (8)
| Test | Result |
|---|---|
| allowed offer saved with deadline min 24h | OK |
| fte requires ctc and internship requires stipend | OK |
| off campus violation recorded and flagged | OK |
| offer package cannot be edited after creation | OK |
| officer cannot override but admin can with reason | OK |
| officer cannot reinstate expired offer | OK |
| pending offer expires | OK |
| policy violation cannot be saved by officer | OK |

## Policy rule engine (15)
| Test | Result |
|---|---|
| A can only switch to A plus | OK |
| A plus selected is out of process | OK |
| B needs 1 5x package | OK |
| C only higher category | OK |
| IF blocks everything | OK |
| absenteeism flags next three drives only | OK |
| category thresholds | OK |
| company course criteria | OK |
| configurable threshold | OK |
| declined or expired offer does not restrict | OK |
| fte only blocks plain second fte but allows internship and valid switch | OK |
| internship only blocks second internship but allows fte | OK |
| reasons explain decision | OK |
| registration and eligibility | OK |
| unplaced student allowed | OK |

## Reports (2)
| Test | Result |
|---|---|
| coordinator dashboard hides compensation | OK |
| unique students vs offers and separate money | OK |

## Page smoke tests (2)
| Test | Result |
|---|---|
| all pages render for staff | OK |
| drive page explains decisions and saves attendance | OK |

## Web-attack resistance and session security (18)
| Test | Result |
|---|---|
| audit never stores full mobile | OK |
| csp and security headers | OK |
| csrf enforced on state changing requests | OK |
| csv import validates and rejects duplicates | OK |
| duplicate placement id rejected ui and db | OK |
| export restrictions and csv injection guard | OK |
| lockout after repeated failures | OK |
| mfa required when enabled | OK |
| mobile encrypted at rest | OK |
| open redirect blocked on login | OK |
| password hashing and validators | OK |
| reflected xss in search box | OK |
| session cookie flags and logout | OK |
| session key rotates on login | OK |
| sql injection in login | OK |
| sql injection in search and filters | OK |
| state change requires post | OK |
| stored xss is escaped and names validated | OK |
