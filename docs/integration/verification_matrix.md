# Verification Matrix — Target Package v2

| المحور | الحالة المختبرة | السلوك المتوقع | النتيجة |
|---|---|---|---:|
| package builder | package حقيقية مبنية من bbscout | قبول canonical package مع فصل source digest عن content digest | PASS |
| content integrity | تغيير package بعد حساب digest | رفض `content_digest_mismatch` | PASS |
| source provenance | source response hash صحيح شكليًا لكنه مختلف عن content hash | الاحتفاظ به كـsource evidence وعدم مقارنته بـcontent hash | PASS |
| detached signature | Ed25519 signature صحيحة ومفتاحها في trusted map runtime-only | `signature_state=verified` وقابلية engagement consumption | PASS |
| detached signature | unsigned-local-mvp | local validation فقط، رفض execution/engagement | PASS |
| detached signature | مفتاح عام خاطئ أو signature تالفة | fail-closed | PASS |
| freshness | package منتهية | `deny_expired`/blocked preflight | PASS |
| revocation | package revoked | `deny_revoked`/blocked preflight | PASS |
| confirmation | confirmation ناقصة أو digest مختلف | رفض قبل lease/action | PASS |
| secret redaction | secret-like field في package projection | admission rejection وعدم تسريب القيمة | PASS |
| one-time lease | consume package مرتين بنفس أو engagement مختلف | أول consume فقط؛ الثاني conflict/reject | PASS |
| scope | apex مقابل wildcard subdomain | القرار يطابق rule ولا يوسع scope | PASS |
| scope | sibling host خارج wildcard | `deny_out_of_scope` | PASS |
| scope | port/path/scheme mismatch | deny أو allow_with_constraints حسب العقد | PASS |
| scope | userinfo/ambiguous encoding | deny_ambiguous | PASS |
| scope | redirect chain فيها hop خارج النطاق | deny_out_of_scope | PASS |
| action identity | missing package id/SHA أو mismatch | reject قبل handler | PASS |
| capability | local manifest لا يملك capability مطلوبًا | structured knowledge gap/blocked capability، لا clean | PASS |
| proof | causal signal بلا negative control | لا promotion إلى confirmed | PASS |
| proof | package continuity ناقصة في proof input | promotion reject | PASS |
| report | package-backed report | top-level redacted continuity تدخل audit/master hash | PASS |
| validator | replay callers تحمل package context | verifier/proof يحمل identity/digests | PASS |
| legacy | no package / `not_provided` | المسار legacy يبقى متوافقًا ولا يُفتح bypass package | PASS |

## Evidence

التغطية موجودة في `tests/test_target_package_integration.py` و`tests/test_target_package_v2_hardening.py`. الاختباران يعملان offline ولا يرسلان HTTP أو browser أو provider requests. نتيجة focused gate: **31 passed**. نتيجة WebPent الكاملة: **1373 passed**.

## Interpretation

هذه المصفوفة تثبت contracts وgates الداخلية، ولا تثبت فعالية اكتشاف ثغرات على WAPTLab أو Juice Shop، ولا تثبت distributed/Celery qualification أو VIP promotion.
