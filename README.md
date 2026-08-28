# WebPent

**WebPent** هو إطار Python لاختبار اختراق تطبيقات الويب داخل نطاق مصرح ومحدد. يفصل التصميم بين الملاحظة والفرضية والتنفيذ والدليل والـFinding، ويستخدم `TargetSpec` وscope enforcement و`ActionAuthority` وidentity isolation و`ProofBundle` وredaction وreplay لضمان أن النتائج القابلة للتقرير مدعومة بأدلة قابلة للتحقق.

> **الحالة الحالية:** WebPent هو منصة **Engineering-complete bounded autonomous bug-hunting** جاهزة لتقييم qualification رسمي لاحقًا ضمن نطاق offline/advisory/fail-closed. ما زال **ليس VIP Smart Autonomous Bug Hunter مؤهلًا**، وليس P10 أو P9 Qualified.

> **تنبيه قانوني وتشغيلي:** استخدم WebPent فقط على أنظمة تملكها أو لديك تصريح كتابي لاختبارها. لا تستخدمه على أهداف عامة أو Bug Bounty أو أنظمة طرف ثالث دون تفويض صريح. الإعدادات الآمنة تمنع credential use وauto-submission وstate-changing actions وexternal callbacks افتراضيًا.

## الحالة الحالية باختصار

أُجري **VABH Final Audit v10** على source وtests وbenchmarks وreports وdocumentation وartifacts وrelease controls وCI workflows. التدقيق والإصلاحات المحلية لا ترسل requests، ولا تستخدم credentials، ولا تشغّل target، ولا تفتح qualification gate. تم نقل workflow القديم الذي كان يشغّل WAPTLab خارجيًا بجدولة و`--auto-approve` إلى `docs/legacy/workflows/nightly_benchmark.yml.disabled`، ولذلك لم يعد workflow نشطًا.

| المحور | الحالة الحالية | المعنى الصحيح |
|---|---|---|
| Generic Core وTarget Context | `PASS` | عقود typed، scope binding، capability lease، lifecycle، identity isolation، snapshot/restore، cleanup، وevidence boundaries موجودة ومختبرة. |
| Autonomous research loop | `PASS` هندسيًا | core وloop وplanner وreasoning وmemory تعمل فوق recorded state، بدون منح صلاحية تنفيذ أو qualification. |
| Evidence وcausal validation | `PASS` كضوابط | لا يُقبل confirmation بدون oracle وobservations وProofBundle وseal وreplay؛ عدم وجود observations لا يتحول إلى نتيجة إيجابية أو FN. |
| Multi-target lifecycle portability | `PASS` offline | نفس العقود العامة تعمل عبر adapters منفصلة، مع بقاء target-specific semantics داخل profiles/adapters. |
| Final audit v10 | `100/100` engineering scope | درجة implementation/control-plane completeness فقط، وليست detection-quality score أو qualification. |
| Full regression | `2207 passed / 7 failed` | السبعة legacy blockers موثقة ولا تُخفى ولا تُحوّل إلى qualification outcomes. |
| Official P10 runs | `0` | `official_isolated_p10_runs_authorized=false` والـrun gate مغلق. |
| P10 / P9 / VIP | `NOT_QUALIFIED` | لا توجد qualification claim. |
| Bug Bounty / external targets | `BLOCKED` | لا يوجد نطاق خارجي مصرح به. |

## Final Audit v10

توجد مخرجات التدقيق في [`artifacts/vabhfqr_v10/`](artifacts/vabhfqr_v10/):

- [`FINAL_PROJECT_STATE_REPORT.json`](artifacts/vabhfqr_v10/FINAL_PROJECT_STATE_REPORT.json) يسجل capability map وinventory وtechnical debt وrisk assessment والـexternal gaps والـgovernance.
- [`FINAL_VIP_READINESS_SCORECARD.json`](artifacts/vabhfqr_v10/FINAL_VIP_READINESS_SCORECARD.json) يفصل engineering readiness عن `official_qualification=NOT_QUALIFIED`.
- [`VABH-Final-Audit-v10-Gate-Summary.json`](artifacts/vabhfqr_v10/VABH-Final-Audit-v10-Gate-Summary.json) يلخص benchmark والحوكمة وحالة الـworkflow.
- [`VABH-Final-Audit-v10-Repair-Cycle.json`](artifacts/vabhfqr_v10/VABH-Final-Audit-v10-Repair-Cycle.json) يوثق الإصلاحات الداخلية ودورة review → repair → validate.

التقرير البشري هو [`docs/vabhfqr_v10/WebPent-VIP-Final-Audit-Report-v10.md`](docs/vabhfqr_v10/WebPent-VIP-Final-Audit-Report-v10.md). الـrunner [`scripts/run_vabh_final_audit_v10.py`](scripts/run_vabh_final_audit_v10.py) deterministic ويقرأ أدلة محلية مسجلة فقط.

## ما تم بناؤه وإصلاحه

أضيفت حزمة `src/webpent/vabhfqr_v10/` بعقود typed وaudit composition وstrict classification metrics. هذه الطبقة advisory-only ولا تنشئ Findings ولا تعدّل policy أو frozen ground truth أو thresholds ولا تفتح P10/VIP.

أضيفت regression tests في [`tests/test_vabh_final_audit_v10.py`](tests/test_vabh_final_audit_v10.py) تغطي bounded readiness وstable ordering وexternal gap records ورفض qualification promotion ورفض labels غير الصريحة أو الحالات blocked/inconclusive في metrics.

تم إصلاح governance inconsistency في workflow القديم: النسخة السابقة كانت scheduled وتحتوي clone خارجيًا وتشغيلًا تلقائيًا و`--auto-approve`. تم الاحتفاظ بها كمرجع legacy disabled خارج `.github/workflows/`، بينما يظل [`v95-nightly.yml`](.github/workflows/v95-nightly.yml) offline benchmark فقط.

## نتائج الـbenchmark والـdetection quality

الـVABH-FQR v9 final benchmark يسجل **8 classes**، لكن جميع الحالات الثماني `BLOCKED`، وعدد الحالات القابلة للـscoring هو `0`، وعدد requests المرسلة هو `0`. لذلك تظل precision وrecall وF1 وqualification metrics `null`؛ لا توجد candidate/control observations target-backed صالحة لإعادة حساب detection quality.

الحالات `blocked` و`observation-only` و`inconclusive` و`out_of_scope` لا تُحسب FN ولا clean ولا confirmed، كما أن route reachability أو HTTP 200 أو lesson completion أو source presence وحدها ليست دليل vulnerability.

## حدود الحوكمة والنطاق

| Invariant | القيمة |
|---|---|
| `human_independent_signoff_obtained` | `false` |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |
| Qualification effect | `false` |

الأفعال التالية gated: تعديل policy أو frozen Ground Truth أو thresholds، استخدام credentials أو login أو OTP/MFA/CAPTCHA bypass، state-changing أو destructive actions، استخدام target خارجي، فتح Official P10، أو إعلان qualification. مراجعة AI ليست human countersign، والصمت لا يُعتبر موافقة.

لا يتم حفظ cookies أو tokens أو credentials أو raw response bodies أو raw headers أو process arguments أو environment secrets داخل Git أو release artifacts. أي generic change يجب أن يثبت عبر abstraction قابل لإعادة الاستخدام، وأي semantics خاصة بتطبيق تظل داخل adapter أو profile.

## الاختبارات والـrelease gates

من جذر المشروع، بعد تثبيت dependencies:

```bash
PYTHONPATH=src:integrations/bbscout/src pytest -q
ruff check src scripts tests benchmarks
ruff format --check src scripts tests benchmarks
python3 -m compileall -q src scripts benchmarks
PYTHONPATH=src python3 scripts/scan_direct_io.py
python3 scripts/check_generic_target_neutrality.py
python3 scripts/check_tracked_secrets.py
PYTHONPATH=src make g02-check
git diff --check
python3 scripts/verify_release_artifacts.py --repo . --manifest docs/release_manifest.json
python3 scripts/check_release_manifest_provenance.py
```

نتيجة v10 regression هي `5 passed`. نتيجة full suite الأخيرة هي `2207 passed / 7 failed`. التصنيف الصادق للـlegacy blockers هو: أربعة failures في Option B approval boundary بسبب `approval_source_hash_mismatch`، فشلان في WebGoat/crAPI runtime أو source attestation، وفشل واحد بسبب غياب `/tmp/juice-shop-source/data/static/challenges.yml`. هذه blockers موثقة تاريخيًا ولم يتم تخفيف validators أو تغيير evidence لإخفائها.

## المتطلبات المتبقية للوصول إلى VIP

المتبقي ليس abstraction داخليًا جديدًا في هذه المرحلة، بل متطلبات qualification خارجية لا يجوز اختلاقها: approved target-backed ground truth، causal oracle وsafe precondition لكل حالة، independent negative control، sealed/replayable ProofBundle، approved set يحقق `10 cases / 6 classes`، ثم `3` isolated official runs مع إعادة حساب precision/recall/F1/evidence completeness، وindependent human governance signoff، وfinal qualification decision.

بعد تحقق المتطلبات الرسمية فقط يمكن طلب فتح Official P10 بقرار مالك صريح. وحتى ذلك الحين يظل P10/P9/VIP `NOT_QUALIFIED` وBug Bounty `BLOCKED`.

> **الخلاصة:** WebPent وصل إلى engineering-complete platform جاهزة لتقييم VIP qualification رسمي لاحقًا ضمن النطاق المحدود، لكنه لم يثبت بعد detection-quality qualification ولم يحصل على VIP أو P10 أو P9.

**المشروع على GitHub:** [ElgendyMan/webpent-v61](https://github.com/ElgendyMan/webpent-v61)

**إعداد الوثيقة:** Manus AI
