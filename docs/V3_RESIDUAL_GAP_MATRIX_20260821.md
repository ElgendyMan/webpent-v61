# WebPent v3 Residual Gap Matrix

هذه المصفوفة هي سجل العمل التنفيذي لخطة `webpent_v3_strict_ai_executable_vip_implementation.md`. الحالة لا تُغلق بالوثائق وحدها؛ الإغلاق يحتاج code path فعليًا واختبار قبول وartifact runtime.

| ID | الفجوة | الدليل الحالي | البوابة | الحالة | معيار الإغلاق |
|---|---|---|---|---|---|
| G-01 | لا يوجد RuntimeContext/RuntimeFactory جامع لكل graph nodes | graph wiring وdependency injection الحاليان غير موحدين | G2 | OPEN | كل node يحصل على context صالح أو يرجع blocked_by_configuration |
| G-02 | ActionExecutor لا يملك كل transports مركزيًا | ActionAuthority يقبل handler من caller، وCampaign ActionExecutor facade | G2 | OPEN | HTTP/browser/API/GraphQL/upload/OOB/subprocess adapters مسجلة ومراقبة |
| G-03 | ProofBundle ليس mandatory عالميًا | sealing مشروط بـ`proof_evidence` من handler | G7 | OPEN | promotion gate يرفض tool_confirmed بلا bundle sealed immutable |
| G-04 | proof engine يخطط ولا يفرض promotion | enforcement خارج ProofEngine | G7 | OPEN | oracle/negative-control/replay/seal gate مركزي deterministic |
| G-05 | AutonomousController غير موصول بالكامل | graph node لا يمرر runtime dependencies، ومسار التنفيذ محدود | G5 | OPEN | injected context، bounded parallel independent actions، recovery وevents |
| G-06 | Smart/VIP profile opt-in وlegacy defaults | `scan_mode=LEGACY` و`smart_require_proof_bundle=False` في lab default | G1/G5 | OPEN | profiles غير المحلية fail-closed، وVIP لا يعمل مع fallback صامت |
| G-07 | secure defaults غير production-grade بكل المسارات | auth/rate limit/CORS/dev secrets لها lab defaults | G1 | PARTIAL | staging/production hard-stop مع secrets/auth/TLS/trusted hosts/CORS explicit |
| G-08 | direct I/O inventory غير محكوم بCI allowlist | adapters موجودة لكن static inventory/manifest enforcement ناقص | G2 | OPEN | direct-I/O CI test وsigned/approved adapter manifest |
| G-09 | discovery graph/intent/browser/body/schema coverage غير live-qualified | JS/HTTP discovery موجودان جزئيًا | G3 | PARTIAL | surface graph provenance، browser/API/GraphQL/body/multipart replay |
| G-10 | identity/tenant/object/workflow replay غير موحد | IDOR differential موجود جزئيًا | G4 | PARTIAL | second identity/two objects/tenant state/cleanup/replay artifacts |
| G-11 | knowledge gaps وNBA وautonomous recovery غير مكتملة | smart campaigns موجودة لكن controller bounded/legacy paths باقية | G5 | OPEN | typed gaps، expected information gain، recovery، negative evidence |
| G-12 | validators المعقدة ناقصة | registry لا يغطي كل classes المطلوبة في الخطة | G6 | OPEN | plugin contract لكل validator مع oracle/control/cleanup/replay/proof |
| G-13 | external adapters وcapability image غير qualified | nuclei/dalfox fallback موجودان، لكن manifest end-to-end ناقص | G8 | PARTIAL | executable/version/hash/health/fallback/test لكل capability |
| G-14 | Celery/Redis/resume/multi-worker/Docker qualification ناقصة | عقود جزئية واختبارات موجودة، لا qualification كاملة | G8 | PARTIAL | consume-once، fencing، crash recovery، secure transport، Docker E2E |
| G-15 | precision/recall/reproducibility غير مقاسة live | WAPTLab السابق contract/mock أو run artifacts غير كافية للأرقام المطلوبة | G9/G10 | OPEN | ground truth + 3 clean runs + calculations + replay hashes |
| G-16 | prompt-injection/direct transport adversarial tests غير مكتملة | بعض security regressions موجودة | G1/G5/G9 | PARTIAL | scope/tool/evidence/secrets/promotion bypass tests |
| G-17 | release artifacts والقرار النهائي غير مكتملين | ZIP وquality docs موجودان، لكن v3 artifacts المطلوبة ليست كلها موجودة | G10 | OPEN | manifest/SBOM/threat/direct-I/O/qualification/proof/rollback signed decision |

## قاعدة الحالة

`OPEN` يعني أن هناك تنفيذًا أو إثباتًا ناقصًا. `PARTIAL` يعني أن جزءًا من العقد موجود لكن qualification أو coverage أو enforcement غير مكتمل. لا تتحول الفجوة إلى `CLOSED` إلا بعد اختبار قبول وartifact قابل للمراجعة.

## ترتيب التنفيذ

تُغلق G-01 إلى G-08 أولًا لأنها تمنع اعتماد validators أو qualification على transport غير مراقب. بعدها تُغلق G-09 إلى G-12، ثم G-13 إلى G-16، وأخيرًا G-15 وG-17. أي فشل في بوابة dependency يعيد اللوب إلى أصغر فجوة قابلة للإصلاح بدل تخطيها.
