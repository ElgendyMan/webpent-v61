# WebPent × bbscout Target Package v2 — Integration Manifest

**حالة المستند:** release-candidate audit، 22 أغسطس 2026.  
**النطاق:** تكامل offline ومحكوم بالسياسة بين bbscout وWebPent؛ لا يتضمن هذا العمل أي scan حي أو provider I/O أو استخدام credentials.

## النتيجة التنفيذية

تم تنفيذ وربط طبقة intake additive لـ`Target Package v2` داخل WebPent عبر CLI وFastAPI/Celery first-run وresume. الحزمة لا تمنح صلاحية جديدة؛ هي فقط تصف الهوية والنطاق والسياسة والقدرات والـprovenance، ثم تُقبل بعد فحوص integrity وfreshness وrevocation وconfirmation والتوقيع detached. كل action package-backed يمر عبر `ActionAuthority` المركزي، ولا يوجد transport أو HTTP/browser bypass جديد.

التوقيع التنفيذي أصبح **Ed25519 detached حقيقيًا**. حالة `unsigned-local-mvp` تظل صالحة للفحص المحلي والتدقيق فقط، لكنها لا تُستهلك لإنشاء engagement قابل للتنفيذ. لا توجد private keys أو provider secrets أو cookies أو OTPs أو passwords في المصدر أو الحزم أو state أو التقارير أو الأرشيف.

## مكونات التنفيذ

| المجال | التنفيذ | الحالة | الدليل |
|---|---|---:|---|
| عقد package | `contracts/target-package.schema.v2.json` و`contracts/capability-profile.schema.v1.json` | منفذ | schema files + pytest |
| bbscout typed validation | `bbscout/src/bbscout/target_package_v2.py` | منفذ | bbscout full: 7 passed |
| digest separation | `source_response_sha256` مستقل عن canonical `content_sha256` | منفذ | hardening regression، 31 passed |
| detached signature | `bbscout/src/bbscout/signatures.py` مع Ed25519 وtrusted public-key map runtime-only | منفذ | signature tests |
| admission/projection | `webpent/shared/target_package_context.py` | منفذ | admission/revocation/expiry/secret tests |
| one-time consumption | `webpent/shared/engagement_factory.py` وSQLite atomic lease | منفذ offline | lease/conflict tests |
| scope compiler | `webpent/shared/package_scope.py` | منفذ | URL/method/action/redirect adversarial tests |
| central authority | `ActionAuthority` يطبق package identity/digest وscope/policy | منفذ | action-authority tests |
| runtime wiring | `RuntimeFactory` وinitial state وsmart campaign fallback | منفذ | full WebPent suite |
| entrypoint wiring | CLI flags، `ScanRequest`، API dispatch، worker first-run، redelivery/resume continuity | منفذ offline | entrypoint/hardening tests؛ لا broker/multi-worker qualification |
| graph preflight | `package_preflight` قبل wildcard/planner، مع legacy no-package route | منفذ | preflight tests |
| capability intersection | `package_capabilities.py` ينتج available/unavailable/blocked_by_policy/not_qualified/optional | منفذ | capability/preflight tests |
| proof continuity | package id/digests تدخل action metadata وverifier وsealed ProofBundle | منفذ | E2E hardening test |
| target-backed confirmation | baseline + candidate + independent negative control، target fingerprint وrequest/response digests وvalidator continuity | منفذ fail-closed | strict verifier وactive-validator tests |
| sealed/replayable ProofBundle | seal integrity، replay contract، tamper resistance، وعدم حفظ body/cookies/auth material | منفذ | strict verifier tests |
| report continuity | top-level redacted `target_package_continuity` يدخل audit/master hash | منفذ | E2E hardening test |
| direct-I/O inventory | G-02 regenerated and runtime-checked | منفذ | 280 primary records; external_target_contacted=false |
| bounded autonomy contracts | `autonomy_contracts.py`؛ budget/stop/cycle contracts مع legacy resume aliases | منفذ offline | autonomy adversarial tests + full suite |
| unified research loop | smart campaigns تربط session/gaps/actions/target knowledge/attack graph | منفذ offline | research-loop contract tests؛ لا I/O جديد |
| memory/RAG + LLM boundary | redaction-safe bounded telemetry؛ advisory-only؛ لا snippets/claims كدليل | منفذ offline | memory/LLM adversarial tests |
| qualification harness | canonical multi-run outcomes وproof/replay وFP/FN وscope/budget/stop metrics | منفذ offline | qualification harness tests؛ لا live precision/recall |
| provider adapters | Bugcrowd/Intigriti/YesWeHack adapters | **MISSING** | لا يوجد ادعاء تنفيذ |
| live qualification | WAPTLab/Juice Shop live scan | **غير منفذ عمدًا** | لا target I/O في هذه المرحلة |
| distributed qualification | Docker/Celery multi-run evidence | **غير مؤهل** | انظر تقرير Docker/Celery |
| VIP promotion | thresholds الرسمية | **NO** | القياسات المطلوبة غير متاحة |

## الملفات المضافة أو المتأثرة

أضيفت طبقات package إلى `webpent/src/webpent/shared/`، واختبارات التكامل إلى `webpent/tests/test_target_package_integration.py` و`webpent/tests/test_target_package_v2_hardening.py`. كما تم تحديث مسارات runtime، graph، state، campaign executor، validator، proof، reporter، وG-02 inventory renderer. المصدر الأصلي لـbbscout غير موجود كـGit repository بعد فك الأرشيف، ولذلك يُسلّم كجزء من integration archive مع checksum منفصل، وليس كcommit مستقل.

## بوابات التحقق

| البوابة | النتيجة |
|---|---:|
| bbscout full pytest | **7 passed** |
| WebPent full pytest | **1401 passed, 294 warnings** |
| package/entrypoint/hardening focused suite | **35 passed, 2 warnings** |
| autonomy/research/qualification additions | **19 passed ضمن full suite؛ no regression** |
| Ruff full | **passed** بعد إصلاح integration formatting/imports |
| compileall | **passed** |
| G-02 runtime | **passed؛ 280 primary records؛ لا اتصال خارجي** |
| tracked-secret scan | **passed؛ no high-confidence secrets** |
| Bandit على الملفات المعدلة | نتائج LOW legacy فقط؛ لا HIGH/MEDIUM في الملخص |
| LLM doctor | لا يوجد provider active؛ fallback deterministic remains available |

## حدود الإصدار

هذا الإصدار لا يثبت قدرة اكتشاف أو تأكيد عدد معين من الثغرات، ولا يثبت VIP أو autonomous qualification. أضيف harness متعدد التشغيلات لكنه offline deterministic ولا يمثل precision/recall حيًا. confirmation تظل مشروطة بـtarget-backed causal signal مشتق من baseline/candidate، وindependent neutral negative control، وProofBundle sealed قابل لإعادة التشغيل والتحقق من التلاعب. flags أو metadata وحدها لا تكفي. 403 و429 وtimeouts وmissing capabilities والأعطال تُصنف blocked/inconclusive/knowledge gap، ولا تتحول إلى clean.

## سياسة التسليم

قبل أي تشغيل على target حقيقي يجب توفير package موقعة بمفتاح موثوق خارج المصدر، confirmation صريحة مرتبطة بالـdigest، scope صالح، capability manifest محلي، وبيئة transport سليمة. لا يتم auto-submit إلى provider؛ provider discovery، إن أضيف مستقبلًا، يجب أن يبقى read-only حتى يثبت عقده ويُختبر مستقلًا.

## Release identity

| العنصر | القيمة |
|---|---|
| Git commit السابق | `d278653` (`Enforce target-backed causal proof bundles`) |
| Git commit roadmap الحالي | سيُملأ بعد commit/push بوابات phase 6 |
| Git remote | `https://github.com/ElgendyMan/webpent-v61` |
| archive | `webpent_bbscout_integration_release.zip` |
| archive SHA256 | مرفق في `webpent_bbscout_integration_release.sha256` |
| archive content count | يُحدّث بعد بناء archive النهائي؛ يتحقق منه `evidence/release_contents.txt` |
| forbidden artifact scan | clean |
