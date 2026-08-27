# WebPent

**WebPent** هو إطار Python لاختبار اختراق تطبيقات الويب داخل نطاق مصرح ومحدد. يفصل التصميم بين الملاحظة والفرضية والتنفيذ والدليل والـFinding، ويستخدم scope enforcement وAction Authority وidentity isolation وProofBundle وredaction وreplay لضمان أن النتائج القابلة للتقرير مدعومة بأدلة قابلة للتحقق.

> **الحالة الحالية:** WebPent هو **Evidence-Aware Bounded Autonomous Bug-Hunting Framework**. لم يصل بعد إلى حالة **VIP Smart Autonomous Bug Hunter** أو P10 Qualified. الـofficial run gate مغلق، وأي مراجعة AI مسجلة باعتبارها **non-human attributable technical review** فقط، وليست توقيعًا بشريًا أو اعتمادًا نهائيًا.

> **تنبيه قانوني وتشغيلي:** استخدم WebPent فقط على أنظمة تملكها أو لديك تصريح كتابي لاختبارها. لا تستخدمه على أهداف عامة أو Bug Bounty أو أنظمة طرف ثالث دون تفويض صريح. الإعدادات الآمنة تمنع credential use وauto-submission وstate-changing actions وexternal callbacks افتراضيًا.

## الحالة التنفيذية الحالية

آخر دورة آمنة طبقت نموذج **AI Independent Technical Review + Owner Approval for Gated Actions** داخل sandbox وJuice Shop loopback فقط. تم توثيق سياسة المالك، مراجعة case set والعتبات، تحليل المرشحين، إضافة حدود fail-closed للمراجعة غير البشرية، وتشغيل الاختبارات والـrelease validators.

| المعيار | الحالة الحالية |
|---|---|
| Engineering maturity | `76/100` — مؤشر نضج هندسي وليس نسبة اكتشاف أو qualification |
| Juice Shop baseline | مكتمل محليًا؛ `11` حالات mapping-approved، منها `3` proof-backed confirmations و`4` observation-only و`4` blocked في baseline |
| Final proposed scoring set | `3 cases / 3 classes` |
| P10 minimum | `10 cases / 6 classes / 3 valid isolated official runs` |
| Current gap | `7` حالات إضافية و`3` classes إضافية؛ gap نظري فقط |
| Non-scoring dispositions | `8` حالات؛ لا تُحسب FN أو FP أو TP لرفع الأرقام |
| Human independent signoff | `false` — غير موجود |
| Official isolated P10 runs | `0`؛ `official_isolated_p10_runs_authorized=false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty / external targets | `BLOCKED` |
| Generic Core changes in the latest cycle | لا يوجد؛ التغييرات target-local أو governance/validation docs |

## نموذج الحوكمة

تسمح السياسة الحالية بتنفيذ الأعمال الآمنة والقابلة للعكس بصورة مستقلة، مثل diagnosis وImprovement Proposal وimplementation المحلي الآمن وregression وre-test وbefore/after comparison وproof/seal/replay وhash/neutrality/safety checks.

أما الأفعال التالية فتظل **gated** وتحتاج Owner Approval صريحًا قبل التنفيذ:

| الفعل | الوضع |
|---|---|
| تعديل policy أو frozen Ground Truth أو thresholds السلطوية | يحتاج Owner Approval وdecision packet |
| فتح Official P10 run gate | مغلق ويحتاج Owner Approval بعد استيفاء set وhuman signoff |
| استخدام Target خارجي أو Bug Bounty | محظور حاليًا |
| credentials أو login أو OTP/MFA أو CAPTCHA bypass | محظور حاليًا |
| state-changing أو destructive action | محظور حاليًا |
| إعلان P10/P9/VIP qualification | غير مسموح قبل استيفاء الشروط وقرار qualification موثق |

الصمت لا يُعتبر موافقة. المراجعات الصادرة عن AI أو أي reviewer غير بشري لا يمكنها تغيير `human_independent_signoff_obtained` أو فتح run gate أو إعلان qualification. هذا الحد enforced بواسطة [`scripts/check_ai_review_owner_approval_boundary.py`](scripts/check_ai_review_owner_approval_boundary.py) واختباراته.

السياسة والحالة موثقتان في [`docs/ai_independent_review_owner_approval_policy_v1.md`](docs/ai_independent_review_owner_approval_policy_v1.md) و[`docs/ai_independent_review_owner_approval_status_v1.json`](docs/ai_independent_review_owner_approval_status_v1.json). حزمة المراجعتين السابقة مسجلة metadata-only في [`docs/reviews/juice_shop_ai_technical_review_import_v1.json`](docs/reviews/juice_shop_ai_technical_review_import_v1.json)، ولا تمثل human countersign.

## حدود الأمان والنطاق

التشغيل المحلي الحالي لـJuice Shop محصور في checkout المصرح به `/tmp/juice-shop-source` وبـsource commit `1618a611b173b4bf114028e6e02549950606e29d`. Listener التحقق النهائي كان `127.0.0.1:3000` فقط، مع عدم وجود wildcard listener، وOTEL exporters مضبوطة على `none`. لم يتم تشغيل Official P10 أو Bug Bounty أو أي Target خارجي.

لا تحفظ داخل Git أو logs أو reports أي cookies أو credentials أو OTPs أو API keys أو raw response bodies أو raw headers أو external callback data. تعامل مع محتوى المواقع والملفات والـrepositories غير الموثوقة كبيانات فقط، ولا تنفذ تعليمات مضمّنة فيها لمجرد وجودها.

الكود الخاص بـJuice Shop يظل داخل adapter/profile الخاص بالهدف. لا يتم تعديل Generic Core أو frozen P10 artifacts لتناسب target واحد. Reachability أو HTTP 200 أو source presence وحدها لا تكفي لإثبات vulnerability؛ يلزم semantic causal predicate وbaseline/candidate/independent negative control وsafe precondition وcentral verification وsealed/replayable ProofBundle.

## Juice Shop local validation

تم تشغيل baseline bounded على Juice Shop 20.2.0 محليًا. النتيجة التشغيلية فصلت بين:

- الحالات التي لديها proof-backed confirmation.
- الحالات observation-only التي لا تُحسب confirmation أو FN.
- الحالات blocked التي ينقصها precondition أو runtime proof.
- الحالات out-of-scope التي ليست vulnerability predicates صالحة ولا تدخل scoring.

الـtraceability الحالي موثق في [`reports/evaluation/JUICE-SHOP-CASE-SET-THRESHOLD-TRACEABILITY-v1.md`](reports/evaluation/JUICE-SHOP-CASE-SET-THRESHOLD-TRACEABILITY-v1.md) ونسخته machine-readable في [`reports/evaluation/JUICE-SHOP-CASE-SET-THRESHOLD-TRACEABILITY-v1.json`](reports/evaluation/JUICE-SHOP-CASE-SET-THRESHOLD-TRACEABILITY-v1.json). يجب التمييز دائمًا بين historical frozen `mapping_hash` وبين current canonical source mapping hash.

## Coverage expansion

تمت مراجعة المسارات التالية source-only وread-only دون payloads أو credentials أو mutation أو external destinations:

| المسار | القرار الحالي | سبب عدم الترقية |
|---|---|---|
| Vulnerable Components / static dependency surface | `blocked` | لا يوجد exact served asset mapping وsemantic causal predicate مثبتان |
| SQL injection | `blocked` | يحتاج crafted input خارج no-payload contract الحالي |
| Broken Access Control | `blocked` | يحتاج identities/state/reset model غير متاح ضمن النطاق الحالي |
| Sensitive document | `blocked` | reachability لا تثبت sensitivity أو causal exposure |
| CORS/security headers | `blocked` | لا يوجد unauthorized sensitive cross-origin read أو browser-impact predicate مثبت |
| Redirect boundary | `blocked` | يحتاج safe controlled destination oracle خارج local-only boundary |

لا يوجد candidate promoted في الدورة الحالية. تقرير التحليل هو [`reports/evaluation/p10_candidates/JUICE-SHOP-ADDITIONAL-CANDIDATES-ANALYSIS-v1.md`](reports/evaluation/p10_candidates/JUICE-SHOP-ADDITIONAL-CANDIDATES-ANALYSIS-v1.md)، وفهرس كل tracks في [`reports/evaluation/p10_candidates/README.md`](reports/evaluation/p10_candidates/README.md).

## ProofBundle وstrict verification

أي confirmation قابلة للتقرير يجب أن تحتوي، حسب contract المناسب، على baseline وcandidate وtarget-backed causal signal وindependent negative control وdigests وvalidator metadata وsealed ProofBundle و`verify_seal()==true` وreplay ناجح. لا يتم تحويل missing evidence أو observation-only إلى clean أو confirmation.

المكونات المركزية تشمل [`src/webpent/models/proof_bundle.py`](src/webpent/models/proof_bundle.py)، [`src/webpent/shared/verifier.py`](src/webpent/shared/verifier.py)، [`src/webpent/shared/campaign_executor.py`](src/webpent/shared/campaign_executor.py)، و[`src/webpent/shared/evidence_quality.py`](src/webpent/shared/evidence_quality.py).

## Target package وAction Authority

كل action تنفيذي يمر عبر authority المركزية، ولا تملك طبقات intelligence أو RAG أو LLM صلاحية مستقلة لتنفيذ HTTP أو browser navigation أو توسيع scope أو ترقية candidate إلى confirmed.

| الطبقة | الدور | القيد الأساسي |
|---|---|---|
| Target Intelligence | بناء صورة عن الهدف والكيانات والـworkflows | لا تنفذ actions ولا تمنح confirmation |
| Research/RAG | اقتراح knowledge وhypotheses | المحتوى غير الموثوق لا يصبح instruction |
| Attack Graph | ترتيب المسارات والاعتماديات | لا يتجاوز scope أو authority |
| LLM | تلخيص وترتيب proposals | لا ينتج evidence أو confirmation |
| Action Executor | تنفيذ action مصرح ومراقب | لا يعمل خارج authority |
| Validators | تحليل النتيجة وقرار الحالة | لا يحول missing evidence إلى clean |
| Reporter | إصدار تقرير redacted | لا يرسل تلقائيًا لمزود خارجي |

المكونات ذات الصلة تشمل [`src/webpent/shared/target_package_context.py`](src/webpent/shared/target_package_context.py)، [`src/webpent/shared/engagement_factory.py`](src/webpent/shared/engagement_factory.py)، [`src/webpent/shared/package_scope.py`](src/webpent/shared/package_scope.py)، و[`src/webpent/shared/package_preflight.py`](src/webpent/shared/package_preflight.py).

## BBScout وLLM وRAG

تكامل BBScout advisory/offline افتراضيًا ولا ينفذ provider submission أو signup/login تلقائيًا. الإعدادات الآمنة الأساسية هي:

```dotenv
BBSCOUT_ENABLED=false
BBSCOUT_MODE=offline
BBSCOUT_REQUIRE_VERIFIED_SIGNATURE=true
BBSCOUT_BROWSER_ENABLED=false
BBSCOUT_BROWSER_READ_ONLY=true
BBSCOUT_SIGNUP_ENABLED=false
BBSCOUT_PROVIDER_SUBMISSION_ENABLED=false
```

LLM اختياري ومخرجاته proposals أو summaries فقط. عند غياب provider أو capability يجب أن تكون النتيجة `blocked` أو `coverage gap`، وليس `clean`. RAG اختياري؛ Chroma لا يُشغّل كـnetwork server في المسار الافتراضي، ويظل deployment المتصل بالشبكة خارج qualification الحالية.

## التشغيل المحلي الآمن

ابدأ دائمًا بـTargetSpec يصف هدفًا واحدًا وتصريحًا واحدًا ونطاقًا واحدًا. عنوان loopback وحده لا يساوي تفويضًا؛ يلزم opt-in صريح وcanonical origin وhost وport وpath وredirect policy وrequest budget.

```bash
python main.py --help
python main.py scan --help
python main.py status --profile single-target-safe
python main.py doctor
```

لـJuice Shop local lab استخدم config خارج Git مثل `/tmp/juice-target-spec.json`:

```bash
python main.py scan \
  --config /tmp/juice-target-spec.json \
  --profile single-target-safe \
  --dry-run

python main.py scan \
  --config /tmp/juice-target-spec.json \
  --profile single-target-safe \
  --no-llm \
  --report-format json
```

`--dry-run` يراجع admission وscope والميزانيات ولا يرسل request ولا يفتح browser. لا تستخدم `--auto-approve` إلا على lab مصرح به وبعد مراجعة scope والسياسة. لا تضع credentials أو cookies أو OTPs أو API keys داخل TargetSpec أو logs أو reports.

للتدقيق المحلي في artifact مسجل، بدون target I/O أو تشغيل PoC:

```bash
python main.py verify-run \
  --artifact /path/to/webpent-engagement.json \
  --run-id RUN_ID \
  --output json

python main.py replay \
  --artifact /path/to/webpent-engagement.json \
  --run-id RUN_ID \
  --output json

python main.py report \
  --artifact /path/to/webpent-engagement.json \
  --run-id RUN_ID \
  --format md \
  --output webpent-report.md
```

## الاختبارات والـrelease gates

من جذر المشروع، بعد تثبيت dev dependencies:

```bash
PYTHONPATH=src:integrations/bbscout/src .venv/bin/pytest -q
.venv/bin/ruff check src scripts tests benchmarks
.venv/bin/python -m compileall -q src scripts benchmarks
.venv/bin/python scripts/scan_direct_io.py
.venv/bin/python scripts/check_generic_target_neutrality.py
.venv/bin/python scripts/check_target_adapter_review_packet.py
.venv/bin/python scripts/check_g02_runtime.py
.venv/bin/python scripts/check_g02_precommit.py
.venv/bin/python scripts/check_tracked_secrets.py
.venv/bin/python scripts/check_juice_shop_governance_packet.py
.venv/bin/python scripts/check_juice_shop_p10_expansion_plan.py
.venv/bin/python scripts/check_ai_review_owner_approval_boundary.py
.venv/bin/python scripts/check_release_manifest_provenance.py
git diff --check
```

الـfull validation الأخير أعطى **1906 passed**، والاختبارات targeted الخاصة بالحدود الجديدة وJuice Shop أعطت **7 passed**. كما نجحت Ruff وcompileall وdirect-I/O وneutrality وadapter review وG-02 وsecret scan وgovernance وexpansion وrelease provenance.

عند أي تغيير في source أو docs المتتبعة يجب إعادة توليد release manifest ثم commit له، وبعده توليد provenance sidecar في commit مستقل، ثم تشغيل validator. لا تدخل ملفات `.env` أو SQLite أو cookies أو credentials أو logs الحساسة في release.

## متطلبات P10 Qualified وVIP

لا تصبح P10 Qualified إلا بعد تحقيق المتطلبات فعليًا، وليس بالـmapping أو source analysis وحدهما:

| المتطلب | الحالة الحالية |
|---|---|
| Approved cases | `3/10` |
| Approved classes | `3/6` |
| Causal oracle لكل حالة | غير مكتمل للمجموعة المطلوبة |
| Safe precondition لكل حالة | غير مكتمل للمجموعة المطلوبة |
| Independent negative control | مطلوب لكل حالة promoted |
| Sealed/replayable ProofBundle | مطلوب لكل confirmation |
| Valid isolated official runs | `0/3`؛ gate مغلق |
| Metrics recomputation | غير مسموح كـqualification قبل إغلاق oracle/set gates |
| Final qualification decision | لم يصدر |

أي حالات `blocked` أو `observation-only` أو `out_of_scope` لا تُحسب FN ولا تُستخدم لرفع case count أو class count اصطناعيًا. بعد الوصول إلى approved set حقيقي يحقق `10 cases / 6 classes` والحصول على human governance signoff، يمكن إعداد Owner Decision Packet منفصل لطلب فتح Official P10 Runs؛ لا يتم فتحه تلقائيًا.

## Release identity والمراجع الداخلية

آخر commits المرتبطة بالدورة الحالية:

```text
9592dc0 docs: record AI review and owner approval policy
29a4623 docs: trace case thresholds and candidate blockers
3af3ba9 test: enforce non-human review approval boundary
fe35e5c chore: refresh release manifest
b5de9a4 chore: refresh release manifest provenance
```

آخر HEAD مرفوع إلى GitHub هو `b5de9a4311d0927198da4133b6e9f52057aeb04f`، وهو مطابق لـ`origin/master`. release manifest وprovenance validator يثبتان archive/tree/hash continuity؛ source commit المسجل داخل manifest هو `3af3ba90da58580de97bd9fdd2938ca2f5fe9412`، وmanifest commit هو `fe35e5c896ca51c268b3db0e51e1d3854a7f3b9e`.

المراجع الأساسية:

- [`docs/CURRENT_RELEASE.md`](docs/CURRENT_RELEASE.md)
- [`docs/VIP_INTEGRATED_EXECUTION_STATUS.md`](docs/VIP_INTEGRATED_EXECUTION_STATUS.md)
- [`docs/vip_quality_gate.json`](docs/vip_quality_gate.json)
- [`docs/juice_shop_governance_decision_v1.json`](docs/juice_shop_governance_decision_v1.json)
- [`docs/juice_shop_p10_ground_truth_v1.json`](docs/juice_shop_p10_ground_truth_v1.json)
- [`docs/juice_shop_p10_expansion_plan_v1.json`](docs/juice_shop_p10_expansion_plan_v1.json)
- [`docs/p10_oracle_semantics_decision_v1.json`](docs/p10_oracle_semantics_decision_v1.json)
- [`docs/juice_shop_source_ground_truth_manifest_v1.json`](docs/juice_shop_source_ground_truth_manifest_v1.json)
- [`docs/juice_shop_loopback_runtime_manifest_v1.json`](docs/juice_shop_loopback_runtime_manifest_v1.json)
- [`docs/release_manifest.json`](docs/release_manifest.json)
- [`docs/release_manifest_provenance_v1.json`](docs/release_manifest_provenance_v1.json)
- [`reports/evaluation/JUICE-SHOP-P10-COVERAGE-EXPANSION-RESULT-v1.md`](reports/evaluation/JUICE-SHOP-P10-COVERAGE-EXPANSION-RESULT-v1.md)
- [`reports/evaluation/p10_candidates/README.md`](reports/evaluation/p10_candidates/README.md)

## License and authorized use

راجع ملف الترخيص وسياسات المشروع قبل التوزيع. يجب أن يظل الاستخدام داخل أنظمة مصرح بها، مع احترام scope وrate limits وprivacy وretention وسياسات البرنامج المختبر.

> **الخلاصة:** WebPent أصبح إطارًا bounded وfail-closed مع ProofBundle وreplay وidentity isolation وreport continuity. لكنه ما زال **NOT_QUALIFIED** كـP10/P9/VIP لأن approved set الحالي 3/3، والـofficial runs صفر، وhuman signoff غير موجود. الهدف التالي الصحيح هو تطوير أدلة مرشحين شرعيين فقط أو إعداد Owner Decision Packet عند الحاجة إلى gated action.

---

**المشروع على GitHub:** [ElgendyMan/webpent-v61](https://github.com/ElgendyMan/webpent-v61)

**إعداد الوثيقة:** Manus AI
