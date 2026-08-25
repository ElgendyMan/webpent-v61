# WebPent

**WebPent** هو إطار عمل Python لاختبار اختراق تطبيقات الويب داخل نطاق مصرح ومحدد. يجمع بين الاكتشاف الحتمي، إدارة الفرضيات، تحليل الهوية والصلاحيات، التخطيط bounded، التحقق القابل لإعادة التشغيل، الذاكرة وRAG، التقارير redacted، والتكامل الاختياري مع LLM. التصميم يفصل بوضوح بين **الملاحظة** و**الفرضية** و**التنفيذ** و**الدليل** و**الـFinding**.

> **الحالة الحالية:** WebPent هو **Evidence-Aware Bounded Autonomous Bug-Hunting Framework** وليس VIP Smart Autonomous Bug Hunter مؤهلًا رسميًا بعد. لديه authority وscope وidentity isolation وProofBundle وreplay وnegative-control gates، لكن qualification الحية المستقلة لم تكتمل بعد.

> **تنبيه قانوني:** استخدم WebPent فقط على أنظمة تملكها أو لديك تصريح كتابي لاختبارها. لا تستخدمه على أهداف عامة أو أنظمة طرف ثالث دون تفويض صريح. هذا المشروع لا يرسل تقارير تلقائيًا إلى منصات bug bounty ولا ينفذ signup/login أو أي إجراء خارجي دون policy وauthorization وHuman-in-the-Loop مناسبة.

## الحكم التنفيذي الحالي

التقييم الهندسي الموثق هو **76/100 Engineering Maturity**. هذه النسبة تقيس نضج البنية، سلامة النطاق، authority، جودة الإثبات، orchestration، recovery، والـruntime readiness. لا تعني أن النظام يكتشف 76% من الثغرات، ولا تعني أنه اجتاز qualification حيًا.

الحكم التشغيلي الحالي هو:

> **Bounded Autonomous Bug-Hunting Framework — NOT VIP-qualified.**

المشروع يستطيع تنظيم حملة داخل scope، توليد hypotheses، ترتيب actions، تشغيل validators، ربط findings بالأهداف والهويات، بناء ProofBundle مختومة، وإصدار تقارير redacted. لكنه لم يثبت بعد في ثلاث جولات حية مستقلة أنه يكتشف ويؤكد العدد المطلوب من الثغرات على target حقيقي مصرح به مع thresholds المطلوبة.

| المعيار | الحالة الحالية |
|---|---|
| Engineering maturity | `76/100` |
| VIP qualification | `NOT_QUALIFIED` |
| Qualification runs | `0/3` جولات حية مؤهلة مثبتة |
| WAPTLab live qualification | غير مكتملة؛ التحقق الأخير تعطل بـ`HTTP 403` في التدفقات الطبيعية |
| Strict live confirmed findings في qualification الحالية | `0` |
| Promoted live ProofBundles في qualification الحالية | `0` |
| G-02 direct-I/O gate | ناجح؛ `external_target_contacted=false` |
| Full regression في آخر تحقق | `1739 passed, 6 skipped, 62 warnings` |
| Release manifest | verifier ناجح على الشجرة الحالية؛ provenance يعاد توليده ضمن release gate |

## ما الذي نُفذ في الخطة؟

### 1. Foundation وTarget Package v2

تم بناء عقد intake يصف البرنامج والهدف والنطاق والسياسة والقدرات ومصدر البيانات. الحزمة تصف القيود ولا تمنح صلاحيات إضافية، ولا تستطيع توسيع scope أو تجاوز `ActionAuthority` أو شروط الإثبات.

تم تنفيذ والتحقق من العناصر التالية:

- canonical `content_sha256` مع فصل `source_response_sha256` عن hash محتوى الحزمة.
- detached Ed25519 signature verification للحزم التنفيذية.
- `EngagementFactory` مع one-time engagement lease في SQLite صغير لا يحفظ raw package أو secrets.
- رفض package ID أو digest غير المطابق، والهدف الخارج عن النطاق، والحزمة المنتهية أو الملغاة، وإعادة استهلاك package أو engagement.
- `ScopeCompiler` موحد يفحص scheme وhost وport وpath وwildcard وexclusion وmethod وaction class وredirect chain.
- capability preflight يحول غياب capability إلى `blocked` أو `inconclusive` أو knowledge gap، وليس إلى `clean`.

المكونات المركزية موجودة في [`src/webpent/shared/target_package_context.py`](src/webpent/shared/target_package_context.py)، و[`src/webpent/shared/engagement_factory.py`](src/webpent/shared/engagement_factory.py)، و[`src/webpent/shared/package_scope.py`](src/webpent/shared/package_scope.py)، و[`src/webpent/shared/package_preflight.py`](src/webpent/shared/package_preflight.py).

### 2. Central Action Authority وsafe execution

كل action تنفيذي يجب أن يمر عبر authority المركزية. طبقات intelligence وRAG وLLM والـresearchers لا تملك صلاحية مستقلة لتنفيذ HTTP أو browser navigation أو توسيع scope أو ترقية candidate إلى confirmed.

`ActionAuthority` وpolicy gates يحافظان على الفصل بين:

| الطبقة | الدور | ما لا تستطيع فعله |
|---|---|---|
| Target Intelligence | بناء صورة عن الهدف والكيانات والـworkflows | لا تنفذ actions ولا تمنح confirmation |
| Research/RAG | اقتراح knowledge أو hypotheses | لا تعتبر المحتوى تعليمات تنفيذ |
| Attack Graph | ترتيب المسارات والاعتماديات | لا يتجاوز scope أو authority |
| LLM | تلخيص وترتيب وتحسين proposals ضمن policy | لا ينتج evidence أو confirmation |
| Action Executor | تنفيذ action مصرح ومراقب | لا يعمل خارج authority |
| Validators | تحليل النتيجة وقرار الحالة | لا يحول missing evidence إلى clean |
| Reporter | إصدار finding/report redacted | لا يرفع التقرير تلقائيًا لمزود خارجي |

### 3. Identity isolation وtarget isolation

تم تعزيز عزل engagements وtargets وfindings والهويات. الـmemory والـlessons والـRAG projections ترتبط بالسياق المناسب، ولا يجوز أن تنتقل cookies أو credentials أو ownership claims من target أو identity إلى آخر.

مسار BAC/IDOR يستخدم `IdentityProfile` وownership provenance وobservations منزوعة الحساسية. confirmation لا تعتمد على اختلاف response فقط، بل تحتاج إلى target-backed causal signal مع baseline وcandidate وindependent negative control.

### 4. Target Brain وAttack Graph وbounded research

تمت إضافة طبقات advisory لتحليل target entities والـworkflows والـpermissions والـstate transitions، مع bounded planning وspecialist researcher contracts وhypothesis bridge. هذه الطبقات تفيد في ترتيب الاختبارات وتحديد gaps، لكنها لا تملك execution authority ولا تستطيع توسيع النطاق.

المحتوى القادم من RAG أو write-ups أو repositories يعامل كبيانات غير موثوقة داخل trust boundary. لا يتم تنفيذ تعليمات موجودة داخل هذه المصادر لمجرد ظهورها في النص.

### 5. BBScout integration

WebPent يقرأ bbscout كمصدر advisory لـ`Target Package v2` فقط عبر [`src/webpent/shared/bbscout_bridge.py`](src/webpent/shared/bbscout_bridge.py)، مع bundled source مراجع تحت [`integrations/bbscout`](integrations/bbscout) لا يعتمد على مسار خارجي. التكامل لا يرسل HTTP أو browser navigation أو signup/login أو provider submission من تلقاء نفسه؛ provider-live qualification تظل منفصلة عن fixtures والعقود.

الإعدادات الآمنة الافتراضية:

```dotenv
BBSCOUT_ENABLED=false
BBSCOUT_MODE=offline
BBSCOUT_REQUIRE_VERIFIED_SIGNATURE=true
BBSCOUT_BROWSER_ENABLED=false
BBSCOUT_BROWSER_READ_ONLY=true
BBSCOUT_SIGNUP_ENABLED=false
BBSCOUT_PROVIDER_SUBMISSION_ENABLED=false
```

لا تضع Gmail passwords أو cookies أو OTPs أو API keys داخل `.env` أو source أو checkpoints أو prompts أو reports. إذا استُخدم `BBSCOUT_CREDENTIALS_REF` مستقبلًا، يجب أن يكون reference opaque إلى secret manager مع human-approved session handoff.

### 6. ProofBundle وstrict verification

تم بناء ProofBundle مركزي immutable وقابل للختم والتحقق وإعادة التشغيل. أي confirmation قابلة للتقرير يجب أن تحتوي على:

1. baseline request/response.
2. candidate request/response.
3. causal signal target-backed.
4. independent neutral negative control.
5. baseline/candidate/response digests.
6. validator وreplayable metadata.
7. sealed bundle و`verify_seal() == true`.
8. replay ناجح على نفس engagement/finding/target.
9. cleanup status مناسب عند الحاجة.

في Phase 4 تم تنفيذ hardening إضافي:

- إلزام `hypothesis_id` و`scope_context` و`identity_context` عندما تكون موجودة في الحزمة.
- مقارنة replay metadata بعد redaction وبـdigest ثابت.
- رفض replay context الذي يحتوي على حقول غير معروفة.
- رفض اختلاف engagement أو finding أو target أو scope أو identity أو target package.
- منع mutation أثناء replay المتكرر.
- استكمال metadata الناقصة من نفس الـbundle في `CampaignExecutor` و`evidence_quality` فقط، مع إبقاء أي mismatch مقدم مرفوضًا fail-closed.

المسارات المركزية هي [`src/webpent/models/proof_bundle.py`](src/webpent/models/proof_bundle.py)، و[`src/webpent/shared/verifier.py`](src/webpent/shared/verifier.py)، و[`src/webpent/shared/campaign_executor.py`](src/webpent/shared/campaign_executor.py)، و[`src/webpent/shared/evidence_quality.py`](src/webpent/shared/evidence_quality.py).

### 7. Aggregation وreporting

تم الحفاظ على aggregation وعدم خلط findings بين engagements أو targets. يتم استخدام endpoint-scoped fingerprints عند الحاجة، خصوصًا في IDOR/BAC، مع منع تحويل تكرار تاريخي أو finding مشابه من target آخر إلى evidence جديد.

التقارير الحالية تدعم JSON وHTML وMarkdown وPDF عندما تكون المخرجات مفعلة في النسخة المستخدمة. التقرير redaction-safe ويحتوي على audit trail وpackage continuity عند وجود package-backed engagement. الـProofBundle لا يصعد إلى التقرير top-level إلا بعد validation ناجح.

### 8. G-02 direct-I/O inventory

تم تنفيذ direct-I/O inventory deterministic لتتبع transports ومسارات الاتصال المباشر. آخر artifact متولد يحتوي على `321 records`، ونجح checker بدون اتصال بهدف خارجي:

```text
{"errors": [], "external_target_contacted": false, "passed": true}
```

الملفات هي [`docs/direct_io_inventory.json`](docs/direct_io_inventory.json) و[`docs/DIRECT_IO_INVENTORY.md`](docs/DIRECT_IO_INVENTORY.md).

### 9. Docker وRedis وCelery وPlaywright

يوجد مسار Docker/Compose وRedis وCelery worker وPlaywright/Chromium. تم اختبار contracts وdev smoke محليًا في بيئات سابقة، لكن **distributed production qualification** ليست مكتملة. نجاح SQLite المحلي أو تشغيل worker واحد لا يثبت HA أو outage recovery أو multi-worker checkpoint qualification.

تشغيل dev stack يحتاج بيئة Docker-capable:

```bash
make build-base
docker compose -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.dev.yml ps
docker compose -f docker-compose.dev.yml logs -f api worker
```

### 10. Phase 3: BAC/IDOR proof validation

تم تنفيذ وإثبات BAC/IDOR حي على WAPTLab المحلي المصرح فقط للهدف Catalog #6:

```text
GET /v1/crm/download/1
```

الإثبات السابق استخدم owner وforeign مستقلين، baseline وcandidate وanonymous negative control، target-backed causal signal، ProofBundle sealed، `verify_seal()==true`، وreplay passed/replay_verified. تم رفع التغييرات في commit:

```text
dceca57fea222a1ca5851dc98eaccffc9661c27f
```

### 11. Phase 4: proof/replay hardening

تم تنفيذ hardening محافظ في ProofBundle وstrict verifier وCampaignExecutor وevidence_quality، مع regression tests للعزل وunknown fields وidempotent replay. نتائج التحقق الأخيرة:

```text
Targeted regression: passed
G-02 tests: 18 passed
Full pytest: 1739 passed, 6 skipped, 62 warnings
Ruff: All checks passed!
compileall: passed
git diff --check: passed
```

تم رفع Phase 4 في commit:

```text
5e12aeadf1dbab0ce35c73845ec69c781ce583cf
```

### 12. Phase 5: release verification

تمت مراجعة local/remote SHA، الحذفات، الملفات الحساسة، G-02، Ruff، compileall، targeted tests، وfull pytest. النتيجة:

```text
HEAD=5e12aeadf1dbab0ce35c73845ec69c781ce583cf
ORIGIN_MASTER=5e12aeadf1dbab0ce35c73845ec69c781ce583cf
working_tree_clean
DELETED_FILES_FROM_PHASE3=[empty]
CURRENT_DELETED_FILES=[empty]
```

لكن التحقق اللاحق من `scripts/verify_release_artifacts.py` كشف أن [`docs/release_manifest.json`](docs/release_manifest.json) يحمل commit/hash metadata قديمة، ولذلك يجب اعتبار **release provenance غير مغلق** إلى أن يعاد توليد manifest من HEAD الحالي ويعاد تشغيل verifier بنجاح.

## المتطلبات والتثبيت

- Python 3.12.
- Docker Compose وRedis لمسارات Celery والـstack الكامل.
- Playwright/Chromium لمسارات browser-based.
- `cryptography` لمسار Ed25519.
- LLM provider وembedding model اختياريان.

من جذر المشروع:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
playwright install chromium
```

للتشغيل الحتمي بدون LLM:

```bash
export LLM_ENABLED=false
export WEBPENT_LLM_ENABLED=false
```

أنشئ secrets محلية وقت التشغيل فقط، ولا تضعها في Git أو logs أو reports:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

استخدم قيمًا مختلفة وقوية مع `JWT_SECRET_KEY` و`AUDIT_SECRET_KEY` و`CELERY_PAYLOAD_KEY` عند الحاجة. لا تضع API keys أو cookies أو credentials داخل source أو prompts أو checkpoints.

## التشغيل المحلي

تحقق من options الفعلية في النسخة التي ستشغلها:

```bash
python main.py --help
python main.py scan --help
python main.py status --profile smart-observe
python main.py preflight
```

مثال على local lab مصرح به:

```bash
python main.py scan \
  --url http://127.0.0.1:4280 \
  --profile smart-observe
```

`--profile` يحدد composition والسياسة الفعلية للحملة. لا تستخدم `--auto-approve` إلا على lab مصرح به وبعد مراجعة scope والسياسة. الوضع الافتراضي يحافظ على Human-in-the-Loop قبل العمليات النشطة أو الحساسة.

## الاختبارات وبوابات الإصدار

من جذر WebPent وبعد تثبيت dev dependencies:

```bash
PYTHONPATH=src python -m pytest -q
ruff check src tests scripts
python -m compileall -q src scripts tests
PYTHONPATH=src python scripts/scan_direct_io.py
python scripts/check_g02_precommit.py
python scripts/verify_release_artifacts.py \
  --repo . \
  --manifest docs/release_manifest.json
```

في archive التكامل الذي يحتوي bbscout وWebPent متجاورين:

```bash
cd bbscout
PYTHONPATH=src python -m pytest -q

cd ../webpent
PYTHONPATH=../bbscout/src:src python -m pytest tests/ -q --tb=short
```

نجاح الاختبارات لا يثبت qualification حيًا أو موزعًا. يجب حفظ logs خارج archive وعدم إدخال SQLite أو cookies أو credentials أو `.env` في release.

## ما الذي ما زال ناقصًا؟

### 1. Release manifest drift — blocker فوري

يجب إعادة توليد `docs/release_manifest.json` من HEAD النهائي `5e12aeadf1dbab0ce35c73845ec69c781ce583cf`، ثم تشغيل verifier الرسمي والتأكد من:

```text
passed=true
manifest_git_commit == HEAD
manifest hashes == current tracked source hashes
```

هذه الخطوة ضرورية لإغلاق provenance، ولا تعني أن source code الحالي غير صالح.

### 2. Live VIP qualification على WAPTLab

لم يتم اجتياز qualification الحية. WAPTLab المحلي أعاد `HTTP 403` على health/register وCatalog #6 في الجولة الأخيرة، ولذلك لم يتم استخدام bypass أو قراءة database أو sessions أو OTPs.

المطلوب بعد عودة التدفقات الطبيعية للعمل:

| الشرط | المطلوب |
|---|---|
| Independent repetitions | 3 جولات مستقلة مع reset نظيف لكل جولة |
| Coverage | على الأقل 15 confirmed findings من catalog المطلوب في كل جولة |
| Precision | لا تقل عن 90% |
| Reproducibility | لا تقل عن 95% |
| Proof coverage | 100% من confirmations لديها causal signal وnegative control وsealed/replayable ProofBundle |
| Isolation | صفر cross-target أو cross-engagement contamination |
| Deduplication | صفر duplicates تؤثر على metric |
| Scope safety | صفر scope violations |

لا يجوز استخدام candidates أو offline fixtures أو نتائج تراكمية من engagements مختلفة بدل هذه الشروط.

### 3. Distributed production qualification

وجود Docker وRedis وCelery contracts لا يثبت production readiness. ما زال يلزم staging قابل لإعادة الإنتاج يثبت:

- worker/Redis broker behavior.
- checkpoint resume بعد redelivery.
- idempotency مع أكثر من worker.
- outage وretry وbackpressure.
- backup/restore وretention.
- secrets وTLS وCORS وlogging بدون تسريب.
- عدم اختلاف policy variables بين API وworker.

### 4. Runtime discovery capabilities

بعض أدوات discovery الخارجية capability-dependent. عند عدم وجود الأداة يجب أن يظهر gap أو blocked state صريح، لا clean. يلزم اختبار runtime حقيقي لكل أداة يريد المستخدم اعتبارها جزءًا من autonomous workflow، خصوصًا typed browser handler وPlaywright proof plane وأدوات discovery المساندة.

### 5. Live provider adapters وauto-submission

HackerOne adapter الحالي محدود، بينما تكاملات Bugcrowd وIntigriti وYesWeHack تعمل كـoffline fixtures أو advisory contracts وليست live qualification. Auto-submit غير مفعّل في المسار الحالي ويجب ألا يفعّل بدون authorization منفصل وconfirmation صريحة وaudit كامل.

### 6. Live LLM provider qualification

LLM اختياري. deterministic fallback هو المسار الآمن عند غياب API key أو rate limit أو provider failure. يلزم اختبار كل provider فعليًا إذا كان مطلوبًا تشغيله، مع التأكد أن مخرجات LLM تظل proposals أو summaries ولا تتحول إلى evidence أو confirmation.

## التقييم النهائي

| البعد | التقييم |
|---|---:|
| Safety وscope enforcement | قوي |
| Proof/replay reliability | قوي offline وcontract-wise |
| Identity/target isolation | قوي في الاختبارات المركزية |
| Aggregation/report integrity | جيد ومربوط بالسياق |
| Discovery coverage الحية | غير مثبتة كفاية |
| Live confirmation | غير مؤهلة حاليًا |
| Distributed runtime | غير مؤهل بالكامل |
| Provider/browser ecosystem | جزئي وcapability-dependent |
| Engineering maturity | `76/100` |
| Autonomous Bug Hunter qualification | **لا، NOT_QUALIFIED** |

لو استخدمنا رقمًا واحدًا للقرب من الهدف، فالمشروع عند **76% نضج هندسيًا**. لكن هذا الرقم لا يساوي 76% من qualification الحية؛ qualification الرسمية ما زالت `0/3` جولات مؤهلة، والهدف لا يُعلن محققًا إلا بعد تنفيذ live matrix بالأدلة الصارمة.

## المراجع الداخلية

- [`docs/CURRENT_RELEASE.md`](docs/CURRENT_RELEASE.md) — canonical release identity.
- [`docs/VIP_INTEGRATED_EXECUTION_STATUS.md`](docs/VIP_INTEGRATED_EXECUTION_STATUS.md) — سجل تنفيذ المراحل والقيود.
- [`docs/PASTED_CONTENT_3_EXECUTION_STATUS.md`](docs/PASTED_CONTENT_3_EXECUTION_STATUS.md) — مصفوفة phases والـsource paths والاختبارات.
- [`docs/V75_MATURITY_SCORECARD.md`](docs/V75_MATURITY_SCORECARD.md) — engineering maturity scorecard.
- [`docs/vip_quality_gate.json`](docs/vip_quality_gate.json) — شروط بوابة VIP الآلية.
- [`docs/WAPTLAB_QUALIFICATION_STATUS.md`](docs/WAPTLAB_QUALIFICATION_STATUS.md) — حالة qualification الخاصة بـWAPTLab.
- [`docs/integration/final_audit.md`](docs/integration/final_audit.md) — final audit وحدود الادعاء.
- [`docs/release_manifest.json`](docs/release_manifest.json) — release provenance وhashes؛ تم التحقق منه على الشجرة الحالية عبر `verify_release_artifacts.py`.
- [`docs/integration/production_qualification.md`](docs/integration/production_qualification.md) — متطلبات production/distributed qualification.
- [`docs/integration/BBSCOUT_INTEGRATION.md`](docs/integration/BBSCOUT_INTEGRATION.md) — تكامل bbscout وحدوده.
- [`docs/LLM_PROVIDER_READINESS_2026-08-24.md`](docs/LLM_PROVIDER_READINESS_2026-08-24.md) — provider-aware LLM configuration.

## License and authorized use

راجع ملف الترخيص وسياسات المشروع قبل التوزيع. الاستخدام يجب أن يظل داخل أنظمة مصرح بها، مع احترام scope وrate limits وprivacy وretention وسياسات البرنامج المختبر.

> **الخلاصة:** WebPent أصبح إطارًا أمنيًا قويًا، bounded، وfail-closed مع ProofBundle وreplay وidentity isolation وreport continuity. ما ينقصه للوصول إلى وصف **VIP Smart Autonomous Bug Hunter** هو إثبات qualification حي مستقل وقابل للتكرار، ثم تأهيل distributed runtime وcapability-dependent adapters بصورة واقعية لا تعتمد على fixtures فقط.

---

**آخر حالة موثقة:** source hardening بدأ من commit `5e12aeadf1dbab0ce35c73845ec69c781ce583cf`، والـrelease manifest الحالي يمر بالـoffline verifier؛ أي commit release جديد يجب أن يعيد توليد manifest ويعيد تشغيل verifier.

**المشروع على GitHub:** [ElgendyMan/webpent-v61](https://github.com/ElgendyMan/webpent-v61)
**إعداد الوثيقة:** Manus AI


## Dependency Security Boundary: RAG and ChromaDB

The core WebPent installation does not require ChromaDB, `langchain-chroma`, or `sentence-transformers`. These packages are available only through the opt-in `rag` extra:

```bash
python -m pip install -e ".[dev,rag]"
```

WebPent uses Chroma through a local embedded `persist_directory` path and does not use `HttpClient`, `PersistentClient`, or a Chroma network server. The default release and CI posture keeps `DISABLE_RAG=true` and `EMBEDDINGS_OFFLINE=true`; SQLite and deterministic fallback paths remain available when RAG is unavailable.

The `rag` extra must not be deployed with an exposed Chroma server. Current Chroma advisories affecting the 1.x server line remain a release blocker for an RAG-enabled deployment until an upstream fixed version and a fresh dependency audit are available. Moving the extra out of core prevents the vulnerable server package from being installed by default, but it does not claim that the optional extra is fully security-qualified.

## Plan Execution Status

The implemented roadmap focused on bounded autonomy rather than unsafe broad scanning. Phase 1 established explicit scope, target identity, engagement identity, authorization, HITL, rate-limit, redaction, and fail-closed execution contracts. Phase 2 added target intelligence, endpoint and parameter normalization, target brain metadata, attack-graph planning, and deterministic fallbacks while keeping LLM output advisory-only. Phase 3 added research and memory isolation, bounded RAG retrieval, provenance, reusable methodology packs, and target-scoped persistence. Phase 4 added validation state transitions, causal-signal and negative-control requirements, sealed and replayable `ProofBundle` evidence, aggregation, report linkage, and strict cross-target/cross-identity binding. Phase 5 added release artifacts, preflight/capability reports, G-02 direct-I/O inventory, security scans, CI/Make release entry points, dependency boundary controls, bundled bbscout contracts, and final provenance verification. The remaining qualification work is explicitly separated from these offline/contract accomplishments.

The most recent hardening also makes release-manifest freshness a real gate. The quality gate rebuilds and verifies the manifest against the final source tree instead of accepting generation alone. The CI workflow and Makefile expose the same release verification path.

## Current Evidence

The current validation includes the dependency-boundary and bundled-bbscout work after `5e12aeadf1dbab0ce35c73845ec69c781ce583cf`. Regression evidence includes `1739 passed, 6 skipped, 62 warnings`, successful Ruff and `compileall`, G-02 with `external_target_contacted=false`, a passing offline release-manifest verifier, and no live qualification claim. The local WAPTLab run remains limited to the authorized environment; Docker is available but the natural application flow returned HTTP 403.

After any change to dependencies or release scripts, regenerate `uv.lock`, run the focused deployment/release tests, run the complete quality gate, regenerate `docs/release_manifest.json`, and execute the manifest verifier. Do not interpret a passing offline contract report as live WAPTLab qualification.

## Remaining Blockers to VIP Qualification

WebPent is a bounded autonomous bug-hunting framework, but it is not yet VIP-qualified as an autonomous bug hunter. The remaining blockers are:

1. Any release commit must regenerate the manifest from that tree and pass the official offline verifier with matching hashes.
2. WAPTLab qualification requires three independent natural-flow resets, with baseline, candidate, independent negative control, target-backed causal signal, sealed ProofBundle, `verify_seal()==true`, and successful replay for every promoted finding.
3. Each qualification run must meet the documented thresholds: at least 15 of 20 distinct catalog findings, at least 90% precision, at least 95% reproducibility, 100% proof coverage, no scope violations, and no duplicate inflation.
4. The bundled bbscout boundary is now reproducible and covered by fixtures/contracts; provider-live qualification remains separate and must not be inferred from fixtures.
5. Docker/Redis/Celery worker critical-path qualification and the typed browser/discovery runtime path still require a real, authorized environment check; their contracts alone are not live proof.
6. The optional RAG extra remains security-gated until the remaining ChromaDB advisory is resolved or a reviewed, supported alternative is used.

The honest current label is **Bounded Autonomous Bug-Hunting Framework — NOT VIP-qualified**. The engineering maturity score is approximately 76/100, but that score must not be converted into a live vulnerability-discovery or qualification percentage.

## Release Checklist

```bash
# Core development environment
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Optional local-only RAG, after reviewing current advisories
.venv/bin/pip install -e ".[dev,rag]"

# Static and focused checks
.venv/bin/ruff check src tests scripts
PYTHONPATH=src .venv/bin/python -m compileall -q src scripts
PYTHONPATH=src .venv/bin/python -m pytest -q tests/test_production_deployment_contract.py tests/test_release_artifact_audit.py tests/security_invariants

# Release artifacts and provenance
PYTHONPATH=src .venv/bin/python scripts/scan_direct_io.py
PYTHONPATH=src .venv/bin/python scripts/check_g02_precommit.py
PYTHONPATH=src .venv/bin/python scripts/build_release_manifest.py
PYTHONPATH=src .venv/bin/python scripts/verify_release_artifacts.py --repo . --manifest docs/release_manifest.json

# Full suite
PYTHONPATH=src .venv/bin/python -m pytest -q
```

Never add `.venv`, local profiles, cookies, sessions, OTPs, reset URLs, API keys, mail logs, or target secrets to Git. Never use database/session/OTP bypasses, broad external scanning, OAST, or live bug-bounty submission as a substitute for the documented authorization and evidence gates.
