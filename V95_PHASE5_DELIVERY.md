# WebPent v95 — Phase 5 Delivery

## Scope

تم استكمال Phase 5.1 للـnegative feedback loop، وتحويل Devil’s Advocate في Phase 5.2 إلى hard gate bounded، ثم إضافة طبقات v95 الخاصة بالمراجعة المستقلة، KEV advisory context، scope drift، LLM budget fail-closed، وoffline nightly benchmark.

## Implemented controls

| Control | Behavior | Confirmation impact |
|---|---|---|
| Negative lessons | تخزين scoped باستخدام `target_signature` بدون URL خام أو payload خام، واسترجاعها كـadvisory constraints | لا يرفع confirmation ولا ينشئ hypothesis تلقائيًا |
| Devil’s Advocate gate | finding المرفوضة عالية الخطورة تعود إلى validator مرة واحدة فقط عبر latch | تتحول إلى Pending/Needs Review ولا تُثبت تلقائيًا |
| Independent ensemble | provider ثانٍ مستقل يراجع High/Critical فقط عند توفره | يضيف `ensemble_review` داخل evidence فقط |
| KEV context | يطابق CVE مع catalog injected | advisory-only، لا يؤكد الثغرة |
| Scope drift | يكتشف origins المكتشفة خارج origin المعلن | يسجل HITL-required event ويظل التنفيذ fail-closed |
| LLM budget | يمنع planner LLM عند نفاد السقف ويستخدم fallback deterministic | يسجل `llm_budget_trace` |
| Nightly benchmark | workflow offline يعتمد على fixtures وcontract tests | لا يشغل WAPTLab أو Juice Shop |

## Verification

تم تشغيل compileall وRuff على `src` و`tests`، ونجحت جميع الفحوص. النتيجة النهائية: **1136 اختبارًا ناجحًا**، مع 207 warnings غير حاجبة. كما نجح offline benchmark بنتيجة finding واحدة، confirmed واحدة، وevidence-backed واحدة.

لم يتم تشغيل WAPTLab أو Juice Shop في هذه المرحلة، التزامًا بالقيد الصريح. لا يجوز تفسير نتائج fixture أو contract tests على أنها نتائج live scanning.

## Production notes

التحكم في LLM اختياري ويفشل مغلقًا عند غياب provider مستقل أو نفاد budget. يجب ضبط production secrets الحقيقية قبل التشغيل؛ تحذيرات dev secrets المتبقية في الاختبارات مقصودة ولا تمثل إعداد production صالحًا.
