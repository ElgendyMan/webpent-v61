# WebPent

**WebPent** هو إطار Python لاختبار اختراق تطبيقات الويب داخل نطاق مصرح ومحدد. يفصل التصميم بين الملاحظة والفرضية والتنفيذ والدليل والـFinding، ويستخدم `TargetSpec` وscope enforcement و`ActionAuthority` وidentity isolation و`ProofBundle` وredaction وreplay لضمان أن النتائج القابلة للتقرير مدعومة بأدلة قابلة للتحقق.

> **الحالة الحالية:** WebPent أصبح **Evidence-Aware Bounded Autonomous Bug-Hunting Framework** مع Generic Target Context Layer قابلة لإعادة الاستخدام. ما زال **ليس VIP Smart Autonomous Bug Hunter**، وليس P10 Qualified أو P9 Qualified. هذه الوثيقة تميز بوضوح بين تقدم الهندسة وبين إثبات جودة الكشف على أهداف حية.

> **تنبيه قانوني وتشغيلي:** استخدم WebPent فقط على أنظمة تملكها أو لديك تصريح كتابي لاختبارها. لا تستخدمه على أهداف عامة أو Bug Bounty أو أنظمة طرف ثالث دون تفويض صريح. الإعدادات الآمنة تمنع credential use وauto-submission وstate-changing actions وexternal callbacks افتراضيًا.

## الحالة الحالية باختصار

آخر commit منشور للكود هو `618ab5e87ff702150396906de4c5781b40d439b5`، وهو مطابق لـ`origin/master`. هذه النسخة من README وتقرير التقييم هما تغييرا توثيق محليان سيُثبتان في commit مستقل قبل التسليم. أحدث milestone أضاف طبقة عامة لإدارة Target Context وsynthetic session metadata وdisposable fixtures وsnapshot/restore وcapability leases، وربطها اختياريًا بـ`CampaignExecutor` مع الحفاظ على backward compatibility. تم اختبار نفس دورة lifecycle عبر Mock وJuice Shop وWebGoat وcrAPI offline، ولم تُعتبر حالات target-live غير الحاسمة نجاحًا أو فشلًا في الكشف.

| المحور | الحالة الحالية | المعنى الصحيح |
|---|---|---|
| Generic Core وTarget Context | `PASS` | عقود typed، capability lease، scope binding، lifecycle، revoke، cleanup، snapshot/restore موجودة ومختبرة. |
| Multi-target lifecycle portability | `PASS` offline | Mock وJuice Shop وWebGoat وcrAPI يستخدمون نفس العقود العامة من خلال adapters منفصلة. |
| Target Context regression | `39/39 passed` | نجاح هندسي مستهدف، وليس metric لجودة اكتشاف vulnerabilities. |
| WebGoat B2.1 IDOR | `INCONCLUSIVE` | baseline وcandidate وnegative control أعطت نفس redirect semantics (`302`)؛ لا يوجد causal confirmation. |
| crAPI object access | `BLOCKED` | لا يوجد requester/owner fixture injection وreset آمن قابل للتحقق ضمن النطاق الحالي. |
| Sealed scoring ProofBundles الجديدة | `0` | عدم إنشاء bundle صحيح عندما يكون oracle غير حاسم أو الحالة blocked. |
| Full regression | `1987 passed / 4 failures` | الأربعة failures تاريخية مرتبطة بـapproval-source hash drift؛ لم يتم إخفاؤها أو تخفيف validator. |
| Official P10 runs | `0` | `official_isolated_p10_runs_authorized=false` والـrun gate مغلق. |
| P10 / P9 / VIP | `NOT_QUALIFIED` | لا توجد qualification claim. |
| Bug Bounty / external targets | `BLOCKED` | لا يوجد نطاق خارجي مصرح به. |

## التقييم الحالي

التقدير المركب الحالي هو **حوالي 63/100 من نضج الطريق إلى VIP**. هذا رقم تحليلي شفاف، وليس معيارًا رسميًا ولا نتيجة qualification. تم حسابه من أوزان معلنة: foundation الهندسي `85/100` بوزن 30%، السلامة والحوكمة `90/100` بوزن 20%، portability الخاصة بالـlifecycle `90/100` بوزن 15%، target-live readiness `40/100` بوزن 15%، causal detection evidence `0/100` بوزن 10%، والـofficial qualification gates `0/100` بوزن 10%. النتيجة لا تحول blocked أو inconclusive إلى FN أو clean أو confirmed.

| محور التقييم | الدرجة التحليلية | سبب الدرجة |
|---|---:|---|
| Foundation الهندسي | `85/100` | Generic contracts، execution authority، evidence pipeline، lifecycle management، regression، وneutrality موجودة بدرجة قوية. |
| السلامة والحوكمة | `90/100` | fail-closed boundaries، scope isolation، redaction، وعدم فتح P10 أو Bug Bounty مطبقة. |
| Lifecycle portability | `90/100` | نفس Target Context contract يعمل offline عبر أربعة adapters. |
| Target-live readiness | `40/100` | WebGoat runtime alignment مثبت، لكن oracle غير حاسم؛ crAPI fixture prerequisites غير متاحة. |
| Causal detection quality | `0/100` حاليًا | لا توجد confirmations سببية target-backed صالحة للـWebGoat أو crAPI في هذه الدورة. |
| Official qualification | `0/100` | لا يوجد human independent signoff، ولا approved set يحقق 10 cases/6 classes، ولا 3 isolated official runs. |
| **المحصلة المركبة** | **`63/100`** | تقدير تقدم هندسي نحو الهدف، وليس qualification score. |

## ما تم بناؤه في آخر milestone

تمت إضافة [`src/webpent/shared/target_context.py`](src/webpent/shared/target_context.py) كعقد عام لإدارة target scope وcampaign/run binding وsynthetic identity metadata وsession وfixture وsnapshot وrestore وcapability lease وreadiness وdisposal. لا تحتوي الطبقة العامة على routes أو business logic أو semantics خاصة بـWebGoat أو crAPI أو Juice Shop.

تم ربط lifecycle اختياريًا بـ[`src/webpent/shared/campaign_executor.py`](src/webpent/shared/campaign_executor.py). عند تفعيل context-aware execution يجب أن ينجح acquisition والـlease والـreadiness والـsnapshot، وتُنفذ restore/dispose في مسارات النجاح والفشل. الـdispose يلغي lease نفسه، وفشل fixture ينظف session والـlease السابقين، مع اختبارات regression لهذه المسارات.

تمت إضافة providers target-local منفصلة في `src/webpent/adapters/` لـMock وWebGoat وcrAPI وJuice Shop. هذه providers offline وdeterministic وتستخدم metadata synthetic فقط. لا تنفذ live authentication أو credential handling أو auth bypass أو external callbacks أو state mutation.

## نتائج WebGoat وcrAPI

في WebGoat، تم إثبات service-to-build alignment للـruntime المحلي، لكن دورة IDOR السببية بقيت `INCONCLUSIVE`: observations الخاصة بالـbaseline وcandidate وindependent negative control اختزلت إلى نفس `302` redirect behavior. هذا لا يثبت vulnerability ولا clean result، ولذلك لم يتم إنشاء scoring ProofBundle.

في crAPI، بقي object-access case `BLOCKED` لأن requester/owner state وownership canaries لا يملكان fixture injection وreset آمنين قابلين للتحقق ضمن النطاق المصرح. لم يتم استخدام credentials أو token generation أو mutation لتجاوز ذلك.

## حدود الحوكمة والنطاق

الحالة الرسمية الحالية هي:

| invariant | القيمة |
|---|---|
| `human_independent_signoff_obtained` | `false` |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |

الأفعال التالية ما زالت gated: تعديل policy أو frozen Ground Truth أو thresholds، استخدام credentials أو login أو OTP/MFA/CAPTCHA bypass، state-changing أو destructive actions، استخدام target خارجي، فتح Official P10، أو إعلان qualification. الصمت لا يُعتبر موافقة، ومراجعة AI ليست human countersign.

لا يتم حفظ cookies أو tokens أو credentials أو raw response bodies أو raw headers أو process arguments أو environment secrets داخل Git أو release artifacts. جميع target-specific semantics تبقى داخل adapters أو profiles، وأي generic change يجب أن يثبت عبر أكثر من target abstraction.

## الاختبارات والـrelease gates

من جذر المشروع، بعد تثبيت dependencies:

```bash
PYTHONPATH=src:integrations/bbscout/src .venv/bin/pytest -q
.venv/bin/ruff check src scripts tests benchmarks
.venv/bin/python -m compileall -q src scripts benchmarks
.venv/bin/python scripts/scan_direct_io.py
.venv/bin/python scripts/check_generic_target_neutrality.py
.venv/bin/python scripts/check_g02_runtime.py
.venv/bin/python scripts/check_g02_precommit.py
.venv/bin/python scripts/check_tracked_secrets.py
.venv/bin/python scripts/check_release_manifest_provenance.py
git diff --check
```

نتائج الـTarget Context regression وCampaignExecutor وB2/B2.1 هي `39/39 passed`، وRuff وcompileall وG-02 وneutrality وsecret scan وrelease provenance ناجحة حسب artifacts الحالية. الـfull suite سجل 1987 نجاحًا و4 failures تاريخية تخص provenance لموافقة Option B القديمة؛ لا يجوز إصلاحها بإعادة كتابة السجل التاريخي أو تخفيف validator. راجع [تقرير التشخيص][1] و[تقرير E2E][2] للتفاصيل.

## المتطلبات المتبقية للوصول إلى VIP

أول فجوة فعلية هي إثبات target-backed causal detection، وليس إضافة abstraction جديدة فقط. يجب أولًا حل أو اعتماد disposition نهائي للـWebGoat oracle، وتوفير crAPI fixture/reset آمنين إذا كان ذلك مطلوبًا، ثم تنفيذ baseline/candidate/independent negative control مع oracle سببي حاسم وProofBundle sealed/replayable لكل حالة promoted.

بعد ذلك يلزم بناء approved case set حقيقي يحقق `10 cases / 6 classes`، والحصول على human independent governance signoff، ثم طلب Owner Decision منفصل لفتح Official P10. لا تُعتبر P10 مكتملة قبل `3` isolated official runs صحيحة وإعادة حساب metrics وصدور final qualification decision. وبعد تحقق كل ذلك فقط يمكن دراسة portability إلى نطاق Bug Bounty أو targets خارجية بقرار صريح.

الحالات `blocked` و`observation-only` و`inconclusive` و`out_of_scope` لا تُحسب FN ولا تُستخدم لرفع case count أو class count اصطناعيًا. كذلك لا تعتبر route reachability أو HTTP 200 أو lesson completion أو source presence وحدها دليل vulnerability.

## المراجع الداخلية

[1]: reports/evaluation/core_context/CORE-CONTEXT-LAYER-FAILURE-DIAGNOSIS-v1.md "Core Target Context Layer Failure Diagnosis"
[2]: reports/evaluation/core_context/TARGET-CONTEXT-LAYER-LOCAL-E2E-v1.json "Target Context Layer Local E2E Evidence"
[3]: reports/evaluation/core_context/CORE-CONTEXT-LAYER-BEFORE-AFTER-v1.md "Core Target Context Layer Before/After"
[4]: reports/evaluation/local_causal_lab/B2.1-TARGET-LIVE-REPORT-v1.md "B2.1 WebGoat IDOR Target-Live Report"
[5]: reports/evaluation/local_causal_lab/B2.1-FAILURE-TRIAGE-v1.md "B2.1 Failure Triage"
[6]: docs/release_manifest.json "Release Manifest"
[7]: docs/release_manifest_provenance_v1.json "Release Manifest Provenance"

## الاستخدام المصرح

راجع الترخيص وسياسات المشروع قبل التوزيع. يجب أن يظل الاستخدام داخل أنظمة مصرح بها، مع احترام scope وrate limits وprivacy وretention وسياسات البرنامج المختبر.

> **الخلاصة:** WebPent عند مستوى قوي هندسيًا في bounded execution والسلامة وlifecycle portability، لكنه لم يثبت بعد causal detection quality على WebGoat أو crAPI، ولذلك يظل `P10/P9/VIP=NOT_QUALIFIED` وBug Bounty=`BLOCKED`.

**المشروع على GitHub:** [ElgendyMan/webpent-v61](https://github.com/ElgendyMan/webpent-v61)

**إعداد الوثيقة:** Manus AI
