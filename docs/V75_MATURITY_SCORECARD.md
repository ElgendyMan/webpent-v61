# WebPent — V75 Engineering Maturity Scorecard

## الغرض وحدود الحكم

هذا المستند يعرّف مقياسًا هندسيًا شفافًا للوصول إلى هدف **75% maturity** في مشروع WebPent. الرقم ليس نسبة اكتشاف ثغرات، وليس عددًا تراكميًا للـfindings، وليس بديلًا عن qualification الخاصة بـVIP. لا يُسمح بتحويل candidate أو inventory أو نتيجة human review إلى confirmed finding.

> **الحكم الحالي:** WebPent حقق **76/100 في maturity الهندسية** وفق هذا المقياس، لكنه ما زال **NOT QUALIFIED كـVIP Smart Autonomous Bug Hunter**؛ لأن التشغيل الحي المكتمل الأخير أنتج صفر strict confirmed وصفر ProofBundle promoted.

## طريقة الحساب

المقياس موزون إلى ستة مكونات، ومجموع أوزانها 100 نقطة. النقاط الممنوحة لكل مكون لا تتجاوز وزنه، وتُمنح فقط عند وجود دليل قابل للمراجعة في الاختبارات أو artifacts أو commit pushed. الحساب الحالي هو:

| المكوّن | الوزن | النقاط المتحققة | الحالة |
|---|---:|---:|---|
| Build وrelease quality | 20 | 20 | Verified |
| Scope وexecution safety | 20 | 20 | Verified |
| Discovery وcampaign coverage | 20 | 12 | Partially verified |
| Validator وproof completeness | 20 | 8 | Contract present; live proof missing |
| Autonomy وrecovery | 10 | 9 | Verified with end-to-end gap |
| Runtime qualification | 10 | 7 | Completed smoke; not VIP-qualified |
| **الإجمالي** | **100** | **76** | **Engineering target reached** |

> **الحساب:** `20 + 20 + 12 + 8 + 9 + 7 = 76`.

## الأدلة التي بُني عليها التقييم

| المجال | الدليل القابل للمراجعة |
|---|---|
| Regression | `1471 passed, 56 warnings` في full suite بعد الإصلاح النهائي |
| Static quality | Ruff وcompileall و`git diff --check` نجحت |
| G-02 | direct-I/O inventory يحوي 283 سجلًا، واختبارات G-02 المستهدفة نجحت (`38 passed`) |
| Lifecycle | regression يثبت أن child tool لا يبقى orphan عند موت orchestrator الأب |
| Smoke runtime | WAPTLab محلي مصرح: target reachable، live target executed، scan completed خلال 149.53 ثانية |
| Reports | تم تصدير `report.json` و`report.html` و`report.md` في workspace التشغيل |
| Discovery limit | التقرير احتوى 4 candidate records، وليس 4 confirmations |
| Proof limit | `strict_confirmed=0`، وartifact tree لم يحوِ promoted proof bundles |
| Source provenance | التغييرات في commit [`42f1003`](https://github.com/ElgendyMan/webpent-v61/commit/42f1003) المرفوع إلى `origin/master` |

## الإصلاح المنفذ في هذه الدورة

كشف التشخيص أن timeout السابق لم يكن دليلًا على target unreachable؛ كان scan الأب ينتظر child `nuclei` ظل حيًا بعد إنهاء orchestrator/harness. السبب أن `start_new_session=True` يعزل child في session مستقلة، ولذلك يعالج timeout الذي يحدث داخل wrapper لكنه لا يكفي وحده عندما يموت orchestrator أولًا.

تمت إضافة Linux parent-death safeguard باستخدام `PR_SET_PDEATHSIG=SIGKILL` داخل [subprocess wrapper](../src/webpent/tools/utils/subprocess.py). يظل التنفيذ `shell=False`، وتظل قائمة executable المسموح بها، وargv validation، والـtimeouts، وprocess sessions، وscope/proof gates كما هي. لا يقوم الإصلاح بإرسال transport جديد، ولا يرقّي أي finding، ولا يخفّض أي threshold.

قبل patch، فشل regression بعد ملاحظة child نشط في حالة `State: S (sleeping)` عقب موت الأب. بعد patch، نجحت اختبارات lifecycle الأربعة، ثم نجحت full regression كاملة.

## نتيجة WAPTLab post-fix

تم تشغيل **smoke واحد فقط** على WAPTLab المحلي المصرح به باستخدام `authorized-active` و`--no-llm` وcampaign inventory المعلن. التشغيل اكتمل، ووصل إلى target، ونفذ live target، وأصدر التقارير. النتيجة المنشورة كانت أربعة candidates؛ جدول التقرير صنفها كـtentative/pending/needs human review، ولذلك لا تُعامل كـstrict confirmed.

| مقياس qualification | النتيجة |
|---|---:|
| Smoke runs completed | 1 |
| Qualifying runs completed | 0 |
| Scan completed | Yes |
| Target reachable | Yes |
| Live target executed | Yes |
| Candidate records | 4 |
| Strict confirmed | 0 |
| Promoted ProofBundles | 0 |
| Qualification status | NOT QUALIFIED |

## لماذا لا يساوي 76% حالة VIP؟

حالة VIP تتطلب دليلًا أقوى من جودة البناء أو اكتمال التقرير. الترقية الصارمة تحتاج **target-backed causal signal**، و**independent negative control**، و**sealed/replayable ProofBundle**، ثم replay ناجح، وبشكل قابل للتكرار عبر جولات qualification المطلوبة. التشغيل الحالي أثبت runtime reliability أفضل، لكنه لم يثبت causal proof لأي finding؛ لذلك الإبقاء على `NOT QUALIFIED` هو الحكم الصحيح fail-closed.

كما أن campaign ledger ما زال يحتوي على `18 not_observed` و`2 missing-validator`. هذه فجوات coverage/capability وليست findings. لا يجوز سدها بتخمين routes أو بإرسال transport غير مصرح أو بتغيير قواعد promotion.

## الخطوات المتبقية للوصول إلى VIP فعليًا

الخطوة التالية ليست تشغيل ثلاث جولات عشوائية. يجب أولًا جعل smoke واحد مكتملًا ينتج ProofBundle حقيقيًا لكل ترقية مرشحة، مع causal signal وnegative control وsealed replay. بعد نجاح ذلك فقط تُجرى الجولات الثلاث المطلوبة بنفس thresholds، وتُحسب precision وreproducibility من artifacts مستقلة. إلى أن يحدث ذلك، يظل المشروع في حالة **engineering maturity target reached / VIP qualification pending**.

## مراجع داخلية

| المرجع | الغرض |
|---|---|
| [`v75_maturity_scorecard.json`](./v75_maturity_scorecard.json) | المصدر الآلي للأوزان والنقاط والحكم |
| [`V97_EXECUTION_STATUS.md`](./V97_EXECUTION_STATUS.md) | التقرير التاريخي السابق، وحالته NOT QUALIFIED |
| [`direct_io_inventory.json`](./direct_io_inventory.json) | inventory deterministic الخاص بـG-02 |
| [`../tests/test_subprocess_lifecycle.py`](../tests/test_subprocess_lifecycle.py) | regression الخاص بمنع orphan tool children |
| `/home/ubuntu/upload/webpent_75_waptlab_42f1003/` | artifact runtime خارج Git للـsmoke المكتمل |
