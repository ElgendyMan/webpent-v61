# bbscout

`bbscout` أداة لينكس **read-only وfail-closed** لاختيار برامج bug bounty المتاحة لحسابك، وتطبيع الـ scope، ثم إنشاء `Target Package` قابلة للتحقق قبل إدخالها إلى WebPent. الأداة لا تعمل crawl أو scan أو exploit أو report submission، ولا تقبل tokens كـ command-line arguments.

> البرنامج ليس تصريح اختبار في حد ذاته. لا توجد Package صالحة إلا إذا كان الـ scope منظمًا وواضحًا، والـ policy موجودة، والـ profile مؤهل، وأنت أكدت الاختيار صراحةً.

## الموجود في النسخة المنفذة

| مكوّن | الحالة | التوضيح |
| --- | --- | --- |
| HackerOne fixture mode | جاهز | يعمل Offline ببيانات اختبار ثابتة، من غير network أو credential. |
| HackerOne live adapter | جاهز مبدئيًا | عمليات `GET` فقط: البرامج، تفاصيل البرنامج، والـ structured scopes. |
| Bugcrowd / Intigriti / YesWeHack | غير منفذ | لا يوجد أي اتصال أو تخمين لـ APIs الخاصة بهم. |
| Scope compiler | جاهز | exact URLs، path، wildcard domains، IP/CIDR، exclusions، freshness، والغموض. |
| Ranking engine | جاهز | Eligibility gate ثم score شفاف مع confidence وعدم يقين. |
| Target Package | جاهز | JSON v2 مع hash، انتهاء صلاحية، explicit confirmation، وsecret scan. |
| Detached signature | غير منفذ | النسخة الحالية تتحقق من content hash محليًا فقط. |
| WebPent preflight | جاهز | `TargetPackageIngestor` يتحقق Offline من الحزمة ويطبق scope authorization محليًا؛ لا ينفذ target I/O. |

## تشغيل سريع — Offline

بعد تثبيت المشروع، نفّذ المسار ده. الـ fixtures مقصودة لتجربة السلوك، وليست برامج حقيقية.

```bash
bbscout programs discover --provider hackerone --mode fixture --format table
bbscout programs score --provider hackerone --mode fixture \
  --webpent-profile ./examples/webpent-capabilities.json --format table
bbscout programs recommend --provider hackerone --mode fixture \
  --webpent-profile ./examples/webpent-capabilities.json --top 3 --explain
bbscout package build --provider hackerone --mode fixture acme-api \
  --webpent-profile ./examples/webpent-capabilities.json \
  --output ./examples/acme-target-package.json --confirm
bbscout package verify ./examples/acme-target-package.json
```

## ربط HackerOne الحقيقي

الـ adapter الحي لا يقرأ credentials من CLI أو ملف المشروع. استخدم environment session أو secret manager، ثم شغّل وضع `live`. لا تضع أي token في history أو log أو package.

```bash
export BBSCOUT_HACKERONE_TOKEN_ID='YOUR_TOKEN_IDENTIFIER'
export BBSCOUT_HACKERONE_TOKEN='YOUR_TOKEN_VALUE'
bbscout auth status --all --mode live
bbscout programs discover --provider hackerone --mode live --format table
```

بعدها راجع كل Program وscope يدويًا قبل البناء:

```bash
bbscout programs inspect --provider hackerone --mode live PROGRAM_HANDLE --policy --scope
bbscout programs score --provider hackerone --mode live \
  --webpent-profile ./examples/webpent-capabilities.json --format table
```

لو ظهر `forbidden` أو `rate_limited` أو `schema_changed`، الأداة تفشل صراحةً ولا تحول الخطأ لقائمة فارغة. HackerOne توثق المصادقة بـ HTTP Basic Auth، وتطلب تحديد نسخة API في المسار، وتضع حدًا أقصى 600 طلب قراءة/دقيقة و50 طلب structured scope/دقيقة. الـ adapter يتعمد التشغيل أقل من هذه الحدود.[1]

## قواعد الأمان الأساسية

الـ scope compiler لا يستنتج الصلاحية من نص مثل “all company assets”. الـ structured scope غير المدعومة أو القديمة أو الغامضة تحول البرنامج إلى `scope_ambiguous` أو `stale` أو `partial_scope` وتمنع بناء package بحالة `ready`.

Wildcard مثل `*.example.com` يسمح بالـ subdomains المطابقة فقط؛ لا يسمح بالـ apex `example.com` إلا لو فيه include rule منفصل. وأي redirect destination يجب التحقق منه مستقلًا؛ لا يكتسب الصلاحية تلقائيًا.

الـ score لا يتعامل مع bounty أو شهرة البرنامج أو عدد الدومينات على أنها علامة صلاحية. يتم احتساب القدرة فقط إذا كانت موجودة في `webpent-capabilities.json` ومؤهلة بـ local qualification test. الـ package ترفض التعديل، انتهاء الصلاحية، غياب تأكيد المستخدم، scope غير `ready`، أو وجود مسارات أسرار مثل `access_token` أو `cookie`.

## اختبار المشروع

```bash
cd /home/ubuntu/bbscout
python3 -m pytest -q
```

تشمل الاختبارات: path handling، wildcard/apex semantics، exclusions، stale/ambiguous scope، blocking rules، package confirmation، tamper detection، وsecret rejection.

## الخطوة الهندسية التالية

اربط `TargetPackageIngestor` الموجود في `src/bbscout/webpent_ingestor.py` داخل WebPent. هو ينفذ schema validation، hash verification، expiry/revocation check، وScopeCompiler preflight محليًا. بعد كده فقط أنشئ Engagement في وضع dry-run. لا تضف crawling أو target I/O قبل ربط كل ذلك بـ ActionAuthority مركزي ومُراجع.

## References

[1]: https://api.hackerone.com/getting-started-hacker-api/ "HackerOne — Getting Started Hacker API"

[2]: https://api.hackerone.com/hacker-resources/#programs "HackerOne — Hacker Resources: Programs and Structured Scopes"
