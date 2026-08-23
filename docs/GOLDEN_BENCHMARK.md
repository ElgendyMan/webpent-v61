# Golden Benchmark Contract

## الغرض

هذا الـbenchmark يقيس صحة طبقة التقييم بصورة deterministic من خلال حالات contract معلنة داخل `webpent.benchmark.golden`. الحالات ليست نتائج WAPTLab ولا findings حية، ولا تنفذ network أو browser أو LLM أو credential I/O.

## ما الذي يقيسه

يتم حساب **precision** و**recall** و**false-discovery rate** و**evidence quality** و**reproducibility** لكل حالة. تُحسب **false-positive rate (FPR)** فقط عند تمرير `negative_case_ids` تمثل universe سلبية معلنة؛ عند غيابها تكون القيمة `0.0` بمعنى أن المقام غير معروف، وليس بمعنى أن الجولة خالية من false positives. ولقياس false positives بين التوقعات فقط استُخدم الاسم الصريح `false_discovery_rate`.

| الحالة | الغرض | ما تثبته | ما لا تثبته |
|---|---|---|---|
| `complete-evidence-and-replay` | baseline صحيح | حسابات كاملة وإعادة إنتاج ثابتة | وجود ثغرة في target حي |
| `incomplete-evidence-and-drift` | negative/control case | missed case وfalse discovery ونقص evidence وعدم reproducibility | confirmation أو proof حقيقي |

## قواعد التشغيل

يجب أن تظل الحالات محددة بمفاتيح case صريحة، وأن تكون نتائجها قابلة للتكرار. لا يجوز تحويل predicted أو candidate إلى confirmed، ولا استخدام benchmark كبديل عن causal signal وindependent negative control وsealed/replayable ProofBundle. أي qualification حي يظل منفصلًا ويحتاج target-backed evidence موثقًا داخل WAPTLab المصرح فقط.

## التحقق

بوابة Phase 8 الحالية: `26 passed` لاختبارات golden وmetrics وrelease contracts، مع نجاح Ruff وcompileall و`git diff --check`.
