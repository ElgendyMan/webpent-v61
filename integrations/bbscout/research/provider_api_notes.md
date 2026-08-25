# ملاحظات توثيق الـ Provider APIs

## HackerOne — مراجعة 2026-08-22

المصدر الرسمي: https://api.hackerone.com/getting-started-hacker-api/

- الـ API endpoint الأساسي: `https://api.hackerone.com/`.
- يجب إدراج API version في الـ URL؛ لا توجد نسخة افتراضية.
- مصادقة الباحث تتم بـ HTTP Basic Auth، حيث API token identifier هو اسم المستخدم، وAPI token value هي كلمة المرور في Authorization header.
- حدود القراءة الموثقة: 600 طلب/دقيقة.
- Structured scopes لها حد أكثر صرامة: 50 طلب/دقيقة.
- دلالات أخطاء مهمة: `401` غير مصادق، `403` ممنوع وليس نتيجة فارغة، `404` غير موجود، `429` تجاوز الحد، `503` غير متاح.
- في الـ MVP: لا يتم تثبيت مسارات programs/scope من الذاكرة. يوضع Adapter أولي متصل فقط بعد توفير credential مرجعي وتثبيت endpoint/response contract من المرجع الرسمي الحالي أو fixture موثقة.

تفاصيل البرامج المؤكدة من مرجع HackerOne الرسمي:

| عملية قراءة | المسار الرسمي النسبي | ملاحظات التنفيذ |
| --- | --- | --- |
| قائمة البرامج | `GET /v1/hackers/programs` | Paginated بـ `page[number]` و`page[size]` حتى 100 عنصر. |
| برنامج محدد | `GET /v1/hackers/programs/{handle}` | الـ handle يأتي من قائمة البرامج. |
| Structured scope | `GET /v1/hackers/programs/{handle}/structured_scopes` | Paginated؛ يتضمن `asset_type` و`asset_identifier` و`eligible_for_submission` وinstruction وتواريخ التحديث. |
| Scope exclusions | `GET /v1/hackers/programs/{handle}/scope_exclusions` | تقرأ للاستبعاد فقط؛ لا تعامل `403` على أنه قائمة فارغة. |

الـ Adapter في النسخة الأولى سيستخدم عمليات GET السابقة فقط، ويتحقق من `Accept: application/json` وBasic Auth ومن قائمة الاستجابات المسموح بها. أي POST/PATCH/DELETE غير موجودة في الكود.
