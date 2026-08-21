# WebPent v3 Direct-I/O Inventory

**الغرض:** تسجيل كل موضع محتمل للـHTTP/browser/socket/subprocess/file I/O قبل بناء allowlist CI. هذه الوثيقة لا تمنح استثناءات تلقائية؛ كل entry يحتاج adapter contract واختبار policy مكافئ.

## مصادر التنفيذ الحالية

| الفئة | المواضع الحالية | الملاحظة |
|---|---|---|
| HTTP transport | `shared/http.py`, `shared/http_discovery.py`, `shared/httpx_client.py` وأي wrappers تحت `shared/` | يجب أن تمر scope/SSRF/redirect/resolver من policy موحدة |
| Browser | `shared/browser.py` وPlaywright agents | يجب تسجيل navigation/form/upload/network observation عبر executor |
| Subprocess tools | `tools/utils/subprocess.py` ثم `tools/exploitation/{dalfox,phpggc,sqlmap,ysoserial}.py` و`tools/recon/{ffuf,httpx,katana,nuclei,subfinder}.py` | wrapper مركزي موجود، لكن registration وevent/proof ownership يحتاجان G2 |
| Socket/OOB | OOB helpers وraw transport candidates | يجب قصر listeners على interfaces/ports مصرح بها واختبارها محليًا |
| File I/O | artifact/report/export/ingest/memory modules | يجب redaction وengagement isolation وعدم إدخال ملفات target كتعليمات |
| Broker/worker | Celery task dispatch وRedis helpers | يجب encrypt payload، TLS في non-local، idempotency وfencing |
| Database | SQLite action ledger وstate/report stores | يجب transaction boundaries وresume/crash tests |

## قواعد allowlist المقترحة

1. لا يُسمح باستدعاء `requests`, `httpx`, `urllib`, `aiohttp`, Playwright، socket، أو subprocess من agent جديد مباشرة.
2. أدوات CLI لا تُشغّل إلا عبر `webpent.tools.utils.subprocess.run_command` أو adapter مسجل يثبت `shell=False` وargument allowlist وtarget policy.
3. Browser actions لا تُنفّذ من node مباشرة؛ يلزم browser adapter يربط action/identity/tenant/correlation ID بالـActionExecutor.
4. أي socket/OOB capability غير مسجلة تعود `blocked_by_capability` ولا تعود `clean`.
5. CI يجب أن يفشل عند إضافة direct-I/O خارج manifest معتمد، ويجب أن يحتوي كل استثناء على اختبار يثبت scope وredaction وbudget وevent logging.

## الوضع الحالي

تم توليد candidate inventory آليًا من `src/webpent/**/*.py` في Phase A. توجد wrappers آمنة جزئيًا، لكن لا يوجد حتى الآن enforcement واحد يمنع كل graph nodes من حقن handlers أو استخدام transport خارج runtime spine. لذلك حالة G-08 هي `OPEN`، ولا يمكن إعلان G2 مغلقًا.

## الاختبار المطلوب

يجب أن يحتوي direct-I/O CI على كشف AST/import، مقارنة manifest، واختبارات تشغيلية لرفض host/port/redirect خارج scope، ورفض capability غير المسجلة، وإثبات أن blocked/inconclusive لا تتحول إلى clean.
