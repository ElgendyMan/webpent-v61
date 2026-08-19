# WebPent v57 Delivery Notes

## What changed

v57 هو إصدار readability/wiring cleanup وليس تغييراً يَعِد بنتائج ثغرات ثابتة على كل target. تم تبسيط دورة الحالة والـdebugging مع الحفاظ على evidence-first behavior.

أهم التغييرات هي factory مشتركة للـinitial state بين CLI وCelery worker، إزالة DVWA-specific cookie mutation من authentication، إضافة LLM enable/disable control وlocal diagnostics، تحويل tool discovery إلى lazy/idempotent، تحديث graph documentation، وإضافة README وجراف تفصيلي وجراف مبسط.

## Validation

| Check | Result |
|---|---:|
| Full pytest | 359 passed, 0 failed |
| Focused v57/v29/v30/auth tests | 37 passed |
| Python compileall | Passed |
| Scoped Ruff on modified files | All checks passed |
| LLM offline guard | Passed |
| Registry lazy discovery | Passed |
| CLI/worker state parity | Passed |
| DVWA cookie neutrality contract | Passed |

## Important safety boundaries

LLM optional وليس شرطاً لتشغيل المسار deterministic. إيقافه يمنع provider calls وcache reuse. تشغيله لا يسمح بتجاوز scope أو approval أو evidence contracts.

Surface observations وrelational edges ليست Findings مؤكدة تلقائياً. الـdestructive PoC مرفوض افتراضياً، وhigh-risk يحتاج موافقة بشرية صريحة.

لم تُحذف modules لمجرد أنها غير ظاهرة في static grep؛ تم حذف generated caches وbytecode فقط، وتم توثيق المرشحين في `audit/v57_dead_code_review.md`.

## Run locally

```bash
cd /home/ubuntu/webpent_review
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
PYTHONPATH=src pytest -q
```

للتشخيص المحلي:

```bash
PYTHONPATH=src python scripts/doctor.py
LLM_ENABLED=false PYTHONPATH=src python scripts/doctor.py
```

لشرح البنية، ابدأ بالترتيب التالي:

1. `docs/architecture_simple.md`
2. `README.md`
3. `docs/architecture_detailed.md`
4. `audit/v57_architecture_review.md`
5. `audit/v57_dead_code_review.md`

## Scope of claims

هذه الحزمة لا تحتوي على live scan جديد، ولا تدّعي عدداً ثابتاً من Tool-Confirmed vulnerabilities. قياس النتائج يحتاج target مصرحاً به، credentials صحيحة عند الحاجة، وactive integration run منفصل.
