# Juice Shop JWT endpoint research

The OWASP Juice Shop challenge-solution documentation identifies `/rest/user/whoami` as the normal authenticated user-information API endpoint. Source: https://help.owasp.org/juice-shop/appendix/solutions.html (search result accessed 2026-08-21). A separate search result also referenced `/rest/user/whoami` as the API endpoint for the whoami flow: https://medium.com/@0xH4ck3r_4k/%EF%B8%8F-web-application-security-testing-using-owasp-juice-shop-a-beginner-friendly-guide-ad06684df4b7.

Local read-only checks against Juice Shop showed `/me` and `/rest/user/whoami` both returned the same public JSON/SPA-style response for baseline, alg=none, and invalid-token probes in the current lab state. Therefore a 200 alone is not sufficient evidence; the validator must require a distinct unsigned response plus rejected baseline and rejected invalid-token control.
