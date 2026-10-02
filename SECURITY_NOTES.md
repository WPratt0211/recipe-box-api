# Security baseline — 2026-09-14

- GET /recipes — 200 OK — lists all recipes — works anonymously, no authentication.
- POST /recipes — 201 Created — creates a new recipe — works anonymously, no authentication.
- DELETE /recipes/1 — 204 No Content — deletes recipe 1 — works anonymously, no authentication.
- “Users table: passwords stored as hashes (not plaintext).”
- “Protected routes require JWT; anonymous gets 401.”
- “Ownership enforced: non-owners get 403 on update/delete.”
- “Admin-only route: 403 for normal user, success for admin.”
- “Previously vulnerable requests now return 401/403/404; data unchanged.”