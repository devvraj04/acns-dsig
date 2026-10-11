# ACNS-DSIG Security Fixes Task Progress

- [x] 1. Registration: Disallow self-assignment of `ROLE_ADMIN` in `AuthController` and `register.html`
- [x] 2. Rate limiting: Ignore `X-Forwarded-For` by default in `RateLimitFilter` (configurable via `dsig.security.rate-limit.trust-forwarded-for`)
- [x] 3. Upload guard: Enforce envelope size cap (512 KB) in `UploadGuard` and `VerifyController` before reading bytes
- [x] 4. Sign flow: Sanitize document filenames in `SignController` and safely encode `Content-Disposition`
- [x] 5. Lockout extension: Prevent resetting lockout timer on already locked accounts in `SecurityConfig` and `LoginAttemptService`
- [x] 6. Lockout tracking & concurrency: Make `isBlocked` read-only and add `@Transactional` to `LoginAttemptService`
- [x] 7. Exception handling: Sanitize raw exception messages in `GlobalExceptionHandler` and `UploadGuard`
- [x] 8. Security headers test: Verify actual HTTP response headers via `MockMvc`
- [x] 9. Configuration: Clean up port/cookie/upload-limit settings and properties in `application.yml`
- [x] 10. Run tests and verify Maven build passes: **68 tests run, 0 failures, 0 errors across all modules (BUILD SUCCESS)**
- [x] 11. Independent security verification complete: All 10 verification checks PASS

