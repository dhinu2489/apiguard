# 🛡️ apiguard

**Stack-agnostic, drop-in security middleware for Python and Java REST APIs.**

`apiguard` provides a composable, reusable security layer you can plug into any backend framework — FastAPI, Flask, Django, Spring Boot, Quarkus, or Micronaut — with minimal configuration and zero business logic changes.

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://pypi.org/project/apiguard/)
[![Java](https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk)](https://central.sonatype.com/)

---

## ✨ Features

- 🔐 **JWT Validation** — RS256/ES256 asymmetric token verification with issuer & audience enforcement
- 🪪 **RBAC Enforcement** — Role-based access control via decorators/annotations, no logic changes needed
- ⏱️ **Rate Limiting** — Sliding window limiter per IP and per user, configurable per endpoint
- 🧹 **Input Validation** — Schema-based request body validation with strict size and type enforcement
- 📋 **Security Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options applied automatically
- 🔑 **Secrets Integration** — First-class support for HashiCorp Vault, AWS KMS, and environment-based config
- 📊 **Audit Logging** — Structured logs with request ID, user ID, IP, endpoint, and latency — PII-safe

---

## 🏗️ Architecture

apiguard implements **defense in depth** across 8 independent security layers. Each layer is composable — use all of them or only the ones you need.

```
Request
  │
  ▼
┌─────────────────────────────────────────┐
│  1. Transport (TLS enforcement)         │
│  2. Authentication (JWT / API Key)      │
│  3. Authorization (RBAC / ABAC)         │
│  4. Input Validation (Schema / Size)    │
│  5. Rate Limiting (IP + User)           │
│  6. Security Headers (HSTS, CSP, ...)   │
│  7. Secrets Management (Vault / KMS)    │
│  8. Audit Logging (Structured / PII-safe│
└─────────────────────────────────────────┘
  │
  ▼
Your Business Logic (untouched)
```

---

## 🐍 Python — Quick Start

### Installation

```bash
pip install apiguard
```

### FastAPI

```python
from fastapi import FastAPI
from apiguard import SecurityMiddleware, JWTValidator, RateLimiter

app = FastAPI()

validator = JWTValidator(
    public_key=open("public.pem").read(),
    algorithm="RS256",
    audience="api",
    issuer="https://auth.yourcompany.com"
)

limiter = RateLimiter(max_calls=100, window_secs=60)

app.add_middleware(
    SecurityMiddleware,
    validator=validator,
    limiter=limiter,
    public_paths=["/health", "/docs", "/openapi.json"]
)
```

### RBAC on Routes

```python
from apiguard import RBACEnforcer

rbac = RBACEnforcer({
    "admin": ["read", "write", "delete"],
    "user":  ["read"],
})

@app.delete("/invoices/{id}")
@rbac.require("delete")
async def delete_invoice(id: str, request: Request):
    ...
```

### Flask

```python
from flask import Flask
from apiguard.flask import init_security

app = Flask(__name__)
init_security(app, validator=validator, limiter=limiter)
```

---

## ☕ Java — Quick Start

### Maven

```xml
<dependency>
    <groupId>io.apiguard</groupId>
    <artifactId>apiguard-spring</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'io.apiguard:apiguard-spring:1.0.0'
```

### Spring Boot — Auto-configuration

Add your public key to `application.yml`:

```yaml
apiguard:
  jwt:
    public-key: classpath:public.pem
    algorithm: RS256
    issuer: https://auth.yourcompany.com
    audience: api
  rate-limit:
    max-calls: 100
    window-seconds: 60
  public-paths:
    - /actuator/health
    - /swagger-ui
    - /v3/api-docs
```

That's it — `SecurityFilter` and `RBACEnforcer` are auto-registered.

### RBAC on Controllers

```java
@RestController
public class InvoiceController {

    @DeleteMapping("/invoices/{id}")
    @RequiresPermission("invoices:delete")
    public ResponseEntity<Void> deleteInvoice(@PathVariable String id) {
        // ...
    }
}
```

### Quarkus / Micronaut

```java
// Register the filter manually as a CDI bean
@ApplicationScoped
public class SecurityConfig {

    @Produces
    public SecurityFilter securityFilter(JwtValidator validator, RateLimiter limiter) {
        return new SecurityFilter(validator, limiter,
            Set.of("/health", "/metrics"));
    }
}
```

---

## ⚙️ Configuration Reference

| Property | Default | Description |
|---|---|---|
| `jwt.algorithm` | `RS256` | Signing algorithm (`RS256`, `ES256`) |
| `jwt.issuer` | — | Expected `iss` claim in JWT |
| `jwt.audience` | — | Expected `aud` claim in JWT |
| `rate-limit.max-calls` | `100` | Max requests per window |
| `rate-limit.window-seconds` | `60` | Sliding window duration |
| `public-paths` | `["/health"]` | Paths that skip auth |
| `headers.hsts` | `true` | Add `Strict-Transport-Security` |
| `headers.csp` | `default-src 'self'` | Content Security Policy value |
| `headers.frame-options` | `DENY` | X-Frame-Options value |

---

## 🔒 Security Headers Applied

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=()` |

---

## 🧪 Running Tests

**Python**

```bash
pip install apiguard[dev]
pytest tests/ -v --cov=apiguard
```

**Java**

```bash
./mvnw test
# or
./gradlew test
```

---

## 🗺️ Roadmap

- [ ] ABAC support via Open Policy Agent (OPA) integration
- [ ] Redis-backed distributed rate limiter
- [ ] API key hashing and management utilities
- [ ] mTLS helper for service-to-service auth
- [ ] Django REST Framework middleware
- [ ] Quarkus extension (native GraalVM support)
- [ ] OpenTelemetry trace propagation in audit logs

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [PyJWT](https://pyjwt.readthedocs.io/) — JWT decoding for Python
- [JJWT](https://github.com/jwtk/jjwt) — JWT library for Java
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Security best practices reference
