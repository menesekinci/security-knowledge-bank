# NestJS Security (TypeScript)

> **Severity:** High
> **CWE:** CWE-284 (Improper Access Control), CWE-915 (Mass Assignment), CWE-20 (Improper Input Validation), CWE-94 (Code Injection), CWE-200 (Information Exposure), CWE-1321 (Prototype Pollution)
> **AI Generation Risk:** High — open CORS, missing guards, DTO without whitelist, missing rate limiting, unprotected mass assignment

---

## Vulnerability Explanation

NestJS encourages decorators, DTOs, and dependency injection — which is generally good for structure. However, AI-generated NestJS apps commonly fall into these traps:

- **Missing or misconfigured `ValidationPipe`** — Without `whitelist: true`, attackers can send unexpected fields that get silently merged into DTOs (mass assignment / over-posting)
- **`@Public()` too broadly applied** — AI guards are often overly permissive, exposing endpoints meant to be protected
- **CORS `origin: '*'` with `credentials: true`** — A dangerous combination that allows any website to make authenticated requests on behalf of the user
- **Trusting `@Req() user` without guard** — TypeScript types suggest `user` exists but without a guard running, it may be undefined or spoofed
- **`TypeORM synchronize: true` in production** — Auto-syncs schema, potentially dropping or altering tables
- **File upload MIME type bypass** — Using `FileTypeValidator` without content inspection allows uploading malicious files (CVE-2024-29409)
- **Prototype pollution via `constructor` property** — `ValidationPipe.stripProtoKeys()` only stripped `__proto__` but not `constructor`, enabling prototype pollution through unsafe merge operations (Issue #16050)

---

## How AI / Vibe Coding Generates This

Common AI-generated anti-patterns:

```typescript
// 💀 AI-generated: Open CORS, no validation, no guards
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: '*', credentials: true });  // CORS disaster
  app.useGlobalPipes(new ValidationPipe());  // whitelist: false by default!
  await app.listen(3000);
}
```

```typescript
// 💀 AI-generated IDOR — no user ownership check
@Get(':id')
findOne(@Param('id') id: string) {
  return this.usersRepo.findOneBy({ id }); // Any user can read any record
}
```

```typescript
// 💀 AI-generated mass assignment — using entity as DTO
@Patch(':id')
update(@Param('id') id: string, @Body() dto: User) {  // User entity = mass assignment
  return this.usersRepo.update(id, dto);  // Attacker can set role, isAdmin, etc.
}
```

```typescript
// 💀 AI-generated file upload — no content-type validation
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
uploadFile(@UploadedFile(
  new ParseFilePipe({ validators: [new FileTypeValidator({ fileType: 'image/png' })] })
) file: Express.Multer.File) {
  // FileTypeValidator only checks Content-Type header — trivially spoofable!
}
```

---

## Vulnerable Code Examples + Secure Code Fix

### 1. Mass Assignment via Entity as DTO

```typescript
// 💀 VULNERABLE — Entity used directly as DTO
@Patch(':id')
update(@Param('id') id: string, @Body() dto: User) {  // User is a TypeORM entity!
  return this.usersRepo.update(id, dto);
  // POST {"isAdmin": true, "role": "superadmin"} → attacker becomes admin
}

// ✅ SECURE — Separate DTO with explicit allowed fields
export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  // NOTE: No role, isAdmin, password fields here!
}

@Patch(':id')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
update(@Param('id') id: string, @Body() dto: UpdateUserDto) {
  return this.usersService.update(id, dto);
}
```

### 2. CORS Misconfiguration

```typescript
// 💀 VULNERABLE — Any origin with credentials
app.enableCors({
  origin: '*',          // Any website can make cross-origin requests
  credentials: true,    // Cookies/Authorization headers are sent
});

// ✅ SECURE — Explicit allowlist
app.enableCors({
  origin: ['https://myapp.com', 'https://admin.myapp.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});
```

### 3. ValidationPipe Without Whitelist (Mass Assignment)

```typescript
// 💀 VULNERABLE — whitelist: false (default)
app.useGlobalPipes(new ValidationPipe());
// Extra fields in request body pass through to the DTO!

// ✅ SECURE — Complete ValidationPipe config
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,                  // Strip unknown properties
  forbidNonWhitelisted: true,       // Throw error on unknown properties
  transform: true,                  // Auto-transform types (string "1" → number 1)
  disableErrorMessages: false,      // Set true in production
}));
```

### 4. Prototype Pollution via constructor Property

```typescript
// 💀 VULNERABLE — ValidationPipe (pre-fix) only strips __proto__
// Sending this payload:
// { "name": "attacker", "constructor": { "prototype": { "isAdmin": true } } }
// The constructor property persists through stripProtoKeys()
// If subsequently used in unsafe merge (Object.assign, lodash.merge):
// → Object.prototype.isAdmin = true → every object has isAdmin=true

// ✅ SECURE — After fix (NestJS PR #16079), stripProtoKeys also removes constructor
// Or use Zod for request validation instead of plain DTOs
```

### 5. File Upload MIME Bypass (CVE-2024-29409)

```typescript
// 💀 VULNERABLE — Only checks Content-Type header
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
uploadFile(@UploadedFile(
  new ParseFilePipe({
    validators: [new FileTypeValidator({ fileType: 'image/jpeg' })]
  })
) file: Express.Multer.File) {
  // Attacker sets Content-Type: image/jpeg but uploads a .html file with <script> tags
}

// ✅ SECURE — Validate file content (magic bytes), not just header
import { fileTypeFromBuffer } from 'file-type';

@Post('upload')
@UseInterceptors(FileInterceptor('file'))
async uploadFile(@UploadedFile() file: Express.Multer.File) {
  const type = await fileTypeFromBuffer(file.buffer);
  if (!type || !['image/jpeg', 'image/png'].includes(type.mime)) {
    throw new BadRequestException('Invalid file type');
  }
  // Also: scan with ClamAV or similar, store outside webroot, serve with Content-Disposition: attachment
}
```

### 6. IDOR — Missing Ownership Check

```typescript
// 💀 VULNERABLE — No ownership verification
@Get('orders/:id')
getOrder(@Param('id') id: string) {
  return this.ordersRepo.findOneBy({ id });
  // User A can read User B's order by guessing/changing the ID
}

// ✅ SECURE — Scope by authenticated user
@Get('orders/:id')
@UseGuards(JwtAuthGuard)
getOrder(@Param('id') id: string, @Req() req: AuthenticatedRequest) {
  return this.ordersRepo.findOneBy({
    id,
    userId: req.user.id,  // CRITICAL: Scope query to the authenticated user
  });
}
```

### 7. Rate Limiting for Auth Endpoints

```typescript
// 💀 VULNERABLE — No rate limiting on login
@Post('auth/login')
async login(@Body() dto: LoginDto) {
  // Attacker can brute-force passwords with unlimited requests
}

// ✅ SECURE — Apply @Throttle() decorator
import { ThrottlerGuard } from '@nestjs/throttler';

@UseGuards(ThrottlerGuard)
@Controller('auth')
export class AuthController {
  @Throttle({ default: { limit: 5, ttl: 60000 } })  // 5 attempts per minute
  @Post('login')
  async login(@Body() dto: LoginDto) {
    // Rate limited!
  }
}
```

### 8. CSRF Protection

```typescript
// 💀 VULNERABLE — No CSRF protection on state-changing endpoints
@Post('transfer')
async transfer(@Body() dto: TransferDto, @Req() req: AuthenticatedRequest) {
  // A malicious site can forge this POST request if user is authenticated via cookies
}

// ✅ SECURE — Enable CSRF (Express + csurf or use SameSite cookies + double-submit pattern)
// In main.ts:
import * as csurf from 'csurf';
// or for cookie-based sessions:
app.use(csurf({ cookie: true }));

// Alternative: Use SameSite=Strict/Lax cookies and custom header (X-CSRF-Token)
```

### 9. Security Headers with Helmet

```typescript
// ✅ SECURE — Security headers with CSP
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://"],
      connectSrc: ["'self'", "https://api.myapp.com"],
    },
  },
  hsts: {
    maxAge: 31536000,     // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: 'deny' },  // Prevent clickjacking
}));
```

---

## Prevention Checklist

- [ ] **Global `ValidationPipe`** with `whitelist: true`, `forbidNonWhitelisted: true`, `transform: true`
- [ ] **Auth guards default-deny** — Use `@UseGuards(JwtAuthGuard)` at controller level, only `@Public()` on truly open endpoints
- [ ] **CORS allowlist** — Never `origin: '*'` with `credentials: true`. Always specify exact origins
- [ ] **Helmet / security headers** — `app.use(helmet())` with explicit CSP directives
- [ ] **Rate limiting** — Use `@nestjs/throttler` on auth, password reset, and public API endpoints
- [ ] **No entity as `@Body()` type** — Always create separate DTO classes with `class-validator` decorators
- [ ] **CSRF protection** — Enable for cookie-based auth; use `SameSite=Strict` cookies or CSRF tokens
- [ ] **File upload validation** — Never trust `Content-Type` header. Validate file content (magic bytes)
- [ ] **Disable `synchronize: true` in production** — Use TypeORM/Prisma migrations instead
- [ ] **Scope DB queries by authenticated user** — Every query that reads/writes user data must filter by `req.user.id`
- [ ] **Prototype pollution defense** — Ensure `stripProtoKeys` removes `constructor` and `prototype` properties
- [ ] **Disable detailed errors in production** — `disableErrorMessages: true` on ValidationPipe
- [ ] **Use `class-validator` transform decorators** — `@Transform(({value}) => sanitize(value))` for input sanitization
- [ ] **Log security events** — Failed auth attempts, validation failures, unauthorized access attempts

---

## Real CVEs / Case Refs

| CVE | Component | Score | Type | Description | Source |
|-----|-----------|-------|------|-------------|--------|
| CVE-2024-29409 | `@nestjs/common` (FileTypeValidator) | 5.5 MEDIUM | Code Injection / File Upload Bypass | Improper MIME type validation — `FileTypeValidator` only checks the `Content-Type` header, not actual file content. Attacker can upload `.html` files as `image/jpeg` by forging the header. Fixed in 10.4.16 / 11.0.16. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-29409), [Snyk](https://security.snyk.io/vuln/SNYK-JS-NESTJSCOMMON-9538801), [Analysis](https://gist.github.com/aydinnyunus/801342361584d1491c67a820a714f53f) |
| CVE-2023-26108 | `@nestjs/core` (StreamableFile) | 5.3 MEDIUM | Information Exposure | When a client cancels a request during stream of a `StreamableFile`, the underlying stream is kept open — exposing file descriptors and potentially leaking sensitive data. Fixed in 9.0.5. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-26108), [Snyk](https://security.snyk.io/vuln/SNYK-JS-NESTJSCORE-2869127), [Patch](https://github.com/nestjs/nest/pull/9819) |
| CVE-2026-3304 | `@nestjs/platform-express` | HIGH | Dependency Vulnerability | Multer (file upload middleware) dependency in platform-express had a DoS vulnerability. Express v11 users on Multer <2.1.0 vulnerable to connection-drop DoS. | [GitHub Issue](https://github.com/nestjs/nest/issues/16484), [Express Security Release](https://expressjs.com/en/blog/2026-02-27-security-releases/) |
| CVE-2026-35515 | NestJS Framework | — | XSS | Cross-site scripting vulnerability in NestJS framework affecting Server-Sent Events (SSE) processing. Attackers can inject arbitrary SSE content. | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-35515/) |
| CVE-2026-40879 | Nest.js | — | Buffer Overflow | Buffer overflow vulnerability allowing attackers to trigger call stack overflow via crafted small JSON messages. | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-40879/) |
| ValidationPipe PP | `@nestjs/common` (ValidationPipe) | HIGH (unassigned) | Prototype Pollution | `stripProtoKeys()` only stripped `__proto__` but not `constructor` or `prototype`. Attacker could send `{constructor: {prototype: {isAdmin: true}}}` to pollute `Object.prototype`. Fixed in PR #16079. | [GitHub Issue #16050](https://github.com/nestjs/nest/issues/16050), [Fix PR #16079](https://github.com/nestjs/nest/pull/16079) |

### Key NestJS Security Resources

- [NestJS Validation Documentation](https://docs.nestjs.com/techniques/validation) — Official `ValidationPipe` guide with whitelist/transform options
- [NestJS CORS Documentation](https://docs.nestjs.com/security/cors) — Official CORS configuration guide
- [NestJS Helmet Documentation](https://docs.nestjs.com/security/helmet) — Security headers best practices
- [OWASP API Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — API security risks relevant to NestJS
- [Snyk: Avoiding Mass Assignment in Node.js](https://snyk.io/blog/avoiding-mass-assignment-node-js/) — Mass assignment patterns and fixes

---

## Vibe-Coding Red Flags

- No `ValidationPipe` configured globally — **Red Flag #1**
- `origin: '*'` + `credentials: true` — **Critical misconfiguration**
- Services using raw `repository.save(body)` with entity as DTO — **Mass assignment**
- `@Public()` decorator on more than a few endpoints — **Overexposure**
- No `@UseGuards()` on controller classes — **No auth protection**
- Entity/Model classes imported directly into controllers — **DTOs should be separate**
- `TypeORM synchronize: true` in `NODE_ENV=production` — **Risk of data loss**
- No rate limiting on login/register endpoints — **Brute-force attack surface**
- `FileTypeValidator` as sole file validation — **MIME type bypass**
- `@Req() user` used without a preceding guard check — **User may be undefined**
- No security headers (Helmet) — **Missing CSP, HSTS, X-Frame-Options**
- No CSRF protection for cookie-based auth — **State-changing requests can be forged**
- Error messages exposing internal details — **Information leakage**
