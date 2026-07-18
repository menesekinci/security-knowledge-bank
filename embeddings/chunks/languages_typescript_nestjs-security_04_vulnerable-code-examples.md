---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "Vulnerable Code Examples + Secure Code Fix"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 4/7
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