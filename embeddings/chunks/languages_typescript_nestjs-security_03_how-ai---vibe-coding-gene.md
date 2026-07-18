---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 3/7
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