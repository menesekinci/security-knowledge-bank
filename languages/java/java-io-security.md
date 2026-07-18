# ☕ Java I/O Security

## Zip Slip Attack
Extracting files via symlink/path traversal inside a zip file.
```java
// VULNERABLE:
ZipInputStream zis = new ZipInputStream(inputStream);
ZipEntry entry = zis.getNextEntry();
while (entry != null) {
    String fileName = entry.getName(); // could be "../../etc/passwd"!
    File newFile = new File(outputDir + fileName); // Traversal!
    // ...
    entry = zis.getNextEntry();
}

// SECURE:
Path outputDir = Path.of("/safe/dir");
ZipInputStream zis = new ZipInputStream(inputStream);
ZipEntry entry = zis.getNextEntry();
while (entry != null) {
    Path destPath = outputDir.resolve(entry.getName()).normalize();
    if (!destPath.startsWith(outputDir)) {
        throw new SecurityException("Zip Slip detected!");
    }
    // ...
}
```

## Symlink Attacks
Symlink race condition when creating temporary files — an attacker can create a symlink beforehand and change its target.

## File Descriptor Exhaustion
```java
// VULNERABLE:
for (int i = 0; i < 100000; i++) {
    FileInputStream fis = new FileInputStream("/dev/random");
    // fis.close() FORGOTTEN! → FD exhaustion → DoS
}

// SECURE: try-with-resources
try (FileInputStream fis = new FileInputStream("/dev/random")) {
    // Automatic close()
}
```

**Source:** CVE-2024-38819 (Spring Path Traversal)
