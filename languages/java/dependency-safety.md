# Dependency Safety — Maven/Gradle Supply Chain

## Overview

Java's dependency management ecosystem (Maven Central, Maven/Gradle) is one of the oldest and largest in the world, with hundreds of thousands of artifacts. The age and complexity of this ecosystem create unique supply chain risks that AI-generated code frequently overlooks or exacerbates.

## The Unique Risk Profile of Java Dependencies

| Factor | Impact |
|---|---|
| **Age of ecosystem** | Maven Central artifacts from 2000s are still used; some maintainers have passed away |
| **Transitive depth** | A Spring Boot app can have 200+ transitive dependencies |
| **Gradle vs. Maven** | Different resolution strategies, version conflict handling |
| **Binary-only artifacts** | Many JARs have no source code available for review |
| **Multi-module projects** | Complex dependency graphs across modules |
| **System dependency scope** | JRE/JDK itself is a dependency (Oracle JRE vs OpenJDK) |

## AI-Generated Vulnerability: No Version Pinning

```xml
<!-- AI-GENERATED pom.xml — uses version ranges (DANGEROUS!) -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>vulnerable-library</artifactId>
    <version>[1.0,)</version>  <!-- BUG: Resolves to LATEST version -->
</dependency>
```

**Problems with version ranges**:
- `[1.0,)` = any version >= 1.0, may resolve to a backdoored version
- `(,1.0]` = any version ≤ 1.0, may include vulnerable versions
- `[1.0,2.0)` = within range, but Maven may pick a compromised subversion
- Maven's version range resolution is non-deterministic across mirrors

**Secure Fix**: Pin to exact versions.
```xml
<dependency>
    <groupId>com.example</groupId>
    <artifactId>safe-library</artifactId>
    <version>1.2.5</version>  <!-- Exact version -->
</dependency>
```

## AI-Generated Vulnerability: Dependency Confusion

```xml
<!-- AI-GENERATED — uses a dependency name that exists internally AND externally -->
<dependency>
    <groupId>com.company</groupId>
    <artifactId>internal-auth-library</artifactId>
    <version>3.0.0</version>
</dependency>
```

**Risk**: If an attacker publishes `com.company:internal-auth-library:4.0.0` to Maven Central, and the build resolves external repositories before internal ones, the attacker's version is used.

**Fix**: Require internal repository for internal group IDs.
```xml
<repositories>
    <repository>
        <id>internal</id>
        <url>https://internal-nexus.company.com/repository/maven-releases/</url>
    </repository>
</repositories>

<!-- In settings.xml, force internal repos first -->
<pluginRepositories>
    <pluginRepository>
        <id>internal</id>
        <url>https://internal-nexus.company.com/repository/maven-releases/</url>
        <releases><enabled>true</enabled></releases>
        <snapshots><enabled>false</enabled></snapshots>
    </pluginRepository>
</pluginRepositories>
```

## AI-Generated Vulnerability: Using Deprecated/Vulnerable Logging Libraries

```xml
<!-- AI-GENERATED — uses Log4j 2.14.1 (PRE-Log4Shell!) -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 (Log4Shell) -->
</dependency>
```

## AI-Generated Vulnerability: Using Snapshots in Production

```xml
<!-- AI-GENERATED — uses snapshot in production -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>rapid-dev-framework</artifactId>
    <version>1.0-SNAPSHOT</version>  <!-- BUG: SNAPSHOT changes without warning! -->
</dependency>
```

**SNAPSHOT dependencies can change without a version bump** — a build that passed today may fail or behave differently tomorrow, including introducing vulnerabilities.

## Gradle-Specific Issues

### Dynamic Versions in Gradle

```groovy
// AI-GENERATED build.gradle — dynamic versions
dependencies {
    implementation 'com.example:library:1.+'   // BUG: Picks latest patch
    implementation 'com.example:another:latest.integration'  // BUG: Always latest!
    implementation 'com.example:newest:+'  // BUG: Any version
}
```

### Gradle Module Metadata Attack

Gradle's module metadata (.module files) can replace transitive dependencies — a technique used in dependency confusion attacks. AI-generated Gradle code rarely pins these.

## The Transitive Dependency Bomb

```xml
<!-- AI adds one dependency, which pulls in 50 more -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.4</version>
</dependency>
<!-- This pulls in: commons-collections4, commons-lang3, etc. -->
```

AI-generated code frequently adds entire framework starters when a single lightweight library would suffice:

```xml
<!-- AI adds the whole Spring Boot starter for one feature -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- Instead of a specific lightweight library -->
```

## Security Scanning Tools

### OWASP Dependency-Check (Maven)

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <formats>
            <format>HTML</format>
            <format>JSON</format>
        </formats>
    </configuration>
    <executions>
        <execution>
            <goals><goal>check</goal></goals>
        </execution>
    </executions>
</plugin>
```

### OWASP Dependency-Check (Gradle)

```groovy
plugins {
    id 'org.owasp.dependencycheck' version '9.0.0'
}

dependencyCheck {
    failBuildOnCVSS = 7
    formats = ['HTML', 'JSON']
}
```

### Snyk

```bash
# CLI scan
snyk test --all-projects

# Monitor for continuous scanning
snyk monitor
```

### GitHub Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

## Maven Enforcer Plugin

Prevent common dependency mistakes:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.4.1</version>
    <executions>
        <execution>
            <id>enforce</id>
            <goals><goal>enforce</goal></goals>
            <configuration>
                <rules>
                    <bannedDependencies>
                        <excludes>
                            <exclude>commons-collections:commons-collections:*</exclude>
                            <exclude>log4j:log4j:*</exclude>
                            <exclude>com.sun.jmx:*</exclude>
                        </excludes>
                    </bannedDependencies>
                    <requireReleaseDeps>
                        <message>No snapshots allowed in releases</message>
                    </requireReleaseDeps>
                    <dependencyConvergence/>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
```

## Real CVEs

- **CVE-2021-44228 (Log4Shell)**: CVSS 10.0 — The most impactful supply chain vulnerability. Log4j 2.x was a transitive dependency in thousands of Java applications. Organizations that didn't track transitive deps were vulnerable without knowing it.
- **CVE-2022-22965 (Spring4Shell)**: CVSS 9.8 — Spring Framework vulnerability affecting all applications using Spring MVC or WebFlux with JDK 9+. Required urgent patching across the entire Java ecosystem.
- **CVE-2023-46604 (Apache ActiveMQ)**: CVSS 9.8 — RCE in the Java OpenWire protocol marshaller: a crafted serialized class type lets an unauthenticated attacker instantiate arbitrary classpath objects and run shell commands. Widely exploited in the wild against outdated ActiveMQ deployments.
- **CVE-2024-38808 (Spring SpEL)**: CVSS 4.3 — a crafted SpEL expression triggers a **denial of service** in Spring Framework's `spring-expression` module — a transitive dependency of virtually every Spring Boot application.

## Prevention Checklist

1. **Pin exact versions** — Never use version ranges or `+` in Gradle.
2. **Use OWASP Dependency-Check in CI** — Fail the build on CVSS 7+ vulnerabilities.
3. **Review all transitive dependencies** — `mvn dependency:tree` or `gradle dependencies`.
4. **Ban known-problematic libraries** — Commons Collections 3.x, Log4j < 2.17, older Struts.
5. **Use Maven Enforcer** — Enforce no Snapshots, dependency convergence, banned deps.
6. **Use a private artifact repository** — Nexus, Artifactory control which artifacts enter your build.
7. **Scan for dependency confusion** — Ensure internal artifact names are reserved on Maven Central.
8. **Update dependencies regularly** — Don't accumulate technical debt in vulnerable libs.
9. **Use `mvn verify` and `gradle build` with security scanning** — Every build.
10. **Generate SBOM (Software Bill of Materials)** — `mvn cyclonedx:makeBom` or `gradle cyclonedxBom`.
