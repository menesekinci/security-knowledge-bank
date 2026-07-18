# Dependency Confusion: Hacking Apple, Microsoft, and Dozens of Companies via Java/Maven

**Date:** 2020–2021 (published February 2021)  
**Type:** Software Supply Chain Attack / Dependency Confusion  
**Researcher:** Alex Birsan

## Summary

In 2020, security researcher Alex Birsan developed a novel supply chain attack called **"Dependency Confusion"** that compromised **over 35 major technology companies**, including Apple, Microsoft, PayPal, Shopify, Tesla, and Yelp. The attack exploited how package managers (including Maven for Java) resolve dependency names when both public and private packages share the same name.

While the attack was demonstrated across JavaScript (npm), Python (PyPI), and Ruby (RubyGems), it also applies to **Maven-based Java projects**, with the same principles affecting Gradle and other JVM build tools.

## How It Works

### The Core Problem
Many companies use **private packages** (hosted on internal registries) for internal libraries. But their build tools also pull from **public registries** (Maven Central, npm, PyPI). When a dependency name matches both a public and private package, the build tool must decide which to use — and many tools prioritize public registries or higher version numbers.

### The Attack
1. Researcher finds internal package names from leaked `pom.xml` files, JavaScript bundles, or public configs
2. Uploads a package with the **same name** to the public registry (Maven Central, npm, etc.)
3. The package contains benign "phone home" code (DNS exfiltration)
4. When companies run builds, they accidentally download the public malicious package instead of the internal one
5. Code execution occurs on developer machines, build servers, or CI pipelines

### For Java/Maven Specifically
```xml
<!-- Internal dependency in company's private repo -->
<dependency>
    <groupId>com.company.internal</groupId>
    <artifactId>secret-library</artifactId>
    <version>1.0.0</version>
</dependency>
```

If an attacker publishes `com.company.internal:secret-library` to Maven Central with a **higher version** (e.g., `99.0.0`), Maven's dependency resolution may prefer the public version with the higher version number.

## Results

| Company | Reward | Details |
|---------|--------|---------|
| **Apple** | $30,000 | Code executed on Apple ID authentication system servers |
| **Shopify** | $30,000 | Ruby gem automatically installed by build system |
| **Microsoft** | $40,000 | Internal npm packages compromised (Microsoft's highest bounty) |
| **PayPal** | $30,000 | Initial inspiration for the research |
| **Tesla, Yelp, and 30+ others** | Various | All affected via similar patterns |

## Impact

- Remote code execution on **internal build servers** and developer machines
- Potential for **backdoor injection into production builds** at any stage
- Apple's affected projects were related to the **Apple ID authentication system**
- 75% of callbacks came from npm, but Java/Maven and other ecosystems are equally vulnerable
- The technique was novel enough to warrant its own classification: **Dependency Confusion**

## Mitigation

For Java/Maven projects:
1. Use `<exclusions>` to ensure Maven doesn't resolve internal names from public repos
2. Mirror/proxy public repos through an internal repository manager (Nexus, Artifactory) with strict rules
3. Configure Maven to only use internal repos for internal namespace groups (e.g., `com.yourcompany.*`)
4. Pin exact dependency versions with checksums
5. Use lock files where available (Gradle supports dependency locking)

## Key Lesson

The simplicity and effectiveness of dependency confusion make it one of the most dangerous supply chain attacks. It doesn't require compromising any legitimate package or developer account — just uploading a new package with a name the target already uses internally. **Anyone with a public registry account can attempt this attack against any company.** Organizations must explicitly configure their build tools to separate internal and external namespaces.

## References

- https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610
- https://www.sonatype.com/blog/dependency-hijacking-software-supply-chain-attack-hits-more-than-35-organizations
- https://www.aquasec.com/cloud-native-academy/supply-chain-security/dependency-confusion/
