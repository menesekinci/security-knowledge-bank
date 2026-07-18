---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 11
total_chunks: 13
heading: "Maven Enforcer Plugin"
---

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