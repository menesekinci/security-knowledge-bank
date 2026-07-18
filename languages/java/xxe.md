# XML External Entity (XXE) Processing

## Overview

XML External Entity (XXE) injection is a vulnerability that occurs when an XML parser processes user-supplied XML input containing references to external entities. Java's default XML parser configurations have historically been **insecure by default** — many standard Java XML parsers allow DTDs and external entity resolution unless explicitly disabled.

## How XXE Works

An XXE attack exploits the XML specification's ability to define entities that reference external resources:

```xml
<!-- Malicious XML payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

When parsed, `&xxe;` is replaced with the contents of `/etc/passwd`. The parsed content is returned to the attacker in the application's response. More advanced XXE attacks include:
- **SSRF**: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`
- **DoS (Billion Laughs)**: Nested entity expansion causing OOM
- **Blind XXE**: Exfiltration via out-of-band HTTP/DNS requests

## Why AI Generates XXE-Vulnerable Java Code

LLMs frequently use `DocumentBuilderFactory` or `SAXParser` without configuring them securely:

```java
// AI-GENERATED — vulnerable XML parser
public String parseXml(String xmlData) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // BUG: No XXE protection configured!
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
    // XXE succeeds — attacker reads local files
}
```

## Vulnerable Parser Patterns

### Pattern 1: DocumentBuilderFactory (DOM)

```java
// AI-GENERATED — DOM parser without XXE protection
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(userXml)));
```

**Secure Fix**:
```java
public Document parseSafeXml(String xmlData) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Disable DOCTYPE declarations (prevents most XXE)
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    
    // Or if DOCTYPE is needed, disable external entities:
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    
    // Also disable XInclude
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlData)));
}
```

### Pattern 2: SAXParser

```java
// AI-GENERATED — SAX parser without XXE protection
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(new InputSource(new StringReader(userXml)), handler);
```

**Secure Fix**:
```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = factory.newSAXParser();
parser.parse(new InputSource(new StringReader(userXml)), handler);
```

### Pattern 3: XMLInputFactory (StAX)

```java
// AI-GENERATED — StAX parser without XXE protection
XMLInputFactory factory = XMLInputFactory.newInstance();
XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(userXml));
```

**Secure Fix**:
```java
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // Disable DTDs
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(userXml));
```

### Pattern 4: TransformerFactory (XSLT)

```java
// AI-GENERATED — XSLT transformation with XXE
TransformerFactory factory = TransformerFactory.newInstance();
Transformer transformer = factory.newTransformer(new StreamSource(xslStream));
```

**Secure Fix**:
```java
TransformerFactory factory = TransformerFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
Transformer transformer = factory.newTransformer(new StreamSource(xslStream));
```

### Pattern 5: Unmarshalling (JAXB)

```java
// AI-GENERATED — JAXB without XXE protection
JAXBContext context = JAXBContext.newInstance(MyClass.class);
Unmarshaller unmarshaller = context.createUnmarshaller();
MyClass obj = (MyClass) unmarshaller.unmarshal(new StringReader(userXml));
```

**Secure Fix**:
```java
JAXBContext context = JAXBContext.newInstance(MyClass.class);
Unmarshaller unmarshaller = context.createUnmarshaller();

// Set XML parser properties on the unmarshaller
unmarshaller.setProperty("com.sun.xml.bind.disableExternalEntityProcessing", true);

// Or configure the underlying XML parser:
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
SAXParser parser = spf.newSAXParser();
XMLReader reader = parser.getXMLReader();
InputSource is = new InputSource(new StringReader(userXml));
JAXBElement<MyClass> obj = unmarshaller.unmarshal(reader, MyClass.class);
```

## AI-Generated Vulnerability: XXE in SOAP Web Services

```java
// AI-GENERATED — JAX-WS SOAP endpoint
@WebMethod
public String processData(String xmlData) {
    // BUG: AI-generated SOAP handlers often parse XML without protection
    // XXE in SOAP can read server files
}
```

## Billion Laughs Attack (Entity Expansion DoS)

```xml
<!-- Billion Laughs: causes OOM via entity expansion -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

This creates an entity that expands to ~3 billion copies of "lol" — bringing the JVM to its knees.

## Real CVEs

- **CVE-2016-3720 (FasterXML jackson-dataformat-xml)**: CVSS 9.8 — XML External Entity (XXE) vulnerability in `XmlMapper` in jackson-dataformat-xml up to and including 2.7.3. Because the underlying XML input factory did not disable external entities, deserializing attacker-supplied XML could read local files or perform SSRF. Fixed in 2.7.4 / 2.8.0.
- **CVE-2021-33813 (JDOM)**: CVSS 7.5 — XXE issue in `SAXBuilder` in JDOM through 2.0.6. A crafted XML document (e.g. in an HTTP request) triggers external entity / DTD processing, enabling denial of service (and information disclosure depending on configuration). Affected downstreams included Apache Solr and Apache Tika. Fixed in JDOM 2.0.6.1.
- **CVE-2022-40152 (Woodstox)**: CVSS 7.5 — Applications using the Woodstox XML parser (FasterXML `woodstox-core`) before 5.4.0 / 6.4.0 are vulnerable to a denial-of-service crash (stack overflow) when DTD support is enabled and the parser runs on user-supplied input. A classic DTD/entity-expansion resource-exhaustion vector. Fixed in 6.4.0 (and 5.4.0).

## Detection

```bash
# Find XML parser instantiation
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory" src/

# Find XXE-vulnerable patterns (no features set)
grep -A5 "DocumentBuilderFactory.newInstance()" src/

# Find disallow-doctype-decl (properly configured)
grep -rn "disallow-doctype-decl" src/

# Use FindSecBugs
mvn com.h3xstream.findsecbugs:findsecbugs-plugin:findsecbugs
```

## Prevention Checklist

1. **Always disable DOCTYPE declarations** — `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
2. **If DTDs are required** — Disable external entities: `external-general-entities=false`, `external-parameter-entities=false`.
3. **Disable XInclude** — `setXIncludeAware(false)`.
4. **Use `disableExternalEntityProcessing` for JAXB** — Set this property on `Unmarshaller`.
5. **Prefer JSON over XML** — If you don't need XML features, JSON doesn't have entity injection.
6. **Use a secure XML parser wrapper** — Libraries like `OWASP XML Security` provide pre-configured safe parsers.
7. **Apply the principle of least privilege** — Even if XXE reads files, file permissions still apply.
8. **Validate XML against a schema** — Prevents unexpected DOCTYPE declarations.
9. **Set entity expansion limits** — Java 8+ `FEATURE_SECURE_PROCESSING` limits entity expansion.
10. **Test with XXE payloads** — Include `file:///etc/passwd` tests in your security test suite.
