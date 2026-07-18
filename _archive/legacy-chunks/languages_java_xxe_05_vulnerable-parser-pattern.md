---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 5
total_chunks: 10
heading: "Vulnerable Parser Patterns"
---

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