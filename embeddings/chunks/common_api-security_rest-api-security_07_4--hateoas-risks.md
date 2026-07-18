---
source: "common/api-security/rest-api-security.md"
title: "REST API Security"
heading: "4. HATEOAS Risks"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, authentication, limiting, methods, overview, pagination, rate, security, table]
chunk: 7/9
---

## 4. HATEOAS Risks

HATEOAS (Hypermedia as the Engine of Application State) embeds links in API responses. Risks include:

- **Link injection** — attacker-controlled URLs in responses leading to phishing
- **Dynamic link generation** — path traversal or SSRF via link templates
- **Excessive information disclosure** — exposing admin-only endpoints via links
- **Insecure link templating** — template injection in URL patterns

### Vulnerable Code (HATEOAS — Dynamic Link Injection)

```java
// VULNERABLE: Using user input directly in HATEOAS links
// User-controlled "nextUrl" parameter embedded in response links
@GetMapping("/api/orders/{id}")
public EntityModel<Order> getOrder(@PathVariable Long id,
                                    @RequestParam String baseUrl) {
    Order order = orderService.findById(id);
    EntityModel<Order> model = EntityModel.of(order);
    
    // Attacker can inject malicious URLs!
    model.add(Link.of(baseUrl + "/orders/" + id + "/pay", "payment"));
    
    return model;
}
```

### Secure Code (HATEOAS — Whitelist Link Sources)

```java
// SECURE: Use configured base URL, never user input
@GetMapping("/api/orders/{id}")
public EntityModel<Order> getOrder(@PathVariable Long id) {
    Order order = orderService.findById(id);
    EntityModel<Order> model = EntityModel.of(order);
    
    // Use only server-configured link builder
    model.add(linkTo(methodOn(OrderController.class).payOrder(id)).withRel("payment"));
    model.add(linkTo(methodOn(OrderController.class).getOrder(id)).withSelfRel());
    
    // Conditional links based on actual authorization
    if (currentUser.canCancel(order)) {
        model.add(linkTo(methodOn(OrderController.class).cancelOrder(id)).withRel("cancel"));
    }
    
    return model;
}
```

---