package com.titan.scanner.service;

import com.titan.scanner.model.Dependency;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts a list of {@link Dependency} objects from raw manifest file content.
 *
 * Supported formats:
 *   pom.xml          → Maven
 *   build.gradle     → Maven (Gradle uses Maven coordinates)
 *   build.gradle.kts → Maven
 *   requirements.txt → PyPI
 *   go.mod           → Go
 *   package.json     → npm
 */
@Slf4j
@Service
public class DependencyExtractorService {

    public List<Dependency> extract(String filename, String content) {
        String base = filename.contains("/") ? filename.substring(filename.lastIndexOf('/') + 1) : filename;
        return switch (base) {
            case "pom.xml"           -> parsePom(content, filename);
            case "build.gradle",
                 "build.gradle.kts"  -> parseGradle(content, filename);
            case "requirements.txt"  -> parseRequirements(content, filename);
            case "go.mod"            -> parseGoMod(content, filename);
            case "package.json"      -> parsePackageJson(content, filename);
            default -> {
                log.warn("No parser for: {}", filename);
                yield List.of();
            }
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // pom.xml  (DOM parsing — no external library needed)
    // ─────────────────────────────────────────────────────────────────────────

    private List<Dependency> parsePom(String xml, String sourceFile) {
        List<Dependency> deps = new ArrayList<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Disable XXE
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            doc.getDocumentElement().normalize();

            // Extract top-level <properties> for variable substitution
            Map<String, String> props = extractPomProperties(doc);

            NodeList depNodes = doc.getElementsByTagName("dependency");
            for (int i = 0; i < depNodes.getLength(); i++) {
                Element dep = (Element) depNodes.item(i);
                String groupId    = text(dep, "groupId");
                String artifactId = text(dep, "artifactId");
                String version    = resolve(text(dep, "version"), props);
                String scope      = text(dep, "scope");

                // Skip test/provided/import scoped deps (optional — comment out if you want them)
                if ("test".equalsIgnoreCase(scope) || "import".equalsIgnoreCase(scope)) continue;

                if (groupId.isBlank() || artifactId.isBlank()) continue;
                if (version.isBlank()) continue; // managed deps with no version — skip

                deps.add(new Dependency(groupId, artifactId, version, "Maven", sourceFile));
            }
        } catch (Exception e) {
            log.warn("Failed to parse pom.xml [{}]: {}", sourceFile, e.getMessage());
        }
        log.debug("[{}] extracted {} Maven deps", sourceFile, deps.size());
        return deps;
    }

    private Map<String, String> extractPomProperties(Document doc) {
        Map<String, String> map = new HashMap<>();
        NodeList propsNodes = doc.getElementsByTagName("properties");
        for (int i = 0; i < propsNodes.getLength(); i++) {
            Element props = (Element) propsNodes.item(i);
            NodeList children = props.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                if (children.item(j) instanceof Element el) {
                    map.put("${" + el.getTagName() + "}", el.getTextContent().trim());
                }
            }
        }
        return map;
    }

    private String text(Element parent, String tag) {
        NodeList nl = parent.getElementsByTagName(tag);
        if (nl.getLength() == 0) return "";
        return nl.item(0).getTextContent().trim();
    }

    private String resolve(String value, Map<String, String> props) {
        if (value == null || !value.startsWith("${")) return value == null ? "" : value;
        return props.getOrDefault(value, ""); // return empty if unresolvable
    }

    // ─────────────────────────────────────────────────────────────────────────
    // build.gradle / build.gradle.kts  (regex-based)
    // ─────────────────────────────────────────────────────────────────────────

    // Matches: implementation 'group:artifact:1.0'  or  ("group:artifact:1.0")
    private static final Pattern GRADLE_SHORT = Pattern.compile(
            """
            (?:implementation|api|compile|runtimeOnly|testImplementation|\
            classpath|annotationProcessor|kapt|ksp)\
            \\s*[\\(]?\\s*["']([\\w.\\-]+):([\\w.\\-]+):([\\w.\\-+]+)["']""",
            Pattern.MULTILINE
    );

    // Matches: implementation group: 'x', name: 'y', version: 'z'
    private static final Pattern GRADLE_LONG = Pattern.compile(
            "group:\\s*['\"]([\\w.\\-]+)['\"].*?name:\\s*['\"]([\\w.\\-]+)['\"].*?version:\\s*['\"]([\\w.\\-+]+)['\"]",
            Pattern.DOTALL
    );

    private List<Dependency> parseGradle(String content, String sourceFile) {
        List<Dependency> deps = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        Matcher m1 = GRADLE_SHORT.matcher(content);
        while (m1.find()) {
            String key = m1.group(1) + ":" + m1.group(2) + ":" + m1.group(3);
            if (seen.add(key)) {
                deps.add(new Dependency(m1.group(1), m1.group(2), m1.group(3), "Maven", sourceFile));
            }
        }

        Matcher m2 = GRADLE_LONG.matcher(content);
        while (m2.find()) {
            String key = m2.group(1) + ":" + m2.group(2) + ":" + m2.group(3);
            if (seen.add(key)) {
                deps.add(new Dependency(m2.group(1), m2.group(2), m2.group(3), "Maven", sourceFile));
            }
        }

        log.debug("[{}] extracted {} Gradle deps", sourceFile, deps.size());
        return deps;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // requirements.txt  (PyPI)
    // ─────────────────────────────────────────────────────────────────────────

    private static final Pattern REQ_LINE = Pattern.compile(
            "^([A-Za-z0-9_\\-\\.]+)(?:[=~!<>]+)([A-Za-z0-9_\\-.]+)"
    );

    private List<Dependency> parseRequirements(String content, String sourceFile) {
        List<Dependency> deps = new ArrayList<>();
        for (String line : content.split("\n")) {
            line = line.trim();
            if (line.isBlank() || line.startsWith("#") || line.startsWith("-")) continue;
            Matcher m = REQ_LINE.matcher(line);
            if (m.find()) {
                deps.add(new Dependency(m.group(1), "", m.group(2), "PyPI", sourceFile));
            }
        }
        log.debug("[{}] extracted {} PyPI deps", sourceFile, deps.size());
        return deps;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // go.mod  (Go modules)
    // ─────────────────────────────────────────────────────────────────────────

    private static final Pattern GO_REQUIRE = Pattern.compile(
            "^\\s+([\\w./\\-]+)\\s+(v[\\w.\\-+]+)", Pattern.MULTILINE
    );

    private List<Dependency> parseGoMod(String content, String sourceFile) {
        List<Dependency> deps = new ArrayList<>();
        boolean inRequire = false;
        for (String line : content.split("\n")) {
            String t = line.trim();
            if (t.startsWith("require (")) { inRequire = true; continue; }
            if (inRequire && t.equals(")"))  { inRequire = false; continue; }

            if (inRequire || t.startsWith("require ")) {
                Matcher m = GO_REQUIRE.matcher(t.startsWith("require ") ? t.substring(8) : line);
                if (!m.find()) m = GO_REQUIRE.matcher(t);
                if (m.find()) {
                    deps.add(new Dependency(m.group(1), "", m.group(2), "Go", sourceFile));
                }
            }
        }
        log.debug("[{}] extracted {} Go deps", sourceFile, deps.size());
        return deps;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // package.json  (npm)  — minimal regex, avoids pulling in a JSON lib
    // ─────────────────────────────────────────────────────────────────────────

    private static final Pattern NPM_DEP = Pattern.compile(
            "\"([\\w@/\\-.]+)\"\\s*:\\s*\"([~^]?[\\w.\\-*]+)\""
    );

    private List<Dependency> parsePackageJson(String content, String sourceFile) {
        List<Dependency> deps = new ArrayList<>();
        boolean inDeps = false;
        Set<String> seen = new HashSet<>();

        for (String line : content.split("\n")) {
            String t = line.trim();
            if (t.contains("\"dependencies\"") || t.contains("\"devDependencies\"")) {
                inDeps = true; continue;
            }
            if (inDeps && t.equals("}")) { inDeps = false; continue; }
            if (!inDeps) continue;

            Matcher m = NPM_DEP.matcher(t);
            if (m.find()) {
                String name    = m.group(1);
                String version = m.group(2).replaceAll("[~^]", "");
                if (seen.add(name)) {
                    deps.add(new Dependency(name, "", version, "npm", sourceFile));
                }
            }
        }
        log.debug("[{}] extracted {} npm deps", sourceFile, deps.size());
        return deps;
    }
}
