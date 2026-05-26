package com.titan.scanner.model;

/**
 * A single resolved dependency extracted from a manifest file.
 *
 * @param groupId    Maven groupId, Go module path, or Python package name
 * @param artifactId Maven artifactId (empty for non-Maven ecosystems)
 * @param version    Resolved version string (may be null if unresolvable)
 * @param ecosystem  OSV ecosystem string: Maven | npm | PyPI | Go | NuGet | Gradle
 * @param sourceFile The manifest file this dep was found in (e.g. "pom.xml")
 */
public record Dependency(
        String groupId,
        String artifactId,
        String version,
        String ecosystem,
        String sourceFile
) {
    /** OSV package name: Maven uses "groupId:artifactId", others use the package name. */
    public String osvPackageName() {
        if ("Maven".equals(ecosystem) && artifactId != null && !artifactId.isBlank()) {
            return groupId + ":" + artifactId;
        }
        return groupId;
    }

    public String displayName() {
        if (artifactId != null && !artifactId.isBlank()) {
            return groupId + ":" + artifactId + ":" + version;
        }
        return groupId + ":" + version;
    }
}
