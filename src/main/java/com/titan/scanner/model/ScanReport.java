package com.titan.scanner.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Full vulnerability scan report returned by POST /api/scan.
 */
public record ScanReport(
        String repoUrl,
        String owner,
        String repo,
        String defaultBranch,
        Instant scannedAt,
        List<String> scannedFiles,
        Summary summary,
        List<VulnerabilityInfo> vulnerabilities,
        List<Dependency> cleanDependencies,
        String error
) {

    public record Summary(
            int totalDependencies,
            int vulnerableDependencies,
            int criticalCount,
            int highCount,
            int mediumCount,
            int lowCount,
            int unknownCount
    ) {
        public static Summary from(List<Dependency> allDeps, List<VulnerabilityInfo> vulns) {
            Map<VulnerabilityInfo.Severity, Long> counts = vulns.stream()
                    .collect(Collectors.groupingBy(VulnerabilityInfo::severity, Collectors.counting()));

            // count unique vulnerable dependency display names
            long vulnDepCount = vulns.stream()
                    .map(v -> v.dependency().displayName())
                    .distinct()
                    .count();

            return new Summary(
                    allDeps.size(),
                    (int) vulnDepCount,
                    counts.getOrDefault(VulnerabilityInfo.Severity.CRITICAL, 0L).intValue(),
                    counts.getOrDefault(VulnerabilityInfo.Severity.HIGH,     0L).intValue(),
                    counts.getOrDefault(VulnerabilityInfo.Severity.MEDIUM,   0L).intValue(),
                    counts.getOrDefault(VulnerabilityInfo.Severity.LOW,      0L).intValue(),
                    counts.getOrDefault(VulnerabilityInfo.Severity.UNKNOWN,  0L).intValue()
            );
        }
    }

    /** Convenience factory for error reports. */
    public static ScanReport error(String repoUrl, String message) {
        return new ScanReport(repoUrl, null, null, null,
                Instant.now(), List.of(),
                new Summary(0, 0, 0, 0, 0, 0, 0),
                List.of(), List.of(), message);
    }
}
