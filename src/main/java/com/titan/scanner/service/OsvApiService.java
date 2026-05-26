package com.titan.scanner.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.titan.scanner.model.Dependency;
import com.titan.scanner.model.VulnerabilityInfo;
import com.titan.scanner.model.VulnerabilityInfo.Severity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.IntStream;

/**
 * Queries the OSV.dev batch API to find known vulnerabilities for a list of dependencies.
 *
 * API docs: https://google.github.io/osv.dev/post-v1-querybatch/
 *
 * Flow:
 *   1. Split deps into chunks of batchSize (OSV limit: 1000 per request)
 *   2. POST /v1/querybatch  { queries: [ { version, package: { name, ecosystem } } ] }
 *   3. Map result[i] back to deps[i]
 *   4. Flatten all vulns into List<VulnerabilityInfo>
 */
@Slf4j
@Service
public class OsvApiService {

    private final WebClient osvClient;
    private final int batchSize;

    public OsvApiService(
            WebClient.Builder builder,
            @Value("${titan.osv.api-base}") String apiBase,
            @Value("${titan.osv.batch-size:500}") int batchSize
    ) {
        this.osvClient = builder
                .baseUrl(apiBase)
                .defaultHeader("Content-Type", "application/json")
                .build();
        this.batchSize = batchSize;
    }

    /**
     * Scan all dependencies and return every discovered vulnerability.
     * Dependencies with null/blank versions are skipped.
     */
    public Mono<List<VulnerabilityInfo>> scan(List<Dependency> allDeps) {
        List<Dependency> scannable = allDeps.stream()
                .filter(d -> d.version() != null && !d.version().isBlank())
                .toList();

        if (scannable.isEmpty()) return Mono.just(List.of());

        // Split into batches
        List<List<Dependency>> batches = partition(scannable, batchSize);
        log.info("Sending {} deps to OSV in {} batch(es)", scannable.size(), batches.size());

        return Flux.fromIterable(batches)
                .concatMap(this::scanBatch)   // sequential to avoid hammering the API
                .collectList()
                .map(lists -> lists.stream().flatMap(Collection::stream).toList());
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private Mono<List<VulnerabilityInfo>> scanBatch(List<Dependency> batch) {
        List<Map<String, Object>> queries = batch.stream()
                .map(dep -> Map.<String, Object>of(
                        "version", dep.version(),
                        "package", Map.of(
                                "name",      dep.osvPackageName(),
                                "ecosystem", dep.ecosystem()
                        )
                ))
                .toList();

        return osvClient.post()
                .uri("/querybatch")
                .bodyValue(Map.of("queries", queries))
                .retrieve()
                .bodyToMono(OsvBatchResponse.class)
                .map(resp -> mapResults(resp, batch))
                .onErrorResume(e -> {
                    log.error("OSV API error: {}", e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private List<VulnerabilityInfo> mapResults(OsvBatchResponse resp, List<Dependency> batch) {
        List<VulnerabilityInfo> result = new ArrayList<>();
        if (resp == null || resp.results() == null) return result;

        List<OsvResult> results = resp.results();
        IntStream.range(0, Math.min(results.size(), batch.size())).forEach(i -> {
            OsvResult osvResult = results.get(i);
            Dependency dep = batch.get(i);
            if (osvResult.vulns() == null) return;

            for (OsvVuln vuln : osvResult.vulns()) {
                result.add(toVulnInfo(vuln, dep));
            }
        });
        return result;
    }

    private VulnerabilityInfo toVulnInfo(OsvVuln vuln, Dependency dep) {
        // CVE aliases
        List<String> cveIds = Optional.ofNullable(vuln.aliases())
                .orElse(List.of())
                .stream()
                .filter(a -> a.startsWith("CVE-"))
                .toList();

        // Severity: prefer database_specific label, fall back to CVSS score
        Severity severity = Severity.UNKNOWN;
        String cvssVector = null;

        if (vuln.severity() != null) {
            for (OsvSeverity s : vuln.severity()) {
                if ("CVSS_V3".equals(s.type()) && s.score() != null) {
                    cvssVector = s.score();
                    severity = parseCvssV3Severity(s.score());
                    break;
                }
            }
        }

        // GitHub advisory database_specific often has a plain severity label
        if (severity == Severity.UNKNOWN && vuln.databaseSpecific() != null) {
            Object label = vuln.databaseSpecific().get("severity");
            if (label instanceof String l) severity = Severity.fromLabel(l);
        }

        // Find "fixed" version from ranges
        String fixedVersion = extractFixed(vuln);

        return new VulnerabilityInfo(
                vuln.id(), cveIds, vuln.summary(),
                severity, cvssVector, fixedVersion, dep
        );
    }

    /**
     * Extract CVSS v3 base score from a CVSS vector string.
     * Rather than re-implementing the full algorithm, we look at the Impact/Exploitability
     * sub-score letters to make a conservative estimate.
     *
     * A proper implementation would use the official CVSS calculator. Here we parse the
     * CVSS vector string for the AV/AC/PR/UI/S/C/I/A components and look up the score
     * from the known bands. For simplicity, we use a heuristic:
     *   If C, I, or A is "H" and AV=N → Critical/High
     *   Otherwise map to Medium/Low
     *
     * For production use, include the "io.github.maxisoft.utils:cvss-calculator" library
     * or call the NVD API for a precise numeric score.
     */
    private Severity parseCvssV3Severity(String vector) {
        // vector example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        // We extract individual metric values
        if (vector == null) return Severity.UNKNOWN;
        try {
            Map<String, String> metrics = new HashMap<>();
            String[] parts = vector.split("/");
            for (String part : parts) {
                String[] kv = part.split(":");
                if (kv.length == 2) metrics.put(kv[0], kv[1]);
            }
            String av = metrics.getOrDefault("AV", "N");
            String c  = metrics.getOrDefault("C", "N");
            String i  = metrics.getOrDefault("I", "N");
            String a  = metrics.getOrDefault("A", "N");
            String s  = metrics.getOrDefault("S", "U");
            String pr = metrics.getOrDefault("PR", "N");
            String ac = metrics.getOrDefault("AC", "L");

            int impact = score(c) + score(i) + score(a);  // 0-6

            if (impact == 6 && "N".equals(av) && "C".equals(s)) return Severity.CRITICAL;
            if (impact >= 5 && "N".equals(av))                   return Severity.CRITICAL;
            if (impact >= 4)                                      return Severity.HIGH;
            if (impact >= 2)                                      return Severity.MEDIUM;
            if (impact >= 1)                                      return Severity.LOW;
            return Severity.NONE;
        } catch (Exception e) {
            return Severity.UNKNOWN;
        }
    }

    private int score(String val) {
        return switch (val) {
            case "H" -> 2;
            case "L" -> 1;
            default  -> 0;
        };
    }

    private String extractFixed(OsvVuln vuln) {
        if (vuln.affected() == null) return null;
        for (OsvAffected aff : vuln.affected()) {
            if (aff.ranges() == null) continue;
            for (OsvRange range : aff.ranges()) {
                if (!"ECOSYSTEM".equals(range.type())) continue;
                if (range.events() == null) continue;
                for (OsvEvent event : range.events()) {
                    if (event.fixed() != null && !event.fixed().isBlank()) return event.fixed();
                }
            }
        }
        return null;
    }

    private <T> List<List<T>> partition(List<T> list, int size) {
        List<List<T>> result = new ArrayList<>();
        for (int i = 0; i < list.size(); i += size) {
            result.add(list.subList(i, Math.min(i + size, list.size())));
        }
        return result;
    }

    // ── OSV response DTOs (inner records) ─────────────────────────────────────

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvBatchResponse(List<OsvResult> results) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvResult(List<OsvVuln> vulns) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvVuln(
            String id,
            String summary,
            List<String> aliases,
            List<OsvSeverity> severity,
            List<OsvAffected> affected,
            @JsonProperty("database_specific") Map<String, Object> databaseSpecific
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvSeverity(String type, String score) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvAffected(List<OsvRange> ranges) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvRange(String type, List<OsvEvent> events) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OsvEvent(String introduced, String fixed) {}
}
