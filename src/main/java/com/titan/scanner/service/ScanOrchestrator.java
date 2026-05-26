package com.titan.scanner.service;

import com.titan.scanner.model.Dependency;
import com.titan.scanner.model.ScanReport;
import com.titan.scanner.model.VulnerabilityInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Orchestrates the full scan pipeline:
 *   1. Parse GitHub URL → owner / repo
 *   2. Fetch default branch
 *   3. Discover and download dependency manifest files
 *   4. Extract all dependencies
 *   5. Query OSV for vulnerabilities
 *   6. Build and return the final ScanReport
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ScanOrchestrator {

    private final GitHubFetchService github;
    private final DependencyExtractorService extractor;
    private final OsvApiService osv;

    public Mono<ScanReport> scan(String repoUrl, String githubToken) {
        String[] ownerRepo;
        try {
            ownerRepo = GitHubFetchService.parseOwnerRepo(repoUrl);
        } catch (IllegalArgumentException e) {
            return Mono.just(ScanReport.error(repoUrl, e.getMessage()));
        }

        String owner = ownerRepo[0];
        String repo  = ownerRepo[1];

        log.info("Starting scan: {}/{}", owner, repo);

        return github.getDefaultBranch(owner, repo, githubToken)
                .flatMap(branch ->
                    github.fetchDependencyFiles(owner, repo, branch, githubToken)
                            .flatMap(files -> {
                                if (files.isEmpty()) {
                                    return Mono.just(ScanReport.error(repoUrl,
                                            "No supported dependency files found in repository root. " +
                                            "Supported: pom.xml, build.gradle, requirements.txt, go.mod, package.json"));
                                }

                                // Extract all dependencies from all files
                                List<Dependency> allDeps = files.entrySet().stream()
                                        .flatMap(e -> extractor.extract(e.getKey(), e.getValue()).stream())
                                        .collect(Collectors.toList());

                                log.info("[{}/{}] total deps extracted: {}", owner, repo, allDeps.size());

                                // Query OSV
                                return osv.scan(allDeps)
                                        .map(vulns -> buildReport(
                                                repoUrl, owner, repo, branch,
                                                new ArrayList<>(files.keySet()),
                                                allDeps, vulns
                                        ));
                            })
                )
                .doOnSuccess(r -> log.info("Scan complete: {}/{} — {} vulns found",
                        owner, repo, r.vulnerabilities().size()))
                .onErrorResume(e -> {
                    log.error("Scan failed for {}: {}", repoUrl, e.getMessage(), e);
                    return Mono.just(ScanReport.error(repoUrl, "Scan failed: " + e.getMessage()));
                });
    }

    private ScanReport buildReport(
            String repoUrl, String owner, String repo, String branch,
            List<String> scannedFiles, List<Dependency> allDeps,
            List<VulnerabilityInfo> vulns
    ) {
        // Sort vulns: Critical first, then by OSV ID
        List<VulnerabilityInfo> sorted = vulns.stream()
                .sorted(Comparator
                        .comparingInt((VulnerabilityInfo v) -> v.severity().ordinal())
                        .thenComparing(VulnerabilityInfo::osvId))
                .toList();

        // Identify clean (non-vulnerable) dependencies
        Set<String> vulnDepNames = sorted.stream()
                .map(v -> v.dependency().displayName())
                .collect(Collectors.toSet());

        List<Dependency> clean = allDeps.stream()
                .filter(d -> !vulnDepNames.contains(d.displayName()))
                .toList();

        scannedFiles.sort(Comparator.naturalOrder());

        return new ScanReport(
                repoUrl, owner, repo, branch,
                Instant.now(),
                scannedFiles,
                ScanReport.Summary.from(allDeps, sorted),
                sorted,
                clean,
                null
        );
    }
}
