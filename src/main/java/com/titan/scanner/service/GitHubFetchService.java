package com.titan.scanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fetches repository metadata and raw file content from GitHub.
 *
 * Uses the GitHub REST API v3 — no SDK needed.
 * Rate limit: 60 req/hr unauthenticated, 5000 req/hr with a token.
 */
@Slf4j
@Service
public class GitHubFetchService {

    // Files that contain dependency declarations — ordered by priority
    private static final List<String> DEPENDENCY_FILES = List.of(
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "requirements.txt",
            "go.mod",
            "package.json"
    );

    private final WebClient githubClient;
    private final String rawBase;

    public GitHubFetchService(
            WebClient.Builder builder,
            @Value("${titan.github.api-base}") String apiBase,
            @Value("${titan.github.raw-base}") String rawBase,
            @Value("${titan.github.token:}") String serverToken
    ) {
        this.rawBase = rawBase;

        WebClient.Builder b = builder.baseUrl(apiBase)
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28");

        if (serverToken != null && !serverToken.isBlank()) {
            b = b.defaultHeader("Authorization", "Bearer " + serverToken);
        }
        this.githubClient = b.build();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Parse "https://github.com/owner/repo[.git][/...]" → ["owner", "repo"] */
    public static String[] parseOwnerRepo(String url) {
        Pattern p = Pattern.compile("github\\.com/([\\w.-]+)/([\\w.-]+?)(\\.git)?([/?#]|$)");
        Matcher m = p.matcher(url);
        if (!m.find()) throw new IllegalArgumentException("Cannot parse owner/repo from: " + url);
        return new String[]{m.group(1), m.group(2)};
    }

    /** Fetch the default branch name for a repository. */
    public Mono<String> getDefaultBranch(String owner, String repo, String overrideToken) {
        return authedClient(overrideToken)
                .get()
                .uri("/repos/{owner}/{repo}", owner, repo)
                .retrieve()
                .bodyToMono(Map.class)
                .map(body -> (String) body.getOrDefault("default_branch", "main"))
                .doOnNext(b -> log.debug("[{}] default branch = {}", repo, b))
                .onErrorReturn("main");
    }

    /**
     * Discover which dependency files exist in the repo root and fetch their content.
     *
     * @return Map of filename → raw file content (only files that actually exist)
     */
    public Mono<Map<String, String>> fetchDependencyFiles(
            String owner, String repo, String branch, String overrideToken
    ) {
        // Use the Git tree API to list all files (recursive)
        return authedClient(overrideToken)
                .get()
                .uri("/repos/{owner}/{repo}/git/trees/{branch}?recursive=1", owner, repo, branch)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMapMany(tree -> {
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> nodes = (List<Map<String, Object>>) tree.get("tree");
                    if (nodes == null) return Flux.empty();

                    // Collect paths of known dependency files (at any depth)
                    return Flux.fromIterable(nodes)
                            .map(n -> (String) n.get("path"))
                            .filter(path -> DEPENDENCY_FILES.stream()
                                    .anyMatch(f -> path.equals(f) || path.endsWith("/" + f)));
                })
                .take(20) // safety cap
                .flatMap(path -> fetchRaw(owner, repo, branch, path)
                        .map(content -> Map.entry(path, content))
                        .onErrorResume(e -> {
                            log.warn("Could not fetch {}: {}", path, e.getMessage());
                            return Mono.empty();
                        }))
                .collectMap(Map.Entry::getKey, Map.Entry::getValue)
                .doOnNext(m -> log.info("[{}] found {} dependency file(s): {}",
                        repo, m.size(), m.keySet()));
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private Mono<String> fetchRaw(String owner, String repo, String branch, String path) {
        String rawUrl = String.format("%s/%s/%s/%s/%s", rawBase, owner, repo, branch, path);
        return WebClient.create(rawUrl)
                .get()
                .retrieve()
                .bodyToMono(String.class)
                .doOnNext(c -> log.debug("Fetched {} ({} chars)", path, c.length()));
    }

    /** Returns a client that uses the per-request token if provided. */
    private WebClient authedClient(String overrideToken) {
        if (overrideToken != null && !overrideToken.isBlank()) {
            return githubClient.mutate()
                    .defaultHeader("Authorization", "Bearer " + overrideToken)
                    .build();
        }
        return githubClient;
    }
}
