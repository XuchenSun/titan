package com.titan.scanner.controller;

import com.titan.scanner.model.ScanReport;
import com.titan.scanner.model.ScanRequest;
import com.titan.scanner.service.ScanOrchestrator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * REST API for the vulnerability scanner.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * POST /api/scan
 *
 * Request body (JSON):
 * {
 *   "url": "https://github.com/apache/log4j",
 *   "githubToken": "ghp_xxxx"    ← optional
 * }
 *
 * Response (JSON): ScanReport
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Quick test with curl:
 *   curl -s -X POST http://localhost:8080/api/scan \
 *        -H "Content-Type: application/json" \
 *        -d '{"url":"https://github.com/apache/struts"}' | jq .
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ScanController {

    private final ScanOrchestrator orchestrator;

    @PostMapping(
            value = "/scan",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<ResponseEntity<ScanReport>> scan(@Valid @RequestBody ScanRequest request) {
        log.info("Scan requested for: {}", request.url());
        return orchestrator.scan(request.url(), request.githubToken())
                .map(report -> report.error() != null
                        ? ResponseEntity.badRequest().body(report)
                        : ResponseEntity.ok(report));
    }

    /** Health-check endpoint */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Titan Scanner is running");
    }
}
