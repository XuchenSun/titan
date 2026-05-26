package com.titan.scanner.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * POST /api/scan request body.
 *
 * Example:
 * {
 *   "url": "https://github.com/apache/log4j",
 *   "githubToken": "ghp_xxxx"   // optional, increases rate limit
 * }
 */
public record ScanRequest(

        @NotBlank(message = "url must not be blank")
        @Pattern(
                regexp = "https://github\\.com/[\\w.-]+/[\\w.-]+(/.*)?",
                message = "url must be a valid GitHub repository URL"
        )
        String url,

        /** Optional personal access token — overrides the server-level GITHUB_TOKEN. */
        String githubToken
) {}
