# Demo Killer Report

Verdict: Launch Blocked

Supported scope:
- Next.js App Router
- Express
- Fastify
- FastAPI
- Flask
- Django
- Gin
- Echo
- Fiber
- Actix
- Axum
- Rocket
- Spring Boot
- Ktor
- Laravel
- Rails
- Sinatra
- ASP.NET
- Vapor
- http4s
- Akka
- TypeScript
- JavaScript
- Python
- Go
- Rust
- Java
- Kotlin
- Scala
- C#
- PHP
- Ruby
- Swift
- C
- C++
- Lua
- Shell
- Dart
- Zig
- local static inspection
- AI/SaaS launch blockers

## Findings

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: client/src/services/adminService.ts
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: client/src/services/adminService.ts:299 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:590 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:608 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:742 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:1378 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:1396 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/chat.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/chat.py:1444 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/style.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/style.py:328 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/request_context.py
Capability: Taint path: Path parameters → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/request_context.py:106 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/verification.py
Capability: Taint path: Environment variable → Raw SQL query
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/verification.py:118 via call-graph-analysis

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/test/architecture/test_matchbox_platform_config_contracts.py
Capability: Taint path: Environment variable → Python subprocess
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/test/architecture/test_matchbox_platform_config_contracts.py:20 via call-graph-analysis

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/test/architecture/test_matchbox_startup_contracts.py
Capability: Taint path: Environment variable → Python subprocess
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/test/architecture/test_matchbox_startup_contracts.py:24 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: client/src/services/adminService.ts
Capability: Taint path: Path parameters flows through URLSearchParams → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: client/src/services/adminService.ts:299 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/agents/routes/style.py
Capability: Taint path: Path parameters flows through get_style_profile → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/agents/routes/style.py:328 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/auto_migrate.py
Capability: Taint path: Environment variable flows through _stamp_head → Raw SQL query
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/auto_migrate.py:521 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/request_context.py
Capability: Taint path: Path parameters flows through string → SQL query execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/request_context.py:106 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/verification.py
Capability: Taint path: Environment variable flows through _env → Raw SQL query
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/verification.py:118 via call-graph-analysis

### DK-TAINT-001: User input flows to sql operation without sanitization

Severity: blocker
Confidence: high
Entry point: server/core/verification.py
Capability: Taint path: Environment variable flows through _env_bool → Raw SQL query
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches sql through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: server/core/verification.py:118 via call-graph-analysis

### DK-DOCKER-001: Dockerfile has 2 security issue(s)

Severity: high
Confidence: medium
Missing controls: dockerHardening

Production consequence: A misconfigured Docker container can be exploited to escape to the host, access internal services, or compromise the deployment environment.

Acceptance criteria:
- Container runs as a non-root user (USER directive).
- Base images are pinned to specific versions, not :latest.
- Debug ports are not exposed in production.
- HEALTHCHECK instruction is present.

- Evidence: Dockerfile via docker-check
- Evidence: Dockerfile via docker-check

### DK-AGENT-010: Unsafe filesystem tool without path sandboxing

Severity: blocker
Confidence: high
Missing controls: pathSandboxing

Production consequence: A filesystem tool that accepts arbitrary paths allows an agent or attacker to read, write, or delete any file on the host system, including credentials, configuration, and system files.

Acceptance criteria:
- File operations are restricted to an explicit allowlist of directories.
- Paths are resolved and validated with path.resolve + startsWith checks.
- Symlink traversal is prevented by using realpath before validation.

- Evidence: client/scripts/i18n-check.mjs:109 via agent-mcp-scan
- Evidence: client/scripts/i18n-scan.mjs:5 via agent-mcp-scan
- Evidence: server/agents/agent_lorebook.py:178 via agent-mcp-scan
- Evidence: server/agents/agent_utils.py:207 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:86 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:97 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:101 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:105 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:109 via agent-mcp-scan
- Evidence: server/agents/attachment/storage.py:120 via agent-mcp-scan
- Evidence: server/agents/context_provider.py:188 via agent-mcp-scan
- Evidence: server/agents/director_graph.py:108 via agent-mcp-scan
- Evidence: server/agents/graphrag/service.py:78 via agent-mcp-scan
- Evidence: server/agents/graphrag/service.py:81 via agent-mcp-scan
- Evidence: server/agents/graphrag/service.py:82 via agent-mcp-scan
- Evidence: server/agents/graphrag/service.py:461 via agent-mcp-scan
- Evidence: server/agents/project_content.py:9 via agent-mcp-scan
- Evidence: server/agents/prompt_preferences.py:77 via agent-mcp-scan
- Evidence: server/agents/routes/auto_write.py:167 via agent-mcp-scan
- Evidence: server/agents/routes/auto_write.py:933 via agent-mcp-scan
- Evidence: server/agents/routes/auto_write.py:1009 via agent-mcp-scan
- Evidence: server/agents/routes/auto_write.py:1048 via agent-mcp-scan
- Evidence: server/agents/routes/auto_write_state.py:69 via agent-mcp-scan
- Evidence: server/agents/routes/characters.py:119 via agent-mcp-scan
- Evidence: server/agents/routes/characters.py:154 via agent-mcp-scan
- Evidence: server/agents/routes/characters.py:185 via agent-mcp-scan
- Evidence: server/agents/routes/characters.py:243 via agent-mcp-scan
- Evidence: server/agents/routes/characters.py:273 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:124 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:223 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:237 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:251 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:625 via agent-mcp-scan
- Evidence: server/agents/routes/context_builder.py:690 via agent-mcp-scan
- Evidence: server/agents/routes/lorebook.py:173 via agent-mcp-scan
- Evidence: server/agents/routes/lorebook.py:375 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:58 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:88 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:109 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:123 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:147 via agent-mcp-scan
- Evidence: server/agents/routes/outline.py:159 via agent-mcp-scan
- Evidence: server/agents/routes/schemas.py:267 via agent-mcp-scan
- Evidence: server/agents/routes/schemas.py:280 via agent-mcp-scan
- Evidence: server/agents/routes/schemas.py:359 via agent-mcp-scan
- Evidence: server/agents/routes/structure.py:146 via agent-mcp-scan
- Evidence: server/agents/routes/structure.py:172 via agent-mcp-scan
- Evidence: server/agents/routes/style.py:256 via agent-mcp-scan
- Evidence: server/agents/story_memory/facade.py:168 via agent-mcp-scan
- Evidence: server/agents/story_memory/facade.py:172 via agent-mcp-scan
- Evidence: server/agents/tools/automation.py:91 via agent-mcp-scan
- Evidence: server/agents/tools/automation.py:211 via agent-mcp-scan
- Evidence: server/agents/tools/automation.py:269 via agent-mcp-scan
- Evidence: server/agents/tools/lorebook.py:88 via agent-mcp-scan
- Evidence: server/agents/tools/lorebook.py:111 via agent-mcp-scan
- Evidence: server/agents/tools/scriptwriter.py:99 via agent-mcp-scan
- Evidence: server/agents/tools/scriptwriter.py:110 via agent-mcp-scan
- Evidence: server/agents/tools/scriptwriter.py:182 via agent-mcp-scan
- Evidence: server/agents/tools/scriptwriter.py:230 via agent-mcp-scan
- Evidence: server/agents/tools/scriptwriter.py:283 via agent-mcp-scan
- Evidence: server/agents/tools/shared_read.py:29 via agent-mcp-scan
- Evidence: server/agents/tools/shared_read.py:69 via agent-mcp-scan
- Evidence: server/agents/tools/shared_read.py:120 via agent-mcp-scan
- Evidence: server/agents/tools/shared_read.py:138 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:49 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:65 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:81 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:92 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:100 via agent-mcp-scan
- Evidence: server/agents/tools/showrunner.py:108 via agent-mcp-scan
- Evidence: server/agents/vector_index/service.py:100 via agent-mcp-scan
- Evidence: server/agents/vector_index/service.py:101 via agent-mcp-scan
- Evidence: server/app.py:116 via agent-mcp-scan
- Evidence: server/app.py:117 via agent-mcp-scan
- Evidence: server/app.py:698 via agent-mcp-scan
- Evidence: server/app.py:707 via agent-mcp-scan
- Evidence: server/clear_migration.py:253 via agent-mcp-scan
- Evidence: server/core/auth.py:442 via agent-mcp-scan
- Evidence: server/core/auth.py:446 via agent-mcp-scan
- Evidence: server/core/models.py:301 via agent-mcp-scan
- Evidence: server/core/project_settings.py:217 via agent-mcp-scan
- Evidence: server/core/project_settings.py:241 via agent-mcp-scan
- Evidence: server/core/project_settings.py:267 via agent-mcp-scan
- Evidence: server/core/project_settings.py:292 via agent-mcp-scan
- Evidence: server/core/project_settings.py:294 via agent-mcp-scan
- Evidence: server/core/routes_tags.py:52 via agent-mcp-scan
- Evidence: server/core/utils.py:5 via agent-mcp-scan
- Evidence: server/core/utils.py:54 via agent-mcp-scan
- Evidence: server/core/utils.py:58 via agent-mcp-scan
- Evidence: server/core/utils.py:62 via agent-mcp-scan
- Evidence: server/core/utils.py:66 via agent-mcp-scan
- Evidence: server/core/utils.py:70 via agent-mcp-scan
- Evidence: server/core/utils.py:74 via agent-mcp-scan
- Evidence: server/core/utils.py:78 via agent-mcp-scan
- Evidence: server/core/utils.py:93 via agent-mcp-scan
- Evidence: server/core/utils.py:110 via agent-mcp-scan
- Evidence: server/core/utils.py:116 via agent-mcp-scan
- Evidence: server/core/utils.py:120 via agent-mcp-scan
- Evidence: server/core/utils.py:147 via agent-mcp-scan
- Evidence: server/mcp_server/spark_control/server.py:228 via agent-mcp-scan
- Evidence: server/mcp_server/spark_control/server.py:232 via agent-mcp-scan
- Evidence: server/mcp_server/spark_control/server.py:260 via agent-mcp-scan
- Evidence: server/mcp_server/spark_control/server.py:261 via agent-mcp-scan
- Evidence: server/mcp_server/spark_inspiration/logic.py:49 via agent-mcp-scan
- Evidence: server/mcp_server/spark_inspiration/logic.py:54 via agent-mcp-scan
- Evidence: server/story/importer.py:59 via agent-mcp-scan
- Evidence: server/story/importer.py:102 via agent-mcp-scan
- Evidence: server/story/importer.py:193 via agent-mcp-scan
- Evidence: server/story/novel_parser.py:47 via agent-mcp-scan
- Evidence: server/story/novel_parser.py:53 via agent-mcp-scan
- Evidence: server/story/project_files.py:108 via agent-mcp-scan
- Evidence: server/story/project_files.py:236 via agent-mcp-scan
- Evidence: server/story/project_files.py:365 via agent-mcp-scan
- Evidence: server/story/project_files.py:370 via agent-mcp-scan
- Evidence: server/story/project_files.py:375 via agent-mcp-scan
- Evidence: server/story/project_files.py:385 via agent-mcp-scan
- Evidence: server/story/project_files.py:443 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:15 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:27 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:40 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:52 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:65 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:77 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:90 via agent-mcp-scan
- Evidence: server/story/routes_blueprint.py:102 via agent-mcp-scan
- Evidence: server/story/routes_files.py:126 via agent-mcp-scan
- Evidence: server/story/routes_files.py:590 via agent-mcp-scan
- Evidence: server/story/routes_files.py:597 via agent-mcp-scan
- Evidence: server/story/routes_files.py:709 via agent-mcp-scan
- Evidence: server/story/routes_files.py:711 via agent-mcp-scan
- Evidence: server/story/routes_project.py:95 via agent-mcp-scan
- Evidence: server/story/routes_project.py:141 via agent-mcp-scan
- Evidence: server/story/routes_project.py:144 via agent-mcp-scan
- Evidence: server/story/routes_project.py:308 via agent-mcp-scan
- Evidence: server/story/routes_project.py:435 via agent-mcp-scan
- Evidence: server/story/routes_project.py:460 via agent-mcp-scan
- Evidence: server/story/routes_project.py:465 via agent-mcp-scan
- Evidence: server/story/routes_share.py:137 via agent-mcp-scan
- Evidence: server/story/routes_share.py:142 via agent-mcp-scan
- Evidence: server/story/routes_version.py:66 via agent-mcp-scan
- Evidence: server/story/routes_version.py:74 via agent-mcp-scan
- Evidence: server/story/routes_version.py:78 via agent-mcp-scan
- Evidence: server/story/routes_version.py:294 via agent-mcp-scan
- Evidence: server/story/semantic_chunker/chunker.py:65 via agent-mcp-scan
- Evidence: server/test/architecture/test_mcp_control_contracts.py:304 via agent-mcp-scan
- Evidence: server/test/story_context/test_system_characters_contracts.py:17 via agent-mcp-scan
- Evidence: server/test/story_context/test_system_characters_contracts.py:24 via agent-mcp-scan

### DK-AGENT-008: Secret or context leak in agent/tool responses

Severity: blocker
Confidence: medium
Missing controls: outputRedaction

Production consequence: API keys, tokens, database credentials, or internal context can leak through agent tool outputs, exposing sensitive infrastructure to end users or attackers.

Acceptance criteria:
- Sensitive values are redacted or omitted from tool outputs.
- Structured response schemas prevent accidental secret inclusion.
- Output scanning detects and blocks secret patterns before responses are sent.

- Evidence: scripts/gitea-release-upload.mjs:7 via agent-mcp-scan
- Evidence: server/agents/tools/web_search.py:29 via agent-mcp-scan
- Evidence: server/core/runtime_cache.py:39 via agent-mcp-scan

### DK-AGENT-009: Unbounded agent loop without iteration limit

Severity: high
Confidence: high
Missing controls: iterationLimit

Production consequence: An agent loop without a maximum iteration count can run indefinitely, consuming API credits, CPU, and memory until the process crashes or the budget is exhausted.

Acceptance criteria:
- Agent loops have an explicit maxIterations or maxSteps limit.
- A timeout is configured for the entire agent run.
- Recursive agent calls track depth and terminate at a configured maximum.

- Evidence: server/agents/agent_lorebook.py:34 via agent-mcp-scan
- Evidence: server/agents/agent_scriptwriter.py:47 via agent-mcp-scan
- Evidence: server/agents/agent_showrunner.py:48 via agent-mcp-scan
- Evidence: server/agents/agent_utils.py:8 via agent-mcp-scan
- Evidence: server/agents/agent_utils.py:47 via agent-mcp-scan
- Evidence: server/agents/agent_utils.py:61 via agent-mcp-scan
- Evidence: server/agents/chat_manager.py:64 via agent-mcp-scan
- Evidence: server/agents/chat_manager.py:82 via agent-mcp-scan
- Evidence: server/agents/chat_manager.py:159 via agent-mcp-scan
- Evidence: server/agents/chat_manager.py:175 via agent-mcp-scan
- Evidence: server/agents/chat_manager.py:190 via agent-mcp-scan
- Evidence: server/agents/communication.py:24 via agent-mcp-scan
- Evidence: server/agents/routes/chat.py:950 via agent-mcp-scan
- Evidence: server/agents/routes/lorebook.py:283 via agent-mcp-scan
- Evidence: server/agents/routes/lorebook.py:474 via agent-mcp-scan
- Evidence: server/agents/routes/muse.py:300 via agent-mcp-scan
- Evidence: server/agents/routes/muse.py:363 via agent-mcp-scan
- Evidence: server/agents/routes/production.py:612 via agent-mcp-scan
- Evidence: server/agents/routes/production.py:778 via agent-mcp-scan
- Evidence: server/agents/routes/streaming_utils.py:147 via agent-mcp-scan
- Evidence: server/agents/routes/structure.py:134 via agent-mcp-scan
- Evidence: server/agents/routes/structure.py:236 via agent-mcp-scan
- Evidence: server/agents/routes/structure.py:318 via agent-mcp-scan
- Evidence: server/agents/setup_agents.py:46 via agent-mcp-scan
- Evidence: server/agents/tools/muse.py:92 via agent-mcp-scan
- Evidence: server/alembic/env.py:381 via agent-mcp-scan
- Evidence: server/alembic/env.py:387 via agent-mcp-scan
- Evidence: server/alembic/env.py:391 via agent-mcp-scan
- Evidence: server/app.py:543 via agent-mcp-scan
- Evidence: server/app.py:554 via agent-mcp-scan
- Evidence: server/app.py:600 via agent-mcp-scan
- Evidence: server/app.py:663 via agent-mcp-scan
- Evidence: server/clear_migration.py:136 via agent-mcp-scan
- Evidence: server/clear_migration.py:202 via agent-mcp-scan
- Evidence: server/clear_migration.py:212 via agent-mcp-scan
- Evidence: server/core/auth.py:46 via agent-mcp-scan
- Evidence: server/core/auth.py:51 via agent-mcp-scan
- Evidence: server/core/auth.py:66 via agent-mcp-scan
- Evidence: server/core/auth.py:83 via agent-mcp-scan
- Evidence: server/core/auth.py:103 via agent-mcp-scan
- Evidence: server/core/auth.py:106 via agent-mcp-scan
- Evidence: server/core/auth.py:123 via agent-mcp-scan
- Evidence: server/core/auth.py:132 via agent-mcp-scan
- Evidence: server/core/auth.py:146 via agent-mcp-scan
- Evidence: server/core/auth.py:153 via agent-mcp-scan
- Evidence: server/core/auth.py:167 via agent-mcp-scan
- Evidence: server/core/auth.py:180 via agent-mcp-scan
- Evidence: server/core/auth.py:213 via agent-mcp-scan
- Evidence: server/core/auth.py:233 via agent-mcp-scan
- Evidence: server/core/auth.py:254 via agent-mcp-scan
- Evidence: server/core/auth.py:269 via agent-mcp-scan
- Evidence: server/core/auth.py:281 via agent-mcp-scan
- Evidence: server/core/auto_migrate.py:42 via agent-mcp-scan
- Evidence: server/core/auto_migrate.py:59 via agent-mcp-scan
- Evidence: server/core/auto_migrate.py:109 via agent-mcp-scan
- Evidence: server/core/auto_migrate.py:452 via agent-mcp-scan
- Evidence: server/core/db_engine.py:47 via agent-mcp-scan
- Evidence: server/core/db_engine.py:48 via agent-mcp-scan
- Evidence: server/core/db_engine.py:49 via agent-mcp-scan
- Evidence: server/core/db_engine.py:50 via agent-mcp-scan
- Evidence: server/core/db_engine.py:51 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:121 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:126 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:145 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:176 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:217 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:220 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:249 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:287 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:320 via agent-mcp-scan
- Evidence: server/core/routes_feedback.py:349 via agent-mcp-scan
- Evidence: server/core/routes_tos.py:64 via agent-mcp-scan
- Evidence: server/core/routes_tos.py:83 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:119 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:129 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:140 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:176 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:177 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:194 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:204 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:205 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:206 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:212 via agent-mcp-scan
- Evidence: server/llm/agen_matchbox/manager.py:230 via agent-mcp-scan
- Evidence: server/mcp_server/spark_inspiration/server.py:111 via agent-mcp-scan
- Evidence: server/story/importer.py:91 via agent-mcp-scan
- Evidence: server/story/importer.py:92 via agent-mcp-scan
- Evidence: server/story/importer.py:93 via agent-mcp-scan
- Evidence: server/story/importer.py:94 via agent-mcp-scan
- Evidence: server/story/importer.py:96 via agent-mcp-scan
- Evidence: server/story/importer.py:153 via agent-mcp-scan
- Evidence: server/story/importer.py:169 via agent-mcp-scan
- Evidence: server/story/importer.py:192 via agent-mcp-scan
- Evidence: server/story/importer.py:213 via agent-mcp-scan
- Evidence: server/test/story_context/test_unity_runtime_export.py:80 via agent-mcp-scan
- Evidence: server/test/story_context/test_unity_runtime_export.py:86 via agent-mcp-scan
- Evidence: server/test/story_context/test_unity_runtime_export.py:90 via agent-mcp-scan

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_start" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_start" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:get_auto_write_state" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_stream" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_stream" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_pause" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:auto_write_acknowledge" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:get_characters" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:get_character_content" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:create_character" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:save_character" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:rename_character" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/characters.py:delete_character" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/characters.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/graphrag_routes.py:get_graphrag_status" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/graphrag_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/graphrag_routes.py:enable_graphrag" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/graphrag_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/graphrag_routes.py:disable_graphrag" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/graphrag_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/graphrag_routes.py:set_graphrag_defaults" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/graphrag_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:get_worldview" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:reset_lorebook" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:generate_worldview" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → agent.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:generate_worldview" flows through function calls to dangerous sink "agent.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:generate_worldview" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:get_lorebook_file" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/lorebook.py:save_lorebook_file" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/lorebook.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → muse.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/muse.py:muse_expand" flows through function calls to dangerous sink "muse.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/muse.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → muse.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/muse.py:muse_generate_and_save" flows through function calls to dangerous sink "muse.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/muse.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:get_outline" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:save_outline" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:get_outline_history" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:save_outline_history_endpoint" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:delete_outline_history" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:restore_outline_from_history" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/outline.py:export_outline_to_files" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/outline.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:run_critic_review" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:run_critic_review" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → agent.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:scriptwriter_compose_stream" flows through function calls to dangerous sink "agent.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:scriptwriter_compose_stream" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:scriptwriter_compose_stream" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/production.py:scriptwriter_feedback_stream" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/production.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/prompt_preferences.py:save_prompt_preferences" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/prompt_preferences.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:get_semantic_search_status" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:get_semantic_search_status" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:enable_semantic_search" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:disable_semantic_search" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:test_semantic_embedding" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:set_local_embedding" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/semantic_search_routes.py:set_semantic_search_defaults" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/semantic_search_routes.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → showrunner.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_synopsis_stream_ai" flows through function calls to dangerous sink "showrunner.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_synopsis_stream_ai" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_synopsis_stream_ai" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:get_synopsis" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:get_beat_sheet" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → showrunner.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_beat_sheet_stream_ai" flows through function calls to dangerous sink "showrunner.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_beat_sheet_stream_ai" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_beat_sheet_stream_ai" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → showrunner.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_outline_stream_ai" flows through function calls to dangerous sink "showrunner.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_outline_stream_ai" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/structure.py:generate_outline_stream_ai" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/structure.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:apply_style" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:apply_style" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:list_styles" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:list_styles" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:get_style_profile" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:get_style_profile" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:get_default_style" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:get_default_style" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:set_default_style" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/style.py:set_default_style" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/style.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → s.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:get_notice" flows through function calls to dangerous sink "s.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:get_notice" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:get_notice_history" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:create_new_notice" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:update_existing_notice" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → s.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:mark_notice_read" flows through function calls to dangerous sink "s.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/app.py:delete_existing_notice" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/app.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/auth.py:registration_verification_config" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/auth.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/auth.py:register" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/auth.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/auth.py:register" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/auth.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_admin_config.py:update_global_config" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_admin_config.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_admin_config.py:get_registration_verification" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_admin_config.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_admin_config.py:update_registration_verification" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_admin_config.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:get_my_feedbacks" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:mark_feedback_read" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:get_my_unread_count" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:get_all_feedbacks" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:update_feedback_status" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:reply_feedback" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:admin_mark_feedback_read" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_feedback.py:get_admin_unread_count" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_feedback.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_import.py:update_chunk_tokens_setting" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_import.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_import.py:parse_import_file" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_import.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tags.py:get_custom_tags" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tags.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tags.py:save_custom_tags" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tags.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tags.py:get_tags_catalog" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tags.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tags.py:set_project_story_tags_api" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tags.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tos.py:get_tos" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tos.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → s.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tos.py:accept_tos" flows through function calls to dangerous sink "s.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tos.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → s.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/core/routes_tos.py:check_tos_status" flows through function calls to dangerous sink "s.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/core/routes_tos.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:get_blueprint" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:save_blueprint" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:get_bindings" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:save_bindings" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:get_action_bindings" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:save_action_bindings" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:get_registries" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_blueprint.py:save_registries" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_blueprint.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:get_story_files" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:get_file_content" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:save_story" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:absorb_story_memory" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:create_file_or_folder" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:save_stories_order" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:export_to_sqlite" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:export_to_sqlite" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:export_and_download_sqlite" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:export_and_download_sqlite" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:get_novel_toc" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_files.py:export_novel_markdown" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_files.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_project.py:create_project" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_project.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_project.py:import_project" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_project.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_project.py:import_project" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_project.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_project.py:import_project" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_project.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_share.py:create_share" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_share.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_share.py:create_share" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_share.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_share.py:update_share" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_share.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_share.py:get_version_share_data" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_share.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:create_version" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:create_version" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:create_preview_version" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:create_preview_version" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:update_version" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/attachment/storage.py:save_attachment" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/attachment/storage.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/auto_write_service.py:start_auto_write_background" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/auto_write_service.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/auto_write_service.py:start_auto_write_background" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/auto_write_service.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:generate_script_stream" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → Path without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write.py:generate_script_stream" flows through function calls to dangerous sink "Path" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write_state.py:begin_auto_write_run" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write_state.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/routes/auto_write_state.py:build_auto_write_state_payload" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/routes/auto_write_state.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/tools/web_search.py:_mcp_post" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/tools/web_search.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/tools/web_search.py:_call_exa_web_search" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/tools/web_search.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/agents/tools/web_search.py:web_search" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/agents/tools/web_search.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.get without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/llm/agen_matchbox/manager.py:proxy_list_models" flows through function calls to dangerous sink "requests.get" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/llm/agen_matchbox/manager.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → requests.post without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/llm/agen_matchbox/utils.py:test_platform_chat" flows through function calls to dangerous sink "requests.post" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/llm/agen_matchbox/utils.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/novel_parser.py:get_novel_chapter_list" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/novel_parser.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/novel_parser.py:aggregate_novel" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/novel_parser.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/public_share_review.py:build_public_share_source_text" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/public_share_review.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/public_share_review.py:review_public_share" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/public_share_review.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/public_share_review.py:ensure_public_share_allowed" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/public_share_review.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → open without sanitization

Severity: high
Confidence: low
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:_create_snapshot_for_format" flows through function calls to dangerous sink "open" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-PY-007: Cross-function taint path: route handler → session.execute without sanitization

Severity: blocker
Confidence: high
Missing controls: crossFunctionTaintSanitization

Production consequence: User input from route handler "server/story/routes_version.py:_create_snapshot_for_format" flows through function calls to dangerous sink "session.execute" without passing through a sanitization function. This enables multi-step injection attacks where tainted data crosses function boundaries.

Acceptance criteria:
- Sanitize all user input before it reaches dangerous functions (execute, eval, os.system, etc.).
- Use a centralized input validation/sanitization layer at the route handler boundary.
- Prefer parameterized queries over string interpolation for database operations.
- Use subprocess with argument lists instead of shell strings.

- Evidence: server/story/routes_version.py via python-call-graph

### DK-CICD-001: Secrets in pipeline configuration

Severity: blocker
Confidence: medium
Missing controls: secretManagement

Production consequence: Hardcoded secrets in pipeline files are committed to version control, exposing credentials to anyone with repository access. Secret rotation requires code changes and risks accidental exposure in build logs.

Acceptance criteria:
- Secrets are stored in the CI platform's secret manager (GitHub Actions secrets, GitLab CI variables, etc.).
- Pipeline files reference secrets via environment variable bindings, not hardcoded values.
- Secret values are never committed to version control.

- Evidence: . via pattern-match

### DK-CICD-003: Artifact publishing without signing or provenance attestation

Severity: medium
Confidence: medium
Missing controls: artifactSigning

Production consequence: Published artifacts lack cryptographic signatures or provenance attestations. Downstream consumers cannot verify artifact integrity or origin, making supply-chain attacks undetectable.

Acceptance criteria:
- Published artifacts are signed with cosign, GPG, or an equivalent signing mechanism.
- Build provenance or SBOM is generated and attached to each release.
- Consumer-side verification is documented or enforced.

- Evidence: . via pattern-match

### DK-UNIVERSAL-001: Project type: CI/CD Pipeline — 5 production concerns to verify

Severity: advisory
Confidence: medium
Missing controls: secret masking, artifact integrity, pipeline as code review, runner security, deployment gate

Production consequence: As a ci/cd pipeline, this project has specific production readiness requirements beyond generic code quality checks.

Acceptance criteria:
- Verify: secret masking
- Verify: artifact integrity
- Verify: pipeline as code review
- Verify: runner security
- Verify: deployment gate

- Evidence: package.json via inventory

## Hardening Plan

Kill the demo by removing launch blockers first, then establish a production baseline, then improve operational confidence.

### Phase 0: Stop Launch

Fix these before real users or production traffic touch the system.

1. DK-TAINT-001
2. DK-AGENT-010
3. DK-AGENT-008
4. DK-PY-007
5. DK-CICD-001

### Phase 1: Production Baseline

Add the minimum controls needed for reproducible, diagnosable production operation.

1. DK-DOCKER-001
2. DK-AGENT-009
3. DK-PY-007

### Phase 2: Operational Confidence

Reduce residual operational risk after launch blockers and baseline gaps are closed.

1. DK-CICD-003
2. DK-UNIVERSAL-001

Recheck command:

`demokiller inspect . --markdown`
