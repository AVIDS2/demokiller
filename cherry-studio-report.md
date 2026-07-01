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

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: resources/skills/skill-creator/scripts/improve_description.py
Capability: Taint path: Environment variable → Python subprocess
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: resources/skills/skill-creator/scripts/improve_description.py:33 via call-graph-analysis

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: resources/skills/skill-creator/scripts/run_eval.py
Capability: Taint path: Environment variable → Python subprocess
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: resources/skills/skill-creator/scripts/run_eval.py:84 via call-graph-analysis

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: scripts/version.js
Capability: Taint path: CLI arguments flows through execSync → Command execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: scripts/version.js:10 via call-graph-analysis

### DK-TAINT-001: User input flows to command operation without sanitization

Severity: blocker
Confidence: high
Entry point: scripts/version.js
Capability: Taint path: CLI arguments flows through exec → Command execution
Asset: system integrity
Missing controls: taintSanitization

Production consequence: User-controlled data reaches command through the call chain. This enables injection attacks that pattern matching alone cannot detect.

Acceptance criteria:
- User input is validated before reaching dangerous operations.
- Dangerous operations use parameterized/safe APIs.
- Input is sanitized at the boundary, not at each sink.

- Evidence: scripts/version.js:10 via call-graph-analysis

### DK-DESK-002: Node integration enabled in renderer process

Severity: blocker
Confidence: high
Missing controls: contextIsolation, sandboxedRenderer

Production consequence: With nodeIntegration enabled or contextIsolation disabled, any XSS vulnerability in the renderer process grants the attacker full access to the Node.js runtime, including the filesystem, child processes, and network. This effectively gives remote code execution on the user's machine from a simple web content injection.

Acceptance criteria:
- nodeIntegration is set to false in all BrowserWindow configurations.
- contextIsolation is set to true (default since Electron 12).
- Communication between renderer and main process uses contextBridge with a minimal, typed API.
- Renderer process runs in a sandboxed environment with no direct Node.js access.

- Evidence: . via project-scan

### DK-AGENT-008: Secret or context leak in agent/tool responses

Severity: blocker
Confidence: medium
Missing controls: outputRedaction

Production consequence: API keys, tokens, database credentials, or internal context can leak through agent tool outputs, exposing sensitive infrastructure to end users or attackers.

Acceptance criteria:
- Sensitive values are redacted or omitted from tool outputs.
- Structured response schemas prevent accidental secret inclusion.
- Output scanning detects and blocks secret patterns before responses are sent.

- Evidence: electron.vite.config.ts:13 via agent-mcp-scan
- Evidence: src/main/ai/channels/security/__tests__/OutputSanitizer.test.ts:107 via agent-mcp-scan
- Evidence: src/main/core/preboot/userDataLocation.ts:67 via agent-mcp-scan
- Evidence: src/main/core/preboot/userDataLocation.ts:70 via agent-mcp-scan
- Evidence: src/main/core/preboot/userDataLocation.ts:160 via agent-mcp-scan
- Evidence: src/main/ipc/validateSender.ts:87 via agent-mcp-scan
- Evidence: src/main/services/AppUpdaterService.ts:373 via agent-mcp-scan
- Evidence: src/main/services/VersionService.ts:81 via agent-mcp-scan
- Evidence: src/renderer/pages/code/index.ts:195 via agent-mcp-scan

### DK-AGENT-009: Unbounded agent loop without iteration limit

Severity: high
Confidence: high
Missing controls: iterationLimit

Production consequence: An agent loop without a maximum iteration count can run indefinitely, consuming API credits, CPU, and memory until the process crashes or the budget is exhausted.

Acceptance criteria:
- Agent loops have an explicit maxIterations or maxSteps limit.
- A timeout is configured for the entire agent run.
- Recursive agent calls track depth and terminate at a configured maximum.

- Evidence: packages/aiCore/src/core/agents/__tests__/createAgent.test.ts:63 via agent-mcp-scan
- Evidence: packages/aiCore/src/core/agents/__tests__/createAgent.test.ts:92 via agent-mcp-scan
- Evidence: packages/aiCore/src/core/agents/__tests__/createAgent.test.ts:113 via agent-mcp-scan
- Evidence: packages/ui/scripts/pipeline.ts:83 via agent-mcp-scan
- Evidence: packages/ui/scripts/pipeline.ts:160 via agent-mcp-scan
- Evidence: packages/ui/src/components/composites/markdown/__tests__/utils/sanitize.test.ts:36 via agent-mcp-scan
- Evidence: packages/ui/src/components/composites/markdown/__tests__/utils/sanitize.test.ts:56 via agent-mcp-scan
- Evidence: packages/ui/src/components/composites/markdown/__tests__/utils/sanitize.test.ts:71 via agent-mcp-scan
- Evidence: packages/ui/src/components/composites/markdown/__tests__/utils/sanitize.test.ts:95 via agent-mcp-scan
- Evidence: packages/ui/src/components/composites/markdown/__tests__/utils/sanitize.test.ts:114 via agent-mcp-scan
- Evidence: scripts/auto-translate-i18n.ts:128 via agent-mcp-scan
- Evidence: src/main/ai/agents/agentTaskJobHandler.ts:62 via agent-mcp-scan
- Evidence: src/main/ai/agents/__tests__/agentTaskJobHandler.test.ts:114 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/browser/controller.ts:682 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/browser/tools/execute.ts:46 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/browser/tools/snapshot.ts:121 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/__tests__/browser.test.ts:131 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/__tests__/browser.test.ts:152 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/__tests__/browser.test.ts:160 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/__tests__/browser.test.ts:161 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/__tests__/workspaceMemory.test.ts:54 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/imageGenerationJobHandler.ts:41 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:124 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:141 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:157 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:170 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:188 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:209 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:222 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:228 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:234 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:244 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:250 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:256 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:271 via agent-mcp-scan
- Evidence: src/main/ai/provider/custom/tasks/__tests__/imageGenerationJobHandler.test.ts:278 via agent-mcp-scan
- Evidence: src/main/ai/provider/listModels.ts:2 via agent-mcp-scan
- Evidence: src/main/ai/runtime/aiSdk/Agent.ts:69 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/builtin/__tests__/KnowledgeListTool.test.ts:159 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/builtin/__tests__/KnowledgeSearchTool.test.ts:45 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/builtin/__tests__/WebSearchTool.test.ts:49 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/builtin/__tests__/WebSearchTool.test.ts:57 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/mcp/__tests__/mcpTools.execute.test.ts:81 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/mcp/__tests__/mcpTools.execute.test.ts:98 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/mcp/__tests__/mcpTools.execute.test.ts:112 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/exec/runtime.ts:156 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/toolInvoke.ts:100 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/__tests__/toolInspect.test.ts:27 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/__tests__/toolInvoke.test.ts:62 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/__tests__/toolInvoke.test.ts:248 via agent-mcp-scan
- Evidence: src/main/ai/tools/adapters/aiSdk/meta/__tests__/toolSearch.test.ts:29 via agent-mcp-scan
- Evidence: src/main/core/job/JobManager.ts:1102 via agent-mcp-scan
- Evidence: src/main/core/job/runtime/__tests__/catchUp.test.ts:37 via agent-mcp-scan
- Evidence: src/main/core/job/runtime/__tests__/catchUp.test.ts:49 via agent-mcp-scan
- Evidence: src/main/core/job/runtime/__tests__/recovery.test.ts:35 via agent-mcp-scan
- Evidence: src/main/core/job/types.ts:84 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.integration.test.ts:60 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.integration.test.ts:285 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.integration.test.ts:308 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.integration.test.ts:598 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.integration.test.ts:654 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.schedule.test.ts:49 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.smoke.test.ts:63 via agent-mcp-scan
- Evidence: src/main/core/job/__tests__/JobManager.smoke.test.ts:99 via agent-mcp-scan
- Evidence: src/main/core/logger/LoggerService.ts:328 via agent-mcp-scan
- Evidence: src/main/data/api/core/MiddlewareEngine.ts:62 via agent-mcp-scan
- Evidence: src/main/data/api/handlers/__tests__/temporaryChats.integration.test.ts:125 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:24 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:32 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:33 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:34 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:35 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:36 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:37 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:41 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:106 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:172 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/ftsRebuild.test.ts:207 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:36 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:41 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:52 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:57 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:62 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:74 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:77 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:80 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:91 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:136 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:144 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:150 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:152 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:156 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:186 via agent-mcp-scan
- Evidence: src/main/data/db/__tests__/pragmaReplay.test.ts:190 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationEngine.ts:222 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/AgentsMigrator.ts:100 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/AssistantMigrator.ts:218 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/BaseMigrator.ts:107 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/BootConfigMigrator.ts:126 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/ChatMigrator.ts:397 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/FileMigrator.ts:307 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeMigrator.ts:296 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeMigrator.ts:306 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeMigrator.ts:864 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:169 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:265 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:364 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:855 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:889 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:925 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:927 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:1004 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:1186 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/KnowledgeVectorMigrator.ts:1241 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/McpServerMigrator.ts:104 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/MiniAppMigrator.ts:176 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/NoteMigrator.ts:96 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/PaintingMigrator.ts:35 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/PaintingMigrator.ts:136 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/PreferencesMigrator.ts:207 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/PromptMigrator.ts:99 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/ProviderModelMigrator.ts:386 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/TranslateMigrator.ts:171 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:6 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:40 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:58 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:71 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:79 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:84 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:89 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:96 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:101 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:110 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:114 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:275 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:287 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:297 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.task.test.ts:302 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.test.ts:132 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.test.ts:148 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.test.ts:203 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AgentsMigrator.test.ts:361 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:437 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:471 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:490 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:537 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:581 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:594 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:605 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:649 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:717 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:741 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:773 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/AssistantMigrator.test.ts:868 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BaseMigrator.test.ts:25 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:101 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:119 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:136 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:150 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:165 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/BootConfigMigrator.test.ts:186 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:147 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:160 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:175 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:180 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:207 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:227 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:250 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:262 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:274 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:289 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:338 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:360 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:381 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:400 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:426 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:439 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:489 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:501 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:525 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:551 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:630 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:649 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:665 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:686 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:700 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:718 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:733 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/FileMigrator.test.ts:748 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileCopy.test.ts:130 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileCopy.test.ts:187 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileCopy.test.ts:223 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileCopy.test.ts:274 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:7 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:109 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:113 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:122 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:159 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:173 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:181 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:251 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:263 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:274 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:303 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:309 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:347 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:377 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:381 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:395 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:427 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:458 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:480 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileRefIntegration.test.ts:496 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:1873 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:1903 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:1955 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2019 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2069 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2104 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2160 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2229 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2386 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.test.ts:2433 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:123 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:135 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:151 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:153 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:157 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:159 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:164 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:167 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1083 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1224 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1305 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1306 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1317 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1319 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1386 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1390 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1465 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1474 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1476 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1531 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1568 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1569 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1617 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1719 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1768 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1807 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1860 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1897 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1945 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2012 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2056 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2105 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2153 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2244 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2293 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2297 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2351 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2435 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2489 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2542 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2589 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2635 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2691 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2766 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/McpServerMigrator.test.ts:167 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/McpServerMigrator.test.ts:175 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/McpServerMigrator.test.ts:183 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:117 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:137 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:231 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:300 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:321 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:346 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:372 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:395 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:425 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:447 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:461 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:494 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:521 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:44 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:67 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:94 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:120 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:121 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/NoteMigrator.test.ts:141 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:6 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:8 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:16 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:103 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:125 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:157 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:176 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:194 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:204 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:222 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:240 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PaintingMigrator.test.ts:256 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:84 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:93 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:103 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:113 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:129 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:153 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:176 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:211 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:236 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:250 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:267 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:284 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:304 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:324 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:335 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:350 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:373 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PreferencesMigrator.test.ts:409 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:169 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:185 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:214 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:244 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:259 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:276 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:305 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:333 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:354 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/PromptMigrator.test.ts:449 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:170 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:184 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:206 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:222 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:251 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:281 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:312 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:345 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:347 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:394 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:426 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:469 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:503 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:532 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:553 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:577 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:594 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:610 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:647 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/ProviderModelMigrator.test.ts:689 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/KnowledgeVectorSourceReader.ts:70 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/KnowledgeVectorSourceReader.ts:79 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/LegacyAgentsDbReader.ts:45 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/LegacyAgentsDbReader.ts:59 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/LegacyAgentsDbReader.ts:91 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:35 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:47 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:62 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:73 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:166 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/LegacyAgentsDbReader.test.ts:28 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/LegacyAgentsDbReader.test.ts:30 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/LegacyAgentsDbReader.test.ts:154 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/LegacyAgentsDbReader.test.ts:155 via agent-mcp-scan
- Evidence: src/main/data/services/utils/__tests__/keysetCursor.test.ts:131 via agent-mcp-scan
- Evidence: src/main/data/services/utils/__tests__/orderKey.test.ts:39 via agent-mcp-scan
- Evidence: src/main/data/services/utils/__tests__/orderKey.test.ts:42 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:303 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:317 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:324 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:513 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:517 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionMessageService.test.ts:527 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionService.test.ts:452 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AgentSessionService.test.ts:462 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AssistantService.test.ts:1236 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/AssistantService.test.ts:1247 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/KnowledgeBaseService.test.ts:478 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/MessageService.test.ts:515 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/MessageService.test.ts:519 via agent-mcp-scan
- Evidence: src/main/data/services/__tests__/MessageService.test.ts:529 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/ocrImageToText.ts:74 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/document-to-markdown/handler.ts:27 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/document-to-markdown/__tests__/handler.test.ts:59 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/document-to-markdown/__tests__/handler.test.ts:129 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/document-to-markdown/__tests__/handler.test.ts:153 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/image-to-text/handler.ts:18 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/mistral/utils.ts:38 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/open-mineru/document-to-markdown/handler.ts:17 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/image-to-text/handler.ts:11 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/paddleocr/image-to-text/handler.ts:20 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/paddleocr/__tests__/handler.test.ts:104 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/paddleocr/__tests__/handler.test.ts:122 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/paddleocr/__tests__/handler.test.ts:293 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/system/image-to-text/handler.ts:21 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/tesseract/image-to-text/handler.ts:14 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/types.ts:54 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/types.ts:91 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/backgroundJobHandler.ts:28 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/backgroundJobHandler.ts:30 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/remotePollJobHandler.ts:25 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/remotePollJobHandler.ts:40 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:5 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:160 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:172 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:196 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:200 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:209 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:222 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:230 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:238 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/backgroundJobHandler.test.ts:245 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:199 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:236 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:258 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:294 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:315 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:322 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:340 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/tasks/__tests__/remotePollJobHandler.test.ts:358 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/checkFileProcessingResultJobHandler.ts:46 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/deleteSubtreeJobHandler.ts:31 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/indexDocumentsJobHandler.ts:52 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/prepareRootJobHandler.ts:40 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/reindexSubtreeJobHandler.ts:48 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:83 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:100 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:134 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:158 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:181 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:201 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:228 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:252 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:270 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:292 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:304 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:316 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:327 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/checkFileProcessingResultJobHandler.test.ts:336 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:61 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:81 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:102 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:123 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:147 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:159 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/deleteSubtreeJobHandler.test.ts:172 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:49 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:71 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:99 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:120 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:137 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:156 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:165 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:182 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:199 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:211 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:221 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:236 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:262 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:279 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:298 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:312 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:327 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:346 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/indexDocumentsJobHandler.test.ts:363 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:28 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:43 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:58 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:78 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:93 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:106 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:123 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:149 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/prepareRootJobHandler.test.ts:172 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:42 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:64 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:84 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:103 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:128 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:160 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:189 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:212 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:241 via agent-mcp-scan
- Evidence: src/main/features/knowledge/tasks/__tests__/reindexSubtreeJobHandler.test.ts:279 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/indexMeta.ts:25 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/indexMeta.ts:31 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/indexMeta.ts:48 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/indexMeta.ts:52 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/indexMeta.ts:59 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:74 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:81 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:95 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:99 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:118 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:133 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:153 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:206 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:227 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:231 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:258 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:271 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:367 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:392 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:420 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:439 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/KnowledgeIndexStore.ts:455 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:58 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:69 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:71 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:88 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:108 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:112 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:115 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:119 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:137 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:153 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:155 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:162 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:163 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:171 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:212 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/LibsqlDriver.ts:222 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/schema.ts:220 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/schema.ts:255 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/types.ts:20 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/indexMeta.test.ts:34 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/indexMeta.test.ts:44 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/indexMeta.test.ts:47 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/indexMeta.test.ts:49 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/indexMeta.test.ts:84 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:53 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:57 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:69 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:89 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:115 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:324 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:355 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:488 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:489 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:490 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:491 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:492 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:504 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:516 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:530 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/KnowledgeIndexStore.test.ts:537 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:25 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:34 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:39 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:42 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:55 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:59 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:64 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:68 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:70 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:76 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:77 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:80 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:87 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:92 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:113 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:129 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:133 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:141 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:144 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:146 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:151 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:161 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:162 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:181 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:187 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:216 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:248 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:250 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:251 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:255 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlDriver.test.ts:260 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlVectorIndex.test.ts:29 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/LibsqlVectorIndex.test.ts:36 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:36 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:46 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:52 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:59 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:66 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:74 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:81 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:107 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:152 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:154 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:166 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:191 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:201 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:204 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:214 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:218 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:224 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:238 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:243 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:281 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:299 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:306 via agent-mcp-scan
- Evidence: src/main/features/knowledge/vectorstore/indexStore/__tests__/schema.test.ts:307 via agent-mcp-scan
- Evidence: src/main/ipc/handlers/webSearch.ts:14 via agent-mcp-scan
- Evidence: src/main/services/AppMenuService.ts:185 via agent-mcp-scan
- Evidence: src/main/services/AppUpdaterService.ts:55 via agent-mcp-scan
- Evidence: src/main/services/CommandService.ts:33 via agent-mcp-scan
- Evidence: src/main/services/CommandService.ts:61 via agent-mcp-scan
- Evidence: src/main/services/ShortcutService.ts:86 via agent-mcp-scan
- Evidence: src/main/services/StorageMonitorService.ts:66 via agent-mcp-scan
- Evidence: src/main/services/__tests__/CommandService.test.ts:101 via agent-mcp-scan
- Evidence: src/main/services/__tests__/CommandService.test.ts:110 via agent-mcp-scan
- Evidence: src/main/services/__tests__/CommandService.test.ts:118 via agent-mcp-scan
- Evidence: src/main/services/__tests__/CommandService.test.ts:126 via agent-mcp-scan
- Evidence: src/main/services/__tests__/CommandService.test.ts:135 via agent-mcp-scan
- Evidence: src/main/utils/remoteUrlSafety.ts:31 via agent-mcp-scan
- Evidence: src/preload/index.ts:146 via agent-mcp-scan
- Evidence: src/renderer/components/chat/actions/actionRegistry.ts:125 via agent-mcp-scan
- Evidence: src/renderer/components/chat/actions/__tests__/actionRegistry.test.ts:37 via agent-mcp-scan
- Evidence: src/renderer/components/chat/actions/__tests__/actionRegistry.test.ts:86 via agent-mcp-scan
- Evidence: src/renderer/components/chat/actions/__tests__/actionRegistry.test.ts:135 via agent-mcp-scan
- Evidence: src/renderer/components/chat/messages/blocks/MessagePartsRenderer.tsx:7 via agent-mcp-scan
- Evidence: src/renderer/components/chat/messages/blocks/MessagePartsRenderer.tsx:699 via agent-mcp-scan
- Evidence: src/renderer/components/chat/messages/frame/messageMenuBarActions.tsx:628 via agent-mcp-scan
- Evidence: src/renderer/components/command/CommandMenus.tsx:498 via agent-mcp-scan
- Evidence: src/renderer/components/command/CommandMenus.tsx:743 via agent-mcp-scan
- Evidence: src/renderer/components/command/CommandProvider.tsx:163 via agent-mcp-scan
- Evidence: src/renderer/components/command/__tests__/CommandProvider.test.tsx:46 via agent-mcp-scan
- Evidence: src/renderer/components/composer/variants/__tests__/AgentComposer.test.tsx:218 via agent-mcp-scan
- Evidence: src/renderer/data/hooks/__tests__/useDataApi.test.ts:517 via agent-mcp-scan
- Evidence: src/renderer/hooks/command/useResolvedCommand.ts:34 via agent-mcp-scan
- Evidence: src/renderer/hooks/useMiniApps.ts:75 via agent-mcp-scan
- Evidence: src/renderer/pages/agents/components/agentGroupActions.tsx:77 via agent-mcp-scan
- Evidence: src/renderer/pages/agents/components/sessionItemActions.tsx:118 via agent-mcp-scan
- Evidence: src/renderer/pages/agents/components/workdirGroupActions.tsx:88 via agent-mcp-scan
- Evidence: src/renderer/pages/agents/__tests__/AgentChatArtifactPane.test.tsx:362 via agent-mcp-scan
- Evidence: src/renderer/pages/agents/__tests__/AgentChatLocate.test.tsx:179 via agent-mcp-scan
- Evidence: src/renderer/pages/home/Tabs/components/assistantGroupActions.tsx:77 via agent-mcp-scan
- Evidence: src/renderer/pages/home/Tabs/components/topicContextMenuActions.tsx:417 via agent-mcp-scan
- Evidence: src/renderer/pages/settings/ChannelsSettings/ChannelForms.tsx:247 via agent-mcp-scan
- Evidence: src/renderer/pages/settings/McpSettings/builtinMcpServers.ts:6 via agent-mcp-scan
- Evidence: src/renderer/types/mcp.ts:68 via agent-mcp-scan
- Evidence: src/renderer/utils/command.ts:15 via agent-mcp-scan
- Evidence: src/shared/data/api/apiTypes.ts:350 via agent-mcp-scan
- Evidence: src/shared/data/migration/v2/types.ts:86 via agent-mcp-scan
- Evidence: src/shared/data/presets/miniApps.ts:5 via agent-mcp-scan
- Evidence: src/shared/data/presets/translateLanguages.ts:6 via agent-mcp-scan
- Evidence: src/shared/IpcChannel.ts:270 via agent-mcp-scan
- Evidence: tests/helpers/db/internal/truncate.ts:26 via agent-mcp-scan
- Evidence: tests/helpers/db/internal/truncate.ts:49 via agent-mcp-scan
- Evidence: tests/helpers/db/testDatabase.ts:101 via agent-mcp-scan
- Evidence: tests/helpers/db/testDatabase.ts:106 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:22 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:27 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:37 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:42 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:62 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:83 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:113 via agent-mcp-scan
- Evidence: tests/helpers/db/__tests__/testDatabase.test.ts:138 via agent-mcp-scan

### DK-AGENT-010: Unsafe filesystem tool without path sandboxing

Severity: blocker
Confidence: high
Missing controls: pathSandboxing

Production consequence: A filesystem tool that accepts arbitrary paths allows an agent or attacker to read, write, or delete any file on the host system, including credentials, configuration, and system files.

Acceptance criteria:
- File operations are restricted to an explicit allowlist of directories.
- Paths are resolved and validated with path.resolve + startsWith checks.
- Symlink traversal is prevented by using realpath before validation.

- Evidence: packages/ui/scripts/build-theme-css.ts:9 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:151 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:154 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:154 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:155 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:155 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:156 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:156 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:157 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:157 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:158 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:158 via agent-mcp-scan
- Evidence: packages/ui/scripts/build-theme-css.ts:173 via agent-mcp-scan
- Evidence: packages/ui/scripts/generate-icons.ts:467 via agent-mcp-scan
- Evidence: packages/ui/scripts/generate-icons.ts:477 via agent-mcp-scan
- Evidence: packages/ui/scripts/generate-icons.ts:483 via agent-mcp-scan
- Evidence: packages/ui/scripts/normalize-viewbox.ts:65 via agent-mcp-scan
- Evidence: packages/ui/scripts/pipeline.ts:98 via agent-mcp-scan
- Evidence: packages/ui/scripts/pipeline.ts:99 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:82 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:86 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:198 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:208 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:211 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:215 via agent-mcp-scan
- Evidence: packages/ui/scripts/vectorize-logo.ts:218 via agent-mcp-scan
- Evidence: resources/scripts/install-ovms.js:95 via agent-mcp-scan
- Evidence: resources/scripts/install-ovms.js:97 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:278 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:283 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:301 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:303 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:316 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:323 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:324 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:337 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:363 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:373 via agent-mcp-scan
- Evidence: scripts/download-binaries.js:374 via agent-mcp-scan
- Evidence: scripts/update-app-upgrade-config.ts:85 via agent-mcp-scan
- Evidence: scripts/update-app-upgrade-config.ts:86 via agent-mcp-scan
- Evidence: src/main/ai/agents/cherryclaw/prompt.ts:208 via agent-mcp-scan
- Evidence: src/main/ai/agents/cherryclaw/prompt.ts:252 via agent-mcp-scan
- Evidence: src/main/ai/agents/cherryclaw/seedWorkspace.ts:89 via agent-mcp-scan
- Evidence: src/main/ai/agents/cherryclaw/seedWorkspace.ts:92 via agent-mcp-scan
- Evidence: src/main/ai/agents/cherryclaw/seedWorkspace.ts:93 via agent-mcp-scan
- Evidence: src/main/ai/channels/adapters/wechat/WeChatProtocol.ts:1013 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:223 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:241 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:600 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:601 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:620 via agent-mcp-scan
- Evidence: src/main/ai/channels/ChannelMessageHandler.ts:621 via agent-mcp-scan
- Evidence: src/main/ai/mcp/McpPackageService.ts:584 via agent-mcp-scan
- Evidence: src/main/ai/mcp/McpPackageService.ts:626 via agent-mcp-scan
- Evidence: src/main/ai/mcp/McpPackageService.ts:632 via agent-mcp-scan
- Evidence: src/main/ai/mcp/McpRuntimeService.ts:557 via agent-mcp-scan
- Evidence: src/main/ai/mcp/McpRuntimeService.ts:1109 via agent-mcp-scan
- Evidence: src/main/ai/mcp/oauth/storage.ts:59 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/assistant.ts:751 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/tools/ls.ts:57 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:19 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:20 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:40 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:41 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:129 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:145 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:146 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:152 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:157 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:162 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:168 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:169 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:174 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:176 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:181 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:187 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:188 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:191 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:193 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:197 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:203 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:204 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/filesystem.test.ts:208 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/grep.test.ts:12 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/filesystem/__tests__/grep.test.ts:13 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/memory.ts:80 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/workspaceMemory.ts:171 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/workspaceMemory.ts:200 via agent-mcp-scan
- Evidence: src/main/ai/mcp/servers/workspaceMemory.ts:226 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:25 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:32 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:33 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:39 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:40 via agent-mcp-scan
- Evidence: src/main/ai/mcp/__tests__/McpPackageService.test.ts:272 via agent-mcp-scan
- Evidence: src/main/ai/observability/storage/TraceStorageService.ts:104 via agent-mcp-scan
- Evidence: src/main/ai/observability/storage/__tests__/TraceStorageService.test.ts:84 via agent-mcp-scan
- Evidence: src/main/ai/skills/SkillService.ts:577 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:215 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:217 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:217 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:218 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:218 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:219 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:219 via agent-mcp-scan
- Evidence: src/main/ai/skills/__tests__/SkillService.test.ts:220 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:33 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:36 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:40 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:58 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:64 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:65 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:71 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:76 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:79 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:80 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:86 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:87 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:90 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:91 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:94 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:95 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:96 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:98 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:101 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:104 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:110 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:113 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:114 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:115 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:116 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:117 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:118 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:119 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:120 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:123 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:124 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:125 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:128 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:131 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:134 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:137 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:140 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:141 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:142 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:143 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:144 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:148 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:151 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:154 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:156 via agent-mcp-scan
- Evidence: src/main/core/paths/pathRegistry.ts:157 via agent-mcp-scan
- Evidence: src/main/core/preboot/userDataLocation.ts:150 via agent-mcp-scan
- Evidence: src/main/data/api/handlers/__tests__/agentWorkspaces.integration.test.ts:34 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:5 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:119 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:165 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:169 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:170 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:172 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:173 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:174 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:175 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:178 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/MigrationPaths.ts:179 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/core/versionPolicy.ts:138 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/FileMigrator.ts:155 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/FileMigrator.ts:156 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/FileMigrator.ts:374 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeMigrator.fileCopy.test.ts:193 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1054 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1483 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1868 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:1970 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2176 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2358 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2550 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/KnowledgeVectorMigrator.test.ts:2698 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:199 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:200 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:201 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:202 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:203 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:227 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/migrators/__tests__/MiniAppMigrator.test.ts:236 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:30 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:31 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:41 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:50 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:52 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/DexieFileReader.ts:64 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:162 via agent-mcp-scan
- Evidence: src/main/data/migration/v2/utils/__tests__/KnowledgeVectorSourceReader.test.ts:163 via agent-mcp-scan
- Evidence: src/main/data/__tests__/CacheService.persist.test.ts:79 via agent-mcp-scan
- Evidence: src/main/data/__tests__/CacheService.persist.test.ts:80 via agent-mcp-scan
- Evidence: src/main/data/__tests__/CacheService.persist.test.ts:113 via agent-mcp-scan
- Evidence: src/main/data/__tests__/CacheService.persist.test.ts:188 via agent-mcp-scan
- Evidence: src/main/data/__tests__/CacheService.persist.test.ts:329 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/persistence/resultPersistence.ts:80 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/persistence/resultPersistence.ts:81 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/persistence/__tests__/resultPersistence.integration.test.ts:18 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/persistence/__tests__/resultPersistence.integration.test.ts:20 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/utils.ts:34 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/utils.ts:45 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/utils.ts:46 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/utils.ts:52 via agent-mcp-scan
- Evidence: src/main/features/fileProcessing/processors/ovocr/utils.ts:64 via agent-mcp-scan
- Evidence: src/main/ipc.ts:559 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:180 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:181 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:188 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:195 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:202 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:215 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:216 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:222 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:223 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:229 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:241 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:440 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:477 via agent-mcp-scan
- Evidence: src/main/services/BinaryManager.ts:490 via agent-mcp-scan
- Evidence: src/main/services/codeCli/CodeCliService.ts:1058 via agent-mcp-scan
- Evidence: src/main/services/CopilotService.ts:115 via agent-mcp-scan
- Evidence: src/main/services/file/internal/entry/rename.ts:47 via agent-mcp-scan
- Evidence: src/main/services/file/internal/entry/__tests__/create.test.ts:148 via agent-mcp-scan
- Evidence: src/main/services/file/internal/entry/__tests__/lifecycle.test.ts:147 via agent-mcp-scan
- Evidence: src/main/services/file/internal/__tests__/orphanSweep.test.ts:662 via agent-mcp-scan
- Evidence: src/main/services/file/internal/__tests__/orphanSweep.test.ts:785 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:126 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:127 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:128 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:129 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:130 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:131 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/builder.test.ts:132 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/DirectoryTreeManager.test.ts:267 via agent-mcp-scan
- Evidence: src/main/services/file/tree/__tests__/DirectoryTreeManager.test.ts:327 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.integration.test.ts:340 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.ipc-v2.test.ts:39 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.ipc-v2.test.ts:102 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.ipc-v2.test.ts:235 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.ipc-v2.test.ts:263 via agent-mcp-scan
- Evidence: src/main/services/file/__tests__/FileManager.ipc-v2.test.ts:276 via agent-mcp-scan
- Evidence: src/main/services/FileStorage.ts:748 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:101 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:102 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:103 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:106 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:107 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:108 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:200 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:201 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:208 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:209 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:226 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:227 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:241 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:241 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:321 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:322 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:338 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:338 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:477 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:587 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:588 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:589 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:593 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:691 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:692 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:695 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:764 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:926 via agent-mcp-scan
- Evidence: src/main/services/LegacyBackupManager.ts:1189 via agent-mcp-scan
- Evidence: src/main/services/OvmsManager.ts:284 via agent-mcp-scan
- Evidence: src/main/services/OvmsManager.ts:477 via agent-mcp-scan
- Evidence: src/main/services/protocol/ProtocolService.ts:178 via agent-mcp-scan
- Evidence: src/main/utils/file/__tests__/fs.test.ts:593 via agent-mcp-scan
- Evidence: src/main/utils/file/__tests__/fs.test.ts:618 via agent-mcp-scan
- Evidence: src/main/utils/file/__tests__/fs.test.ts:626 via agent-mcp-scan
- Evidence: src/main/utils/markdownParser.ts:170 via agent-mcp-scan
- Evidence: src/main/utils/process.ts:59 via agent-mcp-scan
- Evidence: src/main/utils/process.ts:76 via agent-mcp-scan
- Evidence: src/main/utils/process.ts:97 via agent-mcp-scan
- Evidence: src/renderer/utils/error.ts:240 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/DO-NOT-USE-extract-inventory.js:191 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:24 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:30 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:40 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:45 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:60 via agent-mcp-scan
- Evidence: v2-refactor-temp/tools/data-classify/scripts/lib/classificationUtils.js:66 via agent-mcp-scan

### DK-AGENT-006: Tool allowlist not enforced in MCP/agent server

Severity: blocker
Confidence: high
Missing controls: toolAllowlist

Production consequence: Without an explicit tool allowlist, any registered tool can be invoked by the agent or a malicious prompt, leading to unauthorized actions, data access, or system compromise.

Acceptance criteria:
- Tool calls are validated against an explicit allowlist before execution.
- Only pre-approved tools are registered with the MCP server.
- Runtime tool filtering rejects unknown or unauthorized tool names.

- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:29 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:47 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:48 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:67 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:68 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:69 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:93 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:107 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:194 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:195 via agent-mcp-scan
- Evidence: src/renderer/components/ActionTools/__tests__/useToolManager.test.ts:210 via agent-mcp-scan

### DK-AGENT-007: Prompt injection via unsanitized tool inputs

Severity: blocker
Confidence: medium
Missing controls: inputSanitization

Production consequence: User-supplied data is interpolated directly into LLM prompts, allowing attackers to inject instructions that override system behavior, extract secrets, or cause unintended agent actions.

Acceptance criteria:
- Tool inputs are validated and sanitized before inclusion in prompts.
- User input is passed as structured data, not interpolated into prompt templates.
- System prompts use message roles to separate instructions from user content.

- Evidence: src/renderer/components/composer/variants/agentComposerTokens.ts:20 via agent-mcp-scan
- Evidence: src/renderer/services/ErrorDiagnosisService.ts:221 via agent-mcp-scan

### DK-UNIVERSAL-001: Project type: Desktop Application — 6 production concerns to verify

Severity: advisory
Confidence: medium
Missing controls: auto-update mechanism, crash reporting, sandbox security, signed binaries, permission model, local data encryption

Production consequence: As a desktop application, this project has specific production readiness requirements beyond generic code quality checks.

Acceptance criteria:
- Verify: auto-update mechanism
- Verify: crash reporting
- Verify: sandbox security
- Verify: signed binaries
- Verify: permission model
- Verify: local data encryption

- Evidence: package.json via inventory

## Hardening Plan

Kill the demo by removing launch blockers first, then establish a production baseline, then improve operational confidence.

### Phase 0: Stop Launch

Fix these before real users or production traffic touch the system.

1. DK-TAINT-001
2. DK-DESK-002
3. DK-AGENT-008
4. DK-AGENT-010
5. DK-AGENT-006
6. DK-AGENT-007

### Phase 1: Production Baseline

Add the minimum controls needed for reproducible, diagnosable production operation.

1. DK-AGENT-009

### Phase 2: Operational Confidence

Reduce residual operational risk after launch blockers and baseline gaps are closed.

1. DK-UNIVERSAL-001

Recheck command:

`demokiller inspect . --markdown`
