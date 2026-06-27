import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function gameFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "game") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-GAME-001: Unprotected asset integrity
  const assetPattern = /(?:fetch|loadTexture|loadAsset|loadImage|loadAudio)\s*\([^)]*https?:\/\/[^)]+\)/gi;
  const integrityPattern = /(?:hash|integrity|checksum|verify|sri)/i;
  const assetMatches = allContent.match(assetPattern) || [];
  if (assetMatches.length > 0 && !integrityPattern.test(allContent)) {
    findings.push({
      ruleId: "DK-GAME-001",
      title: "Unprotected asset integrity",
      severity: "high",
      confidence: "medium",
      missingControls: ["hash", "integrity", "checksum", "verify"],
      consequence: "Remote assets could be tampered with in transit, leading to malicious code injection or asset substitution",
      acceptanceCriteria: [
        "All remote assets must include integrity verification (SRI hash, checksum, or signature validation)",
        "Asset loading pipeline should reject assets that fail integrity checks"
      ],
      evidence: [{
        id: "DK-GAME-001-1",
        detector: "pattern-match",
        location: { path: files[0] || "unknown" },
        controls: [],
        signals: assetMatches.slice(0, 3).map(m => m.trim())
      }]
    });
  }

  // DK-GAME-002: Unbounded game loop
  const gameLoopPattern = /(?:setInterval|requestAnimationFrame)\s*\(\s*(?:update|gameLoop|tick|render|draw|animate)/i;
  const loopControlPattern = /(?:deltaTime|frameSkip|maxFPS|tickRate|fps\s*cap|frame\s*limit)/i;
  const loopMatches = allContent.match(new RegExp(gameLoopPattern.source, "gi")) || [];
  if (loopMatches.length > 0 && !loopControlPattern.test(allContent)) {
    findings.push({
      ruleId: "DK-GAME-002",
      title: "Unbounded game loop",
      severity: "medium",
      confidence: "medium",
      missingControls: ["deltaTime", "frameSkip", "maxFPS", "tickRate"],
      consequence: "Game loop runs without frame rate control, causing inconsistent behavior across devices and excessive CPU/GPU usage",
      acceptanceCriteria: [
        "Game loop must use deltaTime-based movement for frame-rate independence",
        "Frame rate should be capped to prevent excessive resource consumption on high-refresh displays"
      ],
      evidence: [{
        id: "DK-GAME-002-1",
        detector: "pattern-match",
        location: { path: files[0] || "unknown" },
        controls: [],
        signals: loopMatches.slice(0, 3).map(m => m.trim())
      }]
    });
  }

  // DK-GAME-003: Client-side game state
  const statePatterns = [
    /(?:player|character|entity|sprite)\s*\.\s*(?:health|lives|mana)\s*[=:+]/i,
    /(?:player|game|match)\s*\.\s*score\s*[=:+]/i,
    /(?:player|character)\s*\.\s*inventory\s*[=:+]/i,
    /currency\s*[=:+]/i,
  ];
  const serverValidationPattern = /(?:server.*valid|authoritative|anti.?cheat|server.*sync|server.*state)/i;
  const stateMatches: string[] = [];
  for (const pat of statePatterns) {
    const globalPat = new RegExp(pat.source, "gi");
    const m = allContent.match(globalPat);
    if (m) stateMatches.push(...m);
  }
  if (stateMatches.length > 0 && !serverValidationPattern.test(allContent)) {
    findings.push({
      ruleId: "DK-GAME-003",
      title: "Client-side game state",
      severity: "high",
      confidence: "medium",
      missingControls: ["server validation", "authoritative server", "anti-cheat", "server sync"],
      consequence: "Game state is managed client-side without server-side validation, making it trivially exploitable through memory editing or dev tools",
      acceptanceCriteria: [
        "Critical game state (score, health, currency) must be validated server-side",
        "Server must be authoritative over game state changes",
        "Client-side state changes should be treated as input requests, not truth"
      ],
      evidence: [{
        id: "DK-GAME-003-1",
        detector: "pattern-match",
        location: { path: files[0] || "unknown" },
        controls: [],
        signals: stateMatches.slice(0, 5).map(m => m.trim())
      }]
    });
  }

  // DK-GAME-004: Unauthenticated WebSocket
  const wsPattern = /(?:new\s+WebSocket|socket\.io|wss?:\/\/|\.connect\s*\()/gi;
  const authPattern = /(?:auth|token|jwt|session|handshake.*auth|middleware.*auth)/i;
  const wsMatches = allContent.match(wsPattern) || [];
  if (wsMatches.length > 0 && !authPattern.test(allContent)) {
    findings.push({
      ruleId: "DK-GAME-004",
      title: "Unauthenticated WebSocket",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["auth", "token", "jwt", "session"],
      consequence: "WebSocket connections are accepted without authentication, allowing unauthorized users to connect and send arbitrary game commands",
      acceptanceCriteria: [
        "WebSocket connections must require authentication before accepting game commands",
        "Connection handshake must validate a token, JWT, or session credential",
        "Unauthenticated connections must be rejected immediately"
      ],
      evidence: [{
        id: "DK-GAME-004-1",
        detector: "pattern-match",
        location: { path: files[0] || "unknown" },
        controls: [],
        signals: wsMatches.slice(0, 3).map(m => m.trim())
      }]
    });
  }

  return findings;
}
