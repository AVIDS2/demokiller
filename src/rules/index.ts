import { buildInventory, type ProjectInventory } from "../inventory.js";
import { inspectRouteSource } from "../source-inspector.js";
import { buildCallGraph } from "../call-graph.js";
import { analyzeTaint, findAuthGaps } from "../taint-analysis.js";
import type { Finding } from "../types.js";
// Agent rules
import { agentCodeExecRule } from "./agent-code-exec.js";
import { agentToolLimitRule } from "./agent-tool-limit.js";
import { authChainFindings } from "./auth-chain.js";
import { concurrencyRule, featureFlagRule, paymentIdempotencyRule, transactionSafetyRule } from "./business-logic.js";
import { contextLeakRule } from "./context-leak.js";
import { mcpServerAuthRule } from "./mcp-server-auth.js";
import { promptInjectionRule } from "./prompt-injection.js";
// Security rules
import { adminMutationAuthRule } from "./admin-mutation-auth.js";
import { commandInjectionRule } from "./command-injection.js";
import { connectionPoolingRule } from "./connection-pooling.js";
import { corsWildcardRule } from "./cors-wildcard.js";
import { cspMissingRule } from "./csp-missing.js";
import { hardcodedSecretRule } from "./hardcoded-secret.js";
import { httpsEnforcementRule } from "./https-enforcement.js";
import { insecureDeserializationRule } from "./insecure-deserialization.js";
import { pathTraversalRule } from "./path-traversal.js";
import { publicAiRouteRule } from "./public-ai-route.js";
import { requestTimeoutRule } from "./request-timeout.js";
import { sensitiveDataRule } from "./sensitive-data.js";
import { sqlInjectionRule } from "./sql-injection.js";
import { ssrfRule } from "./ssrf.js";
import { taintPathFindings } from "./taint-path.js";
import { webhookSafetyRule } from "./webhook-safety.js";
// Quality rules
import { debugLeakRule } from "./debug-leak.js";
import { errorLeakRule } from "./error-leak.js";
import { gracefulShutdownRule } from "./graceful-shutdown.js";
import { healthCheckRule } from "./health-check.js";
import { inputValidationRule } from "./input-validation.js";
import { logInjectionRule } from "./log-injection.js";
import { nPlusOneRule } from "./n-plus-one.js";
import { observabilityRule } from "./observability.js";
import { piiExposureRule } from "./pii-exposure.js";
// Project rules
import { cliToolFindings } from "./cli-tool.js";
import { depsVulnerabilityFindings } from "./deps-vulnerability.js";
import { dockerSecurityFindings } from "./docker-security.js";
import { envContractRule } from "./env-contract.js";
import { librarySdkFindings } from "./library-sdk.js";
import { migrationPostureRule } from "./migration-posture.js";
import { missingDocsRule } from "./missing-docs.js";
import { missingTestsRule } from "./missing-tests.js";
import { mqWorkerFindings } from "./mq-worker.js";
import { npmPublishRule } from "./npm-publish.js";
import { iacFindings } from "./iac.js";
import { paymentSystemFindings, authServiceFindings } from "./payment-auth.js";
import { cronJobFindings } from "./cron-job.js";
import { serverlessFuncFindings } from "./serverless-func.js";
import { desktopAppFindings } from "./desktop-app.js";
import { mobileAppFindings } from "./mobile-app.js";
import { agentMcpFindings } from "./agent-mcp.js";
import { pythonFindings } from "./python-taint.js";
import { gameFindings } from "./game.js";
import { mlPipelineFindings } from "./ml-pipeline.js";
import { browserExtensionFindings } from "./browser-extension.js";
import { idePluginFindings } from "./ide-plugin.js";
import { cicdPipelineFindings } from "./cicd-pipeline.js";
import { migrationToolFindings } from "./migration-tool.js";
import { apiGatewayFindings } from "./api-gateway.js";
import { wasmModuleFindings } from "./wasm-module.js";
import { blockchainFindings } from "./blockchain.js";
import { iotEmbeddedFindings } from "./iot-embedded.js";
import { devopsScriptFindings } from "./devops-script.js";
import { staticSiteFindings } from "./static-site.js";
import { cmsFindings } from "./cms.js";
import { monitoringToolFindings } from "./monitoring-tool.js";
import { tsStrictRule } from "./ts-strict.js";
import { projectTypeFindings } from "./universal-project.js";

async function readDeclaredEnvVars(root: string, envExamplePath?: string): Promise<string[]> {
  if (!envExamplePath) return [];
  const { promises: fs } = await import("node:fs");
  const path = await import("node:path");
  const text = await fs.readFile(path.join(root, envExamplePath), "utf8");
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#")).map((l) => l.replace(/^export\s+/, "").split("=", 1)[0]).filter((n) => n.length > 0);
}

export interface AnalysisResult {
  findings: Finding[];
  inventory: ProjectInventory;
}

export async function analyzeFindings(root: string): Promise<AnalysisResult> {
  const inventory = await buildInventory(root);
  const rawEvidence = await Promise.all(inventory.apiRoutes.map((r) => inspectRouteSource(root, r)));
  // Thread projectKind to route-based rules for type-scoped filtering
  const projectKind = inventory.projectKind || "unknown";
  const routeEvidence = rawEvidence.map(e => ({ ...e, projectKind }));
  const usedEnvVars = Array.from(new Set(routeEvidence.flatMap((r) => r.envVars)));
  const declaredEnvVars = await readDeclaredEnvVars(root, inventory.envExamplePath);

  // Phase 1: Call graph analysis
  const callGraph = await buildCallGraph(root);
  const taintPaths = analyzeTaint(callGraph);
  const authGaps = findAuthGaps(callGraph, inventory.apiRoutes);

  const findings = [
    // Pattern-based rules (original)
    ...routeEvidence.flatMap(r => { try { return publicAiRouteRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return adminMutationAuthRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return webhookSafetyRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return observabilityRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return corsWildcardRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return debugLeakRule(r); } catch { return []; } }),
    // Pattern-based security rules
    ...routeEvidence.flatMap(r => { try { return ssrfRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return commandInjectionRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return hardcodedSecretRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return sqlInjectionRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return pathTraversalRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return insecureDeserializationRule(r); } catch { return []; } }),
    // Pattern-based quality rules
    ...routeEvidence.flatMap(r => { try { return inputValidationRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return errorLeakRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return logInjectionRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return sensitiveDataRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return cspMissingRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return httpsEnforcementRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return nPlusOneRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return piiExposureRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return paymentIdempotencyRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return transactionSafetyRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return concurrencyRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return featureFlagRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return requestTimeoutRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return connectionPoolingRule(r); } catch { return []; } }),
    // Agent rules
    ...routeEvidence.flatMap(r => { try { return agentCodeExecRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return mcpServerAuthRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return agentToolLimitRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return promptInjectionRule(r); } catch { return []; } }),
    ...routeEvidence.flatMap(r => { try { return contextLeakRule(r); } catch { return []; } }),
    // Call graph analysis rules (cross-file, data flow)
    ...(function () { try { return taintPathFindings(taintPaths); } catch { return []; } })(),
    ...(function () { try { return authChainFindings(authGaps); } catch { return []; } })(),
    // Project-level rules
    ...(function () { try { return envContractRule(inventory, usedEnvVars, declaredEnvVars); } catch { return []; } })(),
    ...(function () { try { return migrationPostureRule(inventory); } catch { return []; } })(),
    ...(await depsVulnerabilityFindings(inventory).catch(() => [] as Finding[])),
    ...(await dockerSecurityFindings(inventory).catch(() => [] as Finding[])),
    ...(function () { try { return missingTestsRule(inventory); } catch { return []; } })(),
    ...(function () { try { return tsStrictRule(inventory); } catch { return []; } })(),
    ...(function () { try { return missingDocsRule(inventory); } catch { return []; } })(),
    ...(function () { try { return npmPublishRule(inventory); } catch { return []; } })(),
    ...(await librarySdkFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await cliToolFindings(inventory).catch(() => [] as Finding[])),
    ...(await mqWorkerFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await iacFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await paymentSystemFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await authServiceFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await cronJobFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await serverlessFuncFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await desktopAppFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await mobileAppFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await agentMcpFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await pythonFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await gameFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await mlPipelineFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await browserExtensionFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await idePluginFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await cicdPipelineFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await migrationToolFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await apiGatewayFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await wasmModuleFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await blockchainFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await iotEmbeddedFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await devopsScriptFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await staticSiteFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await cmsFindings(root, inventory).catch(() => [] as Finding[])),
    ...(await monitoringToolFindings(root, inventory).catch(() => [] as Finding[])),
    ...(function () { try { return projectTypeFindings(inventory); } catch { return []; } })(),
    ...(await gracefulShutdownRule(inventory).catch(() => [] as Finding[])),
    ...(await healthCheckRule(inventory).catch(() => [] as Finding[])),
  ];

  return { findings, inventory };
}
