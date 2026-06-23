import { describe, expect, it } from "vitest";
import { inspectRouteSource } from "../src/source-inspector.js";

describe("inspectRouteSource", () => {
  it("detects paid AI calls and missing controls", async () => {
    const evidence = await inspectRouteSource(
      "fixtures/next-ai-saas-risky",
      "app/api/chat/route.ts",
    );

    expect(evidence.capabilities).toContain("callsOpenAI");
    expect(evidence.capabilities).toContain("consumesRequestBody");
    expect(evidence.controls).not.toContain("auth");
    expect(evidence.controls).not.toContain("rateLimit");
    expect(evidence.controls).not.toContain("inputValidation");
    expect(evidence.controls).not.toContain("errorHandling");
    expect(evidence.envVars).toContain("OPENAI_API_KEY");
  });

  it("detects auth and rate limit in the partial fix", async () => {
    const evidence = await inspectRouteSource(
      "fixtures/next-ai-saas-partial-fix",
      "app/api/chat/route.ts",
    );

    expect(evidence.capabilities).toContain("callsOpenAI");
    expect(evidence.capabilities).toContain("consumesRequestBody");
    expect(evidence.controls).toEqual(expect.arrayContaining(["auth", "rateLimit"]));
  });

  it("detects admin data mutation and authorization", async () => {
    const evidence = await inspectRouteSource(
      "fixtures/next-ai-saas-partial-fix",
      "app/api/admin/users/route.ts",
    );

    expect(evidence.capabilities).toContain("mutatesDatabase");
    expect(evidence.capabilities).toContain("consumesRequestBody");
    expect(evidence.controls).toEqual(expect.arrayContaining(["auth", "authorization"]));
  });

  it("detects database reads", async () => {
    const evidence = await inspectRouteSource(
      "fixtures/next-ai-saas-risky",
      "app/api/admin/users/route.ts",
    );

    expect(evidence.capabilities).toContain("mutatesDatabase");
    expect(evidence.capabilities).toContain("consumesRequestBody");
  });

  it("detects webhook without signature verification", async () => {
    const evidence = await inspectRouteSource(
      "fixtures/next-ai-saas-risky",
      "app/api/stripe/webhook/route.ts",
    );

    expect(evidence.capabilities).toContain("handlesPaymentProvider");
    expect(evidence.capabilities).toContain("consumesRequestBody");
    expect(evidence.controls).toContain("logging");
    expect(evidence.controls).not.toContain("signatureVerification");
    expect(evidence.controls).not.toContain("idempotency");
    expect(evidence.controls).not.toContain("inputValidation");
    expect(evidence.controls).not.toContain("errorHandling");
  });
});
