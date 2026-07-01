import { describe, expect, it } from "vitest";
import {
  TaintState,
  TAINT_SOURCES,
  TAINT_SINKS,
  TAINT_SANITIZERS,
  isSanitized,
} from "../src/taint-analysis.js";
import type { CallSite } from "../src/call-graph.js";

// ─── Helper to create mock call sites ───────────────────────────

function mockCall(
  caller: string,
  callee: string,
  file: string,
  line: number,
): CallSite {
  return { caller, callee, file, line, argCount: 1 };
}

// ─── TaintState unit tests ──────────────────────────────────────

describe("TaintState", () => {
  it("marks and checks basic taint", () => {
    const state = new TaintState(3);
    const source = TAINT_SOURCES.find((s) => s.pattern === "req.body")!;
    state.markTainted("userInput", source, 1, 0);

    expect(state.isTainted("userInput")).toBe(true);
    expect(state.isTainted("cleanVar")).toBe(false);
  });

  it("propagates through direct alias chain (depth 3)", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "a", source: "req.body.name", file: "test.ts", line: 1 },
      { name: "b", source: "a", file: "test.ts", line: 2 },
      { name: "c", source: "b", file: "test.ts", line: 3 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("a")).toBe(true);
    expect(state.isTainted("b")).toBe(true);
    expect(state.isTainted("c")).toBe(true);
    expect(state.taintDepth.get("c")).toBe(2);
  });

  it("respects maxDepth limit (depth 3 stops at hop 3)", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "a", source: "req.body.x", file: "test.ts", line: 1 },
      { name: "b", source: "a", file: "test.ts", line: 2 },
      { name: "c", source: "b", file: "test.ts", line: 3 },
      { name: "d", source: "c", file: "test.ts", line: 4 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("a")).toBe(true); // depth 0
    expect(state.isTainted("b")).toBe(true); // depth 1
    expect(state.isTainted("c")).toBe(true); // depth 2
    // d would be depth 3 which equals maxDepth, so markTainted rejects it
    expect(state.isTainted("d")).toBe(false);
  });

  it("propagates through object property access", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "user", source: "req.body", file: "test.ts", line: 1 },
      { name: "name", source: "user.name", file: "test.ts", line: 2 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("user")).toBe(true);
    expect(state.isTainted("name")).toBe(true);
  });

  it("propagates through array indexing", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "items", source: "req.body.items", file: "test.ts", line: 1 },
      { name: "first", source: "items[0]", file: "test.ts", line: 2 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("items")).toBe(true);
    expect(state.isTainted("first")).toBe(true);
  });

  it("propagates through method calls on tainted objects", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "a", source: "req.body.name", file: "test.ts", line: 1 },
      { name: "b", source: "a.toUpperCase()", file: "test.ts", line: 2 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("a")).toBe(true);
    expect(state.isTainted("b")).toBe(true);
  });

  it("propagates through template literals", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "name", source: "req.body.name", file: "test.ts", line: 1 },
      {
        name: "greeting",
        source: "`Hello ${name}, welcome!`",
        file: "test.ts",
        line: 2,
      },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("name")).toBe(true);
    expect(state.isTainted("greeting")).toBe(true);
  });

  it("propagates through string concatenation", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "input", source: "req.body.x", file: "test.ts", line: 1 },
      {
        name: "query",
        source: '"SELECT * FROM users WHERE id=" + input',
        file: "test.ts",
        line: 2,
      },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("input")).toBe(true);
    expect(state.isTainted("query")).toBe(true);
  });

  it("handles destructuring from tainted objects", () => {
    const state = new TaintState(3);
    // First seed the taint
    const source = TAINT_SOURCES.find((s) => s.pattern === "req.body")!;
    state.markTainted("reqBody", source, 1, 0);

    // Scan destructuring lines
    const lines = [
      "const reqBody = req.body;",
      "const { name, email } = reqBody;",
    ];
    state.scanDestructuring(lines);

    expect(state.isTainted("name")).toBe(true);
    expect(state.isTainted("email")).toBe(true);
  });

  it("does not taint variables beyond maxDepth", () => {
    const state = new TaintState(1); // depth 1 only
    const assignments = [
      { name: "a", source: "req.body.x", file: "test.ts", line: 1 },
      { name: "b", source: "a", file: "test.ts", line: 2 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("a")).toBe(true); // depth 0
    expect(state.isTainted("b")).toBe(false); // depth 1 == maxDepth, rejected
  });
});

// ─── Sanitizer tests ────────────────────────────────────────────

describe("sanitizer awareness", () => {
  it("detects sanitizer in nearby calls", () => {
    const calls: CallSite[] = [
      mockCall("handler", "req.body", "app.ts", 5),
      mockCall("handler", "escapeHtml", "app.ts", 6),
      mockCall("handler", "res.json", "app.ts", 7),
    ];

    expect(isSanitized("req.body", 5, calls)).toBe(true);
  });

  it("does not flag sanitizer far away from sink", () => {
    const calls: CallSite[] = [
      mockCall("handler", "req.body", "app.ts", 5),
      mockCall("handler", "parseInt", "app.ts", 100),
      mockCall("handler", "res.json", "app.ts", 7),
    ];

    // parseInt at line 100 is > 2 away from req.body at line 5
    expect(isSanitized("req.body", 5, calls)).toBe(false);
  });
});

// ─── Source/Sink pattern tests ──────────────────────────────────

describe("taint sources and sinks", () => {
  it("recognizes all standard source patterns", () => {
    const patterns = TAINT_SOURCES.map((s) => s.pattern);
    expect(patterns).toContain("req.body");
    expect(patterns).toContain("req.params");
    expect(patterns).toContain("req.query");
    expect(patterns).toContain("process.env");
    expect(patterns).toContain("os.environ");
  });

  it("recognizes all standard sink patterns", () => {
    const patterns = TAINT_SINKS.map((s) => s.pattern);
    expect(patterns).toContain("eval");
    expect(patterns).toContain("exec");
    expect(patterns).toContain("query");
    expect(patterns).toContain("readFile");
    expect(patterns).toContain("res.json");
  });

  it("recognizes sanitizer patterns", () => {
    const patterns = TAINT_SANITIZERS.map((s) => s.pattern);
    expect(patterns).toContain("parseInt");
    expect(patterns).toContain("escapeHtml");
    expect(patterns).toContain("sanitize");
    expect(patterns).toContain(".parse(");
  });
});

// ─── Multi-hop integration scenarios ────────────────────────────

describe("multi-hop taint scenarios", () => {
  it("scenario: 3-hop alias chain to eval", () => {
    const state = new TaintState(3);
    const assignments = [
      {
        name: "a",
        source: "req.body.name",
        file: "server.ts",
        line: 10,
      },
      { name: "b", source: "a", file: "server.ts", line: 11 },
      { name: "c", source: "b.toUpperCase()", file: "server.ts", line: 12 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    // c is tainted via: a(source) -> b -> c (method call), depth 2
    expect(state.isTainted("c")).toBe(true);
    expect(state.taintDepth.get("c")).toBe(2);
  });

  it("scenario: object property chain to SQL sink", () => {
    const state = new TaintState(3);
    const assignments = [
      {
        name: "user",
        source: "req.body",
        file: "service.ts",
        line: 5,
      },
      {
        name: "userId",
        source: "user.id",
        file: "service.ts",
        line: 6,
      },
      {
        name: "query",
        source: '"SELECT * FROM users WHERE id=" + userId',
        file: "service.ts",
        line: 7,
      },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("user")).toBe(true);
    expect(state.isTainted("userId")).toBe(true);
    expect(state.isTainted("query")).toBe(true);
  });

  it("scenario: array element extraction to response", () => {
    const state = new TaintState(3);
    const assignments = [
      {
        name: "data",
        source: "req.body.items",
        file: "handler.ts",
        line: 3,
      },
      {
        name: "first",
        source: "data[0]",
        file: "handler.ts",
        line: 4,
      },
      {
        name: "result",
        source: "first.toUpperCase()",
        file: "handler.ts",
        line: 5,
      },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("data")).toBe(true);
    expect(state.isTainted("first")).toBe(true);
    expect(state.isTainted("result")).toBe(true);
  });

  it("scenario: taint stops at type-conversion sanitizer", () => {
    // parseInt breaks the taint chain
    const calls: CallSite[] = [
      mockCall("handler", "req.query", "app.ts", 5),
      mockCall("handler", "parseInt", "app.ts", 6),
      mockCall("handler", "res.json", "app.ts", 8),
    ];

    // parseInt at line 6 is between req.query (5) and res.json (8)
    const intervening = calls.filter(
      (c) => c.line > 5 && c.line < 8,
    );
    const hasSanitizer = intervening.some((c) =>
      TAINT_SANITIZERS.some((s) => c.callee.includes(s.pattern)),
    );

    expect(hasSanitizer).toBe(true);
  });

  it("scenario: 3-hop chain does NOT taint beyond depth 3", () => {
    const state = new TaintState(3);
    const assignments = [
      { name: "a", source: "req.body.x", file: "f.ts", line: 1 },
      { name: "b", source: "a", file: "f.ts", line: 2 },
      { name: "c", source: "b", file: "f.ts", line: 3 },
      { name: "d", source: "c", file: "f.ts", line: 4 },
      { name: "e", source: "d", file: "f.ts", line: 5 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("a")).toBe(true); // depth 0
    expect(state.isTainted("b")).toBe(true); // depth 1
    expect(state.isTainted("c")).toBe(true); // depth 2
    expect(state.isTainted("d")).toBe(false); // depth 3 == maxDepth
    expect(state.isTainted("e")).toBe(false);
  });

  it("scenario: mixed object + alias chain within depth 3", () => {
    const state = new TaintState(3);
    const assignments = [
      {
        name: "body",
        source: "req.body",
        file: "handler.ts",
        line: 1,
      },
      {
        name: "name",
        source: "body.name",
        file: "handler.ts",
        line: 2,
      },
      { name: "upper", source: "name.toUpperCase()", file: "handler.ts", line: 3 },
    ];
    const sources = assignments.filter((a) =>
      TAINT_SOURCES.some((s) => a.source.includes(s.pattern)),
    );

    state.propagate(assignments, sources);

    expect(state.isTainted("body")).toBe(true); // depth 0
    expect(state.isTainted("name")).toBe(true); // depth 1 (object property)
    expect(state.isTainted("upper")).toBe(true); // depth 2 (method call)
  });
});
