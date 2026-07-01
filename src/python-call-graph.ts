import { promises as fs } from "node:fs";
import path from "node:path";

// ─── Types ──────────────────────────────────────────────────────

export interface PythonFuncDef {
  name: string;
  file: string;
  line: number;
  params: string[];
  rawParams: string;   // full parameter text for pattern matching (e.g. Depends(get_current_user))
  decorators: string[];
  bodyRange: { startRow: number; endRow: number };
}

export interface PythonCallSite {
  caller: string;      // "file.py:funcName"
  callee: string;      // e.g. "cursor.execute" or "subprocess.call"
  file: string;
  line: number;
  argCount: number;
}

export interface PythonImportInfo {
  file: string;
  imported: string;     // local name
  source: string;       // module specifier
  resolved?: string;
}

export interface PythonRoute {
  method: string;       // GET, POST, PUT, DELETE, PATCH
  path: string;         // e.g. "/api/chat"
  handler: string;      // function name
  file: string;
  line: number;
  decorators: string[];
}

export interface PythonCallGraph {
  functions: Map<string, PythonFuncDef>;
  calls: PythonCallSite[];
  imports: PythonImportInfo[];
  routes: PythonRoute[];
  fileIndex: Map<string, string>;
}

// ─── Tree-sitter singleton (WASM-based, matching source-inspector.ts) ─

let parser: any = null;
let ParserLib: any = null;
let pythonLang: any = null;

const WASM_DIR = "node_modules/tree-sitter-wasms/out";

async function getParser(): Promise<any> {
  if (parser) return parser;
  const mod = await import("web-tree-sitter");
  ParserLib = mod.Parser ? mod : mod.default ?? mod;
  await ParserLib.Parser.init();
  parser = new ParserLib.Parser();
  return parser;
}

async function getPythonLanguage(): Promise<any> {
  if (pythonLang) return pythonLang;
  const p = await getParser();
  const wasmPath = path.join(WASM_DIR, "tree-sitter-python.wasm");
  pythonLang = await ParserLib.Language.load(wasmPath);
  p.setLanguage(pythonLang);
  return pythonLang;
}

// ─── AST node helpers ───────────────────────────────────────────

interface TSNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number;
  child(index: number): TSNode | null;
  children: TSNode[];
  namedChildren: TSNode[];
  parent: TSNode | null;
  fieldNameForChild(index: number): string | null;
  descendantsOfType(type: string | string[]): TSNode[];
}

function getChildByFieldName(node: TSNode, name: string): TSNode | null {
  for (let i = 0; i < node.childCount; i++) {
    if (node.fieldNameForChild(i) === name) {
      return node.child(i);
    }
  }
  return null;
}

function getTextOfNode(node: TSNode): string {
  return node.text;
}

// ─── File walking ───────────────────────────────────────────────

async function walkPythonFiles(root: string, dir = root): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const result: string[] = [];
  const skip = new Set(["node_modules", ".next", "dist", "build", "__pycache__", ".venv", "venv", ".git", "vendor", "third_party", "fixtures", "testdata", "samples", "test", "tests", "__tests__", "spec", "specs", "example", "examples", "demo", "demos", "bench", "benchmark", "benchmarks", "docs", "doc", ".worktrees", ".demokiller", ".claude"]);
  const SKIP_FILE_RE = /[._](?:test|spec|e2e)\.[^.]+$/i;

  for (const entry of entries) {
    if (skip.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...(await walkPythonFiles(root, fullPath)));
    } else if (entry.name.endsWith(".py") && !SKIP_FILE_RE.test(entry.name)) {
      result.push(path.relative(root, fullPath).replaceAll("\\", "/"));
    }
  }
  return result;
}

// ─── AST extraction ─────────────────────────────────────────────

function extractFunctions(rootNode: TSNode, file: string): PythonFuncDef[] {
  const funcs: PythonFuncDef[] = [];
  const funcDefs = rootNode.descendantsOfType("function_definition") ?? [];

  for (const node of funcDefs) {
    const nameNode = getChildByFieldName(node, "name");
    if (!nameNode) continue;

    const paramsNode = getChildByFieldName(node, "parameters");
    const params: string[] = [];
    let rawParams = "";
    if (paramsNode) {
      rawParams = paramsNode.text;
      for (const child of paramsNode.namedChildren) {
        if (child.type === "identifier") {
          params.push(child.text);
        } else if (child.type === "typed_parameter" || child.type === "default_parameter") {
          // Extract the identifier child
          for (const sub of child.namedChildren) {
            if (sub.type === "identifier") {
              params.push(sub.text);
              break;
            }
          }
        }
      }
    }

    // Get decorators
    const decorators: string[] = [];
    const parent = node.parent;
    if (parent && parent.type === "decorated_definition") {
      const decNodes = parent.descendantsOfType("decorator") ?? [];
      for (const dec of decNodes) {
        decorators.push(dec.text.replace(/^@/, "").trim());
      }
    }

    funcs.push({
      name: nameNode.text,
      file,
      line: node.startPosition.row + 1,
      params,
      rawParams,
      decorators,
      bodyRange: {
        startRow: node.startPosition.row,
        endRow: node.endPosition.row,
      },
    });
  }

  return funcs;
}

function extractCalls(rootNode: TSNode, file: string, funcs: PythonFuncDef[]): PythonCallSite[] {
  const calls: PythonCallSite[] = [];
  const callNodes = rootNode.descendantsOfType("call") ?? [];

  for (const callNode of callNodes) {
    const funcNode = getChildByFieldName(callNode, "function");
    if (!funcNode) continue;

    const callee = getTextOfNode(funcNode);
    const line = callNode.startPosition.row + 1;

    // Skip keywords
    if (/^(if|for|while|return|import|from|class|def|with|as|in|not|and|or|is|lambda|yield|assert|del|global|nonlocal|pass|break|continue|raise|try|except|finally|else|elif)$/.test(callee)) continue;

    // Count arguments
    const argsNode = getChildByFieldName(callNode, "arguments");
    let argCount = 0;
    if (argsNode) {
      argCount = argsNode.namedChildren.filter(
        (c: TSNode) => c.type !== "comment"
      ).length;
      if (argCount === 0 && argsNode.text !== "()") argCount = 1;
    }

    // Determine which function this call is inside
    let caller = "<module>";
    for (const func of funcs) {
      if (line > func.bodyRange.startRow && line <= func.bodyRange.endRow) {
        caller = func.name;
        break;
      }
    }

    calls.push({ caller: `${file}:${caller}`, callee, file, line, argCount });
  }

  return calls;
}

function extractImports(rootNode: TSNode, file: string): PythonImportInfo[] {
  const imports: PythonImportInfo[] = [];

  // import X, import X.Y.Z
  const importStmts = rootNode.descendantsOfType("import_statement") ?? [];
  for (const stmt of importStmts) {
    const dottedNames = stmt.descendantsOfType("dotted_name") ?? [];
    const aliased = stmt.descendantsOfType("aliased_import") ?? [];

    if (aliased.length > 0) {
      for (const a of aliased) {
        const nameNode = a.namedChildren.find((c: TSNode) => c.type === "dotted_name" || c.type === "identifier");
        const aliasNode = a.namedChildren.find((c: TSNode) => c.type === "identifier" && c !== nameNode);
        imports.push({
          file,
          imported: aliasNode ? aliasNode.text : (nameNode?.text ?? ""),
          source: nameNode?.text ?? "",
        });
      }
    } else {
      for (const d of dottedNames) {
        imports.push({ file, imported: d.text, source: d.text });
      }
    }
  }

  // from X import Y, from X.Y import Z
  const fromStmts = rootNode.descendantsOfType("import_from_statement") ?? [];
  for (const stmt of fromStmts) {
    const moduleNode = stmt.namedChildren.find((c: TSNode) => c.type === "dotted_name" || c.type === "relative_import");
    const source = moduleNode?.text ?? "";

    const names = stmt.namedChildren.filter(
      (c: TSNode) => c.type === "dotted_name" && c !== moduleNode || c.type === "aliased_import" || c.type === "identifier"
    );

    for (const nameNode of names) {
      if (nameNode.type === "aliased_import") {
        const original = nameNode.namedChildren.find((c: TSNode) => c.type === "dotted_name" || c.type === "identifier");
        const alias = nameNode.namedChildren.filter((c: TSNode) => c.type === "identifier").pop();
        imports.push({
          file,
          imported: alias ? alias.text : (original?.text ?? ""),
          source,
        });
      } else if (nameNode.type === "dotted_name" || nameNode.type === "identifier") {
        // Skip the module node itself
        if (nameNode === moduleNode) continue;
        if (nameNode.text === "import") continue;
        imports.push({ file, imported: nameNode.text, source });
      }
    }
  }

  return imports;
}

function extractRoutes(rootNode: TSNode, file: string, funcs: PythonFuncDef[]): PythonRoute[] {
  const routes: PythonRoute[] = [];

  for (const func of funcs) {
    for (const dec of func.decorators) {
      // Match @app.get("/path"), @router.post("/path"), etc.
      const routeMatch = dec.match(/(\w+)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"]([^'"]+)['"]/i);
      if (routeMatch) {
        routes.push({
          method: routeMatch[2].toUpperCase(),
          path: routeMatch[3],
          handler: func.name,
          file,
          line: func.line,
          decorators: func.decorators,
        });
      }

      // Django patterns: @api_view(["GET", "POST"]), @csrf_exempt
      const djangoViewMatch = dec.match(/api_view\s*\(\s*\[([^\]]+)\]/);
      if (djangoViewMatch) {
        const methods = djangoViewMatch[1].match(/['"](GET|POST|PUT|DELETE|PATCH)['"]/g) ?? [];
        for (const m of methods) {
          routes.push({
            method: m.replace(/['"]/g, ""),
            path: `/${func.name}`,
            handler: func.name,
            file,
            line: func.line,
            decorators: func.decorators,
          });
        }
      }
    }
  }

  return routes;
}

// ─── Import resolution (for Python module paths) ───────────────

function buildFileIndex(files: string[]): Map<string, string> {
  const index = new Map<string, string>();
  for (const file of files) {
    const noExt = file.replace(/\.py$/, "");
    index.set(noExt, file);
    const base = path.basename(file, ".py");
    index.set(base, file);
    // __init__.py → directory name
    if (base === "__init__") {
      const dir = path.dirname(file);
      index.set(dir, file);
    }
  }
  return index;
}

function resolvePythonImport(source: string, currentFile: string, fileIndex: Map<string, string>): string | undefined {
  // Absolute imports
  if (fileIndex.has(source)) return fileIndex.get(source);

  // Relative to current file's directory
  const currentDir = path.dirname(currentFile);
  const relPath = path.join(currentDir, source).replaceAll("\\", "/");
  if (fileIndex.has(relPath)) return fileIndex.get(relPath);

  // Try package __init__
  const initPath = path.join(relPath, "__init__").replaceAll("\\", "/");
  if (fileIndex.has(initPath)) return fileIndex.get(initPath);

  return undefined;
}

// ─── Public API ─────────────────────────────────────────────────

export async function buildPythonCallGraph(root: string): Promise<PythonCallGraph> {
  const files = await walkPythonFiles(root);
  const fileIndex = buildFileIndex(files);
  const functions = new Map<string, PythonFuncDef>();
  const allCalls: PythonCallSite[] = [];
  const allImports: PythonImportInfo[] = [];
  const allRoutes: PythonRoute[] = [];

  const p = await getParser();
  await getPythonLanguage();

  for (const file of files) {
    let text: string;
    try {
      text = await fs.readFile(path.join(root, file), "utf8");
    } catch {
      continue;
    }

    let tree: any;
    try {
      tree = p.parse(text);
    } catch {
      continue;
    }

    const rootNode = tree.rootNode as unknown as TSNode;

    // Extract functions
    const funcs = extractFunctions(rootNode, file);
    for (const func of funcs) {
      const qualified = `${file}:${func.name}`;
      functions.set(qualified, func);
    }

    // Extract calls
    const calls = extractCalls(rootNode, file, funcs);
    allCalls.push(...calls);

    // Extract imports
    const imports = extractImports(rootNode, file);
    for (const imp of imports) {
      imp.resolved = resolvePythonImport(imp.source, file, fileIndex);
      allImports.push(imp);
    }

    // Extract routes
    const routes = extractRoutes(rootNode, file, funcs);
    allRoutes.push(...routes);
  }

  return { functions, calls: allCalls, imports: allImports, routes: allRoutes, fileIndex };
}
