import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

export async function systemsCFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"]);
  if (files.length === 0) return [];

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    fileContents.set(file, await readFileContent(root, file));
  }

  function evidence(hits: Map<string, string[]>, ruleId: string) {
    return [...hits.entries()].map(([file, signals]) => ({
      id: `${ruleId}-${file}`,
      detector: "pattern-match",
      location: { path: file },
      controls: [],
      signals
    }));
  }

  // DK-C-001: Buffer overflow via unsafe string functions
  const unsafeStrFn = /\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(/g;
  const scanfNoWidth = /scanf\s*\(\s*"%\*?s"/g;
  const unsafeStrFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const fnMatches = content.match(unsafeStrFn) ?? [];
    const scanfMatches = content.match(scanfNoWidth) ?? [];
    const all = [...fnMatches, ...scanfMatches];
    if (all.length > 0) unsafeStrFiles.set(file, all);
  }
  if (unsafeStrFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-001",
      title: "Buffer overflow risk via unsafe string functions",
      severity: "blocker",
      confidence: "high",
      missingControls: ["boundedStringOperations"],
      consequence: "Functions like strcpy, strcat, sprintf, and gets perform no bounds checking. A single unbounded copy can overwrite adjacent memory, enabling arbitrary code execution or crashes.",
      acceptanceCriteria: [
        "Replace strcpy with strncpy/strlcpy and always NUL-terminate.",
        "Replace sprintf with snprintf and pass the destination buffer size.",
        "Never use gets — use fgets with an explicit size limit.",
        "Replace scanf %s with %Ns where N is the buffer size minus one.",
      ],
      evidence: evidence(unsafeStrFiles, "c-001"),
    });
  }

  // DK-C-002: Use-after-free — free(p); ... use p without NULL assignment in between
  // Check per occurrence: each free(p) followed by p-> before p = NULL
  const uafFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const uafHits: string[] = [];
    const freeThenUse = /\bfree\s*\(\s*(\w+)\s*\)\s*;([^}]{0,200}?)\b\1\s*->/gs;
    for (const m of content.matchAll(freeThenUse)) {
      const ptrName = m[1];
      const between = m[2];
      // If there's a NULL assignment between free and use, this specific occurrence is safe
      if (new RegExp(`${ptrName}\\s*=\\s*(?:NULL|nullptr|0)\\s*;`).test(between)) continue;
      uafHits.push(`free(${ptrName}) then ${ptrName}-> without NULL guard`);
    }
    if (uafHits.length > 0) uafFiles.set(file, uafHits);
  }
  if (uafFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-002",
      title: "Use-after-free: pointer used after free without NULL assignment",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["useAfterFreePrevention"],
      consequence: "Accessing memory after it has been freed leads to undefined behavior, potential code execution, or data corruption. Use-after-free is one of the most exploited vulnerability classes in C/C++.",
      acceptanceCriteria: [
        "Set pointer to NULL immediately after free(): free(p); p = NULL;",
        "Use smart pointers (unique_ptr, shared_ptr) in C++ to manage lifetimes.",
        "Run AddressSanitizer (ASan) in CI to catch UAF at runtime.",
      ],
      evidence: evidence(uafFiles, "c-002"),
    });
  }

  // DK-C-003: Memory leak — malloc/calloc/realloc with 0 frees in file
  const allocPattern = /\b(malloc|calloc|realloc)\s*\(/g;
  const freePattern = /\bfree\s*\(/g;
  const leakFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (/\b(unique_ptr|shared_ptr|make_unique|make_shared)\b/.test(content)) continue;
    const allocCount = (content.match(allocPattern) ?? []).length;
    const freeCount = (content.match(freePattern) ?? []).length;
    if (allocCount > 0 && freeCount === 0) {
      leakFiles.set(file, [`${allocCount} allocation(s), 0 free(s)`]);
    }
  }
  if (leakFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-003",
      title: "Potential memory leak: allocations without any frees",
      severity: "high",
      confidence: "low",
      missingControls: ["memoryLeakPrevention"],
      consequence: "Memory that is allocated but never freed causes memory leaks. In long-running processes, this leads to resource exhaustion, performance degradation, and eventual crash.",
      acceptanceCriteria: [
        "Every malloc/calloc/realloc must have a corresponding free on all exit paths.",
        "Use RAII wrappers or smart pointers in C++ to automate deallocation.",
        "Run Valgrind or LeakSanitizer in CI to detect leaks.",
      ],
      evidence: evidence(leakFiles, "c-003"),
    });
  }

  // DK-C-004: Race condition — threads with global/extern vars but no sync primitives
  const mutexPattern = /\b(pthread_mutex|std::mutex|std::lock_guard|std::unique_lock|spinlock|std::atomic|critical_section|CRITICAL_SECTION|InterlockedExchange)\b/;
  const threadPattern = /\b(pthread_create|std::thread|CreateThread|_beginthreadex)\b/;
  // extern declarations are a reliable signal of shared mutable state
  const externPattern = /^extern\s+(?!const\b)(?:volatile\s+)?(?:int|char|bool|long|short|unsigned|float|double|void|struct|enum|size_t|uint\d+_t|int\d+_t)\s+\w+/gm;
  const raceFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (!threadPattern.test(content)) continue;
    if (mutexPattern.test(content)) continue;
    const externVars = content.match(externPattern) ?? [];
    if (externVars.length > 0) {
      raceFiles.set(file, [`${externVars.length} extern mutable variable(s) with threads but no synchronization`]);
    }
  }
  if (raceFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-004",
      title: "Race condition: shared mutable state without synchronization",
      severity: "high",
      confidence: "low",
      missingControls: ["concurrencyControl"],
      consequence: "Multiple threads accessing shared mutable state without synchronization leads to data races, corrupted state, crashes, and exploitable security vulnerabilities.",
      acceptanceCriteria: [
        "Protect shared mutable state with mutexes, locks, or atomic operations.",
        "Prefer thread-local storage or message passing over shared state.",
        "Run ThreadSanitizer (TSan) in CI to detect data races.",
      ],
      evidence: evidence(raceFiles, "c-004"),
    });
  }

  // DK-C-005: Integer overflow in size calculation before allocation
  const overflowGuard = /\b(__builtin_mul_overflow|__builtin_add_overflow|safe_mul|safe_add|checked_mul|checked_add|OVERFLOW_CHECK)\b/;
  const sizeArithmetic = /\b(size_t|uint32_t|uint64_t|unsigned)\s+\w+\s*=.*[+\*]/g;
  const overflowFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (overflowGuard.test(content)) continue;
    const hasMalloc = /\bmalloc\s*\(/.test(content);
    const hasSizeCalc = (content.match(sizeArithmetic) ?? []).length > 0;
    if (hasMalloc && hasSizeCalc) {
      overflowFiles.set(file, ["size arithmetic before allocation without overflow guard"]);
    }
  }
  if (overflowFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-005",
      title: "Integer overflow in size calculation before allocation",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["integerOverflowPrevention"],
      consequence: "When size calculations overflow before being passed to malloc, a tiny buffer is allocated but a large amount of data is written into it, causing a heap buffer overflow.",
      acceptanceCriteria: [
        "Check for multiplication/addition overflow before passing sizes to allocation functions.",
        "Use __builtin_mul_overflow or equivalent safe math intrinsics.",
        "Validate that element_count * element_size does not wrap before calling malloc.",
      ],
      evidence: evidence(overflowFiles, "c-005"),
    });
  }

  // DK-C-006: Format string vulnerability — per-occurrence check
  // Flag printf(variable) but not printf("literal", ...)
  const fmtUnsafe = /\b(printf|fprintf|dprintf|syslog)\s*\(\s*([a-zA-Z_]\w*)\s*\)/g;
  const fmtStrFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const hits: string[] = [];
    for (const m of content.matchAll(fmtUnsafe)) {
      const varName = m[2];
      // Skip common false positives: stderr, stdout, etc.
      if (["stderr", "stdout", "stdin", "buf", "msg"].includes(varName)) continue;
      hits.push(`${m[1]}(${varName}) — variable used as format string`);
    }
    if (hits.length > 0) fmtStrFiles.set(file, hits.slice(0, 10));
  }
  if (fmtStrFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-006",
      title: "Format string vulnerability: variable used as format string",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["formatStringSafety"],
      consequence: "Passing a user-controlled string as the format argument to printf-family functions allows an attacker to read/write arbitrary memory via format specifiers (%x, %n, etc.).",
      acceptanceCriteria: [
        "Always use a literal format string: printf(\"%s\", var), never printf(var).",
        "Enable -Wformat-security compiler warning and treat warnings as errors.",
        "Audit all syslog/printf-family calls for format string issues.",
      ],
      evidence: evidence(fmtStrFiles, "c-006"),
    });
  }

  // DK-C-007: Double free — per-occurrence: free(p); ... free(p) without p=NULL in between
  const doubleFreeFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const hits: string[] = [];
    const dblPattern = /\bfree\s*\(\s*(\w+)\s*\)\s*;([^}]{0,200}?)\bfree\s*\(\s*\1\s*\)/gs;
    for (const m of content.matchAll(dblPattern)) {
      const ptrName = m[1];
      const between = m[2];
      if (new RegExp(`${ptrName}\\s*=\\s*(?:NULL|nullptr|0)\\s*;`).test(between)) continue;
      hits.push(`double free(${ptrName}) without NULL guard between`);
    }
    if (hits.length > 0) doubleFreeFiles.set(file, hits);
  }
  if (doubleFreeFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-007",
      title: "Double free: memory freed twice without NULL guard",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["doubleFreePrevention"],
      consequence: "Freeing the same memory twice corrupts the heap allocator metadata, leading to arbitrary code execution or crashes. This is a classic exploit primitive.",
      acceptanceCriteria: [
        "Set pointer to NULL after free: free(p); p = NULL;",
        "Check for NULL before free: if (p) { free(p); p = NULL; }",
        "Use smart pointers in C++ to avoid manual free entirely.",
      ],
      evidence: evidence(doubleFreeFiles, "c-007"),
    });
  }

  // DK-C-008: Unchecked return value from allocation or file open
  const uncheckedFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const hits: string[] = [];
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const assignMatch = line.match(/(\w+)\s*=\s*(malloc|calloc|realloc|fopen|tmpfile)\s*\(/);
      if (!assignMatch) continue;
      const varName = assignMatch[1];
      // Look ahead up to 5 lines for a NULL check on this variable
      const ahead = lines.slice(i + 1, i + 6).join("\n");
      if (!new RegExp(`if\\s*\\(\\s*(!\\s*${varName}\\b|${varName}\\s*(?:==|!=)\\s*(?:NULL|nullptr|0))\\b`).test(ahead)) {
        hits.push(`line ${i + 1}: ${varName} = ${assignMatch[2]}(...) without NULL check`);
      }
    }
    if (hits.length > 0) uncheckedFiles.set(file, hits);
  }
  if (uncheckedFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-008",
      title: "Unchecked return value from allocation or file operation",
      severity: "high",
      confidence: "medium",
      missingControls: ["returnValueChecking"],
      consequence: "When malloc/fopen returns NULL and the code proceeds to use the result, it dereferences a null pointer, causing a crash or potentially exploitable behavior.",
      acceptanceCriteria: [
        "Always check the return value of malloc/calloc/realloc for NULL.",
        "Always check the return value of fopen for NULL before use.",
        "Implement consistent error-handling with goto-cleanup or early return patterns.",
      ],
      evidence: evidence(uncheckedFiles, "c-008"),
    });
  }

  // DK-C-009: system()/popen() with dynamically constructed command string
  const cmdFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    const hits: string[] = [];
    // Pattern: system(variable) or system(strcat(...) / sprintf(...) then system(var))
    const systemWithVar = /\b(system|popen)\s*\(\s*([a-zA-Z_]\w*)\s*[,\)]/g;
    for (const m of content.matchAll(systemWithVar)) {
      const fn = m[1];
      const arg = m[2];
      // Check if the argument is a variable that was built dynamically
      const builtPattern = new RegExp(`(?:sprintf|snprintf|strcat|strncat|strcpy|strncpy|memcpy)\\s*\\(\\s*${arg}\\b`);
      if (builtPattern.test(content)) {
        hits.push(`${fn}(${arg}) — argument built via string manipulation`);
      }
    }
    // Also flag system() with inline string concatenation
    const systemConcat = /\b(system|popen)\s*\(\s*[^)]*\+\s*\w/g;
    for (const m of content.matchAll(systemConcat)) {
      hits.push(`${m[1]}() with string concatenation`);
    }
    if (hits.length > 0) cmdFiles.set(file, hits);
  }
  if (cmdFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-009",
      title: "Command injection via system()/popen() with dynamic string",
      severity: "blocker",
      confidence: "high",
      missingControls: ["commandInjectionPrevention"],
      consequence: "Passing dynamically constructed strings to system() or popen() allows arbitrary command execution. An attacker who controls any part of the command string can inject shell commands.",
      acceptanceCriteria: [
        "Never use system() or popen() with dynamically constructed strings.",
        "Use execv-family functions with explicit argument arrays instead.",
        "If a shell is required, sanitize all inputs with a whitelist approach.",
      ],
      evidence: evidence(cmdFiles, "c-009"),
    });
  }

  // DK-C-010: Stack buffer with external input — potential stack overflow
  const stackBufPattern = /\b(char|uint8_t|int8_t|unsigned\s+char)\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;/g;
  const externalInputPattern = /\b(read|recv|recvfrom|recvmsg|fread|fgets|getline|scanf)\s*\(/;
  const stackOverflowFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (!externalInputPattern.test(content)) continue;
    const bufMatches = [...content.matchAll(stackBufPattern)];
    const smallBufs = bufMatches.filter(m => {
      const size = parseInt(m[3], 10);
      return size > 0 && size < 1024;
    });
    if (smallBufs.length > 0) {
      stackOverflowFiles.set(file, smallBufs.map(m => m[0].slice(0, 60)));
    }
  }
  if (stackOverflowFiles.size > 0) {
    findings.push({
      ruleId: "DK-C-010",
      title: "Stack buffer with external input: potential stack overflow",
      severity: "high",
      confidence: "low",
      missingControls: ["stackBufferProtection"],
      consequence: "Small fixed-size stack buffers filled by external input (read/recv/fgets) without strict bounds enforcement can overflow, overwriting return addresses or saved registers.",
      acceptanceCriteria: [
        "Always pass the buffer size to input functions: fgets(buf, sizeof(buf), stdin).",
        "Validate input length before copying into fixed-size buffers.",
        "Enable stack canaries (-fstack-protector-strong) and ASLR in production builds.",
      ],
      evidence: evidence(stackOverflowFiles, "c-010"),
    });
  }

  return findings;
}
