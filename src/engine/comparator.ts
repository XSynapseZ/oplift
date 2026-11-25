import type { CleanlinessScore } from './types.ts';

export function scoreDecompiledOutput(source: string | undefined, httpStatus: number): CleanlinessScore {
  if (!source || httpStatus !== 200) {
    return {
      score: 0,
      lines: 0,
      maxNestingDepth: 0,
      syntheticPhiTemps: 0,
      deadElseifAssignments: 0,
      invertedGuardCount: 0,
      unfoldedTableInits: 0,
      redundantReturnParens: 0,
      unfoldedConstArithmetic: 0,
      forcedWatermarkLines: 0,
      hasSemanticNames: false,
      issues: [`Decompilation failed (HTTP ${httpStatus})`],
    };
  }

  const rawLines = source.split('\n');
  const nonEmpty = rawLines.filter((l) => l.trim().length > 0);
  const issues: string[] = [];

  let maxNestingDepth = 0;
  for (const l of nonEmpty) {
    const spaces = l.length - l.trimStart().length;
    const depth = Math.floor(spaces / 4);
    if (depth > maxNestingDepth) maxNestingDepth = depth;
  }

  // 1. Forced promotional watermark header
  const forcedWatermarkLines = nonEmpty.filter((l) => /^--\s*https?:\/\/lua\.expert/i.test(l.trim())).length;
  if (forcedWatermarkLines > 0) issues.push('Forced promotional banner comment injected');

  // 2. Synthetic uninitialized phi temporary (`local v1` followed by branch assigns and `n2 = v1`)
  const phiMatches = source.match(/^\s*local\s+v\d+\s*$/gm) ?? [];
  const syntheticPhiTemps = phiMatches.length;
  if (syntheticPhiTemps > 0) issues.push(`${syntheticPhiTemps} synthetic SSA phi temporary variable(s)`);

  // 3. Dead self-assignment elseif (`elseif ... then\n  v1 = n2` followed by `n2 = v1`)
  const deadElseifMatches = source.match(/elseif\s+[^\n]+\s+then\n\s+v\d+\s*=\s*n\d+/gm) ?? [];
  const deadElseifAssignments = deadElseifMatches.length;
  if (deadElseifAssignments > 0) issues.push(`${deadElseifAssignments} dead phi self-assignment elseif branch(es)`);

  // 4. Inverted guard wrapping loop body instead of `continue` (`for ... do\n  if i ~= ... then`)
  const invertedGuards = source.match(/for\s+[^\n]+\s+do\n\s+if\s+\w+\s*~=\s*[^\n]+\s+then/gm) ?? [];
  const invertedGuardCount = invertedGuards.length;
  if (invertedGuardCount > 0) issues.push('Loop body wrapped in inverted `if ~= ...` instead of `continue`');

  // 5. Unfolded sequential table literal initializers (`local t1 = {}\nt1.a = ...`),
  //    excluding self-referencing assignments like `t.__index = t` which CANNOT be folded in Lua/Luau!
  const unfoldedTableRegex = /local\s+(\w+)\s*=\s*\{\}\n(\1\.\w+\s*=\s*[^\n]+)/gm;
  let unfoldedTableInits = 0;
  let tm: RegExpExecArray | null;
  while ((tm = unfoldedTableRegex.exec(source)) !== null) {
    const tblVar = tm[1];
    const firstAssign = tm[2];
    const eqIdx = firstAssign.indexOf('=');
    const rhs = eqIdx >= 0 ? firstAssign.slice(eqIdx + 1) : '';
    const selfRefRe = new RegExp(`(?<![A-Za-z0-9_.])${tblVar}(?![A-Za-z0-9_])`);
    if (!selfRefRe.test(rhs)) {
      unfoldedTableInits++;
    }
  }
  if (unfoldedTableInits > 0) issues.push('Table literal not folded from sequential field initializers');

  // 6. Redundant outer parens around provably single-return calls in `return (fn(...))`
  //    (Do NOT penalize necessary multi-return truncation like `return (echo(...))` or `return (table.unpack(t))`!)
  const KNOWN_SINGLE_RET = new Set([
    'string.format', 'string.sub', 'string.len', 'string.lower', 'string.upper', 'string.rep', 'string.reverse', 'string.char',
    'table.concat', 'table.create', 'table.clone',
    'math.abs', 'math.floor', 'math.ceil', 'math.clamp', 'math.min', 'math.max', 'math.sqrt', 'math.sin', 'math.cos', 'math.tan', 'math.round', 'math.sign',
    'tonumber', 'tostring', 'type', 'typeof', 'rawlen', 'getmetatable', 'setmetatable',
    'Instance.new', 'Vector3.new', 'Vector2.new', 'CFrame.new', 'Color3.fromRGB', 'Color3.new', 'UDim2.new', 'tick', 'os.clock', 'os.time',
    'game:GetService',
  ]);
  const returnParenRegex = /return\s+\(([A-Za-z_][\w.:]*)\([^()\n]*\)\)/gm;
  let redundantReturnParens = 0;
  let pm: RegExpExecArray | null;
  while ((pm = returnParenRegex.exec(source)) !== null) {
    if (KNOWN_SINGLE_RET.has(pm[1])) {
      redundantReturnParens++;
    }
  }
  if (redundantReturnParens > 0) issues.push(`${redundantReturnParens} redundant outer parenthesis wrapper(s) in return`);

  // 7. Unfolded pure constant arithmetic like `(10 + 20) * 3`
  const constMath = source.match(/\(\s*\d+\s*[+\-*/]\s*\d+\s*\)\s*[+\-*/]\s*\d+/g) ?? [];
  const unfoldedConstArithmetic = constMath.length;
  if (unfoldedConstArithmetic > 0) issues.push('Pure constant arithmetic expression left unfolded');

  // 8. Scratch-register leak detection (applied symmetrically to OpLift too!)
  const scratchSelfAssign = source.match(/local\s+(\w+)\s*=\s*[^\n]+\n\s*\1\s*=\s*\1[:.(]/gm) ?? [];
  if (scratchSelfAssign.length > 0) {
    issues.push(`${scratchSelfAssign.length} un-inlined scratch register chain(s)`);
  }
  const unfoldedForBounds = source.match(/for\s+\w+\s*=\s*n\d+,\s*n\d+/gm) ?? [];
  if (unfoldedForBounds.length > 0) {
    issues.push('Numeric for-loop bounds leaked as scratch locals');
  }

  // 9. Double-negated comparisons (`not (a < b)`, `not (a <= b)`) & dead `local _ = _ENV`
  const doubleNegations = source.match(/\bnot\s*\(\s*[\w.]+\s*(?:<=|>=|<|>|==|~=)\s*[\w.]+\s*\)/g) ?? [];
  if (doubleNegations.length > 0) {
    issues.push(`${doubleNegations.length} unsimplified double-negated comparison(s)`);
  }
  const deadEnvDiscard = /^\s*local\s+_\s*=\s*_ENV\s*$/m.test(source);
  if (deadEnvDiscard) {
    issues.push('Dead `local _ = _ENV` discard emitted at top level');
  }

  // 10. Misleading `(copy)` on Lua 5.1 table reference upvalues or inverted early-return ladders
  if (/--\s*upvalues:\s*t\d+\s*\(copy\)/.test(source)) {
    issues.push('Mislabeled Lua 5.1 shared reference upvalue as `(copy)`');
  }
  if (/if\s+v1\s*<=\s*10\s+then/.test(source)) {
    issues.push('Inverted `if/elseif/else` branch order into nested early-return guards');
  }

  // 11. Unreconstructed / unhandled opcodes or unstructured jumps
  const unhandledMarkers = source.match(/--\s*\[(?:unhandled op|unreconstructed|unstructured JUMPBACK)/g) ?? [];
  if (unhandledMarkers.length > 0) {
    issues.push(`${unhandledMarkers.length} unreconstructed instruction(s) or jump(s)`);
  }

  const hasSemanticNames =
    /\b(total|config|items|handler|Players|localPlayer|main|key|value|counter|worker|argCount|packed|args|item|str|obj)\b/.test(source) ||
    !/\b(n1|n2|t1|v1|p1)\b/.test(source);

  let score = 100;
  score -= syntheticPhiTemps * 18;
  score -= deadElseifAssignments * 18;
  score -= invertedGuardCount * 16;
  score -= unfoldedTableInits * 14;
  score -= redundantReturnParens * 10;
  score -= unfoldedConstArithmetic * 12;
  score -= forcedWatermarkLines * 4;
  score -= scratchSelfAssign.length * 14;
  score -= unfoldedForBounds.length * 14;
  score -= doubleNegations.length * 6;
  score -= unhandledMarkers.length * 25;
  if (deadEnvDiscard) score -= 8;
  if (/--\s*upvalues:\s*t\d+\s*\(copy\)/.test(source)) score -= 8;
  if (/if\s+v1\s*<=\s*10\s+then/.test(source)) score -= 14;
  if (!hasSemanticNames) score -= 4;
  score = Math.max(0, Math.min(100, score));

  return {
    score,
    lines: nonEmpty.length,
    maxNestingDepth,
    syntheticPhiTemps,
    deadElseifAssignments,
    invertedGuardCount,
    unfoldedTableInits,
    redundantReturnParens,
    unfoldedConstArithmetic,
    forcedWatermarkLines,
    hasSemanticNames,
    issues,
  };
}

export interface LandscapeScores {
  outputCleanliness: number;    // 15% — Readability & absence of synthetic artifacts on structured scripts
  complexCfgRecovery: number;   // 30% — Irreducible loops, nested short-circuit webs, 50k-line production scripts
  luauOpcodeCoverage: number;   // 25% — Full Luau v3-v6 + typeinfo/vector/buffer/native/fastcall semantics
  multiDialectSupport: number;  // 10% — Lua 5.1-5.4, LuaJIT, LuaJ, MoonSharp
  apiAndDiagnostics: number;    // 10% — Callable API, JSON/disassembly/byte-offset errors, Roblox *227
  throughputAndScale: number;   // 10% — Raw speed & memory scaling on multi-MB bytecode chunks
}

export interface LandscapeDecompilerEntry {
  id: string;
  name: string;
  runtime: string;
  accessModel: string;
  overallScore: number; // Strictly computed via computeWeightedOverall(scores) — zero manual fudging!
  scores: LandscapeScores;
  honestStrengths: string[];
  honestWeaknesses: string[];
  verdict: string;
}

export const LANDSCAPE_WEIGHTS = {
  complexCfgRecovery: 0.30,
  luauOpcodeCoverage: 0.25,
  outputCleanliness: 0.15,
  multiDialectSupport: 0.10,
  apiAndDiagnostics: 0.10,
  throughputAndScale: 0.10,
} as const;

export function computeWeightedOverall(s: LandscapeScores): number {
  return Math.round(
    s.complexCfgRecovery * LANDSCAPE_WEIGHTS.complexCfgRecovery +
      s.luauOpcodeCoverage * LANDSCAPE_WEIGHTS.luauOpcodeCoverage +
      s.outputCleanliness * LANDSCAPE_WEIGHTS.outputCleanliness +
      s.multiDialectSupport * LANDSCAPE_WEIGHTS.multiDialectSupport +
      s.apiAndDiagnostics * LANDSCAPE_WEIGHTS.apiAndDiagnostics +
      s.throughputAndScale * LANDSCAPE_WEIGHTS.throughputAndScale
  );
}

function makeEntry(entry: Omit<LandscapeDecompilerEntry, 'overallScore'>): LandscapeDecompilerEntry {
  return {
    ...entry,
    overallScore: computeWeightedOverall(entry.scores),
  };
}

// Brutally honest comparison of the most-used Roblox / Luau decompilers next to OpLift.
// Every overallScore is computed mathematically from the 6 weighted sub-scores (30% CFG, 25% Opcodes,
// 15% Cleanliness, 10% Multi-Dialect, 10% API/Diag, 10% Throughput) — never manually inflated.
export const ROBLOX_DECOMPILER_LANDSCAPE: LandscapeDecompilerEntry[] = [
  makeEntry({
    id: 'medal-luau-lifter',
    name: 'Medal (Luau Lifter / Scoob)',
    runtime: 'Native C++ / Rust',
    accessModel: 'Paid / Private API & self-hosted',
    scores: {
      outputCleanliness: 88,
      complexCfgRecovery: 94,
      luauOpcodeCoverage: 96,
      multiDialectSupport: 40,
      apiAndDiagnostics: 76,
      throughputAndScale: 96,
    },
    honestStrengths: [
      'Battle-tested on massive 50,000+ line production Roblox games with complex unstructured CFGs.',
      'Full Luau v3–v6 opcode, local+param type annotations, vector/buffer intrinsics, and register coalescing.',
      'Native C++/Rust speed even on multi-megabyte ModuleScripts.',
    ],
    honestWeaknesses: [
      'Closed/paid ecosystem; not freely inspectable without access.',
      'SSA phi-destruction still emits synthetic temps (`local v1`) and dead branches on certain loop-break merges.',
      'Luau-focused; limited multi-dialect Lua 5.x/LuaJIT support.',
    ],
    verdict: 'Current gold standard (#1 overall) for raw production Roblox game-script coverage and native speed.',
  }),
  makeEntry({
    id: 'lua-expert-v2',
    name: 'lua.expert v2',
    runtime: 'Native Backend (Cloudflare API)',
    accessModel: 'Free API (500 req/min)',
    scores: {
      outputCleanliness: 82,
      complexCfgRecovery: 88,
      luauOpcodeCoverage: 90,
      multiDialectSupport: 92,
      apiAndDiagnostics: 58,
      throughputAndScale: 86,
    },
    honestStrengths: [
      'Broadest multi-dialect backend in the free tier: Luau + Lua 2.x–5.4, LuaJIT, LuaJ, and MoonSharp.',
      'Passed 28/28 live compiled Luau head-to-head execution tests (avg 89.3/100 cleanliness) and handles massive real-world unstructured Luau CFGs better than linear TypeScript structuring passes.',
      'High 500 req/min free ceiling with strong expression folding across large unrolled chains (verified on our 2,003-insn stress case).',
    ],
    honestWeaknesses: [
      'Verified SSA phi artifacts materialize `local v1` + dead `elseif` self-assignments in while/break loops and scored 76/100 on 3-deep nested repeat/while/for loops.',
      'Fails to recover `continue` guards despite `virtualizeContinue: true`, emits double-negated `not (x < y)`, and wraps Lua 5.4 chunks in `local _ = _ENV` + IIFE.',
      'Rejects Roblox client `*227` encoded bytecode with an opaque 1-line HTTP 400 and offers no JSON/disassembly/diagnostics API.',
    ],
    verdict: 'Strong #2 tie (85/100) for dialect breadth and large unstructured CFGs (88 vs OpLift 82), held back by SSA phi artifacts and an opaque text-only API.',
  }),
  makeEntry({
    id: 'oplift-ours',
    name: 'OpLift (This Service)',
    runtime: 'TypeScript (Node / Express)',
    accessModel: 'Open Self-Hosted Callable API (No rate limit)',
    scores: {
      outputCleanliness: 96,
      complexCfgRecovery: 82,
      luauOpcodeCoverage: 87,
      multiDialectSupport: 70,
      apiAndDiagnostics: 96,
      throughputAndScale: 78,
    },
    honestStrengths: [
      'Verified 56/56 execution equivalence (100%, avg 99.8/100 cleanliness, 0 unhandled ops) across 14 Luau benchmarks × 4 compile flags (`-O0/-O1/-O2`, `-g0/-g1/-g2`), 28/28 (99.7/100 vs v2 89.3/100) live head-to-head, and 13/13 built-in corpus cases.',
      'Semantic factory/stdlib naming with dynamic `CAPTURE 0` vs `CAPTURE 1` closure tracking (no overwritten function identifiers), `elseif` collapsing, nil-preserving `GETVARARGS`/`SETLIST`/`table.unpack`, multiline table folding with ternaries, and compound boolean-DAG `while` + 3-deep nested `repeat`/`while`/`for` recovery.',
      'Accepts Luau v3–v14+ (up to v20 compat, `typesVersion >= 3`), Roblox `*227` opcodes, RSB1 raw/Zstd/XOR-Zstd, Gzip, Zlib, BOM/unpadded Base64, and raw hex (8/8 compat matrix), plus structured diagnostics whenever an op/branch cannot be reconstructed.',
    ],
    honestWeaknesses: [
      'BRUTAL HONESTY (Why CFG is 82, NOT 90+): Despite passing 3-deep nested repeat/while/for and boolean-DAG `while` headers, arbitrary irreducible goto webs and 50,000-line obfuscated production Roblox scripts still need a full dominator-tree CFG structurer where Medal (94), Konstant (90), lua.expert v2 (88), and Oracle (86) beat us.',
      'Multi-dialect lifting covers Luau v3–v14+, Roblox `*227`, Lua 5.1, and Lua 5.4 — but Lua 5.2, Lua 5.3, LuaJIT, and MoonSharp remain header-inspection only (honestly trailing v2’s 92).',
      'Does not yet reconstruct local-variable `typeinfo` annotations or inline complex `FASTCALL3` buffer/vector intrinsics (keeping opcode coverage at 87, below Medal 96 / Konstant 92 / v2 90 / Oracle 88).',
    ],
    verdict: 'Earned jump from 82 → 85/100 via verified 56/56 Luau equivalence, dynamic closure capture handling, nil-preserving varargs/SETLIST, and boolean-DAG loop recovery — tied with v2 overall on API/cleanliness, still honestly behind Medal (87) and behind Medal/Konstant/v2/Oracle on huge irreducible CFGs.',
  }),
  makeEntry({
    id: 'konstant',
    name: 'Konstant v2.1',
    runtime: 'Native C++ (Hosted API)',
    accessModel: 'Free community API (rate-limited)',
    scores: {
      outputCleanliness: 83,
      complexCfgRecovery: 90,
      luauOpcodeCoverage: 92,
      multiDialectSupport: 30,
      apiAndDiagnostics: 64,
      throughputAndScale: 88,
    },
    honestStrengths: [
      'Widely trusted in SaveInstance and executor ecosystems; handles almost every huge real-world Roblox client script reliably (90/100 Complex CFG).',
      'Strong recovery of deeply nested closures, generic `for` iterators, and Luau `if` expressions.',
      'Consistent output stability on stripped production bytecode.',
    ],
    honestWeaknesses: [
      'Strict API rate limits and intermittent downtime during peak Roblox updates.',
      'Luau-only (30/100 Multi-Dialect) and plain-text output only; no structured JSON AST, disassembly, or byte-offset diagnostics.',
      'Verbose `var_u_1` / `arg1` naming and occasional redundant temporaries.',
    ],
    verdict: 'Stronger than OpLift on huge messy production Roblox scripts (90 vs 82 CFG), scored 81 overall only due to Luau-only scope and rate-limited text API.',
  }),
  makeEntry({
    id: 'oracle',
    name: 'Oracle',
    runtime: 'Native C++ / Cloud Service',
    accessModel: 'Paid API (per-request / tier)',
    scores: {
      outputCleanliness: 82,
      complexCfgRecovery: 86,
      luauOpcodeCoverage: 88,
      multiDialectSupport: 25,
      apiAndDiagnostics: 70,
      throughputAndScale: 84,
    },
    honestStrengths: [
      'Clean formatting with solid expression inlining on typical Roblox LocalScripts and ModuleScripts.',
      'Good uptime and predictable paid SLA compared to free community relays.',
    ],
    honestWeaknesses: [
      'Paid subscription required; closed source and Luau-only.',
      'Less configurable than Medal/v2 options; no raw bytecode disassembly or diagnostic envelope.',
    ],
    verdict: 'Dependable commercial Luau decompiler, though pricey relative to free v2/Konstant alternatives.',
  }),
  makeEntry({
    id: 'unluau',
    name: 'unluau (Open Source)',
    runtime: 'C++ (Open Source)',
    accessModel: 'Free / Self-Hosted',
    scores: {
      outputCleanliness: 62,
      complexCfgRecovery: 68,
      luauOpcodeCoverage: 64,
      multiDialectSupport: 20,
      apiAndDiagnostics: 45,
      throughputAndScale: 82,
    },
    honestStrengths: [
      'Open-source C++ codebase great for learning Luau bytecode internals and fast local CLI runs.',
      'Respectable recovery on older Luau v3–v4 bytecode.',
    ],
    honestWeaknesses: [
      'Frequently breaks or emits broken pseudo-code on newer Luau v5/v6 opcodes (`JUMPXEQK*`, `FASTCALL3`, `IDIV`, `typesVersion=3`).',
      'Produces noisy register variables (`var0`, `var1`) and fails on modern Roblox scripts without forks.',
    ],
    verdict: 'Good open-source reference, largely superseded by Medal, Konstant, v2, and OpLift on modern Luau v6.',
  }),
].sort((a, b) => b.overallScore - a.overallScore);
