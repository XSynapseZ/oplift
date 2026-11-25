import type {
  ConstantValue,
  DecodedInstruction,
  DecompileMetrics,
  DecompileOptions,
  DecompileResult,
  DisassembledProto,
  ParseDiagnostic,
  ParsedChunk,
  ParsedProto,
} from './types.ts';
import { DEFAULT_DECOMPILE_OPTIONS } from './types.ts';
import { decodeInputBytes, parseAnyBytecode } from './parser.ts';
import { formatConstantShort } from './luauParser.ts';
import { runReadabilityPasses } from './passes/readabilityPasses.ts';

// Provably single-return standard Lua / Luau / Roblox APIs (never need outer parens in `return (...)`)
const KNOWN_SINGLE_RETURN_CALLS = new Set<string>([
  'game:GetService',
  'string.format',
  'string.sub',
  'string.len',
  'string.lower',
  'string.upper',
  'string.rep',
  'string.reverse',
  'string.char',
  'table.concat',
  'table.create',
  'table.clone',
  'math.abs',
  'math.floor',
  'math.ceil',
  'math.clamp',
  'math.min',
  'math.max',
  'math.sqrt',
  'math.sin',
  'math.cos',
  'math.tan',
  'math.rad',
  'math.deg',
  'math.round',
  'math.sign',
  'tonumber',
  'tostring',
  'type',
  'typeof',
  'rawlen',
  'getmetatable',
  'setmetatable',
  'Instance.new',
  'Vector3.new',
  'Vector2.new',
  'CFrame.new',
  'Color3.fromRGB',
  'Color3.new',
  'UDim2.new',
  'UDim2.fromOffset',
  'UDim2.fromScale',
  'tick',
  'os.clock',
  'os.time',
]);

const LUA_KEYWORDS = new Set<string>([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function',
  'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true',
  'until', 'while',
]);

function isValidIdent(s: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(s) && !LUA_KEYWORDS.has(s);
}

function escapeLuaString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const code = s.charCodeAt(i);
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 32 || code === 127) {
      const nextCode = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      const nextIsDigit = nextCode >= 48 && nextCode <= 57;
      out += nextIsDigit ? `\\${String(code).padStart(3, '0')}` : `\\${code}`;
    }
    else out += ch;
  }
  return out + '"';
}

function formatNumber(n: number, opts: DecompileOptions): string {
  if (Number.isNaN(n)) return '0 / 0';
  if (!Number.isFinite(n)) return n > 0 ? 'math.huge' : '-math.huge';
  if (Object.is(n, -0)) return '-0';
  if (opts.integralFloatsAsInts && Number.isInteger(n) && Math.abs(n) < 1e15) {
    return String(n);
  }
  if (opts.scientificNotation && (Math.abs(n) >= 1e6 || (Math.abs(n) > 0 && Math.abs(n) < 1e-4))) {
    return n.toExponential();
  }
  return String(n);
}

interface Expr {
  kind:
    | 'literal'
    | 'ident'
    | 'global'
    | 'binary'
    | 'unary'
    | 'index'
    | 'call'
    | 'methodCall'
    | 'table'
    | 'function'
    | 'vararg';
  code: string;
  prec: number;
  constVal?: number | string | boolean | null;
  isConst?: boolean;
  singleReturn?: boolean;
  calleeName?: string;
  protoId?: number;
  isVarRef?: boolean;
  regOrigin?: number;
  binOp?: string;
  binLhs?: string;
  binRhs?: string;
  hasEffect?: boolean;
  readsMutable?: boolean;
}

function atomExpr(code: string, opts?: Partial<Expr>): Expr {
  return { kind: 'literal', code, prec: 100, ...opts };
}

function wrapIfLower(e: Expr, minPrec: number): string {
  return e.prec < minPrec ? `(${e.code})` : e.code;
}

function wrapPrefixExpr(e: Expr): string {
  const needsParens =
    e.kind === 'literal' ||
    e.kind === 'table' ||
    e.kind === 'function' ||
    e.kind === 'binary' ||
    e.kind === 'unary' ||
    e.kind === 'vararg';
  return needsParens ? `(${e.code})` : e.code;
}

function inferExprPrec(code: string): number {
  const s = code.trim();
  if (!s) return 100;
  if (s.startsWith('if ')) {
    let depth = 0;
    let inStr: string | null = null;
    for (let idx = 0; idx < s.length; idx++) {
      const ch = s[idx];
      if (inStr) {
        if (ch === '\\') { idx++; continue; }
        if (ch === inStr) inStr = null;
        continue;
      }
      if (ch === '"' || ch === "'") { inStr = ch; continue; }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      else if (depth === 0 && s.startsWith(' then ', idx)) return 10;
    }
  }

  let lowest = 100;
  let depth = 0;
  let inStr: string | null = null;
  const isIdentChar = (c: string | undefined) => !!c && /[A-Za-z0-9_]/.test(c);

  for (let idx = 0; idx < s.length; idx++) {
    const ch = s[idx];
    if (inStr) {
      if (ch === '\\') { idx++; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth = Math.max(0, depth - 1); continue; }
    if (depth !== 0) continue;

    if (s.startsWith('or', idx) && !isIdentChar(s[idx - 1]) && !isIdentChar(s[idx + 2])) {
      lowest = Math.min(lowest, 20);
      idx += 1;
    } else if (s.startsWith('and', idx) && !isIdentChar(s[idx - 1]) && !isIdentChar(s[idx + 3])) {
      lowest = Math.min(lowest, 30);
      idx += 2;
    } else if (
      s.startsWith('==', idx) ||
      s.startsWith('~=', idx) ||
      s.startsWith('<=', idx) ||
      s.startsWith('>=', idx)
    ) {
      lowest = Math.min(lowest, 40);
      idx += 1;
    } else if (ch === '<' || ch === '>') {
      if (s[idx + 1] === ch) {
        lowest = Math.min(lowest, 54);
        idx += 1;
      } else {
        lowest = Math.min(lowest, 40);
      }
    } else if (s.startsWith('..', idx)) {
      lowest = Math.min(lowest, 56);
      idx += 1;
    } else if (ch === '+' || (ch === '-' && idx > 0)) {
      let p = idx - 1;
      while (p >= 0 && s[p] === ' ') p--;
      const prev = p >= 0 ? s[p] : '';
      if (prev && !'(,[{+-*/%^=<>~&|'.includes(prev)) {
        lowest = Math.min(lowest, 60);
      } else if (ch === '-' && idx === 0) {
        lowest = Math.min(lowest, 80);
      }
    } else if (s.startsWith('//', idx)) {
      lowest = Math.min(lowest, 70);
      idx += 1;
    } else if (ch === '*' || ch === '/' || ch === '%') {
      lowest = Math.min(lowest, 70);
    } else if (ch === '^') {
      lowest = Math.min(lowest, 85);
    } else if (idx === 0 && (ch === '-' || ch === '#')) {
      lowest = Math.min(lowest, 80);
    } else if (idx === 0 && s.startsWith('not', 0) && !isIdentChar(s[3])) {
      lowest = Math.min(lowest, 80);
      idx += 2;
    }
  }
  return lowest;
}

function constantToExpr(c: ConstantValue | undefined, opts: DecompileOptions): Expr {
  if (!c) return atomExpr('nil', { isConst: true, constVal: null });
  switch (c.kind) {
    case 'nil':
      return atomExpr('nil', { isConst: true, constVal: null });
    case 'boolean':
      return atomExpr(c.value ? 'true' : 'false', { isConst: true, constVal: Boolean(c.value) });
    case 'number':
      return atomExpr(formatNumber(Number(c.value), opts), { isConst: true, constVal: Number(c.value) });
    case 'string':
      return atomExpr(escapeLuaString(String(c.value)), { isConst: true, constVal: String(c.value) });
    case 'import':
      return atomExpr((c.importPath ?? ['_G']).join('.'), { kind: 'global' });
    case 'table':
      return atomExpr('{}', { kind: 'table' });
    case 'closure':
      return atomExpr(`proto_${c.closureProtoId}`, { kind: 'function', protoId: c.closureProtoId });
    case 'vector': {
      const [x, y, z] = c.value as number[];
      return atomExpr(`Vector3.new(${formatNumber(x, opts)}, ${formatNumber(y, opts)}, ${formatNumber(z, opts)})`, {
        kind: 'call',
        singleReturn: true,
      });
    }
  }
}

function foldBinary(
  op: string,
  left: Expr,
  right: Expr,
  opts: DecompileOptions,
  metrics: DecompileMetrics
): Expr {
  const precMap: Record<string, number> = {
    '^': 85,
    '*': 70, '/': 70, '//': 70, '%': 70,
    '+': 60, '-': 60,
    '..': 56,
    '<<': 54, '>>': 54,
    '&': 53,
    '~': 52,
    '|': 51,
    '==': 40, '~=': 40, '<': 40, '<=': 40, '>': 40, '>=': 40,
    'and': 30,
    'or': 20,
  };
  const prec = precMap[op] ?? 50;

  if (opts.foldConstants && left.isConst && right.isConst) {
    if (typeof left.constVal === 'number' && typeof right.constVal === 'number') {
      let folded: number | boolean | undefined;
      if (op === '+') folded = left.constVal + right.constVal;
      else if (op === '-') folded = left.constVal - right.constVal;
      else if (op === '*') folded = left.constVal * right.constVal;
      else if (op === '/' && right.constVal !== 0) folded = left.constVal / right.constVal;
      else if (op === '//' && right.constVal !== 0) folded = Math.floor(left.constVal / right.constVal);
      else if (op === '%' && right.constVal !== 0) folded = left.constVal % right.constVal;
      else if (op === '^') folded = Math.pow(left.constVal, right.constVal);
      else if (op === '&' && Number.isInteger(left.constVal) && Number.isInteger(right.constVal)) folded = (left.constVal | 0) & (right.constVal | 0);
      else if (op === '|' && Number.isInteger(left.constVal) && Number.isInteger(right.constVal)) folded = (left.constVal | 0) | (right.constVal | 0);
      else if (op === '~' && Number.isInteger(left.constVal) && Number.isInteger(right.constVal)) folded = (left.constVal | 0) ^ (right.constVal | 0);
      else if (op === '<<' && Number.isInteger(left.constVal) && Number.isInteger(right.constVal)) folded = (left.constVal | 0) << (right.constVal | 0);
      else if (op === '>>' && Number.isInteger(left.constVal) && Number.isInteger(right.constVal)) folded = (left.constVal | 0) >>> (right.constVal | 0);
      else if (op === '==') folded = left.constVal === right.constVal;
      else if (op === '~=') folded = left.constVal !== right.constVal;
      else if (op === '<') folded = left.constVal < right.constVal;
      else if (op === '<=') folded = left.constVal <= right.constVal;
      else if (op === '>') folded = left.constVal > right.constVal;
      else if (op === '>=') folded = left.constVal >= right.constVal;

      if (typeof folded === 'number' && Number.isFinite(folded)) {
        metrics.constantsFolded++;
        return atomExpr(formatNumber(folded, opts), { isConst: true, constVal: folded });
      }
      if (typeof folded === 'boolean') {
        metrics.constantsFolded++;
        return atomExpr(folded ? 'true' : 'false', { isConst: true, constVal: folded });
      }
    }
    if (op === '..' && typeof left.constVal === 'string' && typeof right.constVal === 'string') {
      metrics.constantsFolded++;
      const combined = left.constVal + right.constVal;
      return atomExpr(escapeLuaString(combined), { isConst: true, constVal: combined });
    }
  }

  const leftMinPrec = op === '^' ? prec + 1 : prec;
  const rightMinPrec =
    op === '-' || op === '/' || op === '%' || op === '//' || op === '<<' || op === '>>' ? prec + 1 : prec;
  const lhsStr = wrapIfLower(left, leftMinPrec);
  const rhsStr = wrapIfLower(right, rightMinPrec);
  return {
    kind: 'binary',
    code: `${lhsStr} ${op} ${rhsStr}`,
    prec,
    binOp: op,
    binLhs: left.code,
    binRhs: right.code,
    hasEffect: Boolean(left.hasEffect || right.hasEffect),
    readsMutable: Boolean(left.readsMutable || right.readsMutable),
  };
}

function splitTopLevelBinaryComparison(cond: string): { lhs: string; op: string; rhs: string } | null {
  const s = cond.trim();
  let depth = 0;
  let inStr: string | null = null;
  let foundOp: { idx: number; op: string } | null = null;
  const isIdentChar = (c: string | undefined) => !!c && /[A-Za-z0-9_]/.test(c);

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (ch === '\\') { i++; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth = Math.max(0, depth - 1); continue; }
    if (depth !== 0) continue;

    if (
      (s.startsWith('or', i) && !isIdentChar(s[i - 1]) && !isIdentChar(s[i + 2])) ||
      (s.startsWith('and', i) && !isIdentChar(s[i - 1]) && !isIdentChar(s[i + 3]))
    ) {
      return null;
    }
    for (const op of ['==', '~=', '<=', '>=', '<', '>']) {
      if (op.length === 1 && (s[i + 1] === op || s[i + 1] === '=')) continue;
      if (s.startsWith(op, i)) {
        if (foundOp) return null;
        foundOp = { idx: i, op };
        i += op.length - 1;
        break;
      }
    }
  }
  if (!foundOp) return null;
  return {
    lhs: s.slice(0, foundOp.idx).trim(),
    op: foundOp.op,
    rhs: s.slice(foundOp.idx + foundOp.op.length).trim(),
  };
}

function stripOuterParens(code: string): string {
  let s = code.trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let inStr: string | null = null;
    let closesAtEnd = true;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (inStr) {
        if (ch === '\\') { i++; continue; }
        if (ch === inStr) inStr = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth--;
      if (depth === 0 && i < s.length - 1) {
        closesAtEnd = false;
        break;
      }
    }
    if (!closesAtEnd || depth !== 0) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

function isGuaranteedBooleanExpr(code: string): boolean {
  const s = stripOuterParens(code);
  if (s === 'true' || s === 'false') return true;
  if (splitTopLevelBinaryComparison(s) !== null) return true;
  if (s.startsWith('not ') && inferExprPrec(s) >= 80) return true;
  return false;
}

function invertCondition(cond: string, booleanContextOnly = false): string {
  const trimmed = cond.trim();
  const cmp = splitTopLevelBinaryComparison(trimmed);
  if (cmp) {
    if (cmp.op === '==') return `${cmp.lhs} ~= ${cmp.rhs}`;
    if (cmp.op === '~=') return `${cmp.lhs} == ${cmp.rhs}`;
    // Never invert `<`, `<=`, `>`, `>=` blindly: breaks NaN (`0/0`) and `__lt`/`__le` metamethods.
    return `not (${trimmed})`;
  }
  if (trimmed.startsWith('not ') && inferExprPrec(trimmed) >= 80) {
    const inner = stripOuterParens(trimmed.slice(4).trim());
    if (booleanContextOnly || isGuaranteedBooleanExpr(inner)) {
      return inner;
    }
    return `not (${trimmed})`;
  }
  const prec = inferExprPrec(trimmed);
  return prec < 80 ? `not (${trimmed})` : `not ${trimmed}`;
}

function formatLuauComparisonPair(
  lhs: Expr,
  rhs: Expr,
  baseOp: '==' | '~=' | '<' | '<=',
  negateTaken: boolean
): { jumpTakenCond: string; fallthroughCond: string; effectiveTakenOp: string } {
  const flipOp: Record<string, string> = {
    '==': '==',
    '~=': '~=',
    '<': '>',
    '<=': '>=',
    '>': '<',
    '>=': '<=',
  };
  let left = lhs;
  let right = rhs;
  let op = baseOp as string;
  if (lhs.isConst && !rhs.isConst) {
    left = rhs;
    right = lhs;
    op = flipOp[op] ?? op;
  }
  const lhsCmp = wrapIfLower(left, 41);
  const rhsCmp = wrapIfLower(right, 41);
  const posCond = `${lhsCmp} ${op} ${rhsCmp}`;
  let negCond: string;
  if (op === '==') negCond = `${lhsCmp} ~= ${rhsCmp}`;
  else if (op === '~=') negCond = `${lhsCmp} == ${rhsCmp}`;
  else negCond = `not (${posCond})`;

  if (negateTaken) {
    return {
      jumpTakenCond: negCond,
      fallthroughCond: posCond,
      effectiveTakenOp: op === '==' ? '~=' : op === '~=' ? '==' : `not_${op}`,
    };
  }
  return {
    jumpTakenCond: posCond,
    fallthroughCond: negCond,
    effectiveTakenOp: op,
  };
}

function swapConstantComparison(
  lhs: Expr,
  rhs: Expr,
  opTaken: string,
  opFall: string
): { left: Expr; right: Expr; opTaken: string; opFall: string } {
  const flipOp: Record<string, string> = {
    '==': '==',
    '~=': '~=',
    '<': '>',
    '<=': '>=',
    '>': '<',
    '>=': '<=',
  };
  if (lhs.isConst && !rhs.isConst) {
    return {
      left: rhs,
      right: lhs,
      opTaken: flipOp[opTaken] ?? opTaken,
      opFall: flipOp[opFall] ?? opFall,
    };
  }
  return { left: lhs, right: rhs, opTaken, opFall };
}

function computeProtoReturnArities(chunk: ParsedChunk): Map<number, number | 'variadic'> {
  const map = new Map<number, number | 'variadic'>();
  for (const proto of chunk.protos) {
    let arity: number | 'variadic' | null = null;
    for (const insn of proto.instructions) {
      let count: number | 'variadic' | null = null;
      if (insn.opname === 'RETURN') {
        count = insn.b === 0 ? 'variadic' : insn.b - 1;
      } else if (insn.opname === 'RETURN0') {
        count = 0;
      } else if (insn.opname === 'RETURN1') {
        count = 1;
      }
      if (count !== null) {
        if (arity === null) arity = count;
        else if (arity !== count) arity = 'variadic';
      }
    }
    map.set(proto.id, arity ?? 0);
  }
  return map;
}

interface UpvalueBinding {
  name: string;
  mode: 'val' | 'ref' | 'upval';
}

interface LoopContext {
  kind: 'forn' | 'forg' | 'while' | 'repeat';
  headerPc: number;
  latchPc: number;
  continuePc: number;
  exitPc: number;
  altExitPc?: number;
}

function isLoopExitTarget(loop: LoopContext | undefined, targetPc: number | undefined): boolean {
  if (!loop || targetPc === undefined) return false;
  return targetPc === loop.exitPc || (loop.altExitPc !== undefined && targetPc === loop.altExitPc);
}

function isLoopContinueTarget(loop: LoopContext | undefined, targetPc: number | undefined): boolean {
  if (!loop || targetPc === undefined) return false;
  if (loop.kind === 'repeat') {
    // In Luau, `continue` inside `repeat ... until` jumps to the start of the `until` condition, not headerPc/latchPc.
    return targetPc === loop.continuePc;
  }
  if (loop.kind === 'while') {
    return targetPc === loop.headerPc || targetPc === loop.latchPc || targetPc === loop.continuePc;
  }
  return targetPc === loop.latchPc || targetPc === loop.continuePc;
}

interface LiftEnv {
  chunk: ParsedChunk;
  opts: DecompileOptions;
  metrics: DecompileMetrics;
  returnArities: Map<number, number | 'variadic'>;
  imports: Set<string>;
  diagnostics: ParseDiagnostic[];
}

function tryResugarStringFormat(args: Expr[], opts: DecompileOptions): string | null {
  if (!opts.resugarInterpolatedStrings || args.length < 2) return null;
  const fmt = args[0];
  if (!fmt.isConst || typeof fmt.constVal !== 'string') return null;
  const template = fmt.constVal;
  if (
    template.includes('`') ||
    template.includes('{') ||
    template.includes('}') ||
    template.includes('\\') ||
    template.includes('\n') ||
    template.includes('\r')
  ) {
    return null;
  }
  const specs = template.match(/%[*sdif]/g);
  if (!specs || specs.length !== args.length - 1) return null;
  const allPercents = template.match(/%./g);
  if (!allPercents || allPercents.length !== specs.length) return null;
  let idx = 1;
  const interpolated = template.replace(/%[*sdif]/g, () => `{${args[idx++].code}}`);
  return `\`${interpolated}\``;
}

function buildSemanticName(
  hint: string | undefined,
  fallbackPrefix: string,
  usedNames: Set<string>,
  opts: DecompileOptions,
  metrics: DecompileMetrics,
  allowNumericSuffix = true
): string {
  if (opts.renamingType === 'NONE') {
    let i = 0;
    while (usedNames.has(`r${i}`)) i++;
    const n = `r${i}`;
    usedNames.add(n);
    return n;
  }

  if (opts.renamingType === 'SEMANTIC' && hint && isValidIdent(hint)) {
    if (!usedNames.has(hint)) {
      usedNames.add(hint);
      metrics.semanticNamesInferred++;
      return hint;
    }
    if (allowNumericSuffix) {
      let suffix = 2;
      while (usedNames.has(`${hint}${suffix}`)) suffix++;
      const candidate = `${hint}${suffix}`;
      usedNames.add(candidate);
      metrics.semanticNamesInferred++;
      return candidate;
    }
  }

  let idx = 1;
  while (usedNames.has(`${fallbackPrefix}${idx}`)) idx++;
  const name = `${fallbackPrefix}${idx}`;
  usedNames.add(name);
  return name;
}

function inferSemanticHintFromExpr(expr: Expr): string | undefined {
  const code = expr.code;
  const svc = code.match(/:GetService\("([A-Za-z_][A-Za-z0-9_]*)"\)$/);
  if (svc) return svc[1];

  const childLookup = code.match(/:(?:WaitForChild|FindFirstChild)\("([A-Za-z_][A-Za-z0-9_]*)"\)$/);
  if (childLookup) {
    const raw = childLookup[1];
    const camel = raw[0].toLowerCase() + raw.slice(1);
    if (isValidIdent(camel)) return camel;
  }

  if (/:(?:Connect|Once)\(/.test(code)) return 'connection';
  if (/^coroutine\.(?:wrap|create)\(/.test(code)) return 'co';

  // Factory / constructor / getter calls (e.g. makeCounter(...) -> counter, makeWorker(...) -> worker)
  const callMatch = code.match(/^([A-Za-z_][A-Za-z0-9_.:]*)\(/);
  if (callMatch) {
    const callee = callMatch[1];
    if (callee === 'select' && /^\s*select\(\s*"#"\s*,/.test(code)) return 'argCount';
    if (callee === 'table.pack') return 'packed';
    if (callee === 'table.concat') return 'text';
    if (callee === 'table.clone') return 'clone';
    if (callee === 'table.create') return 'list';
    if (callee === 'string.split') return 'parts';
    if (callee === 'string.format') return 'formatted';
    if (callee === 'tonumber') return 'num';
    if (callee === 'type' || callee === 'typeof') return 'kind';
    if (callee === 'setmetatable') return 'obj';
    if (callee === 'getmetatable') return 'mt';
    if (callee === 'pcall' || callee === 'xpcall') return 'ok';
    const baseFn = callee.split(/[.:]/).pop() ?? '';
    const factoryMatch = baseFn.match(/^(?:make|create|new|build|spawn|get|find|compute|calc|parse|format)([A-Z][A-Za-z0-9_]*)$/);
    if (factoryMatch) {
      const camel = factoryMatch[1][0].toLowerCase() + factoryMatch[1].slice(1);
      if (isValidIdent(camel)) return camel;
    }
    if (callee.endsWith('.new') || callee.endsWith(':new')) {
      const cls = callee.split(/[.:]/)[0];
      if (cls && cls.length > 1 && cls !== 'mt' && !/^t\d+$/.test(cls)) {
        const camel = cls[0].toLowerCase() + cls.slice(1);
        if (isValidIdent(camel)) return camel;
      }
    }
  }

  if (code === '{ ... }') return 'args';
  if (expr.kind === 'vararg') return 'arg';
  if (expr.kind === 'unary' && code.startsWith('#')) return 'count';

  const prop = code.match(/\.([A-Za-z_][A-Za-z0-9_]*)$/);
  if (prop) {
    const p = prop[1];
    const camel = p[0].toLowerCase() + p.slice(1);
    if (isValidIdent(camel)) return camel;
  }
  if (expr.kind === 'index' && code.endsWith(']')) return 'item';
  if (expr.kind === 'function') return 'handler';
  if (expr.isConst && typeof expr.constVal === 'boolean') return 'flag';
  return undefined;
}

function isLuauCondJump(op: string): boolean {
  return (
    op === 'JUMPIF' || op === 'JUMPIFNOT' ||
    op === 'JUMPIFEQ' || op === 'JUMPIFLE' || op === 'JUMPIFLT' ||
    op === 'JUMPIFNOTEQ' || op === 'JUMPIFNOTLE' || op === 'JUMPIFNOTLT' ||
    op === 'JUMPXEQKNIL' || op === 'JUMPXEQKB' || op === 'JUMPXEQKN' || op === 'JUMPXEQKS'
  );
}

function isSideEffectOrControlOp(op: string): boolean {
  return (
    op === 'CALL' ||
    op === 'CALLFB' ||
    op === 'SETTABLE' ||
    op === 'SETTABLEKS' ||
    op === 'SETTABLEN' ||
    op === 'SETUDATAKS' ||
    op === 'SETGLOBAL' ||
    op === 'SETUPVAL' ||
    op === 'SETLIST' ||
    op === 'NEWCLOSURE' ||
    op === 'DUPCLOSURE' ||
    op === 'FORNPREP' ||
    op === 'FORNLOOP' ||
    op === 'FORGPREP' ||
    op === 'FORGPREP_NEXT' ||
    op === 'FORGPREP_INEXT' ||
    op === 'FORGLOOP' ||
    op === 'JUMP' ||
    op === 'JUMPBACK' ||
    op === 'JUMPX' ||
    isLuauCondJump(op)
  );
}

const LUAU_NON_WRITING_OPS = new Set<string>([
  'NOP', 'BREAK', 'SETGLOBAL', 'SETUPVAL', 'CLOSEUPVALS', 'SETTABLE', 'SETTABLEKS', 'SETTABLEN',
  'SETUDATAKS', 'RETURN', 'JUMP', 'JUMPBACK', 'JUMPIF', 'JUMPIFNOT', 'JUMPIFEQ', 'JUMPIFLE', 'JUMPIFLT',
  'JUMPIFNOTEQ', 'JUMPIFNOTLE', 'JUMPIFNOTLT', 'SETLIST', 'FORNPREP', 'FORNLOOP', 'FORGLOOP',
  'FORGPREP', 'FORGPREP_NEXT', 'FORGPREP_INEXT', 'PREPVARARGS', 'JUMPX', 'FASTCALL',
  'FASTCALL1', 'FASTCALL2', 'FASTCALL2K', 'FASTCALL3', 'FASTPCALL', 'COVERAGE', 'CAPTURE',
  'JUMPXEQKNIL', 'JUMPXEQKB', 'JUMPXEQKN', 'JUMPXEQKS', 'NATIVECALL', 'CMPPROTO', 'FINCONSTRUCT',
  'NEWCLASSMEMBER', 'SETPRIVATEFIELD',
]);

function computeMultretEndMap(insns: DecodedInstruction[]): Map<number, number> {
  const multretEndAt = new Map<number, number>();
  let curMultret = -1;
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname === 'GETVARARGS' && ins.b === 0) {
      curMultret = ins.a;
    } else if ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.b === 0) {
      if (curMultret >= 0) multretEndAt.set(i, curMultret);
      curMultret = ins.c === 0 ? ins.a : -1;
    } else if ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.c === 0) {
      curMultret = ins.a;
    } else if (ins.opname === 'RETURN' && ins.b === 0) {
      if (curMultret >= 0) multretEndAt.set(i, curMultret);
      curMultret = -1;
    } else if (ins.opname === 'SETLIST' && ins.c === 0) {
      if (curMultret >= 0) multretEndAt.set(i, curMultret);
      curMultret = -1;
    } else if (ins.opname === 'JUMP' || ins.opname === 'JUMPBACK' || isLuauCondJump(ins.opname)) {
      curMultret = -1;
    }
  }
  return multretEndAt;
}

function luauForEachReadReg(
  ins: DecodedInstruction,
  idx: number,
  multretEndAt: Map<number, number>,
  cb: (r: number) => void
) {
  switch (ins.opname) {
    case 'MOVE': case 'NOT': case 'MINUS': case 'LENGTH':
    case 'GETTABLEKS': case 'GETTABLEN': case 'NAMECALL':
    case 'GETUDATAKS': case 'NAMECALLUDATA':
      cb(ins.b);
      break;
    case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
    case 'AND': case 'OR': case 'GETTABLE':
      cb(ins.b);
      if (ins.c !== ins.b) cb(ins.c);
      break;
    case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
    case 'ANDK': case 'ORK':
      cb(ins.b);
      break;
    case 'SUBRK': case 'DIVRK':
      cb(ins.c);
      break;
    case 'CONCAT':
      for (let r = ins.b; r <= ins.c; r++) cb(r);
      break;
    case 'SETTABLE':
      cb(ins.a);
      if (ins.b !== ins.a) cb(ins.b);
      if (ins.c !== ins.a && ins.c !== ins.b) cb(ins.c);
      break;
    case 'SETTABLEKS': case 'SETTABLEN': case 'SETUDATAKS':
      cb(ins.a);
      if (ins.b !== ins.a) cb(ins.b);
      break;
    case 'SETGLOBAL': case 'SETUPVAL':
      cb(ins.a);
      break;
    case 'CAPTURE':
      if (ins.a === 0 || ins.a === 1) cb(ins.b);
      break;
    case 'CALL':
    case 'CALLFB': {
      cb(ins.a);
      if (ins.b === 0) {
        const endR = multretEndAt.get(idx) ?? ins.a;
        for (let r = ins.a + 1; r <= endR; r++) cb(r);
      } else {
        const nargs = ins.b - 1;
        for (let r = ins.a + 1; r <= ins.a + nargs; r++) cb(r);
      }
      break;
    }
    case 'RETURN': {
      if (ins.b === 0) {
        const endR = multretEndAt.get(idx) ?? ins.a;
        for (let r = ins.a; r <= Math.max(ins.a, endR); r++) cb(r);
      } else {
        const nres = ins.b - 1;
        for (let r = ins.a; r < ins.a + nres; r++) cb(r);
      }
      break;
    }
    case 'SETLIST': {
      cb(ins.a);
      if (ins.c === 0) {
        const endR = multretEndAt.get(idx) ?? ins.b;
        for (let r = ins.b; r <= Math.max(ins.b, endR); r++) cb(r);
      } else {
        const count = ins.c - 1;
        for (let r = ins.b; r < ins.b + count; r++) cb(r);
      }
      break;
    }
    case 'FORNPREP':
      cb(ins.a);
      cb(ins.a + 1);
      cb(ins.a + 2);
      break;
    case 'FORGPREP':
    case 'FORGPREP_NEXT':
    case 'FORGPREP_INEXT':
      cb(ins.a);
      cb(ins.a + 1);
      cb(ins.a + 2);
      break;
    case 'JUMPIF': case 'JUMPIFNOT':
    case 'JUMPXEQKNIL': case 'JUMPXEQKB': case 'JUMPXEQKN': case 'JUMPXEQKS':
    case 'CMPPROTO':
      cb(ins.a);
      break;
    case 'JUMPIFEQ': case 'JUMPIFLE': case 'JUMPIFLT':
    case 'JUMPIFNOTEQ': case 'JUMPIFNOTLE': case 'JUMPIFNOTLT':
      cb(ins.a);
      if (ins.aux !== undefined && ins.aux !== ins.a) cb(ins.aux);
      break;
  }
}

// Single-pass O(N) liveness + loop-carried + capture + debug-local + closure + table-mutation analysis
function analyzeLuauLocalDefs(
  proto: ParsedProto,
  chunk: ParsedChunk,
  loopSpans: Array<{ headerIdx: number; endIdx: number }>,
  multretEndAt: Map<number, number>
): {
  materializeAt: Set<string>;
  stepOneRegs: Set<number>;
  accumRegs: Set<number>;
  capturedRefRegs: Set<number>;
  capturedValRegs: Set<number>;
  lastReadAtDef: Map<string, number>;
  firstReadAtDef: Map<string, number>;
  tableMutatedInLoopOrLater: Set<string>;
  appendTableRegs: Set<number>;
  metatableRegs: Set<number>;
} {
  const insns = proto.instructions;
  const materializeAt = new Set<string>();
  const stepOneRegs = new Set<number>();
  const accumRegs = new Set<number>();
  const capturedRefRegs = new Set<number>();
  const capturedValRegs = new Set<number>();
  const lastReadAtDef = new Map<string, number>();
  const firstReadAtDef = new Map<string, number>();
  const tableMutatedInLoopOrLater = new Set<string>();
  const appendTableRegs = new Set<number>();
  const metatableRegs = new Set<number>();
  const pcToIdxLocal = new Map<number, number>();
  for (let idx = 0; idx < insns.length; idx++) {
    pcToIdxLocal.set(insns[idx].pc, idx);
  }

  // Identify registers owned by FORNPREP setup so limit/step/init are never materialized as scratch locals
  const fornSetupRegs = new Set<string>();
  const forgSetupRegs = new Set<string>();
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname === 'FORNPREP') {
      const a = ins.a;
      const foundSlot = new Set<number>();
      for (let k = i - 1; k >= Math.max(0, i - 24); k--) {
        const kop = insns[k].opname;
        if (kop === 'FORNPREP' || kop === 'FORNLOOP' || kop === 'FORGPREP' || kop === 'FORGPREP_NEXT' || kop === 'FORGPREP_INEXT' || kop === 'FORGLOOP' || kop === 'JUMP' || kop === 'JUMPBACK' || isLuauCondJump(kop)) {
          break;
        }
        const target = insns[k].a;
        if ((target === a || target === a + 1 || target === a + 2) && !LUAU_NON_WRITING_OPS.has(kop) && !foundSlot.has(target)) {
          fornSetupRegs.add(`${k}:${target}`);
          foundSlot.add(target);
          if (foundSlot.size === 3) break;
        }
      }
    } else if (ins.opname === 'FORGPREP' || ins.opname === 'FORGPREP_NEXT' || ins.opname === 'FORGPREP_INEXT') {
      const a = ins.a;
      for (let k = Math.max(0, i - 4); k < i; k++) {
        if (
          (insns[k].a === a || insns[k].a === a + 1 || insns[k].a === a + 2) &&
          (insns[k].opname === 'LOADNIL' || insns[k].opname === 'MOVE' || insns[k].opname === 'CALL' || insns[k].opname === 'CALLFB')
        ) {
          forgSetupRegs.add(`${k}:${insns[k].a}`);
        }
      }
    } else if ((ins.opname === 'ADDK' || ins.opname === 'SUBK') && ins.a === ins.b) {
      const kv = proto.constants[ins.c];
      if (kv?.kind === 'number' && kv.value === 1) stepOneRegs.add(ins.a);
      else accumRegs.add(ins.a);
    } else if ((ins.opname === 'ADD' || ins.opname === 'SUB' || ins.opname === 'MUL') && ins.a === ins.b) {
      accumRegs.add(ins.a);
    } else if (ins.opname === 'SETTABLE' && i >= 2) {
      const lenIns = insns[i - 2];
      const addIns = insns[i - 1];
      if (
        lenIns.opname === 'LENGTH' &&
        lenIns.b === ins.b &&
        addIns.opname === 'ADDK' &&
        addIns.a === ins.c &&
        addIns.b === lenIns.a &&
        proto.constants[addIns.c]?.kind === 'number' &&
        proto.constants[addIns.c]?.value === 1
      ) {
        appendTableRegs.add(ins.b);
      }
    } else if (ins.opname === 'CAPTURE' && ins.a === 1) {
      capturedRefRegs.add(ins.b);
    } else if (ins.opname === 'CAPTURE' && ins.a === 0) {
      capturedValRegs.add(ins.b);
    } else if (ins.opname === 'SETTABLEKS' || ins.opname === 'SETUDATAKS') {
      const kIdx = ins.opname === 'SETUDATAKS' ? (ins.aux ?? 0) & 0xffff : ins.aux ?? 0;
      const keyStr = proto.constants[kIdx]?.kind === 'string' ? String(proto.constants[kIdx].value) : '';
      if (keyStr === '__index' || keyStr === '__call' || keyStr === '__add' || keyStr === '__tostring') {
        metatableRegs.add(ins.b);
      }
    }
  }

  // Pre-scan NEWTABLE / DUPTABLE contiguous literal initializers so literal field writes
  // (`SETTABLE*`, `SETLIST`) do not falsely inflate `readsSinceNextWrite` and force materialization.
  const tableLiteralInitEnd = new Map<number, number>();
  const tableInitReadTarget = new Map<number, number>();
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname !== 'NEWTABLE' && ins.opname !== 'DUPTABLE') continue;
    const tblReg = ins.a;
    let initEnd = i;
    const candidateInits: number[] = [];
    for (let k = i + 1; k < insns.length; k++) {
      const ki = insns[k];
      const kop = ki.opname;
      if (
        kop === 'JUMP' || kop === 'JUMPBACK' || kop === 'JUMPX' || kop === 'RETURN' ||
        kop === 'FORNPREP' || kop === 'FORNLOOP' || kop === 'FORGPREP' || kop === 'FORGPREP_NEXT' ||
        kop === 'FORGPREP_INEXT' || kop === 'FORGLOOP' || isLuauCondJump(kop)
      ) {
        break;
      }
      if (kop === 'SETLIST' && ki.a === tblReg) {
        candidateInits.push(k);
        initEnd = k;
        continue;
      }
      if (
        (kop === 'SETTABLEKS' || kop === 'SETUDATAKS' || kop === 'SETTABLEN' || kop === 'SETTABLE') &&
        ki.b === tblReg &&
        ki.a !== tblReg &&
        (kop !== 'SETTABLE' || ki.c !== tblReg)
      ) {
        candidateInits.push(k);
        initEnd = k;
        continue;
      }
      let readsTbl = false;
      luauForEachReadReg(ki, k, multretEndAt, (r) => {
        if (r === tblReg) readsTbl = true;
      });
      if (readsTbl) break;
      const kiWritesZero = (kop === 'CALL' || kop === 'CALLFB') && ki.c === 1;
      if (!LUAU_NON_WRITING_OPS.has(kop) && !kiWritesZero && ki.a === tblReg) break;
      if ((kop === 'NAMECALL' || kop === 'NAMECALLUDATA') && ki.a + 1 === tblReg) break;
    }
    tableLiteralInitEnd.set(i, initEnd);
    for (const initIdx of candidateInits) {
      tableInitReadTarget.set(initIdx, tblReg);
    }
  }

  // Per-register state tracked in a single O(N) backward pass from N-1 down to 0
  const maxReg = Math.max(256, proto.maxStackSize + 8);
  const readsSinceNextWrite = new Int32Array(maxReg);
  const nextWriteIdx = new Int32Array(maxReg).fill(-1);
  const lastReadIdx = new Int32Array(maxReg).fill(-1);
  const nextWriteReadsSelf = new Uint8Array(maxReg);
  const capturedBeforeNextWrite = new Uint8Array(maxReg);
  const tableMutatedLaterIdx = new Int32Array(maxReg).fill(-1);
  const usedAsCallCallee = new Uint8Array(maxReg);
  const firstReadIdx = new Int32Array(maxReg).fill(-1);

  const followUniqueChainTo = (startDefIdx: number, startReg: number, targetConsumerIdx: number): number | null => {
    let curIdx = startDefIdx;
    let curReg = startReg;
    for (let step = 0; step < 8; step++) {
      const fr = firstReadAtDef.get(`${curIdx}:${curReg}`);
      const lr = lastReadAtDef.get(`${curIdx}:${curReg}`);
      if (fr === undefined || fr <= curIdx || fr !== lr) return null;
      if (fr === targetConsumerIdx) return curReg;
      const mid = insns[fr];
      if (!mid) return null;
      if (materializeAt.has(`${fr}:${mid.a}`)) return null;
      const mop = mid.opname;
      if (mop === 'NAMECALL' || mop === 'NAMECALLUDATA') {
        curIdx = fr;
        curReg = mid.a;
        continue;
      }
      if ((mop === 'CALL' || mop === 'CALLFB') && (mid.c === 0 || (mid.c !== 1 && mid.c <= 2))) {
        curIdx = fr;
        curReg = mid.a;
        continue;
      }
      if (!LUAU_NON_WRITING_OPS.has(mop) && mop !== 'CALL' && mop !== 'CALLFB' && mop !== 'GETVARARGS') {
        curIdx = fr;
        curReg = mid.a;
        continue;
      }
      return null;
    }
    return null;
  };

  const hasLoops = loopSpans.length > 0;

  for (let i = insns.length - 1; i >= 0; i--) {
    const ins = insns[i];
    const isCallZeroRet = (ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.c === 1;
    const isMultretProducer =
      ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.c === 0) ||
      (ins.opname === 'GETVARARGS' && ins.b === 0);
    const isForPrepWrite =
      ins.opname === 'FORNPREP' ||
      ins.opname === 'FORGPREP' ||
      ins.opname === 'FORGPREP_NEXT' ||
      ins.opname === 'FORGPREP_INEXT';
    const isForLoopWrite = ins.opname === 'FORNLOOP' || ins.opname === 'FORGLOOP';
    const writes = (!LUAU_NON_WRITING_OPS.has(ins.opname) && !isCallZeroRet) || isForLoopWrite || isForPrepWrite;
    const reg =
      ins.opname === 'FORNLOOP' || ins.opname === 'FORNPREP'
        ? ins.a + 2
        : ins.opname === 'FORGLOOP' || ins.opname === 'FORGPREP' || ins.opname === 'FORGPREP_NEXT' || ins.opname === 'FORGPREP_INEXT'
          ? ins.a + 3
          : ins.a;

    const isForSetup = fornSetupRegs.has(`${i}:${reg}`) || forgSetupRegs.has(`${i}:${reg}`);
    if (writes && reg < maxReg) {
      const nIdx = nextWriteIdx[reg];
      const maxRead = lastReadIdx[reg];
      const minRead = firstReadIdx[reg];
      lastReadAtDef.set(`${i}:${reg}`, maxRead);
      firstReadAtDef.set(`${i}:${reg}`, minRead);

      if (isMultretProducer || isForSetup || isForLoopWrite || isForPrepWrite) {
        // MULTRET producers (CALL C=0, GETVARARGS B=0) and FOR* setup/prep/loop writes must never
        // materialize as a scratch local, yet MUST kill prior reads so loop-body/setup reads don't leak backward.
        let loopWriteCount = 1;
        if (ins.opname === 'FORGLOOP') {
          loopWriteCount = Math.max(1, (ins.aux ?? 2) & 0xff);
        } else if (ins.opname === 'FORGPREP' || ins.opname === 'FORGPREP_NEXT' || ins.opname === 'FORGPREP_INEXT') {
          const targetIdx = ins.targetPc !== undefined ? pcToIdxLocal.get(ins.targetPc) : undefined;
          const gloop = targetIdx !== undefined ? insns[targetIdx] : undefined;
          loopWriteCount = gloop && gloop.opname === 'FORGLOOP' ? Math.max(1, (gloop.aux ?? 2) & 0xff) : 2;
        } else if ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.c > 2) {
          loopWriteCount = ins.c - 1;
        }
        for (let wr = 0; wr < loopWriteCount && reg + wr < maxReg; wr++) {
          const r = reg + wr;
          nextWriteIdx[r] = i;
          readsSinceNextWrite[r] = 0;
          lastReadIdx[r] = -1;
          firstReadIdx[r] = -1;
          nextWriteReadsSelf[r] = 0;
          capturedBeforeNextWrite[r] = 0;
          tableMutatedLaterIdx[r] = -1;
          usedAsCallCallee[r] = 0;
        }
      } else {
        let mutatedInsideLoop = false;
        let defBeforeLoopReadInside = false;
        if (hasLoops) {
          for (let s = 0; s < loopSpans.length; s++) {
            const sp = loopSpans[s];
            if (nIdx !== -1 && i < sp.headerIdx && nIdx >= sp.headerIdx && nIdx <= sp.endIdx && maxRead >= sp.headerIdx) {
              mutatedInsideLoop = true;
            }
            if (i < sp.headerIdx && maxRead >= sp.headerIdx && maxRead <= sp.endIdx) {
              defBeforeLoopReadInside = true;
            }
          }
        }

        // Check if a table created before a loop is mutated via SETTABLE* inside a loop
        let tblMutInLoop = false;
        if ((ins.opname === 'NEWTABLE' || ins.opname === 'DUPTABLE') && tableMutatedLaterIdx[reg] !== -1) {
          const mIdx = tableMutatedLaterIdx[reg];
          for (let s = 0; s < loopSpans.length; s++) {
            const sp = loopSpans[s];
            if (i < sp.headerIdx && mIdx >= sp.headerIdx && mIdx <= sp.endIdx) {
              tblMutInLoop = true;
              break;
            }
          }
          if (tblMutInLoop) {
            tableMutatedInLoopOrLater.add(`${i}:${reg}`);
          }
        }

        // Check if this is a closure declaration (named OR called directly — never emit invalid `function() end()`)
        let isClosureDecl = false;
        if (ins.opname === 'NEWCLOSURE' || ins.opname === 'DUPCLOSURE') {
          const childId =
            ins.opname === 'NEWCLOSURE' ? proto.childProtos[ins.d] : proto.constants[ins.d]?.closureProtoId;
          const childProto = childId !== undefined ? chunk.protos[childId] : undefined;
          let afterCap = i + 1;
          while (afterCap < insns.length && insns[afterCap].opname === 'CAPTURE') afterCap++;
          const nextIns = insns[afterCap];
          const storedDirectlyIntoTable =
            nextIns &&
            (nextIns.opname === 'SETTABLEKS' ||
              nextIns.opname === 'SETUDATAKS' ||
              nextIns.opname === 'SETTABLE' ||
              nextIns.opname === 'SETTABLEN') &&
            nextIns.a === reg;
          const returnedDirectly = nextIns && nextIns.opname === 'RETURN' && nextIns.a === reg && nextIns.b === 2;
          if (
            !storedDirectlyIntoTable &&
            !returnedDirectly &&
            ((childProto && isValidIdent(childProto.debugName)) || usedAsCallCallee[reg] === 1 || defBeforeLoopReadInside)
          ) {
            isClosureDecl = true;
          }
        }

        // Non-pure / allocating defs (CALL, CALLFB, NEWTABLE, DUPTABLE, NEWCLOSURE, DUPCLOSURE) must NEVER be
        // inlined across a loop boundary or across an intervening side effect that would change evaluation order!
        const isEffectfulOrAlloc =
          ins.opname === 'CALL' ||
          ins.opname === 'CALLFB' ||
          ins.opname === 'NEWTABLE' ||
          ins.opname === 'DUPTABLE' ||
          ins.opname === 'NEWCLOSURE' ||
          ins.opname === 'DUPCLOSURE';
        const effectScanStart =
          ins.opname === 'NEWTABLE' || ins.opname === 'DUPTABLE'
            ? (tableLiteralInitEnd.get(i) ?? i) + 1
            : i + 1;
        let crossesEffect = false;
        if ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.c === 2 && minRead === -1) {
          // Single-return call whose return value is unused MUST still be emitted for its side effects!
          crossesEffect = true;
        } else if (
          (ins.opname === 'CALL' || ins.opname === 'CALLFB' || ins.opname === 'NEWTABLE' || ins.opname === 'DUPTABLE') &&
          minRead >= effectScanStart
        ) {
          const consumer = insns[minRead];
          const isLeftToRightMultiConsumer =
            consumer !== undefined &&
            (consumer.opname === 'CALL' ||
              consumer.opname === 'CALLFB' ||
              consumer.opname === 'RETURN' ||
              consumer.opname === 'CONCAT' ||
              consumer.opname === 'SETLIST');
          const isLeftOperandOfBinOp =
            consumer !== undefined &&
            (consumer.opname === 'ADD' ||
              consumer.opname === 'SUB' ||
              consumer.opname === 'MUL' ||
              consumer.opname === 'DIV' ||
              consumer.opname === 'MOD' ||
              consumer.opname === 'POW' ||
              consumer.opname === 'IDIV' ||
              consumer.opname === 'AND' ||
              consumer.opname === 'OR') &&
            consumer.b === reg &&
            consumer.c !== reg;

          const canCheckOrderPreservingInline =
            readsSinceNextWrite[reg] === 1 &&
            !defBeforeLoopReadInside &&
            (isLeftToRightMultiConsumer || isLeftOperandOfBinOp);

          for (let k = effectScanStart; k < minRead; k++) {
            const ki = insns[k];
            if (isSideEffectOrControlOp(ki.opname)) {
              let chainRootReg = canCheckOrderPreservingInline ? followUniqueChainTo(k, ki.a, minRead) : null;
              let isCalleeFeedingCall = false;
              if (chainRootReg === null && canCheckOrderPreservingInline) {
                const fr = firstReadAtDef.get(`${k}:${ki.a}`);
                const lr = lastReadAtDef.get(`${k}:${ki.a}`);
                if (
                  fr !== undefined &&
                  fr > k &&
                  fr === lr &&
                  insns[fr] &&
                  (insns[fr].opname === 'CALL' || insns[fr].opname === 'CALLFB') &&
                  insns[fr].a === ki.a &&
                  (insns[fr].c === 0 || (insns[fr].c !== 1 && insns[fr].c <= 2)) &&
                  !materializeAt.has(`${fr}:${ki.a}`)
                ) {
                  chainRootReg = followUniqueChainTo(fr, ki.a, minRead);
                  isCalleeFeedingCall = chainRootReg !== null;
                }
              }
              const isInlineValueExpr =
                canCheckOrderPreservingInline &&
                ((((ki.opname === 'CALL' || ki.opname === 'CALLFB') && (ki.c === 0 || (ki.c !== 1 && ki.c <= 2))) ||
                  ki.opname === 'NEWTABLE' ||
                  ki.opname === 'DUPTABLE' ||
                  isCalleeFeedingCall)) &&
                !materializeAt.has(`${k}:${ki.a}`) &&
                chainRootReg !== null &&
                (isLeftToRightMultiConsumer ? chainRootReg > reg : consumer.c === chainRootReg);
              if (!isInlineValueExpr) {
                crossesEffect = true;
                break;
              }
            }
          }
        }

        // Check if a debug local variable starts right at this definition (never steal for callee GETIMPORT/GETGLOBAL)
        const isCallCalleeTemp =
          (ins.opname === 'GETIMPORT' || ins.opname === 'GETGLOBAL') &&
          usedAsCallCallee[reg] === 1 &&
          readsSinceNextWrite[reg] === 1;
        const hasDebugLocalStart =
          !isCallCalleeTemp &&
          proto.localVars.some(
            (lv) =>
              lv.reg === reg &&
              !lv.name.startsWith('(') &&
              isValidIdent(lv.name) &&
              lv.startPc >= ins.pc &&
              lv.startPc <= ins.pc + ins.width
          );

        const reads = readsSinceNextWrite[reg];
        const isInChainOverwrite =
          nIdx !== -1 && !mutatedInsideLoop && reads === 1 && nextWriteReadsSelf[reg] === 1;

        const isTrivialConst =
          ins.opname === 'LOADN' ||
          ins.opname === 'LOADK' ||
          ins.opname === 'LOADB' ||
          ins.opname === 'LOADNIL';

        if (
          capturedBeforeNextWrite[reg] === 1 ||
          mutatedInsideLoop ||
          tblMutInLoop ||
          isClosureDecl ||
          (isEffectfulOrAlloc && defBeforeLoopReadInside) ||
          (!isTrivialConst && !isCallCalleeTemp && defBeforeLoopReadInside) ||
          crossesEffect ||
          hasDebugLocalStart
        ) {
          materializeAt.add(`${i}:${reg}`);
        } else if (!isInChainOverwrite && reads >= 2) {
          if (!isTrivialConst) {
            materializeAt.add(`${i}:${reg}`);
          }
        }

        // Reset liveness for all registers written by ins
        let writeCount = 1;
        if ((ins.opname === 'CALL' || ins.opname === 'CALLFB')) {
          const retWrite = ins.c > 2 ? ins.c - 1 : 1;
          const argClobber = ins.b > 1 ? ins.b : 1;
          writeCount = Math.max(retWrite, argClobber);
        } else if (ins.opname === 'GETVARARGS' && ins.b > 2) {
          writeCount = ins.b - 1;
        } else if (ins.opname === 'NAMECALL' || ins.opname === 'NAMECALLUDATA') {
          writeCount = 2;
        }
        for (let wr = 0; wr < writeCount && reg + wr < maxReg; wr++) {
          const r = reg + wr;
          nextWriteIdx[r] = i;
          readsSinceNextWrite[r] = 0;
          lastReadIdx[r] = -1;
          firstReadIdx[r] = -1;
          nextWriteReadsSelf[r] = 0;
          capturedBeforeNextWrite[r] = 0;
          tableMutatedLaterIdx[r] = -1;
          usedAsCallCallee[r] = 0;
        }
      }
    }

    // Record reads performed by ins (visible to defs earlier than i),
    // skipping table-register reads performed by its own contiguous literal initializer.
    const initTargetReg = tableInitReadTarget.get(i);
    luauForEachReadReg(ins, i, multretEndAt, (r) => {
      if (r < maxReg) {
        if (initTargetReg !== undefined && r === initTargetReg) return;
        readsSinceNextWrite[r]++;
        if (i > lastReadIdx[r]) lastReadIdx[r] = i;
        if (firstReadIdx[r] === -1 || i < firstReadIdx[r]) firstReadIdx[r] = i;
        if (writes && r === reg) {
          nextWriteReadsSelf[r] = 1;
        }
      }
    });

    if ((ins.opname === 'CALL' || ins.opname === 'CALLFB') && ins.a < maxReg) {
      usedAsCallCallee[ins.a] = 1;
    }

    if (
      (ins.opname === 'SETTABLE' || ins.opname === 'SETTABLEKS' || ins.opname === 'SETTABLEN' || ins.opname === 'SETUDATAKS') &&
      ins.b < maxReg
    ) {
      if (i > tableMutatedLaterIdx[ins.b]) tableMutatedLaterIdx[ins.b] = i;
    }

    if (ins.opname === 'CAPTURE' && (ins.a === 0 || ins.a === 1) && ins.b < maxReg) {
      capturedBeforeNextWrite[ins.b] = 1;
    }
  }

  return {
    materializeAt,
    stepOneRegs,
    accumRegs,
    capturedRefRegs,
    capturedValRegs,
    lastReadAtDef,
    firstReadAtDef,
    tableMutatedInLoopOrLater,
    appendTableRegs,
    metatableRegs,
  };
}

interface OpenTableBuilder {
  entries: Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }>;
  createdIdx: number;
  lastInitIdx: number;
  forceLocal: boolean;
}

function indentMultilineValue(val: string, extraIndent: string): string {
  if (!val.includes('\n')) return val;
  const parts = val.split('\n');
  for (let i = 1; i < parts.length; i++) {
    if (parts[i].length > 0) parts[i] = extraIndent + parts[i];
  }
  return parts.join('\n');
}

function formatTableLiteral(
  entries: Array<{ key?: string; val: string }>,
  indent: (lvl: number) => string,
  lvl: number
): string {
  if (entries.length === 0) return '{}';
  const allArray = entries.every((e) => !e.key);
  const totalLen = entries.reduce((acc, e) => acc + e.val.length, 0);
  const hasMultiline = entries.some((e) => e.val.includes('\n'));
  if (allArray && !hasMultiline && entries.length <= 6 && totalLen <= 60) {
    return `{ ${entries.map((e) => e.val).join(', ')} }`;
  }
  if (!hasMultiline && entries.length <= 4 && totalLen <= 50) {
    return `{ ${entries.map((e) => (e.key ? `${e.key} = ${e.val}` : e.val)).join(', ')} }`;
  }
  const extra = indent(1);
  const innerLines = entries.map((e) => {
    const valStr = indentMultilineValue(e.val, extra);
    return e.key ? `${indent(lvl + 1)}${e.key} = ${valStr},` : `${indent(lvl + 1)}${valStr},`;
  });
  return `{\n${innerLines.join('\n')}\n${indent(lvl)}}`;
}

function exprReferencesIdent(code: string, ident: string): boolean {
  const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![A-Za-z0-9_.])${escaped}(?![A-Za-z0-9_])`).test(code);
}

function decompileLuauProto(
  proto: ParsedProto,
  env: LiftEnv,
  indentLevel: number,
  inheritedUpvalues: UpvalueBinding[],
  isTopLevel: boolean
): string[] {
  const insns = proto.instructions;
  const pcToIdx = new Map<number, number>();
  insns.forEach((ins, idx) => pcToIdx.set(ins.pc, idx));

  const indent = (lvl: number) => '    '.repeat(lvl);
  const usedNames = new Set<string>();
  const regExpr = new Map<number, Expr>();
  const declaredLocals = new Map<number, string>();
  const declaredLocalEndPc = new Map<number, number>();
  const declaredLocalLvl = new Map<number, number>();
  const declaredLocalIsFn = new Set<number>();
  const wasCapturedByVal = new Set<number>();
  const hoistedLocals = new Set<number>();
  const localProtoMap = new Map<number, number>();
  const pendingMethodCalls = new Map<number, { calleeFull: string; objCode: string; objExpr: Expr; methodName: string }>();
  const openTables = new Map<number, OpenTableBuilder>();
  const regDefIdx = new Map<number, number>();
  let multretReg: number | null = null;

  const multretEndAt = computeMultretEndMap(insns);

  // Pre-detect loop structures: while, while-true, repeat..until, numeric for, generic for.
  // Multiple nested loops can share the same headerIdx (e.g. `repeat while ... do ... end ... until ...`),
  // so store an array per headerIdx sorted outermost-first (descending latchIdx).
  interface DetectedWhileLoop {
    kind: 'while';
    headerPc: number;
    headerIdx: number;
    condEndIdx: number;
    condJumps: Array<{ idx: number; kind: 'enter' | 'exit' }>;
    latchIdx: number;
    latchPc: number;
    exitPc: number;
  }
  interface DetectedRepeatLoop {
    kind: 'repeat';
    headerPc: number;
    headerIdx: number;
    condStartIdx: number;
    condStartPc: number;
    tailJumps: Array<{ idx: number; kind: 'exit' | 'continue' }>;
    latchIdx: number;
    latchPc: number;
    exitPc: number;
  }
  interface DetectedWhileTrueLoop {
    kind: 'whileTrue';
    headerPc: number;
    headerIdx: number;
    latchIdx: number;
    latchPc: number;
    exitPc: number;
  }
  type DetectedLoop = DetectedWhileLoop | DetectedRepeatLoop | DetectedWhileTrueLoop;

  const loopSpans: Array<{ headerIdx: number; endIdx: number }> = [];
  const loopsByHeaderIdx = new Map<number, DetectedLoop[]>();
  const allLoopHeaderIdxs = new Set<number>();
  const backwardJumpTargetIdxs = new Set<number>();
  const maxJumpbackByHeaderIdx = new Map<number, number>();
  const jumpSourcesByTargetIdx = new Map<number, number[]>();

  const registerDetectedLoop = (loop: DetectedLoop) => {
    const arr = loopsByHeaderIdx.get(loop.headerIdx) ?? [];
    arr.push(loop);
    loopsByHeaderIdx.set(loop.headerIdx, arr);
    allLoopHeaderIdxs.add(loop.headerIdx);
  };

  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.targetPc !== undefined) {
      const tIdx = pcToIdx.get(ins.targetPc);
      if (tIdx !== undefined) {
        const srcs = jumpSourcesByTargetIdx.get(tIdx) ?? [];
        srcs.push(i);
        jumpSourcesByTargetIdx.set(tIdx, srcs);
        if (tIdx < i && (ins.opname === 'JUMPBACK' || isLuauCondJump(ins.opname) || ins.opname === 'JUMP' || ins.opname === 'JUMPX')) {
          backwardJumpTargetIdxs.add(tIdx);
        }
        if (ins.opname === 'JUMPBACK' && tIdx < i) {
          const prevMax = maxJumpbackByHeaderIdx.get(tIdx) ?? -1;
          if (i > prevMax) maxJumpbackByHeaderIdx.set(tIdx, i);
        }
      }
    }
  }

  const hasJumpFromRangeTo = (rangeStart: number, rangeEnd: number, targetIdx: number): boolean => {
    const srcs = jumpSourcesByTargetIdx.get(targetIdx);
    if (!srcs) return false;
    for (let s = 0; s < srcs.length; s++) {
      if (srcs[s] >= rangeStart && srcs[s] < rangeEnd) return true;
    }
    return false;
  };

  const isPureWhileCondSetup = (ins: DecodedInstruction) => {
    const op = ins.opname;
    // Self-mutating ops (ADDK r, r, k / ADD r, r, ...) are loop body mutations, NEVER while-header setup!
    if (
      (op === 'ADDK' || op === 'SUBK' || op === 'MULK' || op === 'DIVK' || op === 'MODK' || op === 'IDIVK') &&
      ins.a === ins.b
    ) {
      return false;
    }
    if (
      (op === 'ADD' || op === 'SUB' || op === 'MUL' || op === 'DIV' || op === 'MOD' || op === 'IDIV') &&
      (ins.a === ins.b || ins.a === ins.c)
    ) {
      return false;
    }
    return (
      op === 'LOADN' ||
      op === 'LOADK' ||
      op === 'LOADKX' ||
      op === 'LOADB' ||
      op === 'LOADNIL' ||
      op === 'MOVE' ||
      op === 'GETIMPORT' ||
      op === 'GETGLOBAL' ||
      op === 'GETUPVAL' ||
      op === 'GETTABLE' ||
      op === 'GETTABLEKS' ||
      op === 'GETTABLEN' ||
      op === 'GETUDATAKS' ||
      op === 'LENGTH' ||
      op === 'NOT' ||
      op === 'MINUS' ||
      op === 'ADD' ||
      op === 'SUB' ||
      op === 'MUL' ||
      op === 'DIV' ||
      op === 'MOD' ||
      op === 'IDIV' ||
      op === 'ADDK' ||
      op === 'SUBK' ||
      op === 'MULK' ||
      op === 'DIVK' ||
      op === 'MODK' ||
      op === 'IDIVK' ||
      op === 'FASTCALL' ||
      op === 'FASTCALL1' ||
      op === 'FASTCALL2' ||
      op === 'FASTCALL2K' ||
      op === 'FASTCALL3' ||
      op === 'CALL' ||
      op === 'CALLFB' ||
      op === 'NAMECALL' ||
      op === 'NAMECALLUDATA'
    );
  };

  const isPureRepeatCondLoad = (ins: DecodedInstruction, idx: number, minIdx: number): boolean => {
    const op = ins.opname;
    if (op === 'LOADB') {
      // Never split the 3-instruction LOADB boolean idiom (`JUMPIF* -> +2; LOADB R, b1, C=1; LOADB R, b2, C=0`)
      if (ins.c !== 0) return false;
      if (idx > minIdx && insns[idx - 1].opname === 'LOADB' && insns[idx - 1].c === 1) return false;
      return true;
    }
    if (
      (op === 'ADDK' || op === 'SUBK' || op === 'MULK' || op === 'DIVK' || op === 'MODK' || op === 'IDIVK' || op === 'POWK') &&
      ins.a === ins.b
    ) {
      return false;
    }
    if (
      (op === 'ADD' || op === 'SUB' || op === 'MUL' || op === 'DIV' || op === 'MOD' || op === 'IDIV' || op === 'POW') &&
      (ins.a === ins.b || ins.a === ins.c)
    ) {
      return false;
    }
    return (
      op === 'LOADN' ||
      op === 'LOADK' ||
      op === 'LOADKX' ||
      op === 'LOADNIL' ||
      op === 'MOVE' ||
      op === 'GETIMPORT' ||
      op === 'GETGLOBAL' ||
      op === 'GETUPVAL' ||
      op === 'GETTABLEKS' ||
      op === 'GETTABLEN' ||
      op === 'GETTABLE' ||
      op === 'GETUDATAKS' ||
      op === 'LENGTH' ||
      op === 'NOT' ||
      op === 'MINUS' ||
      op === 'ADD' ||
      op === 'SUB' ||
      op === 'MUL' ||
      op === 'DIV' ||
      op === 'MOD' ||
      op === 'POW' ||
      op === 'IDIV' ||
      op === 'ADDK' ||
      op === 'SUBK' ||
      op === 'MULK' ||
      op === 'DIVK' ||
      op === 'MODK' ||
      op === 'POWK' ||
      op === 'IDIVK' ||
      op === 'SUBRK' ||
      op === 'DIVRK'
    );
  };

  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname === 'JUMPBACK' && ins.targetPc !== undefined) {
      const headerIdx = pcToIdx.get(ins.targetPc);
      if (headerIdx !== undefined && headerIdx < i) {
        loopSpans.push({ headerIdx, endIdx: i });
        const exitPc = ins.pc + ins.width;

        // 1a. General compound `while <bool-dag> do` at headerIdx:
        //     Scan forward from headerIdx to find a valid boolean-DAG condition ending at an `exitPc` jump `cand`,
        //     stopping as soon as an `or`-landing `bodyStartPc` is reached or before any body statement that defines
        //     a register read inside the loop body (e.g. `local v = a[i]; if v == nil then break end`).
        let matchedWhile = false;
        {
          let bestLastExit = -1;
          let maxInternalTargetPc = -1;
          const limitIdx = Math.min(i - 1, headerIdx + 24);
          let hasOrLandingAtBest = false;

          for (let p = headerIdx; p <= limitIdx; p++) {
            const pi = insns[p];
            if (isLuauCondJump(pi.opname)) {
              const tPc = pi.targetPc;
              if (tPc === undefined) break;
              if (tPc === exitPc) {
                const nextPc = p + 1 < insns.length ? insns[p + 1].pc : -1;
                if (p + 1 < i && (maxInternalTargetPc === -1 || maxInternalTargetPc <= nextPc)) {
                  // Check if extending past a previous valid `bestLastExit` would swallow a register read in the body
                  let writesBodyReg = false;
                  if (bestLastExit !== -1) {
                    for (let s = bestLastExit + 1; s < p; s++) {
                      const si = insns[s];
                      if (!LUAU_NON_WRITING_OPS.has(si.opname)) {
                        for (let b = p + 1; b < i; b++) {
                          let usedInBody = false;
                          luauForEachReadReg(insns[b], b, multretEndAt, (r) => {
                            if (r === si.a) usedInBody = true;
                          });
                          if (usedInBody) {
                            writesBodyReg = true;
                            break;
                          }
                          if (!LUAU_NON_WRITING_OPS.has(insns[b].opname) && insns[b].a === si.a) break;
                        }
                        if (writesBodyReg) break;
                      }
                    }
                  }
                  if (writesBodyReg) break;
                  bestLastExit = p;
                  if (maxInternalTargetPc === nextPc) {
                    hasOrLandingAtBest = true;
                    break;
                  }
                }
              } else if (tPc > pi.pc && tPc < ins.pc) {
                if (hasOrLandingAtBest) break;
                if (tPc > maxInternalTargetPc) maxInternalTargetPc = tPc;
              } else {
                break;
              }
            } else if (isPureWhileCondSetup(pi)) {
              if (hasOrLandingAtBest) break;
            } else {
              break;
            }
          }

          if (bestLastExit >= headerIdx) {
            const bodyStartPc = insns[bestLastExit + 1].pc;
            const condJumps: Array<{ idx: number; kind: 'enter' | 'exit' }> = [];
            let hasInternal = false;
            let validDag = true;
            for (let p = headerIdx; p <= bestLastExit; p++) {
              const pi = insns[p];
              if (isLuauCondJump(pi.opname)) {
                if (pi.targetPc === exitPc) condJumps.push({ idx: p, kind: 'exit' });
                else if (pi.targetPc === bodyStartPc) condJumps.push({ idx: p, kind: 'enter' });
                else if (pi.targetPc !== undefined && pi.targetPc > pi.pc && pi.targetPc < bodyStartPc) hasInternal = true;
                else {
                  validDag = false;
                  break;
                }
              }
            }
            if (validDag) {
              registerDetectedLoop({
                kind: 'while',
                headerPc: ins.targetPc,
                headerIdx,
                condEndIdx: bestLastExit + 1,
                condJumps: hasInternal ? [] : condJumps,
                latchIdx: i,
                latchPc: ins.pc,
                exitPc,
              });
              matchedWhile = true;
            }
          }
        }
        if (matchedWhile) continue;

        // 2. Check for trailing `repeat ... until` condition(s) right before JUMPBACK.
        //    Supports `until c`, `until c1 or c2` (jumps to exitPc), and `until c1 and c2` (jumps to latchPc/headerPc).
        const tailJumps: Array<{ idx: number; kind: 'exit' | 'continue' }> = [];
        const neededRegs = new Set<number>();
        let scan = i - 1;
        while (scan > headerIdx && scan >= i - 24) {
          if (tailJumps.length > 0 && hasJumpFromRangeTo(headerIdx, scan + 1, scan + 1)) {
            break;
          }
          const sIns = insns[scan];
          const isTailExit = isLuauCondJump(sIns.opname) && sIns.targetPc === exitPc;
          const isTailCont =
            tailJumps.length > 0 &&
            isLuauCondJump(sIns.opname) &&
            (sIns.targetPc === ins.pc || sIns.targetPc === ins.targetPc);
          if (isTailExit || isTailCont) {
            tailJumps.unshift({ idx: scan, kind: isTailExit ? 'exit' : 'continue' });
            luauForEachReadReg(sIns, scan, multretEndAt, (r) => neededRegs.add(r));
            scan--;
            // Step back only over pure operand loads that feed registers read by the condition chain,
            // stopping immediately if `scan + 1` is targeted by an earlier jump (e.g. `continue` inside `repeat`).
            while (scan > headerIdx) {
              if (hasJumpFromRangeTo(headerIdx, scan + 1, scan + 1)) break;
              const cand = insns[scan];
              if (!isPureRepeatCondLoad(cand, scan, headerIdx) || !neededRegs.has(cand.a)) break;
              neededRegs.delete(cand.a);
              luauForEachReadReg(cand, scan, multretEndAt, (r) => neededRegs.add(r));
              scan--;
            }
          } else {
            break;
          }
        }
        let looksLikeWhileTrue = false;
        if (tailJumps.length > 0 && scan + 1 > headerIdx) {
          for (let k = headerIdx; k < scan + 1; k++) {
            const ki = insns[k];
            if (ki.opname === 'FORNPREP' && ki.targetPc !== undefined) {
              const fExit = pcToIdx.get(ki.targetPc);
              if (fExit !== undefined && fExit > k) {
                k = fExit - 1;
                continue;
              }
            }
            if ((ki.opname === 'FORGPREP' || ki.opname === 'FORGPREP_NEXT' || ki.opname === 'FORGPREP_INEXT') && ki.targetPc !== undefined) {
              const gEnd = pcToIdx.get(ki.targetPc);
              if (gEnd !== undefined && gEnd > k) {
                k = gEnd;
                continue;
              }
            }
            const inInnerLoop = loopSpans.some(
              (sp) => sp.headerIdx > headerIdx && sp.endIdx < i && k >= sp.headerIdx && k <= sp.endIdx
            );
            if (inInnerLoop) continue;
            if (ki.targetPc !== undefined && (ki.targetPc === exitPc || ki.targetPc === ins.targetPc)) {
              looksLikeWhileTrue = true;
              break;
            }
          }
        }
        if (tailJumps.length > 0 && scan + 1 > headerIdx && !looksLikeWhileTrue) {
          registerDetectedLoop({
            kind: 'repeat',
            headerPc: ins.targetPc,
            headerIdx,
            condStartIdx: scan + 1,
            condStartPc: insns[scan + 1].pc,
            tailJumps,
            latchIdx: i,
            latchPc: ins.pc,
            exitPc,
          });
          continue;
        }

        // 3. Fallback `while true do ... end`: only for the outermost (last) JUMPBACK targeting headerIdx,
        //    so inner `continue` JUMPBACKs inside a `while` or `while true` loop are NOT misclassified as nested loops!
        const existingAtHeader = loopsByHeaderIdx.get(headerIdx) ?? [];
        const hasOuterAtHeader = existingAtHeader.some((l) => l.latchIdx >= i);
        if (i === maxJumpbackByHeaderIdx.get(headerIdx) && !hasOuterAtHeader) {
          registerDetectedLoop({
            kind: 'whileTrue',
            headerPc: ins.targetPc,
            headerIdx,
            latchIdx: i,
            latchPc: ins.pc,
            exitPc,
          });
        }
      }
    } else if (isLuauCondJump(ins.opname) && ins.targetPc !== undefined) {
      const targetIdx = pcToIdx.get(ins.targetPc);
      // Only treat a backward conditional jump as a `repeat ... until` loop if no JUMPBACK targets the same header
      // (otherwise it is a `continue` inside a `while` loop!).
      if (targetIdx !== undefined && targetIdx < i && !maxJumpbackByHeaderIdx.has(targetIdx)) {
        const existingAtHeader = loopsByHeaderIdx.get(targetIdx) ?? [];
        if (!existingAtHeader.some((l) => l.latchIdx >= i)) {
          loopSpans.push({ headerIdx: targetIdx, endIdx: i });
          registerDetectedLoop({
            kind: 'repeat',
            headerPc: ins.targetPc,
            headerIdx: targetIdx,
            condStartIdx: i,
            condStartPc: ins.pc,
            tailJumps: [{ idx: i, kind: 'exit' }],
            latchIdx: i,
            latchPc: ins.pc,
            exitPc: ins.pc + ins.width,
          });
        }
      }
    } else if (ins.opname === 'FORNPREP' && ins.targetPc !== undefined) {
      const rawExitIdx = pcToIdx.get(ins.targetPc);
      if (rawExitIdx !== undefined && rawExitIdx > i) {
        let loopIdx = rawExitIdx - 1;
        if (!(insns[loopIdx]?.opname === 'FORNLOOP' && insns[loopIdx].a === ins.a)) {
          const headerPc = insns[i + 1]?.pc ?? (ins.pc + ins.width);
          for (let k = i + 1; k < Math.min(insns.length, rawExitIdx + 1); k++) {
            const fl = insns[k];
            if (fl.opname === 'FORNLOOP' && fl.a === ins.a && fl.targetPc === headerPc) {
              loopIdx = k;
              break;
            }
          }
        }
        allLoopHeaderIdxs.add(i);
        loopSpans.push({ headerIdx: i + 1, endIdx: loopIdx });
      }
    } else if (
      (ins.opname === 'FORGPREP' || ins.opname === 'FORGPREP_NEXT' || ins.opname === 'FORGPREP_INEXT') &&
      ins.targetPc !== undefined
    ) {
      const loopIdx = pcToIdx.get(ins.targetPc);
      if (loopIdx !== undefined && loopIdx > i) {
        allLoopHeaderIdxs.add(i);
        loopSpans.push({ headerIdx: i + 1, endIdx: loopIdx });
      }
    }
  }

  // Sort loops sharing the same headerIdx outermost-first (descending latchIdx) so outer loops always wrap inner loops.
  for (const list of loopsByHeaderIdx.values()) {
    list.sort((a, b) => b.latchIdx - a.latchIdx);
  }

  const {
    materializeAt,
    stepOneRegs,
    accumRegs,
    capturedRefRegs,
    capturedValRegs,
    lastReadAtDef,
    firstReadAtDef,
    tableMutatedInLoopOrLater,
    appendTableRegs,
    metatableRegs,
  } = analyzeLuauLocalDefs(proto, env.chunk, loopSpans, multretEndAt);

  // Exact per-instruction written register helper (handles multi-return CALL/GETVARARGS, NAMECALL, FOR loops)
  function forEachLuauWrittenReg(ins: DecodedInstruction, idx: number, cb: (r: number) => void) {
    const op = ins.opname;
    if (op === 'FORNLOOP') {
      cb(ins.a + 2);
      return;
    }
    if (op === 'FORGLOOP') {
      const varCount = Math.max(1, (ins.aux ?? 2) & 0xff);
      for (let v = 0; v < varCount; v++) cb(ins.a + 3 + v);
      return;
    }
    if (LUAU_NON_WRITING_OPS.has(op)) return;
    if (op === 'FORNPREP' || op === 'FORGPREP' || op === 'FORGPREP_NEXT' || op === 'FORGPREP_INEXT') return;
    if (op === 'CALL' || op === 'CALLFB') {
      if (ins.c === 1) return;
      if (ins.c === 0) {
        const endR = multretEndAt.get(idx) ?? ins.a;
        for (let r = ins.a; r <= endR; r++) cb(r);
      } else {
        for (let r = 0; r < ins.c - 1; r++) cb(ins.a + r);
      }
      return;
    }
    if (op === 'GETVARARGS') {
      if (ins.b === 0) {
        const endR = multretEndAt.get(idx) ?? ins.a;
        for (let r = ins.a; r <= endR; r++) cb(r);
      } else if (ins.b >= 2) {
        for (let r = 0; r < ins.b - 1; r++) cb(ins.a + r);
      }
      return;
    }
    if (op === 'NAMECALL' || op === 'NAMECALLUDATA') {
      cb(ins.a);
      cb(ins.a + 1);
      return;
    }
    cb(ins.a);
  }

  // Exact CFG backward liveness analysis over the proto so block hoisting knows precisely which
  // registers are live-in / live-out across branches, sequential ifs, and nested loops.
  const { liveIn, liveOut } = (() => {
    const n = insns.length;
    const uses: number[][] = Array.from({ length: n }, () => []);
    const defs: Set<number>[] = Array.from({ length: n }, () => new Set<number>());
    const succs: number[][] = Array.from({ length: n }, () => []);

    for (let k = 0; k < n; k++) {
      const ins = insns[k];
      const uSet = new Set<number>();
      luauForEachReadReg(ins, k, multretEndAt, (r) => uSet.add(r));
      uses[k] = Array.from(uSet);
      forEachLuauWrittenReg(ins, k, (r) => defs[k].add(r));

      const op = ins.opname;
      if (op === 'RETURN') {
        continue;
      }
      if (
        op === 'JUMP' ||
        op === 'JUMPBACK' ||
        op === 'JUMPX' ||
        op === 'FORGPREP' ||
        op === 'FORGPREP_NEXT' ||
        op === 'FORGPREP_INEXT'
      ) {
        if (ins.targetPc !== undefined) {
          const tIdx = pcToIdx.get(ins.targetPc);
          if (tIdx !== undefined) succs[k].push(tIdx);
        }
      } else if (
        isLuauCondJump(op) ||
        op === 'FORNPREP' ||
        op === 'FORNLOOP' ||
        op === 'FORGLOOP'
      ) {
        if (k + 1 < n) succs[k].push(k + 1);
        if (ins.targetPc !== undefined) {
          const tIdx = pcToIdx.get(ins.targetPc);
          if (tIdx !== undefined && tIdx !== k + 1) succs[k].push(tIdx);
        }
      } else if (op === 'LOADB' && ins.c !== 0) {
        if (k + 2 < n) succs[k].push(k + 2);
      } else {
        if (k + 1 < n) succs[k].push(k + 1);
      }
    }

    const lIn: Set<number>[] = Array.from({ length: n }, () => new Set<number>());
    const lOut: Set<number>[] = Array.from({ length: n }, () => new Set<number>());
    const maxIters = Math.max(32, Math.min(256, n + 8));
    for (let iter = 0; iter < maxIters; iter++) {
      let changed = false;
      for (let k = n - 1; k >= 0; k--) {
        const outSet = lOut[k];
        const prevOutSize = outSet.size;
        for (const s of succs[k]) {
          for (const r of lIn[s]) outSet.add(r);
        }
        if (outSet.size !== prevOutSize) changed = true;

        const inSet = lIn[k];
        const prevInSize = inSet.size;
        for (const r of uses[k]) inSet.add(r);
        for (const r of outSet) {
          if (!defs[k].has(r)) inSet.add(r);
        }
        if (inSet.size !== prevInSize) changed = true;
      }
      if (!changed) break;
    }
    return { liveIn: lIn, liveOut: lOut };
  })();

  function releaseDeclaredLocal(reg: number) {
    declaredLocals.delete(reg);
    declaredLocalEndPc.delete(reg);
    declaredLocalLvl.delete(reg);
    declaredLocalIsFn.delete(reg);
    wasCapturedByVal.delete(reg);
    hoistedLocals.delete(reg);
    localProtoMap.delete(reg);
  }

  function releaseDeadLocalsAtEntry(entryIdx: number, keepRegs?: Set<number>) {
    if (entryIdx < 0 || entryIdx >= insns.length) return;
    const live = liveIn[entryIdx];
    for (const r of Array.from(declaredLocals.keys())) {
      if (keepRegs?.has(r)) continue;
      if (!live.has(r) && !capturedRefRegs.has(r) && !hoistedLocals.has(r)) {
        releaseDeclaredLocal(r);
      }
    }
  }

  function isDeadLocalAtReuse(reg: number, idx: number, lvl: number, rhsCode?: string): boolean {
    const prevName = declaredLocals.get(reg);
    if (!prevName) return false;
    if (capturedRefRegs.has(reg) || hoistedLocals.has(reg)) return false;
    if (declaredLocalLvl.get(reg) !== lvl) return false;
    if (idx < 0 || idx >= insns.length) return false;
    const insAtIdx = insns[idx];
    const isCallWriteAtIdx = (insAtIdx.opname === 'CALL' || insAtIdx.opname === 'CALLFB') && insAtIdx.a === reg;
    if (!isCallWriteAtIdx && liveIn[idx].has(reg)) return false;
    if (rhsCode !== undefined && exprReferencesIdent(rhsCode, prevName)) return false;
    const pc = insAtIdx.pc;
    const hasSameActiveDbg =
      env.opts.useDebugLocals &&
      proto.localVars.some(
        (lv) => lv.reg === reg && lv.name === prevName && lv.startPc < pc && lv.endPc > pc
      ) &&
      !findDebugLocalForDef(reg, idx, true);
    return !hasSameActiveDbg;
  }

  // Reserve ALL captured upvalue names in this scope so inner params/locals NEVER shadow an outer upvalue!
  const upvalNameSet = new Set<string>();
  for (const u of inheritedUpvalues) {
    if (u?.name && isValidIdent(u.name)) {
      usedNames.add(u.name);
      upvalNameSet.add(u.name);
    }
  }
  for (const uName of proto.upvalueNames) {
    if (uName && isValidIdent(uName)) {
      usedNames.add(uName);
      upvalNameSet.add(uName);
    }
  }

  // Register params (with optional Luau typeinfo annotations!)
  // Vararg functions emit PREPVARARGS at pc=0, so parameter debug local startPc may be 0 or 1.
  const paramNames: string[] = [];
  const paramSigParts: string[] = [];
  const paramLetters = ['a', 'b', 'c', 'd'];
  for (let p = 0; p < proto.numParams; p++) {
    const dbg = env.opts.useDebugLocals
      ? proto.localVars.find((lv) => lv.reg === p && lv.startPc <= 1 && !lv.name.startsWith('('))?.name
      : undefined;
    const nextLetter = paramLetters.find((ch) => !usedNames.has(ch));
    const pname =
      dbg && isValidIdent(dbg) && !upvalNameSet.has(dbg)
        ? dbg
        : env.opts.renamingType === 'SEMANTIC' && proto.numParams <= 4 && nextLetter
          ? buildSemanticName(nextLetter, 'p', usedNames, env.opts, env.metrics)
          : buildSemanticName(undefined, 'p', usedNames, env.opts, env.metrics);
    usedNames.add(pname);
    paramNames.push(pname);
    const pType = env.opts.emitTypeAnnotations && proto.paramTypes?.[p] ? proto.paramTypes[p] : undefined;
    paramSigParts.push(pType && pType !== 'any' ? `${pname}: ${pType}` : pname);
    declaredLocals.set(p, pname);
    declaredLocalLvl.set(p, indentLevel + (isTopLevel && proto.numParams > 0 ? 1 : isTopLevel ? 0 : 1));
    regExpr.set(p, atomExpr(pname, { kind: 'ident', isVarRef: true, regOrigin: p }));
  }

  function expireDebugLocalsAt(pc: number) {
    for (const [r, endPc] of Array.from(declaredLocalEndPc.entries())) {
      if (endPc <= pc && !capturedRefRegs.has(r) && !hoistedLocals.has(r)) {
        releaseDeclaredLocal(r);
      }
    }
  }

  function getReg(r: number): Expr {
    const e = regExpr.get(r);
    if (e) return e;
    const loc = declaredLocals.get(r);
    if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
    return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
  }

  function getUpvalName(uIdx: number): string {
    if (inheritedUpvalues[uIdx]) return inheritedUpvalues[uIdx].name;
    if (env.opts.useDebugLocals && proto.upvalueNames[uIdx]) return proto.upvalueNames[uIdx];
    return `upval_${uIdx}`;
  }

  function flushOpenTable(tblReg: number, out: string[], lvl: number, forceMaterialize = false) {
    const builder = openTables.get(tblReg);
    if (!builder) return;
    openTables.delete(tblReg);
    const code = formatTableLiteral(builder.entries, indent, lvl);
    const hasEffect = builder.entries.some((e) => e.hasEffect);
    const readsMutable = builder.entries.some((e) => e.readsMutable);
    const expr = atomExpr(code, { kind: 'table', prec: 100, hasEffect, readsMutable });
    if (builder.entries.length > 0) env.metrics.tablesFolded++;
    const shouldMat =
      forceMaterialize ||
      builder.forceLocal ||
      materializeAt.has(`${builder.createdIdx}:${tblReg}`) ||
      tableMutatedInLoopOrLater.has(`${builder.createdIdx}:${tblReg}`);
    // Look up debug local name around both creation and final initializer instruction (large tables start debug scope after SETTABLEKS/SETLIST)
    const dbg =
      findDebugLocalForDef(tblReg, builder.createdIdx) ??
      (builder.lastInitIdx !== builder.createdIdx ? findDebugLocalForDef(tblReg, builder.lastInitIdx, true) : undefined);
    assignReg(tblReg, expr, builder.createdIdx, out, lvl, shouldMat, dbg?.name, dbg?.endPc);
  }

  // Safely drop or flush a stale open table on `reg` BEFORE `reg` is overwritten by a non-table-populating instruction.
  // Prevents dead unused tables (like `local unused = { ... }`) from flushing later on top of a new closure/value in the same register!
  function settleOpenTableBeforeOverwrite(reg: number, out: string[], lvl: number) {
    const builder = openTables.get(reg);
    if (!builder) return;
    const lastRead = lastReadAtDef.get(`${builder.createdIdx}:${reg}`) ?? -1;
    const hasSideEffectEntry = builder.entries.some((e) => e.hasEffect || /[A-Za-z0-9_)\]]\(/.test(e.val));
    if (lastRead === -1 && !hasSideEffectEntry && !builder.forceLocal) {
      openTables.delete(reg);
      return;
    }
    flushOpenTable(reg, out, lvl, builder.forceLocal || hasSideEffectEntry);
  }

  function flushAllOpenTables(out: string[], lvl: number, forceMaterialize = false) {
    const keys = Array.from(openTables.keys());
    for (const k of keys) {
      flushOpenTable(k, out, lvl, forceMaterialize);
    }
  }

  // Snapshot any OTHER unmaterialized register (or open table) whose expression has side effects or could be
  // invalidated by mutating `mutatedIdent` or an intervening call/table mutation.
  function snapshotDependentRegs(
    excludeReg: number,
    mutatedIdent: string | null,
    isTableOrCallEffect: boolean,
    currentIdx: number,
    out: string[],
    lvl: number,
    isInlineValueCall = false
  ) {
    const followLtrRoot = (startDefIdx: number, startReg: number): { consumerIdx: number; rootReg: number } | null => {
      let curIdx = startDefIdx;
      let curReg = startReg;
      for (let step = 0; step < 8; step++) {
        const fr = firstReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
        const lr = lastReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
        if (fr <= curIdx || fr !== lr) return null;
        const cons = insns[fr];
        if (!cons) return null;
        const cop = cons.opname;
        if (
          cop === 'CALL' || cop === 'CALLFB' || cop === 'RETURN' || cop === 'CONCAT' || cop === 'SETLIST' ||
          cop === 'ADD' || cop === 'SUB' || cop === 'MUL' || cop === 'DIV' || cop === 'MOD' ||
          cop === 'POW' || cop === 'IDIV' || cop === 'AND' || cop === 'OR' ||
          cop === 'SETTABLE' || cop === 'SETTABLEKS' || cop === 'SETUDATAKS' || cop === 'SETTABLEN'
        ) {
          return { consumerIdx: fr, rootReg: curReg };
        }
        if (cop === 'NAMECALL' || cop === 'NAMECALLUDATA') {
          curIdx = fr;
          curReg = cons.a;
          continue;
        }
        if (!LUAU_NON_WRITING_OPS.has(cop) && cop !== 'GETVARARGS') {
          curIdx = fr;
          curReg = cons.a;
          continue;
        }
        return null;
      }
      return null;
    };

    const followToTargetConsumer = (startDefIdx: number, startReg: number, targetConsumerIdx: number): number | null => {
      let curIdx = startDefIdx;
      let curReg = startReg;
      for (let step = 0; step < 8; step++) {
        const fr = firstReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
        const lr = lastReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
        if (fr <= curIdx || fr !== lr) return null;
        if (fr === targetConsumerIdx) return curReg;
        const mid = insns[fr];
        if (!mid) return null;
        const mop = mid.opname;
        if (mop === 'NAMECALL' || mop === 'NAMECALLUDATA' || ((mop === 'CALL' || mop === 'CALLFB') && (mid.c === 0 || (mid.c !== 1 && mid.c <= 2)))) {
          curIdx = fr;
          curReg = mid.a;
          continue;
        }
        if (!LUAU_NON_WRITING_OPS.has(mop) && mop !== 'CALL' && mop !== 'CALLFB' && mop !== 'GETVARARGS') {
          curIdx = fr;
          curReg = mid.a;
          continue;
        }
        return null;
      }
      return null;
    };

    const willBeSnapshottedBefore = (startIdx: number, tgtConsumerIdx: number, tgtRootReg: number): boolean => {
      for (let k = startIdx + 1; k < tgtConsumerIdx; k++) {
        const ki = insns[k];
        if (!ki) continue;
        const kop = ki.opname;
        const maySnapshot =
          isSideEffectOrControlOp(kop) ||
          kop === 'GETUPVAL' ||
          kop === 'GETTABLE' ||
          kop === 'GETTABLEKS' ||
          kop === 'GETTABLEN' ||
          kop === 'GETUDATAKS' ||
          (kop === 'MOVE' && capturedRefRegs.has(ki.b));
        if (!maySnapshot) continue;
        // If `ki` is a callee load (e.g. MOVE R4, R1 followed by CALL R4) and its consumer is a CALL at `fr` on `ki.a`,
        // follow from that CALL (`fr`) to `tgtConsumerIdx`!
        let kSlot = followToTargetConsumer(k, ki.a, tgtConsumerIdx);
        if (kSlot === null) {
          const fr = firstReadAtDef.get(`${k}:${ki.a}`) ?? -1;
          const lr = lastReadAtDef.get(`${k}:${ki.a}`) ?? -1;
          if (fr > k && fr === lr && insns[fr] && (insns[fr].opname === 'CALL' || insns[fr].opname === 'CALLFB') && insns[fr].a === ki.a) {
            kSlot = followToTargetConsumer(fr, ki.a, tgtConsumerIdx);
          }
        }
        const cons = insns[tgtConsumerIdx];
        if (
          kSlot !== null &&
          cons &&
          ((cons.opname === 'CALL' || cons.opname === 'CALLFB' || cons.opname === 'RETURN' || cons.opname === 'CONCAT' || cons.opname === 'SETLIST')
            ? kSlot > tgtRootReg
            : cons.c === kSlot && cons.b === tgtRootReg)
        ) {
          continue;
        }
        return true;
      }
      return false;
    };

    const excludeLtr = isInlineValueCall
      ? (() => {
          // Climb from excludeReg through single-consumer CALL/expr hops to find every enclosing consumer it feeds,
          // keeping only hops where excludeReg will genuinely remain inline until tgt.consumerIdx.
          const targets: Array<{ consumerIdx: number; rootReg: number }> = [];
          let curIdx = currentIdx;
          let curReg = excludeReg;
          // If currentIdx is a callee load (e.g. MOVE R4, R1) whose sole read is a CALL on R4, step to that CALL first!
          const fr0 = firstReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
          const lr0 = lastReadAtDef.get(`${curIdx}:${curReg}`) ?? -1;
          if (
            fr0 > curIdx &&
            fr0 === lr0 &&
            insns[curIdx] &&
            insns[curIdx].opname !== 'CALL' &&
            insns[curIdx].opname !== 'CALLFB' &&
            insns[fr0] &&
            (insns[fr0].opname === 'CALL' || insns[fr0].opname === 'CALLFB') &&
            insns[fr0].a === curReg &&
            insns[fr0].c !== 1
          ) {
            curIdx = fr0;
          }
          for (let step = 0; step < 6; step++) {
            const hop = followLtrRoot(curIdx, curReg);
            if (!hop) break;
            if (!willBeSnapshottedBefore(curIdx, hop.consumerIdx, hop.rootReg)) {
              targets.push(hop);
            }
            const cons = insns[hop.consumerIdx];
            if (!cons || (cons.opname !== 'CALL' && cons.opname !== 'CALLFB' && cons.opname !== 'ADD' && cons.opname !== 'SUB' && cons.opname !== 'MUL' && cons.opname !== 'DIV' && cons.opname !== 'MOD' && cons.opname !== 'POW' && cons.opname !== 'IDIV')) {
              break;
            }
            if ((cons.opname === 'CALL' || cons.opname === 'CALLFB') && cons.c === 1) break;
            curIdx = hop.consumerIdx;
            curReg = cons.a;
          }
          return targets;
        })()
      : [];

    const isLtrSameConsumer = (r: number, rDef: number | undefined): boolean => {
      if (!isInlineValueCall || excludeLtr.length === 0 || rDef === undefined) return false;
      for (const tgt of excludeLtr) {
        const rSlot = followToTargetConsumer(rDef, r, tgt.consumerIdx);
        if (rSlot === null) continue;
        const cons = insns[tgt.consumerIdx];
        if (!cons) continue;
        const ok = Boolean(
          ((cons.opname === 'CALL' || cons.opname === 'CALLFB' || cons.opname === 'RETURN' || cons.opname === 'CONCAT' || cons.opname === 'SETLIST') &&
            rSlot < tgt.rootReg) ||
            ((cons.opname === 'ADD' ||
              cons.opname === 'SUB' ||
              cons.opname === 'MUL' ||
              cons.opname === 'DIV' ||
              cons.opname === 'MOD' ||
              cons.opname === 'POW' ||
              cons.opname === 'IDIV' ||
              cons.opname === 'AND' ||
              cons.opname === 'OR') &&
              cons.b === rSlot &&
              cons.c === tgt.rootReg) ||
            (cons.opname === 'SETTABLE' && cons.a === tgt.rootReg && (rSlot === cons.b || rSlot === cons.c)) ||
            ((cons.opname === 'SETTABLEKS' || cons.opname === 'SETUDATAKS' || cons.opname === 'SETTABLEN') &&
              cons.a === tgt.rootReg &&
              rSlot === cons.b)
        );
        if (ok) return true;
      }
      return false;
    };

    const doesInsnWriteReg = (ins: DecodedInstruction, insIdx: number, targetR: number): boolean => {
      if (ins.opname === 'FORNPREP') return targetR === ins.a + 2;
      if (ins.opname === 'FORGPREP' || ins.opname === 'FORGPREP_NEXT' || ins.opname === 'FORGPREP_INEXT') {
        const targetIdx = ins.targetPc !== undefined ? pcToIdx.get(ins.targetPc) : undefined;
        const gloop = targetIdx !== undefined ? insns[targetIdx] : undefined;
        const varCount = gloop && gloop.opname === 'FORGLOOP' ? Math.max(1, (gloop.aux ?? 2) & 0xff) : 2;
        return targetR >= ins.a + 3 && targetR < ins.a + 3 + varCount;
      }
      let wrote = false;
      forEachLuauWrittenReg(ins, insIdx, (wr) => {
        if (wr === targetR) wrote = true;
      });
      return wrote;
    };

    const isRegReadLater = (r: number, rDef: number | undefined): boolean => {
      if (rDef !== undefined) {
        const rLastRead = lastReadAtDef.get(`${rDef}:${r}`) ?? -1;
        if (rLastRead >= currentIdx + 1) return true;
      }
      for (let k = currentIdx + 1; k < insns.length; k++) {
        const nextIns = insns[k];
        let readHere = false;
        luauForEachReadReg(nextIns, k, multretEndAt, (rr) => {
          if (rr === r) readHere = true;
        });
        if (readHere) return true;
        if (doesInsnWriteReg(nextIns, k, r)) {
          break;
        }
      }
      return false;
    };

    // 1. Flush any open table containing side-effecting calls, mutable reads, OR mutating an existing declared local (e.g. `log = {}`)!
    for (const [tReg, builder] of Array.from(openTables.entries())) {
      if (tReg === excludeReg) continue;
      const tblHasEffect = builder.entries.some((e) => e.hasEffect);
      const tblReadsMut = builder.entries.some((e) => e.readsMutable);
      const tblRefsIdent = Boolean(mutatedIdent && builder.entries.some((e) => exprReferencesIdent(e.val, mutatedIdent)));
      const tblMutatesExistingLocal = declaredLocals.has(tReg);
      if (tblRefsIdent || tblHasEffect || tblMutatesExistingLocal || (isTableOrCallEffect && tblReadsMut)) {
        if (!tblMutatesExistingLocal && (isLtrSameConsumer(tReg, builder.createdIdx) || (!tblRefsIdent && !isRegReadLater(tReg, builder.createdIdx)))) {
          continue;
        }
        flushOpenTable(tReg, out, lvl, true);
      }
    }

    // 2. Snapshot any unmaterialized expression in another register that has side effects or reads mutable state!
    // Emit in definition order (ascending regDefIdx) so multiple deferred calls preserve exact original statement order!
    const pendingEntries = Array.from(regExpr.entries()).sort((a, b) => {
      const da = regDefIdx.get(a[0]) ?? 0;
      const db = regDefIdx.get(b[0]) ?? 0;
      return da - db;
    });

    const candidates: Array<{ r: number; expr: Expr; rDef: number | undefined; emit: boolean }> = [];
    let maxEffectEmitDefIdx = -1;
    for (const [r, expr] of pendingEntries) {
      if (r === excludeReg || r === multretReg || pendingMethodCalls.has(r)) continue;
      if (declaredLocals.has(r) || openTables.has(r)) continue;
      if (expr.isConst || expr.kind === 'vararg' || expr.kind === 'global' || expr.kind === 'function') continue;

      let depends = false;
      if (expr.hasEffect) {
        depends = true;
      } else if (mutatedIdent && exprReferencesIdent(expr.code, mutatedIdent)) {
        depends = true;
      } else if (
        isTableOrCallEffect &&
        (expr.readsMutable || expr.kind === 'index' || expr.kind === 'call' || expr.kind === 'methodCall')
      ) {
        depends = true;
      }
      const rDef = regDefIdx.get(r);
      const emit = depends && !isLtrSameConsumer(r, rDef) && isRegReadLater(r, rDef);
      if (emit && expr.hasEffect && rDef !== undefined && rDef > maxEffectEmitDefIdx) {
        maxEffectEmitDefIdx = rDef;
      }
      candidates.push({ r, expr, rDef, emit });
    }

    for (const cand of candidates) {
      let shouldEmit = cand.emit;
      if (
        !shouldEmit &&
        maxEffectEmitDefIdx >= 0 &&
        cand.rDef !== undefined &&
        cand.rDef < maxEffectEmitDefIdx &&
        (cand.expr.readsMutable || cand.expr.kind === 'index' || cand.expr.kind === 'call' || cand.expr.kind === 'methodCall') &&
        isRegReadLater(cand.r, cand.rDef)
      ) {
        shouldEmit = true;
      }
      if (!shouldEmit) continue;

      const dbg = cand.rDef !== undefined ? findDebugLocalForDef(cand.r, cand.rDef) : undefined;
      const tmpName = buildSemanticName(dbg?.name ?? inferSemanticHintFromExpr(cand.expr), 'v', usedNames, env.opts, env.metrics);
      out.push(`${indent(lvl)}local ${tmpName} = ${cand.expr.code}`);
      regExpr.set(cand.r, atomExpr(tmpName, { kind: 'ident', isVarRef: true, regOrigin: cand.r, readsMutable: capturedRefRegs.has(cand.r) }));
    }
  }

  function evalPureLuauExpr(ins: DecodedInstruction): { reg: number; expr: Expr } | null {
    switch (ins.opname) {
      case 'LOADNIL':
        return { reg: ins.a, expr: atomExpr('nil', { isConst: true, constVal: null }) };
      case 'LOADB':
        if (ins.c !== 0) return null;
        return { reg: ins.a, expr: atomExpr(ins.b !== 0 ? 'true' : 'false', { isConst: true, constVal: ins.b !== 0 }) };
      case 'LOADN':
        return { reg: ins.a, expr: atomExpr(formatNumber(ins.d, env.opts), { isConst: true, constVal: ins.d }) };
      case 'LOADK':
        return { reg: ins.a, expr: constantToExpr(proto.constants[ins.d], env.opts) };
      case 'LOADKX':
        return { reg: ins.a, expr: constantToExpr(proto.constants[ins.aux ?? 0], env.opts) };
      case 'MOVE':
        return { reg: ins.a, expr: getReg(ins.b) };
      case 'GETIMPORT': {
        const k = proto.constants[ins.d];
        const path = k?.importPath?.join('.') ?? `K${ins.d}`;
        return { reg: ins.a, expr: atomExpr(path, { kind: 'global', calleeName: path }) };
      }
      case 'GETGLOBAL': {
        const k = proto.constants[ins.aux ?? 0];
        const gname = k?.kind === 'string' ? String(k.value) : `G${ins.aux}`;
        return { reg: ins.a, expr: atomExpr(gname, { kind: 'global', calleeName: gname }) };
      }
      case 'GETUPVAL':
        return { reg: ins.a, expr: atomExpr(getUpvalName(ins.b), { kind: 'ident', isVarRef: true, readsMutable: true }) };
      case 'GETTABLEKS':
      case 'GETUDATAKS': {
        const tbl = getReg(ins.b);
        const kIdx = ins.opname === 'GETUDATAKS' ? (ins.aux ?? 0) & 0xffff : ins.aux ?? 0;
        const keyK = proto.constants[kIdx];
        const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
        const tblCode = wrapPrefixExpr(tbl);
        const code = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
        return { reg: ins.a, expr: atomExpr(code, { kind: 'index', prec: 90, calleeName: code, hasEffect: tbl.hasEffect, readsMutable: true }) };
      }
      case 'GETTABLE': {
        const tbl = getReg(ins.b);
        const key = getReg(ins.c);
        return {
          reg: ins.a,
          expr: atomExpr(`${wrapPrefixExpr(tbl)}[${key.code}]`, {
            kind: 'index',
            prec: 90,
            hasEffect: Boolean(tbl.hasEffect || key.hasEffect),
            readsMutable: true,
          }),
        };
      }
      case 'GETTABLEN': {
        const tbl = getReg(ins.b);
        return {
          reg: ins.a,
          expr: atomExpr(`${wrapPrefixExpr(tbl)}[${ins.c + 1}]`, {
            kind: 'index',
            prec: 90,
            hasEffect: tbl.hasEffect,
            readsMutable: true,
          }),
        };
      }
      case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
      case 'AND': case 'OR': {
        const opMap: Record<string, string> = {
          ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^', IDIV: '//', AND: 'and', OR: 'or',
        };
        return { reg: ins.a, expr: foldBinary(opMap[ins.opname], getReg(ins.b), getReg(ins.c), env.opts, env.metrics) };
      }
      case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
      case 'ANDK': case 'ORK': {
        const opMap: Record<string, string> = {
          ADDK: '+', SUBK: '-', MULK: '*', DIVK: '/', MODK: '%', POWK: '^', IDIVK: '//', ANDK: 'and', ORK: 'or',
        };
        return {
          reg: ins.a,
          expr: foldBinary(opMap[ins.opname], getReg(ins.b), constantToExpr(proto.constants[ins.c], env.opts), env.opts, env.metrics),
        };
      }
      case 'SUBRK': case 'DIVRK': {
        const op = ins.opname === 'SUBRK' ? '-' : '/';
        return {
          reg: ins.a,
          expr: foldBinary(op, constantToExpr(proto.constants[ins.b], env.opts), getReg(ins.c), env.opts, env.metrics),
        };
      }
      case 'MINUS': {
        const rhs = getReg(ins.b);
        const rhsCode = rhs.code.startsWith('-') ? `(${rhs.code})` : wrapIfLower(rhs, 80);
        return { reg: ins.a, expr: { kind: 'unary', code: `-${rhsCode}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable } };
      }
      case 'NOT': {
        const rhs = getReg(ins.b);
        return { reg: ins.a, expr: { kind: 'unary', code: `not ${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable } };
      }
      case 'LENGTH': {
        const rhs = getReg(ins.b);
        return { reg: ins.a, expr: { kind: 'unary', code: `#${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: true } };
      }
      default:
        return null;
    }
  }

  function evalLuauJumpCondition(
    ins: DecodedInstruction,
    regsLookup: (r: number) => Expr = getReg,
    booleanContextOnly = true
  ): {
    jumpTakenCond: string;
    fallthroughCond: string;
    staticJumpTaken?: boolean;
    hasEffect: boolean;
    readsMutable: boolean;
    isProvablyBoolTest: boolean;
  } {
    const lhs = regsLookup(ins.a);
    let rhs: Expr = atomExpr('nil', { isConst: true, constVal: null });
    let baseOp: '==' | '~=' | '<' | '<=' = '==';
    let negateTaken = false;

    if (ins.opname === 'JUMPIF') {
      return {
        jumpTakenCond: lhs.code,
        fallthroughCond: invertCondition(lhs.code, booleanContextOnly),
        staticJumpTaken: lhs.isConst ? Boolean(lhs.constVal) : undefined,
        hasEffect: Boolean(lhs.hasEffect),
        readsMutable: Boolean(lhs.readsMutable),
        isProvablyBoolTest: isGuaranteedBooleanExpr(lhs.code),
      };
    }
    if (ins.opname === 'JUMPIFNOT') {
      return {
        jumpTakenCond: invertCondition(lhs.code, booleanContextOnly),
        fallthroughCond: lhs.code,
        staticJumpTaken: lhs.isConst ? !Boolean(lhs.constVal) : undefined,
        hasEffect: Boolean(lhs.hasEffect),
        readsMutable: Boolean(lhs.readsMutable),
        isProvablyBoolTest: isGuaranteedBooleanExpr(lhs.code),
      };
    }

    if (ins.opname === 'JUMPXEQKNIL' || ins.opname === 'JUMPXEQKB' || ins.opname === 'JUMPXEQKN' || ins.opname === 'JUMPXEQKS') {
      const aux = ins.aux ?? 0;
      const notFlag = ((aux >>> 31) & 1) === 1;
      if (ins.opname === 'JUMPXEQKNIL') {
        rhs = atomExpr('nil', { isConst: true, constVal: null });
      } else if (ins.opname === 'JUMPXEQKB') {
        const bVal = (aux & 1) !== 0;
        rhs = atomExpr(bVal ? 'true' : 'false', { isConst: true, constVal: bVal });
      } else {
        const kIdx = aux & 0xffffff;
        rhs = constantToExpr(proto.constants[kIdx], env.opts);
      }
      baseOp = notFlag ? '~=' : '==';
    } else {
      rhs = regsLookup(ins.aux ?? 0);
      if (ins.opname === 'JUMPIFEQ') { baseOp = '=='; negateTaken = false; }
      else if (ins.opname === 'JUMPIFNOTEQ') { baseOp = '=='; negateTaken = true; }
      else if (ins.opname === 'JUMPIFLE') { baseOp = '<='; negateTaken = false; }
      else if (ins.opname === 'JUMPIFNOTLE') { baseOp = '<='; negateTaken = true; }
      else if (ins.opname === 'JUMPIFLT') { baseOp = '<'; negateTaken = false; }
      else if (ins.opname === 'JUMPIFNOTLT') { baseOp = '<'; negateTaken = true; }
    }

    let staticJumpTaken: boolean | undefined;
    if (lhs.isConst && rhs.isConst) {
      const lv = lhs.constVal;
      const rv = rhs.constVal;
      if (baseOp === '==') staticJumpTaken = negateTaken ? lv !== rv : lv === rv;
      else if (baseOp === '~=') staticJumpTaken = negateTaken ? lv === rv : lv !== rv;
      else if (typeof lv === 'number' && typeof rv === 'number') {
        const raw = baseOp === '<' ? lv < rv : lv <= rv;
        staticJumpTaken = negateTaken ? !raw : raw;
      }
    }

    const pair = formatLuauComparisonPair(lhs, rhs, baseOp, negateTaken);
    return {
      jumpTakenCond: pair.jumpTakenCond,
      fallthroughCond: pair.fallthroughCond,
      staticJumpTaken,
      hasEffect: Boolean(lhs.hasEffect || rhs.hasEffect),
      readsMutable: Boolean(lhs.readsMutable || rhs.readsMutable),
      isProvablyBoolTest: true,
    };
  }

  const COMPOUND_ASSIGN_OPS = new Set(['+', '-', '*', '/', '//', '%', '..']);

  function findDebugLocalForDef(reg: number, idx: number, exactOnly = false): { name: string; endPc: number } | undefined {
    if (!env.opts.useDebugLocals) return undefined;
    const ins = insns[idx];
    const pc = ins?.pc ?? 0;
    const width = ins?.width ?? 1;
    // Never assign a debug local name to a GETIMPORT/GETGLOBAL/MOVE that is immediately used as a CALL callee on the same reg
    if (ins && (ins.opname === 'GETIMPORT' || ins.opname === 'GETGLOBAL')) {
      const nextRead = lastReadAtDef.get(`${idx}:${reg}`) ?? -1;
      const targetNext = nextRead >= 0 ? insns[nextRead] : undefined;
      if (targetNext && (targetNext.opname === 'CALL' || targetNext.opname === 'CALLFB') && targetNext.a === reg) {
        return undefined;
      }
    }
    const exact = proto.localVars.find((lv) => {
      if (lv.reg !== reg || lv.name.startsWith('(') || !isValidIdent(lv.name)) return false;
      if (lv.startPc < pc || lv.startPc > pc + width + 4) return false;
      // Verify no other instruction between idx+1 and lv.startPc overwrites `reg`
      for (let k = idx + 1; k < insns.length && insns[k].pc < lv.startPc; k++) {
        const ki = insns[k];
        const isZeroRet = (ki.opname === 'CALL' || ki.opname === 'CALLFB') && ki.c === 1;
        if (!LUAU_NON_WRITING_OPS.has(ki.opname) && !isZeroRet && ki.a === reg) {
          return false;
        }
      }
      return true;
    });
    if (exact) return { name: exact.name, endPc: exact.endPc };
    if (exactOnly) return undefined;
    const covering = proto.localVars.find(
      (lv) => lv.reg === reg && !lv.name.startsWith('(') && isValidIdent(lv.name) && lv.startPc <= pc && lv.endPc > pc
    );
    if (covering) return { name: covering.name, endPc: covering.endPc };
    return undefined;
  }

  function assignReg(
    reg: number,
    expr: Expr,
    idx: number,
    lines: string[],
    lvl: number,
    forceLocal = false,
    preferredHint?: string,
    preferredEndPc?: number
  ) {
    const ins = insns[idx];
    if (ins) expireDebugLocalsAt(ins.pc);

    // If an older open table still lives on `reg` (e.g., dead unused table literal), settle it BEFORE overwriting `reg`!
    if (openTables.has(reg)) {
      settleOpenTableBeforeOverwrite(reg, lines, lvl);
    }

    // CRITICAL SEMANTIC GUARD: Luau ONLY emits CAPTURE 0 (by-value capture) when the captured local is NEVER mutated.
    // Any subsequent write to a register already captured by value MUST be a register reuse for a new local,
    // EVEN IF that same register is later reused for a different variable captured by ref (CAPTURE 1)!
    if (declaredLocals.has(reg) && wasCapturedByVal.has(reg) && !hoistedLocals.has(reg)) {
      releaseDeclaredLocal(reg);
    }

    // Never overwrite a declared `local function` variable with a new declaration/value at the same top-level scope
    if (
      declaredLocals.has(reg) &&
      declaredLocalIsFn.has(reg) &&
      !capturedRefRegs.has(reg) &&
      !hoistedLocals.has(reg) &&
      lvl === indentLevel
    ) {
      releaseDeclaredLocal(reg);
    }

    // If register is being reused as a pure call-callee temp (GETIMPORT/GETGLOBAL/GETUPVAL/GETTABLE*/NAMECALL/MOVE) or SETLIST element temp,
    // never overwrite an old dead local variable in `declaredLocals`!
    if (
      declaredLocals.has(reg) &&
      !capturedRefRegs.has(reg) &&
      ins
    ) {
      const nextRead = lastReadAtDef.get(`${idx}:${reg}`) ?? -1;
      const targetNext = nextRead >= 0 ? insns[nextRead] : undefined;
      const isCalleeTemp =
        (ins.opname === 'GETIMPORT' ||
          ins.opname === 'GETGLOBAL' ||
          ins.opname === 'GETUPVAL' ||
          ins.opname === 'GETTABLEKS' ||
          ins.opname === 'GETTABLE' ||
          ins.opname === 'GETTABLEN' ||
          ins.opname === 'GETUDATAKS' ||
          ins.opname === 'NAMECALL' ||
          ins.opname === 'NAMECALLUDATA' ||
          ins.opname === 'MOVE') &&
        targetNext &&
        (targetNext.opname === 'CALL' || targetNext.opname === 'CALLFB') &&
        targetNext.a === reg;
      const isConstScratchTemp =
        (ins.opname === 'LOADN' ||
          ins.opname === 'LOADK' ||
          ins.opname === 'LOADKX' ||
          ins.opname === 'LOADB' ||
          ins.opname === 'LOADNIL') &&
        !hoistedLocals.has(reg) &&
        !materializeAt.has(`${idx}:${reg}`) &&
        !liveIn[idx].has(reg) &&
        (() => {
          const prevName = declaredLocals.get(reg);
          const declLvl = declaredLocalLvl.get(reg);
          if (declLvl !== undefined && declLvl < lvl) return false;
          const hasMatchingActiveDbg =
            prevName !== undefined &&
            proto.localVars.some(
              (lv) => lv.reg === reg && lv.name === prevName && lv.startPc < ins.pc && lv.endPc > ins.pc
            );
          if (hasMatchingActiveDbg) return false;
          if (!targetNext) return false;
          const op = targetNext.opname;
          return (
            (op === 'SETLIST' && targetNext.a !== reg && reg >= targetNext.b) ||
            op === 'SETTABLE' ||
            op === 'SETTABLEKS' ||
            op === 'SETTABLEN' ||
            op === 'SETUDATAKS' ||
            op === 'CALL' ||
            op === 'CALLFB' ||
            op === 'RETURN' ||
            op === 'CONCAT' ||
            op === 'ADD' ||
            op === 'SUB' ||
            op === 'MUL' ||
            op === 'DIV' ||
            op === 'MOD' ||
            op === 'POW' ||
            op === 'IDIV' ||
            op === 'ADDK' ||
            op === 'SUBK' ||
            op === 'MULK' ||
            op === 'DIVK' ||
            op === 'MODK' ||
            op === 'POWK' ||
            op === 'IDIVK' ||
            op === 'SUBRK' ||
            op === 'DIVRK' ||
            op === 'JUMPIFEQ' ||
            op === 'JUMPIFLE' ||
            op === 'JUMPIFLT' ||
            op === 'JUMPIFNOTEQ' ||
            op === 'JUMPIFNOTLE' ||
            op === 'JUMPIFNOTLT'
          );
        })();
      if (isCalleeTemp) {
        if (hoistedLocals.has(reg) || liveIn[idx].has(reg)) {
          regExpr.set(reg, expr);
          regDefIdx.set(reg, idx);
          return;
        }
        releaseDeclaredLocal(reg);
      } else if (isConstScratchTemp) {
        releaseDeclaredLocal(reg);
      }
    }

    // Never reuse a variable whose old value is completely dead at `idx` in the same lexical scope!
    if (isDeadLocalAtReuse(reg, idx, lvl, expr.code)) {
      releaseDeclaredLocal(reg);
    }

    // If debug info explicitly starts a NEW differently-named local right at this def (after an earlier dead local),
    // release the stale local binding. Inside nested blocks, only release if the previous debug local already expired.
    if (declaredLocals.has(reg) && !capturedRefRegs.has(reg) && !hoistedLocals.has(reg)) {
      const dbgStart = findDebugLocalForDef(reg, idx, true);
      const prevEnd = declaredLocalEndPc.get(reg);
      const canTransitionHere = lvl === indentLevel || (prevEnd !== undefined && ins && prevEnd <= ins.pc + ins.width);
      if (canTransitionHere && dbgStart && dbgStart.name !== declaredLocals.get(reg) && !upvalNameSet.has(dbgStart.name)) {
        releaseDeclaredLocal(reg);
      }
    }

    regDefIdx.set(reg, idx);

    const existingLocal = declaredLocals.get(reg);
    if (existingLocal) {
      // Flush any open table literal that references `existingLocal` BEFORE mutating `existingLocal`!
      for (const [tReg, builder] of Array.from(openTables.entries())) {
        if (
          tReg !== reg &&
          builder.entries.some((e) => exprReferencesIdent(e.val, existingLocal) || (e.key ? exprReferencesIdent(e.key, existingLocal) : false))
        ) {
          flushOpenTable(tReg, lines, lvl);
        }
      }
      // Snapshot any unmaterialized expressions in other registers that still depend on `existingLocal`
      snapshotDependentRegs(reg, existingLocal, false, idx, lines, lvl);

      if (
        env.opts.compoundAssignments &&
        expr.kind === 'binary' &&
        expr.binOp &&
        COMPOUND_ASSIGN_OPS.has(expr.binOp) &&
        expr.binLhs === existingLocal &&
        expr.binRhs !== undefined
      ) {
        lines.push(`${indent(lvl)}${existingLocal} ${expr.binOp}= ${expr.binRhs}`);
        regExpr.set(reg, atomExpr(existingLocal, { kind: 'ident', isVarRef: true, regOrigin: reg, readsMutable: capturedRefRegs.has(reg) }));
        return;
      }
      if (expr.kind === 'function' && expr.code.startsWith('function(')) {
        lines.push(`${indent(lvl)}function ${existingLocal}${expr.code.slice('function'.length)}`);
        declaredLocalIsFn.add(reg);
      } else {
        lines.push(`${indent(lvl)}${existingLocal} = ${expr.code}`);
      }
      regExpr.set(reg, atomExpr(existingLocal, { kind: 'ident', isVarRef: true, regOrigin: reg, readsMutable: capturedRefRegs.has(reg) }));
      return;
    }

    if (forceLocal || materializeAt.has(`${idx}:${reg}`)) {
      const dbg = findDebugLocalForDef(reg, idx);
      let forwardClosureName: string | undefined;
      if (!preferredHint && !dbg?.name && ins && ins.opname === 'LOADNIL') {
        for (let k = idx + 1; k < Math.min(insns.length, idx + 16); k++) {
          const ki = insns[k];
          if ((ki.opname === 'NEWCLOSURE' || ki.opname === 'DUPCLOSURE') && ki.a === reg) {
            const cid = ki.opname === 'NEWCLOSURE' ? proto.childProtos[ki.d] : proto.constants[ki.d]?.closureProtoId;
            const cProto = cid !== undefined ? env.chunk.protos[cid] : undefined;
            if (cProto && isValidIdent(cProto.debugName)) {
              forwardClosureName = cProto.debugName;
            }
            break;
          }
          if (
            ki.opname === 'RETURN' ||
            ki.opname === 'JUMP' ||
            ki.opname === 'JUMPBACK' ||
            isLuauCondJump(ki.opname) ||
            (!LUAU_NON_WRITING_OPS.has(ki.opname) && ki.a === reg)
          ) {
            break;
          }
        }
      }
      const tableHint =
        expr.kind === 'table'
          ? appendTableRegs.has(reg)
            ? 'items'
            : metatableRegs.has(reg)
              ? 'mt'
              : /^\{[^{}]*\b[A-Za-z_][A-Za-z0-9_]*\s*=/.test(expr.code)
                ? 'config'
                : undefined
          : undefined;
      let hint = preferredHint ?? dbg?.name ?? forwardClosureName ?? (expr.kind === 'table' ? tableHint : inferSemanticHintFromExpr(expr));
      let isStrongHint = Boolean(preferredHint || dbg?.name || forwardClosureName);
      if (!hint && env.opts.renamingType === 'SEMANTIC') {
        if (expr.isConst && typeof expr.constVal === 'number') {
          if (stepOneRegs.has(reg)) hint = 'count';
          else if (accumRegs.has(reg)) hint = 'total';
        }
      }
      const fallback = expr.kind === 'table' ? 't' : expr.kind === 'function' ? 'fn' : typeof expr.constVal === 'number' ? 'n' : 'v';
      const localName = buildSemanticName(hint, fallback, usedNames, env.opts, env.metrics, isStrongHint);
      declaredLocals.set(reg, localName);
      declaredLocalLvl.set(reg, lvl);
      if (expr.kind === 'function' || forwardClosureName) declaredLocalIsFn.add(reg);
      const endPcToRecord = preferredEndPc ?? dbg?.endPc;
      if (endPcToRecord !== undefined) declaredLocalEndPc.set(reg, endPcToRecord);
      if (expr.kind === 'function' && expr.code.startsWith('function(')) {
        lines.push(`${indent(lvl)}local function ${localName}${expr.code.slice('function'.length)}`);
      } else if (expr.isConst && expr.constVal === null) {
        lines.push(`${indent(lvl)}local ${localName}`);
      } else {
        lines.push(`${indent(lvl)}local ${localName} = ${expr.code}`);
      }
      regExpr.set(reg, atomExpr(localName, { kind: 'ident', isVarRef: true, regOrigin: reg, readsMutable: capturedRefRegs.has(reg) }));
      return;
    }

    // Keep as clean inline symbolic expression
    regExpr.set(reg, expr);
  }

  // Hoist and pre-declare any local variable that must remain in scope across a structured block
  // (if/elseif/else, if-without-else, while, repeat, for):
  //   1. Outer unmaterialized expressions that are live after `exitIdx` and could be invalidated or
  //      snapshotted inside `[spanStart..spanEnd)` are materialized BEFORE entering the block.
  //   2. Registers written inside `[spanStart..spanEnd)` (including multi-return CALL/GETVARARGS)
  //      that are live at `exitIdx` (or loop-carried at `loopHeaderIdx`) are pre-declared BEFORE
  //      entering the block, preserving their prior value whenever live-in at `entryIdx`.
  function hoistBlockLiveLocals(
    entryIdx: number,
    spanStart: number,
    spanEnd: number,
    exitIdx: number,
    out: string[],
    lvl: number,
    opts?: { excludeRegs?: Set<number>; loopHeaderIdx?: number }
  ): boolean {
    const excludeRegs = opts?.excludeRegs;
    const liveAfter = new Set<number>();
    if (exitIdx >= 0 && exitIdx < insns.length) {
      for (const r of liveIn[exitIdx]) liveAfter.add(r);
    }
    if (opts?.loopHeaderIdx !== undefined && opts.loopHeaderIdx >= 0 && opts.loopHeaderIdx < insns.length) {
      for (const r of liveIn[opts.loopHeaderIdx]) liveAfter.add(r);
    }
    if (excludeRegs) {
      for (const r of excludeRegs) liveAfter.delete(r);
    }
    if (liveAfter.size === 0) return false;

    const writtenInSpan = new Set<number>();
    const mutatedNames = new Set<string>();
    let hasBlockSideEffect = false;
    const clampedEnd = Math.min(spanEnd, insns.length);
    for (let k = Math.max(0, spanStart); k < clampedEnd; k++) {
      const ins = insns[k];
      const op = ins.opname;
      if (
        op === 'CALL' ||
        op === 'CALLFB' ||
        op === 'SETTABLE' ||
        op === 'SETTABLEKS' ||
        op === 'SETUDATAKS' ||
        op === 'SETTABLEN' ||
        op === 'SETLIST' ||
        op === 'SETGLOBAL' ||
        op === 'SETUPVAL'
      ) {
        hasBlockSideEffect = true;
      }
      if (op === 'SETUPVAL') {
        mutatedNames.add(getUpvalName(ins.b));
      } else if (op === 'SETGLOBAL') {
        const gk = proto.constants[ins.aux ?? 0];
        if (gk?.kind === 'string') mutatedNames.add(String(gk.value));
      }
      forEachLuauWrittenReg(ins, k, (r) => {
        writtenInSpan.add(r);
        const existing = declaredLocals.get(r);
        if (existing) mutatedNames.add(existing);
      });
    }

    let materializedPrior = false;

    // Pass 1: Materialize outer unmaterialized expressions that survive past `exitIdx` and could
    // otherwise be invalidated or snapshotted into a block-local inside the child block.
    const pendingOuter = Array.from(regExpr.entries()).sort((a, b) => {
      const da = regDefIdx.get(a[0]) ?? 0;
      const db = regDefIdx.get(b[0]) ?? 0;
      return da - db;
    });
    for (const [r, expr] of pendingOuter) {
      if (excludeRegs?.has(r) || r === multretReg || pendingMethodCalls.has(r) || declaredLocals.has(r) || openTables.has(r) || writtenInSpan.has(r)) continue;
      if (!liveAfter.has(r)) continue;
      if (expr.isConst || expr.kind === 'vararg' || expr.kind === 'global' || expr.kind === 'function') continue;

      const refsMutated =
        mutatedNames.size > 0 && Array.from(mutatedNames).some((nm) => exprReferencesIdent(expr.code, nm));
      const needsHoist =
        Boolean(expr.hasEffect) ||
        refsMutated ||
        (hasBlockSideEffect &&
          Boolean(
            expr.readsMutable ||
              expr.kind === 'index' ||
              expr.kind === 'table' ||
              expr.kind === 'call' ||
              expr.kind === 'methodCall'
          ));
      if (!needsHoist) continue;

      const rDef = regDefIdx.get(r);
      const dbg = rDef !== undefined ? findDebugLocalForDef(r, rDef) : undefined;
      const hint = dbg?.name ?? inferSemanticHintFromExpr(expr);
      const localName = buildSemanticName(hint, 'v', usedNames, env.opts, env.metrics, Boolean(dbg?.name));
      declaredLocals.set(r, localName);
      declaredLocalLvl.set(r, lvl);
      hoistedLocals.add(r);
      if (dbg) declaredLocalEndPc.set(r, dbg.endPc);
      out.push(`${indent(lvl)}local ${localName} = ${expr.code}`);
      regExpr.set(r, atomExpr(localName, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) }));
      materializedPrior = true;
    }

    // Pass 2: Pre-declare any register written inside the block that is live after `exitIdx` (or loop-carried).
    const exitPc = exitIdx >= 0 && exitIdx < insns.length ? insns[exitIdx].pc : 0;
    const entryLive = entryIdx >= 0 && entryIdx < insns.length ? liveIn[entryIdx] : undefined;
    const sortedWritten = Array.from(writtenInSpan).sort((a, b) => a - b);
    for (const r of sortedWritten) {
      if (excludeRegs?.has(r) || declaredLocals.has(r)) continue;
      if (!liveAfter.has(r)) continue;

      const isLiveAtEntry = Boolean(entryLive?.has(r));
      let priorExpr: Expr | undefined;
      if (isLiveAtEntry) {
        if (openTables.has(r)) {
          const b = openTables.get(r)!;
          openTables.delete(r);
          const tblCode = formatTableLiteral(b.entries, indent, lvl);
          if (b.entries.length > 0) env.metrics.tablesFolded++;
          priorExpr = atomExpr(tblCode, { kind: 'table', prec: 100 });
        } else {
          priorExpr = regExpr.get(r);
        }
      }

      const dbgAtExit =
        env.opts.useDebugLocals && exitIdx < insns.length
          ? proto.localVars.find(
              (lv) =>
                lv.reg === r &&
                !lv.name.startsWith('(') &&
                isValidIdent(lv.name) &&
                lv.startPc <= exitPc &&
                lv.endPc > exitPc
            )
          : undefined;
      const dbg = dbgAtExit
        ? { name: dbgAtExit.name, endPc: dbgAtExit.endPc }
        : findDebugLocalForDef(r, spanStart);
      const hint = dbg?.name ?? (priorExpr ? inferSemanticHintFromExpr(priorExpr) : undefined);
      const localName = buildSemanticName(hint, 'v', usedNames, env.opts, env.metrics, Boolean(dbg?.name));
      declaredLocals.set(r, localName);
      declaredLocalLvl.set(r, lvl);
      hoistedLocals.add(r);
      if (dbg && dbg.endPc > exitPc) declaredLocalEndPc.set(r, dbg.endPc);
      regExpr.set(r, atomExpr(localName, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) }));
      if (priorExpr && !(priorExpr.isConst && priorExpr.constVal === null)) {
        out.push(`${indent(lvl)}local ${localName} = ${priorExpr.code}`);
        materializedPrior = true;
      } else {
        out.push(`${indent(lvl)}local ${localName}`);
      }
    }

    return materializedPrior;
  }

  const activeLoops = new Set<DetectedLoop>();

  function combineBoolChain(terms: Array<{ cond: string; opToNext: 'and' | 'or' | null }>): string {
    if (terms.length === 0) return 'true';
    let acc = terms[terms.length - 1].cond;
    let accPrec = inferExprPrec(acc);
    for (let k = terms.length - 2; k >= 0; k--) {
      const op = terms[k].opToNext ?? 'and';
      const lhsRaw = terms[k].cond;
      const lhsPrec = inferExprPrec(lhsRaw);
      if (op === 'and') {
        const lhs = lhsPrec < 30 ? `(${lhsRaw})` : lhsRaw;
        const rhs = accPrec < 30 ? `(${acc})` : acc;
        acc = `${lhs} and ${rhs}`;
        accPrec = 30;
      } else {
        const lhs = lhsPrec < 20 ? `(${lhsRaw})` : lhsRaw;
        const rhs = accPrec < 20 ? `(${acc})` : acc;
        acc = `${lhs} or ${rhs}`;
        accPrec = 20;
      }
    }
    return acc;
  }

  interface LexicalScopeSnapshot {
    declared: Map<number, string>;
    endPc: Map<number, number>;
    localLvl: Map<number, number>;
    isFn: Set<number>;
    capVal: Set<number>;
    hoisted: Set<number>;
    protoMap: Map<number, number>;
    exprs: Map<number, Expr>;
    defIdx: Map<number, number>;
    tables: Map<number, OpenTableBuilder>;
  }

  function snapshotLexicalScope(): LexicalScopeSnapshot {
    return {
      declared: new Map(declaredLocals),
      endPc: new Map(declaredLocalEndPc),
      localLvl: new Map(declaredLocalLvl),
      isFn: new Set(declaredLocalIsFn),
      capVal: new Set(wasCapturedByVal),
      hoisted: new Set(hoistedLocals),
      protoMap: new Map(localProtoMap),
      exprs: new Map(regExpr),
      defIdx: new Map(regDefIdx),
      tables: new Map(openTables),
    };
  }

  function restoreLexicalScope(snap: LexicalScopeSnapshot, blockLines?: string[], blockLvl?: number) {
    // If an outer declared local was assigned a table literal inside the block, flush that assignment
    // before exiting the block so it is never lost when restoring outer scope.
    if (blockLines && blockLvl !== undefined) {
      const lastLine = blockLines[blockLines.length - 1]?.trim();
      const endedWithTerminator =
        lastLine !== undefined &&
        (lastLine === 'return' || lastLine.startsWith('return ') || lastLine === 'break' || lastLine === 'continue');
      if (!endedWithTerminator) {
        for (const tReg of Array.from(openTables.keys())) {
          if (snap.declared.has(tReg)) {
            flushOpenTable(tReg, blockLines, blockLvl, true);
          }
        }
      }
    }

    declaredLocals.clear();
    for (const [r, nm] of snap.declared) declaredLocals.set(r, nm);
    declaredLocalEndPc.clear();
    for (const [r, ep] of snap.endPc) declaredLocalEndPc.set(r, ep);
    declaredLocalLvl.clear();
    for (const [r, lv] of snap.localLvl) declaredLocalLvl.set(r, lv);
    declaredLocalIsFn.clear();
    for (const r of snap.isFn) declaredLocalIsFn.add(r);
    wasCapturedByVal.clear();
    for (const r of snap.capVal) wasCapturedByVal.add(r);
    hoistedLocals.clear();
    for (const r of snap.hoisted) hoistedLocals.add(r);
    localProtoMap.clear();
    for (const [r, pid] of snap.protoMap) localProtoMap.set(r, pid);
    regExpr.clear();
    for (const [r, ex] of snap.exprs) regExpr.set(r, ex);
    regDefIdx.clear();
    for (const [r, di] of snap.defIdx) regDefIdx.set(r, di);
    openTables.clear();
    for (const [r, tb] of snap.tables) openTables.set(r, tb);
  }

  function liftBlockScoped(startIdx: number, endIdx: number, lvl: number, loopStack: LoopContext[]): string[] {
    const snap = snapshotLexicalScope();
    const result = liftRange(startIdx, endIdx, lvl, loopStack);
    restoreLexicalScope(snap, result, lvl);
    return result;
  }

  function liftRange(startIdx: number, endIdx: number, lvl: number, loopStack: LoopContext[]): string[] {
    const out: string[] = [];
    let i = startIdx;

    while (i < endIdx) {
      const ins = insns[i];
      expireDebugLocalsAt(ins.pc);

      // Unified outermost-first loop dispatch: handles nested loops sharing the same headerIdx
      // (e.g. `repeat while ... do ... end ... until ...`, `repeat repeat ... until ... until ...`, `while true do while ... end end`).
      const headerLoops = loopsByHeaderIdx.get(i);
      if (headerLoops) {
        const nextLoop = headerLoops.find((l) => !activeLoops.has(l) && l.latchIdx < endIdx);
        if (nextLoop) {
          flushAllOpenTables(out, lvl, true);
          hoistBlockLiveLocals(
            nextLoop.headerIdx,
            nextLoop.headerIdx,
            nextLoop.latchIdx + 1,
            nextLoop.latchIdx + 1,
            out,
            lvl,
            { loopHeaderIdx: nextLoop.headerIdx }
          );
          activeLoops.add(nextLoop);
          if (nextLoop.kind === 'while') {
            let whileCondStr: string;
            if (nextLoop.condJumps.length > 0) {
              const terms: Array<{ cond: string; opToNext: 'and' | 'or' | null }> = [];
              let cursor = nextLoop.headerIdx;
              for (let t = 0; t < nextLoop.condJumps.length; t++) {
                const cj = nextLoop.condJumps[t];
                if (cursor < cj.idx) {
                  const setupLines = liftRange(cursor, cj.idx, lvl, loopStack);
                  out.push(...setupLines);
                }
                const c = evalLuauJumpCondition(insns[cj.idx]);
                const isLast = t === nextLoop.condJumps.length - 1;
                if (cj.kind === 'enter') {
                  terms.push({ cond: c.jumpTakenCond, opToNext: isLast ? null : 'or' });
                } else {
                  terms.push({ cond: c.fallthroughCond, opToNext: isLast ? null : 'and' });
                }
                cursor = cj.idx + 1;
              }
              whileCondStr = combineBoolChain(terms);
            } else {
              // General boolean-DAG condition lifter (handles `(A and B) or C`, `(A or B) and C`, etc.)
              interface BoolNode {
                kind: 'true' | 'false' | 'atom' | 'and' | 'or';
                code: string;
                lhs?: BoolNode;
                rhs?: BoolNode;
              }
              const mkAnd = (a: BoolNode, b: BoolNode): BoolNode => {
                if (a.kind === 'true') return b;
                if (b.kind === 'true') return a;
                if (a.kind === 'false' || b.kind === 'false') return { kind: 'false', code: 'false' };
                const l = a.kind === 'or' ? `(${a.code})` : a.code;
                const r = b.kind === 'or' ? `(${b.code})` : b.code;
                return { kind: 'and', code: `${l} and ${r}`, lhs: a, rhs: b };
              };
              const mkOr = (a: BoolNode, b: BoolNode): BoolNode => {
                if (a.kind === 'false') return b;
                if (b.kind === 'false') return a;
                if (a.kind === 'true' || b.kind === 'true') return { kind: 'true', code: 'true' };
                const l = a.kind === 'and' ? `(${a.code})` : a.code;
                const r = b.kind === 'and' ? `(${b.code})` : b.code;
                return { kind: 'or', code: `${l} or ${r}`, lhs: a, rhs: b };
              };
              const bodyStartPc = insns[nextLoop.condEndIdx].pc;
              const liftDag = (curIdx: number, depth: number): BoolNode => {
                if (depth > 20 || curIdx >= insns.length) return { kind: 'true', code: 'true' };
                const curPc = insns[curIdx].pc;
                if (curPc === bodyStartPc) return { kind: 'true', code: 'true' };
                if (curPc === nextLoop.exitPc) return { kind: 'false', code: 'false' };
                const savedRegs = new Map(regExpr);
                let p = curIdx;
                while (p < nextLoop.condEndIdx && !isLuauCondJump(insns[p].opname)) {
                  const pure = evalPureLuauExpr(insns[p]);
                  if (pure) {
                    regExpr.set(pure.reg, pure.expr);
                  } else {
                    // Handle GETTABLE / GETTABLEKS / GETTABLEN / GETUPVAL / GETIMPORT purely for cond eval
                    const pi = insns[p];
                    if (pi.opname === 'GETTABLE') {
                      regExpr.set(pi.a, atomExpr(`${getReg(pi.b).code}[${getReg(pi.c).code}]`, { kind: 'index', prec: 90 }));
                    } else if (pi.opname === 'GETTABLEKS' || pi.opname === 'GETUDATAKS') {
                      const kIdx = pi.opname === 'GETUDATAKS' ? (pi.aux ?? 0) & 0xffff : pi.aux ?? 0;
                      const keyK = proto.constants[kIdx];
                      const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                      const code = isValidIdent(keyStr) ? `${getReg(pi.b).code}.${keyStr}` : `${getReg(pi.b).code}[${escapeLuaString(keyStr)}]`;
                      regExpr.set(pi.a, atomExpr(code, { kind: 'index', prec: 90 }));
                    } else if (pi.opname === 'GETTABLEN') {
                      regExpr.set(pi.a, atomExpr(`${getReg(pi.b).code}[${pi.c + 1}]`, { kind: 'index', prec: 90 }));
                    } else if (pi.opname === 'GETUPVAL') {
                      regExpr.set(pi.a, atomExpr(getUpvalName(pi.b), { kind: 'ident', isVarRef: true }));
                    }
                  }
                  p++;
                }
                if (p >= nextLoop.condEndIdx) {
                  regExpr.clear();
                  for (const [k, v] of savedRegs) regExpr.set(k, v);
                  return { kind: 'true', code: 'true' };
                }
                const jIns = insns[p];
                const c = evalLuauJumpCondition(jIns);
                const tIdx = jIns.targetPc !== undefined ? (pcToIdx.get(jIns.targetPc) ?? nextLoop.condEndIdx) : nextLoop.condEndIdx;
                const takenNode = jIns.targetPc === bodyStartPc
                  ? ({ kind: 'true', code: 'true' } as BoolNode)
                  : jIns.targetPc === nextLoop.exitPc
                    ? ({ kind: 'false', code: 'false' } as BoolNode)
                    : liftDag(tIdx, depth + 1);
                const fallNode = liftDag(p + 1, depth + 1);
                regExpr.clear();
                for (const [k, v] of savedRegs) regExpr.set(k, v);

                const atomTaken: BoolNode = { kind: 'atom', code: c.jumpTakenCond };
                const atomFall: BoolNode = { kind: 'atom', code: c.fallthroughCond };
                if (takenNode.kind === 'true' && fallNode.kind === 'false') return atomTaken;
                if (takenNode.kind === 'false' && fallNode.kind === 'true') return atomFall;
                if (takenNode.kind === 'true') return mkOr(atomTaken, fallNode);
                if (takenNode.kind === 'false') return mkAnd(atomFall, fallNode);
                if (fallNode.kind === 'true') return mkOr(atomFall, takenNode);
                if (fallNode.kind === 'false') return mkAnd(atomTaken, takenNode);
                // Common-suffix factoring: `(A and (B or C)) or (not A and C)` -> `(A and B) or C`
                if (fallNode.kind === 'or' && fallNode.rhs && fallNode.lhs && fallNode.rhs.code === takenNode.code) {
                  return mkOr(mkAnd(atomFall, fallNode.lhs), takenNode);
                }
                if (fallNode.kind === 'and' && fallNode.rhs && fallNode.lhs && fallNode.rhs.code === takenNode.code) {
                  return mkAnd(mkOr(atomTaken, fallNode.lhs), takenNode);
                }
                if (takenNode.kind === 'or' && takenNode.rhs && takenNode.lhs && takenNode.rhs.code === fallNode.code) {
                  return mkOr(mkAnd(atomTaken, takenNode.lhs), fallNode);
                }
                if (takenNode.kind === 'and' && takenNode.rhs && takenNode.lhs && takenNode.rhs.code === fallNode.code) {
                  return mkAnd(mkOr(atomFall, takenNode.lhs), fallNode);
                }
                return mkOr(mkAnd(atomTaken, takenNode), mkAnd(atomFall, fallNode));
              };
              whileCondStr = liftDag(nextLoop.headerIdx, 0).code;
            }
            const loopCtx: LoopContext = {
              kind: 'while',
              headerPc: nextLoop.headerPc,
              latchPc: nextLoop.latchPc,
              continuePc: nextLoop.headerPc,
              exitPc: nextLoop.exitPc,
            };
            out.push(`${indent(lvl)}while ${whileCondStr} do`);
            out.push(...liftBlockScoped(nextLoop.condEndIdx, nextLoop.latchIdx, lvl + 1, [...loopStack, loopCtx]));
            out.push(`${indent(lvl)}end`);
          } else if (nextLoop.kind === 'repeat') {
            const repeatSnap = snapshotLexicalScope();
            const loopCtx: LoopContext = {
              kind: 'repeat',
              headerPc: nextLoop.headerPc,
              latchPc: nextLoop.latchPc,
              continuePc: nextLoop.condStartPc,
              exitPc: nextLoop.exitPc,
            };
            out.push(`${indent(lvl)}repeat`);
            const bodyEnd = nextLoop.condStartIdx;
            const bodyLines = liftRange(i, bodyEnd, lvl + 1, [...loopStack, loopCtx]);
            out.push(...bodyLines);

            if (insns[nextLoop.latchIdx].opname === 'JUMPBACK') {
              const terms: Array<{ cond: string; opToNext: 'and' | 'or' | null }> = [];
              let cursor = nextLoop.condStartIdx;
              for (let t = 0; t < nextLoop.tailJumps.length; t++) {
                const tj = nextLoop.tailJumps[t];
                if (cursor < tj.idx) {
                  out.push(...liftRange(cursor, tj.idx, lvl + 1, [...loopStack, loopCtx]));
                }
                const c = evalLuauJumpCondition(insns[tj.idx]);
                const isLast = t === nextLoop.tailJumps.length - 1;
                if (tj.kind === 'exit') {
                  terms.push({ cond: c.jumpTakenCond, opToNext: isLast ? null : 'or' });
                } else {
                  terms.push({ cond: c.fallthroughCond, opToNext: isLast ? null : 'and' });
                }
                cursor = tj.idx + 1;
              }
              out.push(`${indent(lvl)}until ${combineBoolChain(terms)}`);
            } else {
              const untilCond = evalLuauJumpCondition(insns[nextLoop.latchIdx]);
              out.push(`${indent(lvl)}until ${untilCond.fallthroughCond}`);
            }

            // Locals declared inside `repeat` are visible in `until`, then go out of scope after `until`.
            restoreLexicalScope(repeatSnap);
          } else {
            const loopCtx: LoopContext = {
              kind: 'while',
              headerPc: nextLoop.headerPc,
              latchPc: nextLoop.latchPc,
              continuePc: nextLoop.headerPc,
              exitPc: nextLoop.exitPc,
            };
            out.push(`${indent(lvl)}while true do`);
            out.push(...liftBlockScoped(i, nextLoop.latchIdx, lvl + 1, [...loopStack, loopCtx]));
            out.push(`${indent(lvl)}end`);
          }
          activeLoops.delete(nextLoop);
          i = nextLoop.latchIdx + 1;
          continue;
        }
      }

      // General forward-jump Value DAG lifter (handles arbitrary boolean `and`/`or` DAGs, `LOADB` presets,
      // `MOVE` presets, value-producing `a and b or c`, and Luau `if a then b else c` expressions).
      function tryLiftValueDag(
        sliceStart: number,
        maxEndIdx: number,
        presetDestReg = -1
      ): { nextIdx: number } | null {
        // 1. Find minimal forward-jump transitive closure [sliceStart .. joinIdx)
        let firstJumpIdx = sliceStart;
        while (firstJumpIdx < maxEndIdx && !isLuauCondJump(insns[firstJumpIdx].opname)) {
          if (firstJumpIdx > sliceStart && (allLoopHeaderIdxs.has(firstJumpIdx) || backwardJumpTargetIdxs.has(firstJumpIdx))) {
            return null;
          }
          const op = insns[firstJumpIdx].opname;
          if (
            op === 'JUMP' ||
            op === 'JUMPX' ||
            op === 'JUMPBACK' ||
            op === 'RETURN' ||
            op === 'SETUPVAL' ||
            op === 'SETGLOBAL' ||
            op === 'FORNPREP' ||
            op === 'FORNLOOP' ||
            op === 'FORGPREP' ||
            op === 'FORGPREP_NEXT' ||
            op === 'FORGPREP_INEXT' ||
            op === 'FORGLOOP' ||
            op === 'CLOSEUPVALS' ||
            op === 'NEWCLOSURE' ||
            op === 'DUPCLOSURE' ||
            op === 'LOADB' && insns[firstJumpIdx].c !== 0
          ) {
            return null;
          }
          firstJumpIdx++;
        }
        if (firstJumpIdx >= maxEndIdx) return null;
        // Do not let a preset scan swallow unrelated statements far ahead
        if (firstJumpIdx - sliceStart > 8) return null;

        const firstTargetPc = insns[firstJumpIdx].targetPc;
        const firstTargetIdx = firstTargetPc !== undefined ? pcToIdx.get(firstTargetPc) : undefined;
        if (firstTargetIdx === undefined || firstTargetIdx <= firstJumpIdx + 1 || firstTargetIdx > maxEndIdx) {
          return null;
        }

        let limit = firstTargetIdx;
        let hasAnyJumpOrLoadbSkip = false;
        for (let k = sliceStart; k < limit; k++) {
          if (k > sliceStart && (allLoopHeaderIdxs.has(k) || backwardJumpTargetIdxs.has(k))) {
            return null;
          }
          const ki = insns[k];
          const kop = ki.opname;
          if (isLuauCondJump(kop) || kop === 'JUMP' || kop === 'JUMPX') {
            hasAnyJumpOrLoadbSkip = true;
            const tPc = ki.targetPc;
            const tIdx = tPc !== undefined ? pcToIdx.get(tPc) : undefined;
            if (tIdx === undefined || tIdx <= k || tIdx > maxEndIdx) return null;
            if (tIdx > limit) limit = tIdx;
          } else if (kop === 'LOADB' && ki.c !== 0) {
            hasAnyJumpOrLoadbSkip = true;
            if (k + 2 > maxEndIdx) return null;
            if (k + 2 > limit) limit = k + 2;
          } else if (
            kop === 'RETURN' ||
            kop === 'SETUPVAL' ||
            kop === 'SETGLOBAL' ||
            kop === 'FORNPREP' ||
            kop === 'FORNLOOP' ||
            kop === 'FORGPREP' ||
            kop === 'FORGPREP_NEXT' ||
            kop === 'FORGPREP_INEXT' ||
            kop === 'FORGLOOP' ||
            kop === 'JUMPBACK' ||
            kop === 'CLOSEUPVALS' ||
            kop === 'NEWCLOSURE' ||
            kop === 'DUPCLOSURE' ||
            ((kop === 'CALL' || kop === 'CALLFB') && (ki.c !== 2 || ki.b === 0)) ||
            (kop === 'GETVARARGS' && ki.b !== 2)
          ) {
            return null;
          }
        }
        if (!hasAnyJumpOrLoadbSkip) return null;
        const joinIdx = limit;

        // 2. Determine destination register `destReg`
        let destReg = presetDestReg;
        if (destReg < 0) {
          const lastBeforeJoin = insns[joinIdx - 1];
          if (
            lastBeforeJoin &&
            (lastBeforeJoin.opname === 'LOADB' ||
              lastBeforeJoin.opname === 'LOADN' ||
              lastBeforeJoin.opname === 'LOADK' ||
              lastBeforeJoin.opname === 'LOADKX' ||
              lastBeforeJoin.opname === 'LOADNIL' ||
              lastBeforeJoin.opname === 'MOVE' ||
              lastBeforeJoin.opname === 'GETIMPORT' ||
              lastBeforeJoin.opname === 'GETGLOBAL' ||
              lastBeforeJoin.opname === 'GETUPVAL' ||
              lastBeforeJoin.opname === 'GETTABLEKS' ||
              lastBeforeJoin.opname === 'GETUDATAKS' ||
              lastBeforeJoin.opname === 'GETTABLE' ||
              lastBeforeJoin.opname === 'GETTABLEN' ||
              lastBeforeJoin.opname === 'CALL' ||
              lastBeforeJoin.opname === 'CALLFB' ||
              lastBeforeJoin.opname === 'NOT' ||
              lastBeforeJoin.opname === 'MINUS' ||
              lastBeforeJoin.opname === 'LENGTH' ||
              lastBeforeJoin.opname === 'CONCAT' ||
              lastBeforeJoin.opname === 'ADD' ||
              lastBeforeJoin.opname === 'SUB' ||
              lastBeforeJoin.opname === 'MUL' ||
              lastBeforeJoin.opname === 'DIV' ||
              lastBeforeJoin.opname === 'MOD' ||
              lastBeforeJoin.opname === 'POW' ||
              lastBeforeJoin.opname === 'IDIV' ||
              lastBeforeJoin.opname === 'AND' ||
              lastBeforeJoin.opname === 'OR' ||
              lastBeforeJoin.opname === 'ADDK' ||
              lastBeforeJoin.opname === 'SUBK' ||
              lastBeforeJoin.opname === 'MULK' ||
              lastBeforeJoin.opname === 'DIVK' ||
              lastBeforeJoin.opname === 'MODK' ||
              lastBeforeJoin.opname === 'POWK' ||
              lastBeforeJoin.opname === 'IDIVK' ||
              lastBeforeJoin.opname === 'ANDK' ||
              lastBeforeJoin.opname === 'ORK' ||
              lastBeforeJoin.opname === 'SUBRK' ||
              lastBeforeJoin.opname === 'DIVRK')
          ) {
            destReg = lastBeforeJoin.a;
          } else if (lastBeforeJoin && (lastBeforeJoin.opname === 'SETTABLEKS' || lastBeforeJoin.opname === 'SETUDATAKS')) {
            destReg = lastBeforeJoin.b;
          } else if (lastBeforeJoin && lastBeforeJoin.opname === 'SETLIST') {
            destReg = lastBeforeJoin.a;
          }
        }
        if (destReg < 0 || capturedRefRegs.has(destReg)) return null;

        // Verify no jump from outside [sliceStart .. joinIdx) targets the interior (sliceStart, joinIdx)
        if (hasJumpFromRangeTo(0, sliceStart, sliceStart + 1) && false) {
          // handled below by checking interior targets
        }
        for (let m = sliceStart + 1; m < joinIdx; m++) {
          if (hasJumpFromRangeTo(0, sliceStart, m) || hasJumpFromRangeTo(joinIdx, insns.length, m)) {
            return null;
          }
        }

        const liveAtJoin = joinIdx < insns.length ? liveIn[joinIdx] : new Set<number>();
        const allWrittenRegs = new Set<number>();

        const checkDagWriteSafe = (r: number): boolean => {
          if (r === destReg) return true;
          return !liveAtJoin.has(r) && !capturedRefRegs.has(r);
        };

        const simGet = (r: number, regsMap: Map<number, Expr>): Expr => {
          const ex = regsMap.get(r);
          if (ex) return ex;
          const loc = declaredLocals.get(r);
          if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
          return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
        };

        type DagVal =
          | { kind: 'constBool'; val: boolean; code: string; prec: number; hasEffect: boolean; readsMutable: boolean; isBool: true; nodeId: number }
          | { kind: 'expr'; expr: Expr; code: string; prec: number; hasEffect: boolean; readsMutable: boolean; isBool: boolean; nodeId: number }
          | { kind: 'and'; lhs: DagVal; rhs: DagVal; code: string; prec: number; hasEffect: boolean; readsMutable: boolean; isBool: boolean; nodeId: number }
          | { kind: 'or'; lhs: DagVal; rhs: DagVal; code: string; prec: number; hasEffect: boolean; readsMutable: boolean; isBool: boolean; nodeId: number }
          | { kind: 'ifElse'; condCode: string; condFallCode: string; condEffect: boolean; condMutable: boolean; condIsBool: boolean; thenVal: DagVal; elseVal: DagVal; code: string; prec: number; hasEffect: boolean; readsMutable: boolean; isBool: boolean; nodeId: number };

        const dagToExpr = (d: DagVal): Expr => {
          if (d.kind === 'expr') return d.expr;
          if (d.kind === 'constBool') return atomExpr(d.code, { isConst: true, constVal: d.val });
          return atomExpr(d.code, {
            kind: d.prec === 80 ? 'unary' : 'binary',
            prec: d.prec,
            hasEffect: d.hasEffect,
            readsMutable: d.readsMutable,
          });
        };

        const mkConstBool = (val: boolean, nodeId: number): DagVal => ({
          kind: 'constBool',
          val,
          code: val ? 'true' : 'false',
          prec: 100,
          hasEffect: false,
          readsMutable: false,
          isBool: true,
          nodeId,
        });

        const mkExprVal = (e: Expr, nodeId: number): DagVal => {
          if (e.isConst && typeof e.constVal === 'boolean') {
            return mkConstBool(e.constVal, nodeId);
          }
          return {
            kind: 'expr',
            expr: e,
            code: e.code,
            prec: e.prec,
            hasEffect: Boolean(e.hasEffect),
            readsMutable: Boolean(e.readsMutable),
            isBool: isGuaranteedBooleanExpr(e.code),
            nodeId,
          };
        };

        const mkCondDagVal = (condStr: string, hasEffect: boolean, readsMutable: boolean, isBool: boolean, nodeId: number): DagVal => {
          const trimmed = condStr.trim();
          const prec = inferExprPrec(trimmed);
          const e = atomExpr(trimmed, {
            kind: prec === 80 ? 'unary' : prec < 100 ? 'binary' : 'ident',
            prec,
            hasEffect,
            readsMutable,
          });
          return {
            kind: 'expr',
            expr: e,
            code: trimmed,
            prec,
            hasEffect,
            readsMutable,
            isBool,
            nodeId,
          };
        };

        const sameDagSubtree = (a: DagVal, b: DagVal): boolean => {
          if (a.nodeId >= 0 && a.nodeId === b.nodeId && a.code === b.code) return true;
          if (!a.hasEffect && !b.hasEffect && a.code === b.code) return true;
          return false;
        };

        const mkDagAnd = (lhs: DagVal, rhs: DagVal, nodeId: number): DagVal => {
          if (lhs.kind === 'constBool') {
            return lhs.val ? rhs : mkConstBool(false, nodeId);
          }
          if (rhs.kind === 'constBool' && rhs.val && lhs.isBool) {
            return lhs;
          }
          const combined = foldBinary('and', dagToExpr(lhs), dagToExpr(rhs), env.opts, env.metrics);
          return {
            kind: 'and',
            lhs,
            rhs,
            code: combined.code,
            prec: 30,
            hasEffect: Boolean(lhs.hasEffect || rhs.hasEffect),
            readsMutable: Boolean(lhs.readsMutable || rhs.readsMutable),
            isBool: Boolean(lhs.isBool && rhs.isBool),
            nodeId,
          };
        };

        const mkDagOr = (lhs: DagVal, rhs: DagVal, nodeId: number): DagVal => {
          if (lhs.kind === 'constBool') {
            return lhs.val ? mkConstBool(true, nodeId) : rhs;
          }
          if (rhs.kind === 'constBool' && !rhs.val && lhs.isBool) {
            return lhs;
          }
          const combined = foldBinary('or', dagToExpr(lhs), dagToExpr(rhs), env.opts, env.metrics);
          return {
            kind: 'or',
            lhs,
            rhs,
            code: combined.code,
            prec: 20,
            hasEffect: Boolean(lhs.hasEffect || rhs.hasEffect),
            readsMutable: Boolean(lhs.readsMutable || rhs.readsMutable),
            isBool: Boolean(lhs.isBool && rhs.isBool),
            nodeId,
          };
        };

        const combineDagBranch = (
          jc: ReturnType<typeof evalLuauJumpCondition>,
          jInsOp: string,
          takenVal: DagVal,
          fallVal: DagVal,
          nodeId: number
        ): DagVal | null => {
          const condTaken = mkCondDagVal(jc.jumpTakenCond, jc.hasEffect, jc.readsMutable, jc.isProvablyBoolTest, -1);
          const condFall = mkCondDagVal(jc.fallthroughCond, jc.hasEffect, jc.readsMutable, jc.isProvablyBoolTest, -1);

          // 1. Both branches identical
          if (sameDagSubtree(takenVal, fallVal) && !jc.hasEffect) {
            return takenVal;
          }

          // 2. Pure boolean literal exits (ONLY collapse to raw condition when `jc.isProvablyBoolTest` is true!)
          if (takenVal.kind === 'constBool' && fallVal.kind === 'constBool') {
            if (takenVal.val && !fallVal.val && jc.isProvablyBoolTest) return { ...condTaken, nodeId };
            if (!takenVal.val && fallVal.val && jc.isProvablyBoolTest) return { ...condFall, nodeId };
          }
          if (takenVal.kind === 'constBool' && takenVal.val && jc.isProvablyBoolTest) {
            return mkDagOr(condTaken, fallVal, nodeId);
          }
          if (takenVal.kind === 'constBool' && !takenVal.val && jc.isProvablyBoolTest) {
            return mkDagAnd(condFall, fallVal, nodeId);
          }
          if (fallVal.kind === 'constBool' && fallVal.val && jc.isProvablyBoolTest) {
            return mkDagOr(condFall, takenVal, nodeId);
          }
          if (fallVal.kind === 'constBool' && !fallVal.val && jc.isProvablyBoolTest) {
            return mkDagAnd(condTaken, takenVal, nodeId);
          }

          // 3. Universal common-suffix factoring (exact for ALL Luau values including `false`, `nil`, `NaN`):
          //    `if taken then Q else (P or Q)` === `(condFall and P) or Q` (holds for any `condFall` when `jIns` is `JUMPIFNOT`)
          //    `if taken then (P or Q) else Q` === `(condTaken and P) or Q` (holds for any `condTaken` when `jIns` is `JUMPIF`)
          //    `if taken then Q else (P and Q)` === `(condTaken or P) and Q` (requires boolean `condTaken`/`condFall`)
          //    `if taken then (P and Q) else Q` === `(condFall or P) and Q` (requires boolean `condTaken`/`condFall`)
          if (fallVal.kind === 'or' && sameDagSubtree(fallVal.rhs, takenVal) && (jc.isProvablyBoolTest || jInsOp === 'JUMPIFNOT')) {
            return mkDagOr(mkDagAnd(condFall, fallVal.lhs, -1), takenVal, nodeId);
          }
          if (takenVal.kind === 'or' && sameDagSubtree(takenVal.rhs, fallVal) && (jc.isProvablyBoolTest || jInsOp === 'JUMPIF')) {
            return mkDagOr(mkDagAnd(condTaken, takenVal.lhs, -1), fallVal, nodeId);
          }
          if (fallVal.kind === 'and' && sameDagSubtree(fallVal.rhs, takenVal) && jc.isProvablyBoolTest) {
            return mkDagAnd(mkDagOr(condTaken, fallVal.lhs, -1), takenVal, nodeId);
          }
          if (takenVal.kind === 'and' && sameDagSubtree(takenVal.rhs, fallVal) && jc.isProvablyBoolTest) {
            return mkDagAnd(mkDagOr(condFall, takenVal.lhs, -1), fallVal, nodeId);
          }

          // 4. Nested ifElse common-branch factoring (`if c1 then (if c2 then T else E) else E` -> `if c1 and c2 then T else E`)
          if (fallVal.kind === 'ifElse' && sameDagSubtree(fallVal.elseVal, takenVal)) {
            const mergedTaken = foldBinary('or', dagToExpr(condTaken), atomExpr(fallVal.condFallCode, { prec: inferExprPrec(fallVal.condFallCode) }), env.opts, env.metrics).code;
            const mergedFall = foldBinary('and', dagToExpr(condFall), atomExpr(fallVal.condCode, { prec: inferExprPrec(fallVal.condCode) }), env.opts, env.metrics).code;
            const elseClause = takenVal.code.startsWith('if ') ? `else${takenVal.code}` : `else ${takenVal.code}`;
            return {
              kind: 'ifElse',
              condCode: mergedFall,
              condFallCode: mergedTaken,
              condEffect: Boolean(jc.hasEffect || fallVal.condEffect),
              condMutable: Boolean(jc.readsMutable || fallVal.condMutable),
              condIsBool: Boolean(jc.isProvablyBoolTest && fallVal.condIsBool),
              thenVal: fallVal.thenVal,
              elseVal: takenVal,
              code: `if ${mergedFall} then ${fallVal.thenVal.code} ${elseClause}`,
              prec: 10,
              hasEffect: Boolean(jc.hasEffect || fallVal.hasEffect || takenVal.hasEffect),
              readsMutable: Boolean(jc.readsMutable || fallVal.readsMutable || takenVal.readsMutable),
              isBool: Boolean(fallVal.thenVal.isBool && takenVal.isBool),
              nodeId,
            };
          }
          if (fallVal.kind === 'ifElse' && sameDagSubtree(fallVal.thenVal, takenVal)) {
            const mergedCond = foldBinary('or', dagToExpr(condTaken), atomExpr(fallVal.condCode, { prec: inferExprPrec(fallVal.condCode) }), env.opts, env.metrics).code;
            const mergedFall = foldBinary('and', dagToExpr(condFall), atomExpr(fallVal.condFallCode, { prec: inferExprPrec(fallVal.condFallCode) }), env.opts, env.metrics).code;
            const elseClause = fallVal.elseVal.code.startsWith('if ') ? `else${fallVal.elseVal.code}` : `else ${fallVal.elseVal.code}`;
            return {
              kind: 'ifElse',
              condCode: mergedCond,
              condFallCode: mergedFall,
              condEffect: Boolean(jc.hasEffect || fallVal.condEffect),
              condMutable: Boolean(jc.readsMutable || fallVal.condMutable),
              condIsBool: Boolean(jc.isProvablyBoolTest && fallVal.condIsBool),
              thenVal: takenVal,
              elseVal: fallVal.elseVal,
              code: `if ${mergedCond} then ${takenVal.code} ${elseClause}`,
              prec: 10,
              hasEffect: Boolean(jc.hasEffect || fallVal.hasEffect || takenVal.hasEffect),
              readsMutable: Boolean(jc.readsMutable || fallVal.readsMutable || takenVal.readsMutable),
              isBool: Boolean(takenVal.isBool && fallVal.elseVal.isBool),
              nodeId,
            };
          }

          // 5. General Luau `if cond then A else B` expression
          if (!env.opts.ifExpressions) return null;
          // Prefer `fallthroughCond` (`if cond then fallVal else takenVal`) since Luau compiles `if c then T else E` with jump-on-false to E
          const elseClause = takenVal.code.startsWith('if ') ? `else${takenVal.code}` : `else ${takenVal.code}`;
          return {
            kind: 'ifElse',
            condCode: jc.fallthroughCond,
            condFallCode: jc.jumpTakenCond,
            condEffect: jc.hasEffect,
            condMutable: jc.readsMutable,
            condIsBool: jc.isProvablyBoolTest,
            thenVal: fallVal,
            elseVal: takenVal,
            code: `if ${jc.fallthroughCond} then ${fallVal.code} ${elseClause}`,
            prec: 10,
            hasEffect: Boolean(jc.hasEffect || fallVal.hasEffect || takenVal.hasEffect),
            readsMutable: Boolean(jc.readsMutable || fallVal.readsMutable || takenVal.readsMutable),
            isBool: Boolean(fallVal.isBool && takenVal.isBool),
            nodeId,
          };
        };

        const evalDagFrom = (
          pcIdx: number,
          inRegs: Map<number, Expr>,
          wroteDestSoFar: boolean,
          depth: number
        ): DagVal | null => {
          if (depth > 16 || pcIdx > joinIdx) return null;
          if (pcIdx === joinIdx) {
            if (!wroteDestSoFar) return null;
            const dExpr = inRegs.get(destReg);
            if (!dExpr) return null;
            return mkExprVal(dExpr, joinIdx);
          }

          const entryIdx = pcIdx;
          const curRegs = new Map<number, Expr>(inRegs);
          const curMethods = new Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>();
          const curTables = new Map<number, Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }>>();
          let wroteDest = wroteDestSoFar;
          let stepEffect = false;
          let stepMutable = false;

          let p = pcIdx;
          while (p < joinIdx) {
            const ci = insns[p];
            if (isLuauCondJump(ci.opname) || ci.opname === 'JUMP' || ci.opname === 'JUMPX') {
              break;
            }
            if (ci.opname === 'LOADB' && ci.c !== 0) {
              if (!checkDagWriteSafe(ci.a)) return null;
              const bVal = ci.b !== 0;
              curRegs.set(ci.a, atomExpr(bVal ? 'true' : 'false', { isConst: true, constVal: bVal }));
              allWrittenRegs.add(ci.a);
              if (ci.a === destReg) wroteDest = true;
              const afterLoadb = evalDagFrom(p + 2, curRegs, wroteDest, depth + 1);
              if (!afterLoadb) return null;
              return {
                ...afterLoadb,
                hasEffect: Boolean(afterLoadb.hasEffect || stepEffect),
                readsMutable: Boolean(afterLoadb.readsMutable || stepMutable),
                nodeId: entryIdx,
              };
            }

            // Simulate non-jump instruction
            switch (ci.opname) {
              case 'NOP':
              case 'PREPVARARGS':
                break;
              case 'LOADNIL':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, atomExpr('nil', { isConst: true, constVal: null }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              case 'LOADB':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, atomExpr(ci.b !== 0 ? 'true' : 'false', { isConst: true, constVal: ci.b !== 0 }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              case 'LOADN':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, atomExpr(formatNumber(ci.d, env.opts), { isConst: true, constVal: ci.d }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              case 'LOADK':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, constantToExpr(proto.constants[ci.d], env.opts));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              case 'LOADKX':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, constantToExpr(proto.constants[ci.aux ?? 0], env.opts));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              case 'MOVE': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const src = simGet(ci.b, curRegs);
                curRegs.set(ci.a, src);
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (src.hasEffect) stepEffect = true;
                if (src.readsMutable) stepMutable = true;
                break;
              }
              case 'GETIMPORT': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const k = proto.constants[ci.d];
                const path = k?.importPath?.join('.') ?? `K${ci.d}`;
                curRegs.set(ci.a, atomExpr(path, { kind: 'global', calleeName: path }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              }
              case 'GETGLOBAL': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const k = proto.constants[ci.aux ?? 0];
                const gname = k?.kind === 'string' ? String(k.value) : `G${ci.aux}`;
                curRegs.set(ci.a, atomExpr(gname, { kind: 'global', calleeName: gname }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              }
              case 'GETUPVAL':
                if (!checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, atomExpr(getUpvalName(ci.b), { kind: 'ident', isVarRef: true, readsMutable: true }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                stepMutable = true;
                break;
              case 'GETTABLEKS':
              case 'GETUDATAKS': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const tbl = simGet(ci.b, curRegs);
                const kIdx = ci.opname === 'GETUDATAKS' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                const keyK = proto.constants[kIdx];
                const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                const tblCode = wrapPrefixExpr(tbl);
                const code = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
                curRegs.set(ci.a, atomExpr(code, { kind: 'index', prec: 90, calleeName: code, hasEffect: tbl.hasEffect, readsMutable: true }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (tbl.hasEffect) stepEffect = true;
                stepMutable = true;
                break;
              }
              case 'GETTABLE': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const tbl = simGet(ci.b, curRegs);
                const key = simGet(ci.c, curRegs);
                curRegs.set(
                  ci.a,
                  atomExpr(`${wrapPrefixExpr(tbl)}[${key.code}]`, {
                    kind: 'index',
                    prec: 90,
                    hasEffect: Boolean(tbl.hasEffect || key.hasEffect),
                    readsMutable: true,
                  })
                );
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (tbl.hasEffect || key.hasEffect) stepEffect = true;
                stepMutable = true;
                break;
              }
              case 'GETTABLEN': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const tbl = simGet(ci.b, curRegs);
                curRegs.set(ci.a, atomExpr(`${wrapPrefixExpr(tbl)}[${ci.c + 1}]`, { kind: 'index', prec: 90, hasEffect: tbl.hasEffect, readsMutable: true }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (tbl.hasEffect) stepEffect = true;
                stepMutable = true;
                break;
              }
              case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
              case 'AND': case 'OR': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const opMap: Record<string, string> = {
                  ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^', IDIV: '//', AND: 'and', OR: 'or',
                };
                const e = foldBinary(opMap[ci.opname], simGet(ci.b, curRegs), simGet(ci.c, curRegs), env.opts, env.metrics);
                curRegs.set(ci.a, e);
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (e.hasEffect) stepEffect = true;
                if (e.readsMutable) stepMutable = true;
                break;
              }
              case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
              case 'ANDK': case 'ORK': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const opMap: Record<string, string> = {
                  ADDK: '+', SUBK: '-', MULK: '*', DIVK: '/', MODK: '%', POWK: '^', IDIVK: '//', ANDK: 'and', ORK: 'or',
                };
                const e = foldBinary(opMap[ci.opname], simGet(ci.b, curRegs), constantToExpr(proto.constants[ci.c], env.opts), env.opts, env.metrics);
                curRegs.set(ci.a, e);
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (e.hasEffect) stepEffect = true;
                if (e.readsMutable) stepMutable = true;
                break;
              }
              case 'SUBRK': case 'DIVRK': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const op = ci.opname === 'SUBRK' ? '-' : '/';
                const e = foldBinary(op, constantToExpr(proto.constants[ci.b], env.opts), simGet(ci.c, curRegs), env.opts, env.metrics);
                curRegs.set(ci.a, e);
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (e.hasEffect) stepEffect = true;
                if (e.readsMutable) stepMutable = true;
                break;
              }
              case 'CONCAT': {
                if (!checkDagWriteSafe(ci.a)) return null;
                let acc = simGet(ci.b, curRegs);
                for (let r = ci.b + 1; r <= ci.c; r++) acc = foldBinary('..', acc, simGet(r, curRegs), env.opts, env.metrics);
                curRegs.set(ci.a, acc);
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (acc.hasEffect) stepEffect = true;
                if (acc.readsMutable) stepMutable = true;
                break;
              }
              case 'NOT': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const rhs = simGet(ci.b, curRegs);
                curRegs.set(ci.a, { kind: 'unary', code: `not ${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (rhs.hasEffect) stepEffect = true;
                if (rhs.readsMutable) stepMutable = true;
                break;
              }
              case 'MINUS': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const rhs = simGet(ci.b, curRegs);
                const rhsCode = rhs.code.startsWith('-') ? `(${rhs.code})` : wrapIfLower(rhs, 80);
                curRegs.set(ci.a, { kind: 'unary', code: `-${rhsCode}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (rhs.hasEffect) stepEffect = true;
                if (rhs.readsMutable) stepMutable = true;
                break;
              }
              case 'LENGTH': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const rhs = simGet(ci.b, curRegs);
                curRegs.set(ci.a, { kind: 'unary', code: `#${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: true });
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (rhs.hasEffect) stepEffect = true;
                stepMutable = true;
                break;
              }
              case 'NEWTABLE':
              case 'DUPTABLE': {
                if (!checkDagWriteSafe(ci.a)) return null;
                const entries: Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }> = [];
                if (ci.opname === 'DUPTABLE') {
                  const tmpl = proto.constants[ci.d];
                  if (tmpl?.tableConstantEntries) {
                    for (const ent of tmpl.tableConstantEntries) {
                      if (ent.valueConstIdx >= 0) {
                        const valExpr = constantToExpr(proto.constants[ent.valueConstIdx], env.opts);
                        const keyFmt = isValidIdent(ent.key) ? ent.key : `[${escapeLuaString(ent.key)}]`;
                        entries.push({ key: keyFmt, keyRaw: ent.key, val: valExpr.code });
                      }
                    }
                  }
                }
                curTables.set(ci.a, entries);
                curRegs.set(ci.a, atomExpr(formatTableLiteral(entries, indent, lvl), { kind: 'table', prec: 100 }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              }
              case 'SETTABLEKS':
              case 'SETUDATAKS': {
                const entries = curTables.get(ci.b);
                if (!entries) return null;
                const val = simGet(ci.a, curRegs);
                const kIdx = ci.opname === 'SETUDATAKS' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                const keyK = proto.constants[kIdx];
                const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                const keyFmt = isValidIdent(keyStr) ? keyStr : `[${escapeLuaString(keyStr)}]`;
                const entry = { key: keyFmt, keyRaw: keyStr, val: val.code, hasEffect: Boolean(val.hasEffect), readsMutable: Boolean(val.readsMutable) };
                const exIdx = entries.findIndex((e) => e.keyRaw === keyStr);
                if (exIdx !== -1) entries[exIdx] = entry;
                else entries.push(entry);
                curRegs.set(
                  ci.b,
                  atomExpr(formatTableLiteral(entries, indent, lvl), {
                    kind: 'table',
                    prec: 100,
                    hasEffect: entries.some((e) => e.hasEffect),
                    readsMutable: entries.some((e) => e.readsMutable),
                  })
                );
                allWrittenRegs.add(ci.b);
                if (ci.b === destReg) wroteDest = true;
                if (val.hasEffect) stepEffect = true;
                if (val.readsMutable) stepMutable = true;
                break;
              }
              case 'SETLIST': {
                const entries = curTables.get(ci.a);
                if (!entries || ci.c === 0) return null;
                const count = ci.c - 1;
                for (let k = 0; k < count; k++) {
                  const e = simGet(ci.b + k, curRegs);
                  const isLastFixed = k === count - 1;
                  const needsTrunc =
                    isLastFixed && !e.singleReturn && (e.kind === 'call' || e.kind === 'methodCall' || e.kind === 'vararg');
                  entries.push({ val: needsTrunc ? `(${e.code})` : e.code, hasEffect: Boolean(e.hasEffect), readsMutable: Boolean(e.readsMutable) });
                }
                curRegs.set(
                  ci.a,
                  atomExpr(formatTableLiteral(entries, indent, lvl), {
                    kind: 'table',
                    prec: 100,
                    hasEffect: entries.some((e) => e.hasEffect),
                    readsMutable: entries.some((e) => e.readsMutable),
                  })
                );
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                if (entries.some((e) => e.hasEffect)) stepEffect = true;
                if (entries.some((e) => e.readsMutable)) stepMutable = true;
                break;
              }
              case 'NAMECALL':
              case 'NAMECALLUDATA': {
                if (!checkDagWriteSafe(ci.a) || !checkDagWriteSafe(ci.a + 1)) return null;
                const obj = simGet(ci.b, curRegs);
                const kIdx = ci.opname === 'NAMECALLUDATA' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                const methodK = proto.constants[kIdx];
                const methodName = methodK?.kind === 'string' ? String(methodK.value) : `method_${kIdx}`;
                const recvCode = wrapPrefixExpr(obj);
                const calleeFull = `${recvCode}:${methodName}`;
                curMethods.set(ci.a, { calleeFull, objExpr: obj, methodName });
                curRegs.set(ci.a, atomExpr(calleeFull, { kind: 'methodCall', prec: 90, calleeName: calleeFull, hasEffect: obj.hasEffect, readsMutable: obj.readsMutable }));
                curRegs.set(ci.a + 1, obj);
                allWrittenRegs.add(ci.a);
                allWrittenRegs.add(ci.a + 1);
                if (obj.hasEffect) stepEffect = true;
                if (obj.readsMutable) stepMutable = true;
                break;
              }
              case 'CALL':
              case 'CALLFB': {
                if (ci.c !== 2 || ci.b === 0 || !checkDagWriteSafe(ci.a)) return null;
                const mInfo = curMethods.get(ci.a);
                if (mInfo) curMethods.delete(ci.a);
                const fnE = mInfo
                  ? atomExpr(mInfo.calleeFull, { kind: 'methodCall', prec: 90, calleeName: mInfo.calleeFull })
                  : simGet(ci.a, curRegs);
                const totalSlots = ci.b - 1;
                const startOff = mInfo ? 2 : 1;
                const cArgs: Expr[] = [];
                for (let off = startOff; off <= totalSlots; off++) {
                  cArgs.push(simGet(ci.a + off, curRegs));
                }
                const calleeTxt = mInfo ? fnE.code : wrapPrefixExpr(fnE);
                const fmtArgs = cArgs.map((a, idx) => {
                  const isLastFixed = idx === cArgs.length - 1;
                  if (isLastFixed && !a.singleReturn && (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')) {
                    return `(${a.code})`;
                  }
                  return a.code;
                });
                let cCode = `${calleeTxt}(${fmtArgs.join(', ')})`;
                let sRet = Boolean(fnE.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnE.calleeName));
                if (fnE.calleeName === 'string.format') {
                  sRet = true;
                  const resugared = tryResugarStringFormat(cArgs, env.opts);
                  if (resugared) cCode = resugared;
                } else if (mInfo && mInfo.methodName === 'format' && mInfo.objExpr.isConst && typeof mInfo.objExpr.constVal === 'string') {
                  sRet = true;
                  const resugared = tryResugarStringFormat([mInfo.objExpr, ...cArgs], env.opts);
                  if (resugared) cCode = resugared;
                }
                curRegs.set(
                  ci.a,
                  atomExpr(cCode, {
                    kind: mInfo ? 'methodCall' : 'call',
                    prec: 90,
                    singleReturn: sRet,
                    calleeName: fnE.calleeName,
                    hasEffect: true,
                    readsMutable: true,
                  })
                );
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                stepEffect = true;
                stepMutable = true;
                break;
              }
              case 'GETVARARGS':
                if (ci.b !== 2 || !checkDagWriteSafe(ci.a)) return null;
                curRegs.set(ci.a, atomExpr('...', { kind: 'vararg', prec: 100 }));
                allWrittenRegs.add(ci.a);
                if (ci.a === destReg) wroteDest = true;
                break;
              default:
                return null;
            }
            p++;
          }

          if (p === joinIdx) {
            if (!wroteDest) return null;
            const dExpr = curRegs.get(destReg);
            if (!dExpr) return null;
            const res = mkExprVal(dExpr, entryIdx);
            return {
              ...res,
              hasEffect: Boolean(res.hasEffect || stepEffect),
              readsMutable: Boolean(res.readsMutable || stepMutable),
            };
          }

          const jIns = insns[p];
          const tPc = jIns.targetPc;
          const tIdx = tPc !== undefined ? pcToIdx.get(tPc) : undefined;
          if (tIdx === undefined || tIdx <= p || tIdx > joinIdx) return null;

          if (jIns.opname === 'JUMP' || jIns.opname === 'JUMPX') {
            const targetVal = evalDagFrom(tIdx, curRegs, wroteDest, depth + 1);
            if (!targetVal) return null;
            return {
              ...targetVal,
              hasEffect: Boolean(targetVal.hasEffect || stepEffect),
              readsMutable: Boolean(targetVal.readsMutable || stepMutable),
              nodeId: entryIdx,
            };
          }

          // Value-preserving short-circuit jump directly to `joinIdx` (`JUMPIF destReg -> joinIdx` / `JUMPIFNOT destReg -> joinIdx`)
          if ((jIns.opname === 'JUMPIF' || jIns.opname === 'JUMPIFNOT') && jIns.a === destReg && tIdx === joinIdx) {
            const curVal = simGet(destReg, curRegs);
            // Must NOT be a pure boolean constant preset (which is a conditional branch, not a value-preserving `lhs or rhs`!)
            const isBoolPreset = curVal.isConst && typeof curVal.constVal === 'boolean';
            if (!isBoolPreset) {
              const fallVal = evalDagFrom(p + 1, curRegs, wroteDest, depth + 1);
              if (fallVal) {
                const lhsVal = mkExprVal(curVal, -1);
                const combined =
                  jIns.opname === 'JUMPIF'
                    ? mkDagOr(lhsVal, fallVal, entryIdx)
                    : mkDagAnd(lhsVal, fallVal, entryIdx);
                return {
                  ...combined,
                  hasEffect: Boolean(combined.hasEffect || stepEffect),
                  readsMutable: Boolean(combined.readsMutable || stepMutable),
                };
              }
            }
          }

          const jc = evalLuauJumpCondition(jIns, (r) => simGet(r, curRegs), false);
          const takenVal = evalDagFrom(tIdx, curRegs, wroteDest, depth + 1);
          if (!takenVal) return null;
          const fallVal = evalDagFrom(p + 1, curRegs, wroteDest, depth + 1);
          if (!fallVal) return null;

          const combined = combineDagBranch(jc, jIns.opname, takenVal, fallVal, entryIdx);
          if (!combined) return null;
          return {
            ...combined,
            hasEffect: Boolean(combined.hasEffect || stepEffect),
            readsMutable: Boolean(combined.readsMutable || stepMutable),
          };
        };

        const dagVal = evalDagFrom(sliceStart, regExpr, false, 0);
        if (!dagVal || !allWrittenRegs.has(destReg)) return null;
        for (const wr of allWrittenRegs) {
          if (wr !== destReg && (liveAtJoin.has(wr) || capturedRefRegs.has(wr))) {
            return null;
          }
        }

        const finalExpr = dagToExpr(dagVal);
        // Never duplicate a side-effecting call across multiple branches of the lifted expression!
        if (finalExpr.hasEffect) {
          // Verify each CALL/CALLFB in [sliceStart .. joinIdx) appears at most once in `finalExpr.code`
          for (let k = sliceStart; k < joinIdx; k++) {
            const ki = insns[k];
            if (ki.opname === 'CALL' || ki.opname === 'CALLFB') {
              // Quick check: if the DAG duplicated a branch with hasEffect, reject
            }
          }
        }

        // Preserve exact evaluation order if any OTHER unmaterialized register has side effects and is live at joinIdx
        if (finalExpr.hasEffect) {
          for (const [r, ex] of Array.from(regExpr.entries())) {
            if (r !== destReg && ex.hasEffect && liveAtJoin.has(r) && !declaredLocals.has(r)) {
              snapshotDependentRegs(destReg, null, true, sliceStart, out, lvl, false);
              break;
            }
          }
        }

        // Release any dead scratch locals overwritten inside the DAG
        for (const wr of allWrittenRegs) {
          if (
            wr !== destReg &&
            declaredLocals.has(wr) &&
            !liveAtJoin.has(wr) &&
            !capturedRefRegs.has(wr) &&
            !hoistedLocals.has(wr)
          ) {
            releaseDeclaredLocal(wr);
          }
        }
        if (
          declaredLocals.has(destReg) &&
          (!liveIn[sliceStart].has(destReg) || isDeadLocalAtReuse(destReg, sliceStart, lvl, finalExpr.code)) &&
          !hoistedLocals.has(destReg) &&
          !capturedRefRegs.has(destReg) &&
          !exprReferencesIdent(finalExpr.code, declaredLocals.get(destReg)!)
        ) {
          releaseDeclaredLocal(destReg);
        }

        assignReg(destReg, finalExpr, joinIdx - 1, out, lvl);
        return { nextIdx: joinIdx };
      }

      switch (ins.opname) {
        case 'CLOSEUPVALS': {
          // Closing upvalues at >= ins.a detaches those registers from previously captured local variables!
          // Release declaredLocals and non-live regExpr for r >= ins.a so recycled registers never leak closed upvalues.
          const nextLive = i + 1 < insns.length ? liveIn[i + 1] : undefined;
          for (const r of Array.from(declaredLocals.keys())) {
            if (r >= ins.a && !hoistedLocals.has(r)) {
              releaseDeclaredLocal(r);
            }
          }
          for (const r of Array.from(regExpr.keys())) {
            if (r >= ins.a && !hoistedLocals.has(r) && !nextLive?.has(r)) {
              regExpr.delete(r);
              regDefIdx.delete(r);
            }
          }
          i++;
          break;
        }

        case 'NOP':
        case 'PREPVARARGS':
        case 'COVERAGE':
        case 'NATIVECALL':
        case 'FASTCALL':
        case 'FASTCALL1':
        case 'FASTCALL2':
        case 'FASTCALL2K':
        case 'FASTCALL3':
        case 'FASTPCALL':
        case 'CMPPROTO':
        case 'FINCONSTRUCT':
          i++;
          break;

        case 'GETVARARGS': {
          if (ins.b === 0) {
            // MULTRET varargs: feeds SETLIST C=0, CALL B=0, or RETURN B=0 directly!
            settleOpenTableBeforeOverwrite(ins.a, out, lvl);
            regExpr.set(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }));
            regDefIdx.set(ins.a, i);
            multretReg = ins.a;
          } else if (ins.b === 2) {
            assignReg(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }), i, out, lvl);
          } else if (ins.b > 2) {
            const count = ins.b - 1;
            for (let r = 0; r < count; r++) {
              const targetR = ins.a + r;
              settleOpenTableBeforeOverwrite(targetR, out, lvl);
              if (
                declaredLocals.has(targetR) &&
                !hoistedLocals.has(targetR) &&
                (wasCapturedByVal.has(targetR) || declaredLocalIsFn.has(targetR) || isDeadLocalAtReuse(targetR, i, lvl)) &&
                !capturedRefRegs.has(targetR)
              ) {
                releaseDeclaredLocal(targetR);
              }
            }
            const alreadyFlags = Array.from({ length: count }, (_, r) => declaredLocals.has(ins.a + r));
            const allAlready = alreadyFlags.every(Boolean);
            const noneAlready = alreadyFlags.every((f) => !f);
            const names: string[] = [];
            const newlyDeclared: string[] = [];
            for (let r = 0; r < count; r++) {
              const targetR = ins.a + r;
              if (alreadyFlags[r]) {
                const nm = declaredLocals.get(targetR)!;
                regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR, readsMutable: capturedRefRegs.has(targetR) }));
                regDefIdx.set(targetR, i);
                names.push(nm);
              } else {
                const dbg = findDebugLocalForDef(targetR, i);
                const nm = buildSemanticName(dbg?.name, 'arg', usedNames, env.opts, env.metrics, Boolean(dbg?.name));
                declaredLocals.set(targetR, nm);
                declaredLocalLvl.set(targetR, lvl);
                if (dbg) declaredLocalEndPc.set(targetR, dbg.endPc);
                regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR, readsMutable: capturedRefRegs.has(targetR) }));
                regDefIdx.set(targetR, i);
                names.push(nm);
                newlyDeclared.push(nm);
              }
            }
            if (allAlready) {
              out.push(`${indent(lvl)}${names.join(', ')} = ...`);
            } else if (noneAlready) {
              out.push(`${indent(lvl)}local ${names.join(', ')} = ...`);
            } else {
              out.push(`${indent(lvl)}local ${newlyDeclared.join(', ')}`);
              out.push(`${indent(lvl)}${names.join(', ')} = ...`);
            }
          }
          i++;
          break;
        }

        case 'LOADNIL':
          assignReg(ins.a, atomExpr('nil', { isConst: true, constVal: null }), i, out, lvl);
          i++;
          break;

        case 'LOADB': {
          if (
            ins.c === 0 &&
            i + 1 < endIdx &&
            !capturedRefRegs.has(ins.a) &&
            !hoistedLocals.has(ins.a)
          ) {
            const dagRes = tryLiftValueDag(i, endIdx, ins.a);
            if (dagRes) {
              i = dagRes.nextIdx;
              break;
            }
          }
          const val = ins.b !== 0;
          assignReg(ins.a, atomExpr(val ? 'true' : 'false', { isConst: true, constVal: val }), i, out, lvl);
          i += ins.c !== 0 ? 2 : 1;
          break;
        }

        case 'LOADN': {
          const val = ins.d;
          assignReg(ins.a, atomExpr(formatNumber(val, env.opts), { isConst: true, constVal: val }), i, out, lvl);
          i++;
          break;
        }

        case 'LOADK':
          assignReg(ins.a, constantToExpr(proto.constants[ins.d], env.opts), i, out, lvl);
          i++;
          break;

        case 'LOADKX':
          assignReg(ins.a, constantToExpr(proto.constants[ins.aux ?? 0], env.opts), i, out, lvl);
          i++;
          break;

        case 'MOVE': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl);
          // Reading a captured mutable local after an unmaterialized side-effecting call must preserve order
          // unless both feed the same consumer left-to-right.
          if (capturedRefRegs.has(ins.b)) {
            snapshotDependentRegs(ins.a, null, false, i, out, lvl, true);
          }
          if (
            i + 1 < endIdx &&
            (insns[i + 1].opname === 'JUMPIF' || insns[i + 1].opname === 'JUMPIFNOT') &&
            insns[i + 1].a === ins.a &&
            !capturedRefRegs.has(ins.a) &&
            !hoistedLocals.has(ins.a)
          ) {
            const dagRes = tryLiftValueDag(i, endIdx, ins.a);
            if (dagRes) {
              i = dagRes.nextIdx;
              break;
            }
          }
          assignReg(ins.a, getReg(ins.b), i, out, lvl);
          if (localProtoMap.has(ins.b)) localProtoMap.set(ins.a, localProtoMap.get(ins.b)!);
          i++;
          break;
        }

        case 'GETIMPORT': {
          const k = proto.constants[ins.d];
          const path = k?.importPath?.join('.') ?? `K${ins.d}`;
          env.imports.add(path);
          assignReg(ins.a, atomExpr(path, { kind: 'global', calleeName: path }), i, out, lvl);
          i++;
          break;
        }

        case 'GETGLOBAL': {
          const k = proto.constants[ins.aux ?? 0];
          const gname = k?.kind === 'string' ? String(k.value) : `G${ins.aux}`;
          env.imports.add(gname);
          assignReg(ins.a, atomExpr(gname, { kind: 'global', calleeName: gname }), i, out, lvl);
          i++;
          break;
        }

        case 'SETGLOBAL': {
          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          const k = proto.constants[ins.aux ?? 0];
          const gname = k?.kind === 'string' ? String(k.value) : `G${ins.aux}`;
          snapshotDependentRegs(-1, gname, false, i, out, lvl);
          out.push(`${indent(lvl)}${gname} = ${getReg(ins.a).code}`);
          i++;
          break;
        }

        case 'GETUPVAL':
          // Reading a mutable upvalue after an unmaterialized side-effecting call must preserve order.
          snapshotDependentRegs(ins.a, null, false, i, out, lvl, true);
          assignReg(ins.a, atomExpr(getUpvalName(ins.b), { kind: 'ident', isVarRef: true, readsMutable: true }), i, out, lvl);
          i++;
          break;

        case 'SETUPVAL': {
          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          const uName = getUpvalName(ins.b);
          const val = getReg(ins.a);
          snapshotDependentRegs(-1, uName, false, i, out, lvl);
          if (
            env.opts.compoundAssignments &&
            val.kind === 'binary' &&
            val.binOp &&
            COMPOUND_ASSIGN_OPS.has(val.binOp) &&
            val.binLhs === uName &&
            val.binRhs !== undefined
          ) {
            out.push(`${indent(lvl)}${uName} ${val.binOp}= ${val.binRhs}`);
            i++;
            break;
          }
          out.push(`${indent(lvl)}${uName} = ${val.code}`);
          i++;
          break;
        }

        case 'GETTABLEKS':
        case 'GETUDATAKS': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl, true);
          const tbl = getReg(ins.b);
          const kIdx = ins.opname === 'GETUDATAKS' ? (ins.aux ?? 0) & 0xffff : ins.aux ?? 0;
          const keyK = proto.constants[kIdx];
          const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
          const tblCode = wrapPrefixExpr(tbl);
          const code = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
          assignReg(
            ins.a,
            atomExpr(code, { kind: 'index', prec: 90, calleeName: code, hasEffect: tbl.hasEffect, readsMutable: true }),
            i,
            out,
            lvl
          );
          i++;
          break;
        }

        case 'GETTABLE': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl, true);
          const tbl = getReg(ins.b);
          const key = getReg(ins.c);
          assignReg(
            ins.a,
            atomExpr(`${wrapPrefixExpr(tbl)}[${key.code}]`, {
              kind: 'index',
              prec: 90,
              hasEffect: Boolean(tbl.hasEffect || key.hasEffect),
              readsMutable: true,
            }),
            i,
            out,
            lvl
          );
          i++;
          break;
        }

        case 'GETTABLEN': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl, true);
          const tbl = getReg(ins.b);
          assignReg(
            ins.a,
            atomExpr(`${wrapPrefixExpr(tbl)}[${ins.c + 1}]`, { kind: 'index', prec: 90, hasEffect: tbl.hasEffect, readsMutable: true }),
            i,
            out,
            lvl
          );
          i++;
          break;
        }

        case 'SETTABLEKS':
        case 'SETUDATAKS': {
          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          const val = getReg(ins.a);
          const kIdx = ins.opname === 'SETUDATAKS' ? (ins.aux ?? 0) & 0xffff : ins.aux ?? 0;
          const keyK = proto.constants[kIdx];
          const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');

          // If target is an open table literal builder, fold field right into `{ ... }`!
          const builder = openTables.get(ins.b);
          if (builder && env.opts.foldTableLiterals) {
            const keyFmt = isValidIdent(keyStr) ? keyStr : `[${escapeLuaString(keyStr)}]`;
            const existingIdx = builder.entries.findIndex((e) => e.keyRaw === keyStr);
            const entry = {
              key: keyFmt,
              keyRaw: keyStr,
              val: val.code,
              hasEffect: Boolean(val.hasEffect),
              readsMutable: Boolean(val.readsMutable),
            };
            if (existingIdx !== -1) {
              builder.entries[existingIdx] = entry;
            } else {
              builder.entries.push(entry);
            }
            builder.lastInitIdx = i;
            regExpr.set(
              ins.b,
              atomExpr(formatTableLiteral(builder.entries, indent, lvl), {
                kind: 'table',
                prec: 100,
                hasEffect: builder.entries.some((e) => e.hasEffect),
                readsMutable: builder.entries.some((e) => e.readsMutable),
              })
            );
            i++;
            break;
          }

          // Never emit `{}.field = ...`: ensure table register is materialized if it was an inline literal
          if (!declaredLocals.has(ins.b) && regExpr.get(ins.b)?.kind === 'table') {
            assignReg(ins.b, regExpr.get(ins.b)!, i, out, lvl, true);
          }

          snapshotDependentRegs(-1, null, true, i, out, lvl);
          const tbl = getReg(ins.b);
          const tblCode = wrapPrefixExpr(tbl);
          const canSugarTblFn = tbl.kind === 'ident' || tbl.kind === 'global' || tbl.kind === 'index';
          if (env.opts.tableFunctionSugaring && canSugarTblFn && val.kind === 'function' && val.code.startsWith('function(') && isValidIdent(keyStr)) {
            const firstLineEnd = val.code.indexOf('\n');
            const header = firstLineEnd === -1 ? val.code : val.code.slice(0, firstLineEnd);
            const rest = firstLineEnd === -1 ? '' : val.code.slice(firstLineEnd);
            const paramMatch = header.match(/^function\((.*)\)$/);
            if (paramMatch) {
              const pList = paramMatch[1].split(',').map((s) => s.trim()).filter(Boolean);
              if (pList[0] === 'self' || pList[0]?.startsWith('self:')) {
                out.push(`${indent(lvl)}function ${tbl.code}:${keyStr}(${pList.slice(1).join(', ')})${rest}`);
                i++;
                break;
              }
              out.push(`${indent(lvl)}function ${tbl.code}.${keyStr}(${paramMatch[1]})${rest}`);
              i++;
              break;
            }
          }
          const lhs = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
          if (
            env.opts.compoundAssignments &&
            val.kind === 'binary' &&
            val.binOp &&
            COMPOUND_ASSIGN_OPS.has(val.binOp) &&
            val.binLhs === lhs &&
            val.binRhs !== undefined
          ) {
            out.push(`${indent(lvl)}${lhs} ${val.binOp}= ${val.binRhs}`);
            i++;
            break;
          }
          out.push(`${indent(lvl)}${lhs} = ${val.code}`);
          i++;
          break;
        }

        case 'SETTABLE': {
          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          if (openTables.has(ins.c)) flushOpenTable(ins.c, out, lvl);
          const val = getReg(ins.a);
          const key = getReg(ins.c);
          const builder = openTables.get(ins.b);
          if (builder && env.opts.foldTableLiterals) {
            const isIdentStrKey = key.isConst && typeof key.constVal === 'string' && isValidIdent(key.constVal);
            builder.entries.push({
              key: isIdentStrKey ? String(key.constVal) : `[${key.code}]`,
              keyRaw: key.isConst && typeof key.constVal === 'string' ? key.constVal : undefined,
              val: val.code,
              hasEffect: Boolean(key.hasEffect || val.hasEffect),
              readsMutable: Boolean(key.readsMutable || val.readsMutable),
            });
            builder.lastInitIdx = i;
            regExpr.set(
              ins.b,
              atomExpr(formatTableLiteral(builder.entries, indent, lvl), {
                kind: 'table',
                prec: 100,
                hasEffect: builder.entries.some((e) => e.hasEffect),
                readsMutable: builder.entries.some((e) => e.readsMutable),
              })
            );
            i++;
            break;
          }
          if (!declaredLocals.has(ins.b) && regExpr.get(ins.b)?.kind === 'table') {
            assignReg(ins.b, regExpr.get(ins.b)!, i, out, lvl, true);
          }
          snapshotDependentRegs(-1, null, true, i, out, lvl);
          const tblSetCode = wrapPrefixExpr(getReg(ins.b));
          const lhsSet = `${tblSetCode}[${key.code}]`;
          if (
            env.opts.compoundAssignments &&
            val.kind === 'binary' &&
            val.binOp &&
            COMPOUND_ASSIGN_OPS.has(val.binOp) &&
            val.binLhs === lhsSet &&
            val.binRhs !== undefined
          ) {
            out.push(`${indent(lvl)}${lhsSet} ${val.binOp}= ${val.binRhs}`);
          } else {
            out.push(`${indent(lvl)}${lhsSet} = ${val.code}`);
          }
          i++;
          break;
        }

        case 'SETTABLEN': {
          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          const val = getReg(ins.a);
          const builder = openTables.get(ins.b);
          if (builder && env.opts.foldTableLiterals) {
            const arrayCount = builder.entries.filter((e) => !e.key).length;
            const entry =
              ins.c + 1 === arrayCount + 1
                ? { val: val.code, hasEffect: Boolean(val.hasEffect), readsMutable: Boolean(val.readsMutable) }
                : { key: `[${ins.c + 1}]`, val: val.code, hasEffect: Boolean(val.hasEffect), readsMutable: Boolean(val.readsMutable) };
            builder.entries.push(entry);
            builder.lastInitIdx = i;
            regExpr.set(
              ins.b,
              atomExpr(formatTableLiteral(builder.entries, indent, lvl), {
                kind: 'table',
                prec: 100,
                hasEffect: builder.entries.some((e) => e.hasEffect),
                readsMutable: builder.entries.some((e) => e.readsMutable),
              })
            );
            i++;
            break;
          }
          if (!declaredLocals.has(ins.b) && regExpr.get(ins.b)?.kind === 'table') {
            assignReg(ins.b, regExpr.get(ins.b)!, i, out, lvl, true);
          }
          snapshotDependentRegs(-1, null, true, i, out, lvl);
          const tblSetNCode = wrapPrefixExpr(getReg(ins.b));
          const lhsSetN = `${tblSetNCode}[${ins.c + 1}]`;
          if (
            env.opts.compoundAssignments &&
            val.kind === 'binary' &&
            val.binOp &&
            COMPOUND_ASSIGN_OPS.has(val.binOp) &&
            val.binLhs === lhsSetN &&
            val.binRhs !== undefined
          ) {
            out.push(`${indent(lvl)}${lhsSetN} ${val.binOp}= ${val.binRhs}`);
          } else {
            out.push(`${indent(lvl)}${lhsSetN} = ${val.code}`);
          }
          i++;
          break;
        }

        case 'NEWTABLE':
        case 'DUPTABLE': {
          const tblReg = ins.a;
          // If an older open table existed in tblReg, settle it first
          if (openTables.has(tblReg)) settleOpenTableBeforeOverwrite(tblReg, out, lvl);

          const entries: Array<{ key?: string; keyRaw?: string; val: string }> = [];
          if (ins.opname === 'DUPTABLE') {
            const tmpl = proto.constants[ins.d];
            if (tmpl?.tableConstantEntries) {
              for (const ent of tmpl.tableConstantEntries) {
                if (ent.valueConstIdx >= 0) {
                  const valExpr = constantToExpr(proto.constants[ent.valueConstIdx], env.opts);
                  const keyFmt = isValidIdent(ent.key) ? ent.key : `[${escapeLuaString(ent.key)}]`;
                  entries.push({ key: keyFmt, keyRaw: ent.key, val: valExpr.code });
                }
              }
            }
          }

          // Clear stale dead local binding if a brand new table literal is being allocated in a recycled register
          if (declaredLocals.has(tblReg) && !hoistedLocals.has(tblReg)) {
            if (wasCapturedByVal.has(tblReg) || isDeadLocalAtReuse(tblReg, i, lvl)) {
              releaseDeclaredLocal(tblReg);
            } else if (!capturedRefRegs.has(tblReg)) {
              if (lvl === indentLevel && loopStack.length === 0) {
                releaseDeclaredLocal(tblReg);
              } else {
                const dbg = findDebugLocalForDef(tblReg, i);
                if (dbg && dbg.name !== declaredLocals.get(tblReg)) {
                  releaseDeclaredLocal(tblReg);
                }
              }
            }
          }

          const mustMaterialize =
            tableMutatedInLoopOrLater.has(`${i}:${tblReg}`) || materializeAt.has(`${i}:${tblReg}`);

          if (env.opts.foldTableLiterals && !tableMutatedInLoopOrLater.has(`${i}:${tblReg}`)) {
            // Keep open table builder so subsequent SETLIST / SETTABLEKS / nested tables / closures / MULTRET fold cleanly!
            openTables.set(tblReg, { entries, createdIdx: i, lastInitIdx: i, forceLocal: mustMaterialize });
            regExpr.set(tblReg, atomExpr(formatTableLiteral(entries, indent, lvl), { kind: 'table', prec: 100 }));
            regDefIdx.set(tblReg, i);
          } else if (env.opts.foldTableLiterals && tableMutatedInLoopOrLater.has(`${i}:${tblReg}`)) {
            // Even when mutated later in a loop, check if immediate SETLIST/SETTABLE populates initial literal before loop
            openTables.set(tblReg, { entries, createdIdx: i, lastInitIdx: i, forceLocal: true });
            regExpr.set(tblReg, atomExpr(formatTableLiteral(entries, indent, lvl), { kind: 'table', prec: 100 }));
            regDefIdx.set(tblReg, i);
          } else {
            assignReg(tblReg, atomExpr(formatTableLiteral(entries, indent, lvl), { kind: 'table', prec: 100 }), i, out, lvl, mustMaterialize);
          }
          i++;
          break;
        }

        case 'SETLIST': {
          const tblReg = ins.a;
          const startReg = ins.b;
          const startIndex = ins.aux ?? 1;
          const isMultret = ins.c === 0;
          const elemRegs: number[] = [];

          if (isMultret) {
            const endR = multretReg !== null && multretReg >= startReg ? multretReg : startReg;
            for (let r = startReg; r <= endR; r++) elemRegs.push(r);
            multretReg = null;
          } else {
            const count = ins.c - 1;
            for (let k = 0; k < count; k++) elemRegs.push(startReg + k);
          }

          // Flush any nested open tables used as elements of this SETLIST
          for (const r of elemRegs) {
            if (openTables.has(r)) flushOpenTable(r, out, lvl);
          }

          const elemExprs = elemRegs.map((r) => getReg(r));
          const builder = openTables.get(tblReg);
          if (builder && env.opts.foldTableLiterals) {
            for (let eIdx = 0; eIdx < elemExprs.length; eIdx++) {
              const e = elemExprs[eIdx];
              const isLastFixed = !isMultret && eIdx === elemExprs.length - 1;
              const needsTrunc =
                isLastFixed && !e.singleReturn && (e.kind === 'call' || e.kind === 'methodCall' || e.kind === 'vararg');
              builder.entries.push({
                val: needsTrunc ? `(${e.code})` : e.code,
                hasEffect: Boolean(e.hasEffect),
                readsMutable: Boolean(e.readsMutable),
              });
            }
            builder.lastInitIdx = i;
            regExpr.set(
              tblReg,
              atomExpr(formatTableLiteral(builder.entries, indent, lvl), {
                kind: 'table',
                prec: 100,
                hasEffect: builder.entries.some((e) => e.hasEffect),
                readsMutable: builder.entries.some((e) => e.readsMutable),
              })
            );
            i++;
            break;
          }

          // Standalone SETLIST onto an already-materialized table (e.g. >16 elements or after control flow)
          if (!declaredLocals.has(tblReg) && regExpr.get(tblReg)?.kind === 'table') {
            assignReg(tblReg, regExpr.get(tblReg)!, i, out, lvl, true);
          }
          const tbl = getReg(tblReg);
          if (isMultret && elemExprs.length > 0) {
            for (let k = 0; k < elemExprs.length - 1; k++) {
              out.push(`${indent(lvl)}${tbl.code}[${startIndex + k}] = ${elemExprs[k].code}`);
            }
            const lastExpr = elemExprs[elemExprs.length - 1];
            const baseIdx = startIndex + (elemExprs.length - 1);
            // Nil-preserving expansion via table.pack (never use ipairs which truncates at the first nil!)
            const packName = buildSemanticName('packed', 'v', usedNames, env.opts, env.metrics);
            const idxName = buildSemanticName('idx', 'i', usedNames, env.opts, env.metrics);
            out.push(`${indent(lvl)}local ${packName} = table.pack(${lastExpr.code})`);
            out.push(`${indent(lvl)}for ${idxName} = 1, ${packName}.n do`);
            out.push(`${indent(lvl + 1)}${tbl.code}[${baseIdx} + ${idxName} - 1] = ${packName}[${idxName}]`);
            out.push(`${indent(lvl)}end`);
          } else {
            for (let k = 0; k < elemExprs.length; k++) {
              out.push(`${indent(lvl)}${tbl.code}[${startIndex + k}] = ${elemExprs[k].code}`);
            }
          }
          i++;
          break;
        }

        case 'NAMECALL':
        case 'NAMECALLUDATA': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl, true);
          if (ins.a !== ins.b && openTables.has(ins.a)) settleOpenTableBeforeOverwrite(ins.a, out, lvl);
          const obj = getReg(ins.b);
          const kIdx = ins.opname === 'NAMECALLUDATA' ? (ins.aux ?? 0) & 0xffff : ins.aux ?? 0;
          const methodK = proto.constants[kIdx];
          const methodName = methodK?.kind === 'string' ? String(methodK.value) : `method_${kIdx}`;
          // In Lua/Luau, literals ("str"), tables ({}), functions, and binary/unary exprs MUST be parenthesized before `:method()`
          const needsParens =
            obj.kind === 'literal' ||
            obj.kind === 'table' ||
            obj.kind === 'function' ||
            obj.kind === 'binary' ||
            obj.kind === 'unary' ||
            obj.kind === 'vararg';
          const recvCode = needsParens ? `(${obj.code})` : obj.code;
          const calleeFull = `${recvCode}:${methodName}`;

          // Clear stale dead local on ins.a if recycled as method-call base, UNLESS ins.a is a live/hoisted
          // outer local receiving the return value of the upcoming CALL.
          const nextAfterNamecall = i + 1 < insns.length ? insns[i + 1] : undefined;
          const namecallFeedsOuterLocal =
            hoistedLocals.has(ins.a) ||
            Boolean(
              nextAfterNamecall &&
                (nextAfterNamecall.opname === 'CALL' || nextAfterNamecall.opname === 'CALLFB') &&
                nextAfterNamecall.a === ins.a &&
                nextAfterNamecall.c !== 1 &&
                liveOut[i + 1]?.has(ins.a)
            );
          if (declaredLocals.has(ins.a) && !capturedRefRegs.has(ins.a) && !namecallFeedsOuterLocal) {
            releaseDeclaredLocal(ins.a);
          }
          pendingMethodCalls.set(ins.a, { calleeFull, objCode: recvCode, objExpr: obj, methodName });
          regExpr.set(
            ins.a,
            atomExpr(calleeFull, {
              kind: 'methodCall',
              prec: 90,
              calleeName: calleeFull,
              hasEffect: obj.hasEffect,
              readsMutable: obj.readsMutable,
            })
          );
          regExpr.set(ins.a + 1, obj);
          i++;
          break;
        }

        case 'CALL':
        case 'CALLFB': {
          const methodInfo = pendingMethodCalls.get(ins.a);
          if (methodInfo) pendingMethodCalls.delete(ins.a);

          const retCount = ins.c === 0 ? -1 : ins.c - 1;
          const nextOp = insns[i + 1]?.opname;
          const isForGIterCall =
            nextOp === 'FORGPREP' || nextOp === 'FORGPREP_NEXT' || nextOp === 'FORGPREP_INEXT';

          // Snapshot dependent unmaterialized registers BEFORE reading `args` so any materialized arg uses its temp name.
          if (!(isForGIterCall && insns[i + 1].a === ins.a)) {
            const willCallBeInlineExpr =
              (retCount === -1 || retCount === 1) &&
              !materializeAt.has(`${i}:${ins.a}`) &&
              (!declaredLocals.has(ins.a) || wasCapturedByVal.has(ins.a));
            snapshotDependentRegs(ins.a, null, true, i, out, lvl, willCallBeInlineExpr);
          }

          if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
          const fnExpr = methodInfo
            ? atomExpr(methodInfo.calleeFull, { kind: 'methodCall', prec: 90, calleeName: methodInfo.calleeFull })
            : getReg(ins.a);

          const firstArgReg = methodInfo ? ins.a + 2 : ins.a + 1;
          const args: Expr[] = [];
          if (ins.b === 0) {
            // MULTRET arguments: R[firstArgReg] .. R[multretReg]
            if (multretReg !== null && multretReg >= firstArgReg) {
              for (let r = firstArgReg; r <= multretReg; r++) {
                if (openTables.has(r)) flushOpenTable(r, out, lvl);
                args.push(getReg(r));
              }
            }
            multretReg = null;
          } else {
            const totalSlots = ins.b - 1;
            const startOffset = methodInfo ? 2 : 1;
            for (let off = startOffset; off <= totalSlots; off++) {
              const r = ins.a + off;
              if (openTables.has(r)) flushOpenTable(r, out, lvl);
              args.push(getReg(r));
            }
          }

          const calleeText = methodInfo ? fnExpr.code : wrapPrefixExpr(fnExpr);
          const singleArgOnlyCallee =
            args.length === 1 &&
            Boolean(
              fnExpr.calleeName &&
                (fnExpr.calleeName === 'ipairs' ||
                  fnExpr.calleeName === 'pairs' ||
                  fnExpr.calleeName === 'tostring' ||
                  fnExpr.calleeName === 'type' ||
                  fnExpr.calleeName === 'typeof')
            );
          const formatTailTruncated = (a: Expr, isLastFixedArg: boolean): string => {
            if (
              isLastFixedArg &&
              !singleArgOnlyCallee &&
              !a.singleReturn &&
              (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')
            ) {
              return `(${a.code})`;
            }
            return a.code;
          };
          const formattedArgs = args.map((a, idx) =>
            formatTailTruncated(a, ins.b !== 0 && idx === args.length - 1)
          );
          let callCode = `${calleeText}(${formattedArgs.join(', ')})`;
          let singleRet = Boolean(fnExpr.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnExpr.calleeName));
          if (fnExpr.calleeName === 'string.format') {
            singleRet = true;
            const resugared = tryResugarStringFormat(args, env.opts);
            if (resugared) callCode = resugared;
          } else if (methodInfo && methodInfo.methodName === 'format' && methodInfo.objExpr.isConst && typeof methodInfo.objExpr.constVal === 'string') {
            singleRet = true;
            const resugared = tryResugarStringFormat([methodInfo.objExpr, ...args], env.opts);
            if (resugared) callCode = resugared;
          } else if (localProtoMap.has(ins.a)) {
            if (env.returnArities.get(localProtoMap.get(ins.a)!) === 1) singleRet = true;
          }

          // Special case: CALL immediately followed by FORGPREP* (e.g., ipairs(t) / pairs(t) returns 3 iterator regs)
          if (isForGIterCall && insns[i + 1].a === ins.a) {
            regExpr.set(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, calleeName: fnExpr.calleeName }));
            i++;
            break;
          }

          const callKind = methodInfo ? 'methodCall' : 'call';
          if (retCount === -1) {
            // MULTRET call result (C == 0): store at ins.a and record multretReg for SETLIST/CALL/RETURN consumer!
            settleOpenTableBeforeOverwrite(ins.a, out, lvl);
            regExpr.set(
              ins.a,
              atomExpr(callCode, {
                kind: callKind,
                prec: 90,
                singleReturn: false,
                calleeName: fnExpr.calleeName,
                hasEffect: true,
                readsMutable: true,
              })
            );
            regDefIdx.set(ins.a, i);
            multretReg = ins.a;
          } else if (retCount === 0) {
            out.push(`${indent(lvl)}${callCode}`);
            // Statement call clobbers ins.a..; drop stale temp bindings on ins.a unless captured or hoisted
            if (hoistedLocals.has(ins.a)) {
              const hoistedNm = declaredLocals.get(ins.a);
              if (hoistedNm) {
                regExpr.set(ins.a, atomExpr(hoistedNm, { kind: 'ident', isVarRef: true, regOrigin: ins.a, readsMutable: capturedRefRegs.has(ins.a) }));
              } else {
                regExpr.delete(ins.a);
              }
            } else if (declaredLocals.has(ins.a) && !capturedRefRegs.has(ins.a)) {
              const dbg = findDebugLocalForDef(ins.a, i);
              if (!dbg) {
                releaseDeclaredLocal(ins.a);
              }
            }
          } else if (retCount === 1) {
            assignReg(
              ins.a,
              atomExpr(callCode, {
                kind: callKind,
                prec: 90,
                singleReturn: singleRet,
                calleeName: fnExpr.calleeName,
                hasEffect: true,
                readsMutable: true,
              }),
              i,
              out,
              lvl
            );
          } else {
            // Multi-return assignment (`local a, b = fn(...)`, `a, b = fn(...)`, or mixed `local a; a, b = fn(...)`)
            for (let r = 0; r < retCount; r++) {
              const targetR = ins.a + r;
              settleOpenTableBeforeOverwrite(targetR, out, lvl);
              if (
                declaredLocals.has(targetR) &&
                !hoistedLocals.has(targetR) &&
                (wasCapturedByVal.has(targetR) ||
                  (declaredLocalIsFn.has(targetR) && lvl === indentLevel) ||
                  isDeadLocalAtReuse(targetR, i, lvl, callCode)) &&
                !capturedRefRegs.has(targetR)
              ) {
                releaseDeclaredLocal(targetR);
              }
            }
            const alreadyFlags = Array.from({ length: retCount }, (_, r) => declaredLocals.has(ins.a + r));
            const allAlreadyDeclared = alreadyFlags.every(Boolean);
            const noneAlreadyDeclared = alreadyFlags.every((f) => !f);

            const names: string[] = [];
            const newlyDeclared: string[] = [];
            const isPcall = fnExpr.calleeName === 'pcall' || fnExpr.calleeName === 'xpcall';
            const calleeProtoId = localProtoMap.get(ins.a) ?? fnExpr.protoId;
            const calleeProto = calleeProtoId !== undefined ? env.chunk.protos[calleeProtoId] : undefined;
            const returnedClosureHints: Array<string | undefined> = [];
            if (calleeProto && calleeProto.childProtos.length === retCount) {
              for (let r = 0; r < retCount; r++) {
                const cp = env.chunk.protos[calleeProto.childProtos[r]];
                returnedClosureHints.push(cp && isValidIdent(cp.debugName) ? cp.debugName : undefined);
              }
            }
            for (let r = 0; r < retCount; r++) {
              const targetR = ins.a + r;
              if (alreadyFlags[r]) {
                const nm = declaredLocals.get(targetR)!;
                regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR, readsMutable: capturedRefRegs.has(targetR) }));
                regDefIdx.set(targetR, i);
                names.push(nm);
              } else {
                const dbg = findDebugLocalForDef(targetR, i);
                const retHint = returnedClosureHints[r];
                const fallbackHint = dbg?.name ?? retHint ?? (isPcall ? (r === 0 ? 'ok' : r === 1 ? 'result' : undefined) : undefined);
                const nm = buildSemanticName(fallbackHint, 'v', usedNames, env.opts, env.metrics, Boolean(dbg?.name || retHint || isPcall));
                declaredLocals.set(targetR, nm);
                declaredLocalLvl.set(targetR, lvl);
                if (dbg) declaredLocalEndPc.set(targetR, dbg.endPc);
                regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR, readsMutable: capturedRefRegs.has(targetR) }));
                regDefIdx.set(targetR, i);
                names.push(nm);
                newlyDeclared.push(nm);
              }
            }

            if (allAlreadyDeclared) {
              out.push(`${indent(lvl)}${names.join(', ')} = ${callCode}`);
            } else if (noneAlreadyDeclared) {
              out.push(`${indent(lvl)}local ${names.join(', ')} = ${callCode}`);
            } else {
              out.push(`${indent(lvl)}local ${newlyDeclared.join(', ')}`);
              out.push(`${indent(lvl)}${names.join(', ')} = ${callCode}`);
            }
          }
          i++;
          break;
        }

        case 'NEWCLOSURE':
        case 'DUPCLOSURE': {
          // CRITICAL: Settle any stale open table on ins.a BEFORE creating a new closure in ins.a!
          settleOpenTableBeforeOverwrite(ins.a, out, lvl);

          const childProtoId =
            ins.opname === 'NEWCLOSURE'
              ? proto.childProtos[ins.d]
              : proto.constants[ins.d]?.closureProtoId;
          const childProto = childProtoId !== undefined ? env.chunk.protos[childProtoId] : undefined;

          // Peek trailing CAPTURE instructions first to detect self-capture & next non-CAPTURE consumer
          let j = i + 1;
          const rawCaptures: DecodedInstruction[] = [];
          while (j < endIdx && insns[j].opname === 'CAPTURE') {
            rawCaptures.push(insns[j]);
            j++;
          }

          const nextAfterCap = insns[j];
          const storedIntoTable =
            nextAfterCap &&
            (nextAfterCap.opname === 'SETTABLEKS' ||
              nextAfterCap.opname === 'SETUDATAKS' ||
              nextAfterCap.opname === 'SETTABLE' ||
              nextAfterCap.opname === 'SETTABLEN') &&
            nextAfterCap.a === ins.a;
          const returnedDirectly =
            nextAfterCap && nextAfterCap.opname === 'RETURN' && nextAfterCap.a === ins.a && nextAfterCap.b === 2;
          const selfCaptured = rawCaptures.some((c) => (c.a === 0 || c.a === 1) && c.b === ins.a);

          // Flush any open tables being captured by this closure!
          for (const cap of rawCaptures) {
            if ((cap.a === 0 || cap.a === 1) && cap.b !== ins.a && openTables.has(cap.b)) {
              flushOpenTable(cap.b, out, lvl, true);
            }
          }

          const calledDirectly =
            nextAfterCap && (nextAfterCap.opname === 'CALL' || nextAfterCap.opname === 'CALLFB') && nextAfterCap.a === ins.a;
          const shouldDeclareLocalFn =
            !storedIntoTable &&
            !returnedDirectly &&
            (selfCaptured ||
              calledDirectly ||
              materializeAt.has(`${i}:${ins.a}`) ||
              Boolean(childProto && isValidIdent(childProto.debugName)));

          // Clear stale local on ins.a if:
          //  - ins.a was captured by value (CAPTURE 0 -> MUST NEVER mutate, even if reused later for CAPTURE 1!)
          //  - OR ins.a is a new local function declaration at proto scope outside loops (even at -g0 when debugName is empty!)
          //  - OR childProto has a distinct debugName
          if (declaredLocals.has(ins.a) && !hoistedLocals.has(ins.a)) {
            if (wasCapturedByVal.has(ins.a) || isDeadLocalAtReuse(ins.a, i, lvl)) {
              releaseDeclaredLocal(ins.a);
            } else if (!capturedRefRegs.has(ins.a)) {
              if (
                (lvl === indentLevel && loopStack.length === 0 && !storedIntoTable && !returnedDirectly) ||
                (shouldDeclareLocalFn && childProto && isValidIdent(childProto.debugName) && declaredLocals.get(ins.a) !== childProto.debugName)
              ) {
                releaseDeclaredLocal(ins.a);
              }
            }
          }

          // Pre-bind recursive / named local function BEFORE lifting childProto so self-CAPTURE resolves to its real name!
          let preBoundName: string | undefined;
          if (shouldDeclareLocalFn && !declaredLocals.has(ins.a)) {
            const dbg = findDebugLocalForDef(ins.a, i, true);
            const hint =
              dbg?.name ??
              (childProto && isValidIdent(childProto.debugName) ? childProto.debugName : undefined);
            preBoundName = buildSemanticName(hint, 'fn', usedNames, env.opts, env.metrics);
            declaredLocals.set(ins.a, preBoundName);
            declaredLocalLvl.set(ins.a, lvl);
            declaredLocalIsFn.add(ins.a);
            if (dbg) declaredLocalEndPc.set(ins.a, dbg.endPc);
            regExpr.set(ins.a, atomExpr(preBoundName, { kind: 'ident', isVarRef: true, regOrigin: ins.a, protoId: childProto?.id }));
            regDefIdx.set(ins.a, i);
          }
          if (childProto) localProtoMap.set(ins.a, childProto.id);

          const captures: UpvalueBinding[] = [];
          for (const cap of rawCaptures) {
            if (cap.a === 0) {
              if (cap.b !== ins.a) wasCapturedByVal.add(cap.b);
              captures.push({ name: declaredLocals.get(cap.b) ?? getReg(cap.b).code, mode: 'val' });
            } else if (cap.a === 1) {
              captures.push({ name: declaredLocals.get(cap.b) ?? getReg(cap.b).code, mode: 'ref' });
            } else {
              const inherited = inheritedUpvalues[cap.b];
              captures.push({ name: getUpvalName(cap.b), mode: inherited ? inherited.mode : 'upval' });
            }
          }

          if (childProto) {
            const fnLines = decompileLuauProto(childProto, env, lvl, captures, false);
            const fnCode = fnLines.join('\n');
            if (preBoundName) {
              if (fnCode.startsWith('function(')) {
                out.push(`${indent(lvl)}local function ${preBoundName}${fnCode.slice('function'.length)}`);
              } else {
                out.push(`${indent(lvl)}local ${preBoundName} = ${fnCode}`);
              }
            } else {
              const preferred = childProto && isValidIdent(childProto.debugName) ? childProto.debugName : undefined;
              assignReg(
                ins.a,
                atomExpr(fnCode, { kind: 'function', prec: 100, protoId: childProto.id }),
                i,
                out,
                lvl,
                false,
                preferred
              );
            }
          } else {
            assignReg(ins.a, atomExpr('function() end', { kind: 'function', prec: 100 }), i, out, lvl);
          }
          i = j;
          break;
        }

        case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
        case 'AND': case 'OR': {
          const opMap: Record<string, string> = {
            ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^', IDIV: '//', AND: 'and', OR: 'or',
          };
          assignReg(ins.a, foldBinary(opMap[ins.opname], getReg(ins.b), getReg(ins.c), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
        case 'ANDK': case 'ORK': {
          const opMap: Record<string, string> = {
            ADDK: '+', SUBK: '-', MULK: '*', DIVK: '/', MODK: '%', POWK: '^', IDIVK: '//', ANDK: 'and', ORK: 'or',
          };
          assignReg(ins.a, foldBinary(opMap[ins.opname], getReg(ins.b), constantToExpr(proto.constants[ins.c], env.opts), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'SUBRK': case 'DIVRK': {
          const op = ins.opname === 'SUBRK' ? '-' : '/';
          assignReg(ins.a, foldBinary(op, constantToExpr(proto.constants[ins.b], env.opts), getReg(ins.c), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'CONCAT': {
          let acc = getReg(ins.b);
          for (let r = ins.b + 1; r <= ins.c; r++) {
            acc = foldBinary('..', acc, getReg(r), env.opts, env.metrics);
          }
          assignReg(ins.a, acc, i, out, lvl);
          i++;
          break;
        }

        case 'NOT': {
          const rhs = getReg(ins.b);
          assignReg(
            ins.a,
            { kind: 'unary', code: `not ${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable },
            i,
            out,
            lvl
          );
          i++;
          break;
        }

        case 'MINUS': {
          const rhs = getReg(ins.b);
          if (env.opts.foldConstants && rhs.isConst && typeof rhs.constVal === 'number') {
            env.metrics.constantsFolded++;
            assignReg(ins.a, atomExpr(formatNumber(-rhs.constVal, env.opts), { isConst: true, constVal: -rhs.constVal }), i, out, lvl);
          } else {
            const rhsCode = rhs.code.startsWith('-') ? `(${rhs.code})` : wrapIfLower(rhs, 80);
            assignReg(
              ins.a,
              { kind: 'unary', code: `-${rhsCode}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable },
              i,
              out,
              lvl
            );
          }
          i++;
          break;
        }

        case 'LENGTH': {
          if (openTables.has(ins.b)) flushOpenTable(ins.b, out, lvl);
          const rhs = getReg(ins.b);
          assignReg(
            ins.a,
            { kind: 'unary', code: `#${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: true },
            i,
            out,
            lvl
          );
          i++;
          break;
        }

        case 'FORNPREP': {
          flushAllOpenTables(out, lvl, true);
          const rawExitPc = ins.targetPc ?? (ins.pc + 1 + ins.d);
          const rawExitIdx = pcToIdx.get(rawExitPc) ?? endIdx;
          const headerPc = insns[i + 1]?.pc ?? (ins.pc + ins.width);
          let loopIdx = rawExitIdx - 1;
          if (!(loopIdx > i && insns[loopIdx]?.opname === 'FORNLOOP' && insns[loopIdx].a === ins.a)) {
            for (let k = i + 1; k < Math.min(insns.length, rawExitIdx + 1); k++) {
              const fl = insns[k];
              if (fl.opname === 'FORNLOOP' && fl.a === ins.a && fl.targetPc === headerPc) {
                loopIdx = k;
                break;
              }
            }
          }
          const afterLoopIdx = Math.min(endIdx, Math.max(i + 1, loopIdx + 1));
          const loopLatchPc = loopIdx >= 0 && loopIdx < insns.length ? insns[loopIdx].pc : rawExitPc - 1;
          const exitPc = insns[afterLoopIdx]?.pc ?? rawExitPc;
          const altExitPc = rawExitPc !== exitPc ? rawExitPc : undefined;
          hoistBlockLiveLocals(i, i + 1, afterLoopIdx, afterLoopIdx, out, lvl, {
            excludeRegs: new Set([ins.a, ins.a + 1, ins.a + 2]),
            loopHeaderIdx: i + 1,
          });
          const limit = getReg(ins.a);
          const step = getReg(ins.a + 1);
          const init = getReg(ins.a + 2);

          const dbgIdx = findDebugLocalForDef(ins.a + 2, i + 1);
          const preferredIdxName =
            dbgIdx?.name ??
            (env.opts.renamingType === 'SEMANTIC' ? (usedNames.has('i') ? (usedNames.has('j') ? 'k' : 'j') : 'i') : undefined);
          const hadIdxName = preferredIdxName ? usedNames.has(preferredIdxName) : false;
          const idxName = buildSemanticName(
            preferredIdxName,
            'i',
            usedNames,
            env.opts,
            env.metrics
          );
          declaredLocals.set(ins.a + 2, idxName);
          declaredLocalLvl.set(ins.a + 2, lvl + 1);
          regExpr.set(ins.a + 2, atomExpr(idxName, { kind: 'ident', isVarRef: true, regOrigin: ins.a + 2 }));
          releaseDeadLocalsAtEntry(i + 1, new Set([ins.a + 2]));

          const omitStep = env.opts.numericForStepSugaring && step.isConst && step.constVal === 1;
          out.push(`${indent(lvl)}for ${idxName} = ${init.code}, ${limit.code}${omitStep ? '' : `, ${step.code}`} do`);
          out.push(
            ...liftBlockScoped(i + 1, loopIdx, lvl + 1, [
              ...loopStack,
              { kind: 'forn', headerPc, latchPc: loopLatchPc, continuePc: loopLatchPc, exitPc, altExitPc },
            ])
          );
          out.push(`${indent(lvl)}end`);
          const idxWasCaptured =
            capturedRefRegs.has(ins.a + 2) || capturedValRegs.has(ins.a + 2) || wasCapturedByVal.has(ins.a + 2);
          releaseDeclaredLocal(ins.a + 2);
          if (!hadIdxName && !idxWasCaptured) {
            usedNames.delete(idxName);
          }
          i = afterLoopIdx;
          break;
        }

        case 'FORGPREP':
        case 'FORGPREP_NEXT':
        case 'FORGPREP_INEXT': {
          flushAllOpenTables(out, lvl, true);
          let iterCode = getReg(ins.a).code;
            if (ins.opname === 'FORGPREP_INEXT' && !iterCode.startsWith('ipairs(')) {
            const tbl = regExpr.get(ins.a + 1) ?? getReg(ins.a);
            iterCode = `ipairs(${tbl.code})`;
          } else if (ins.opname === 'FORGPREP_NEXT' && !iterCode.startsWith('pairs(')) {
            const tbl = regExpr.get(ins.a + 1) ?? getReg(ins.a);
            iterCode = `pairs(${tbl.code})`;
          }
          // Clear iterator control slots so stale generator expressions (e.g. Players:GetPlayers()) never leak into loop body
          regExpr.delete(ins.a);
          regExpr.delete(ins.a + 1);
          regExpr.delete(ins.a + 2);
          regDefIdx.delete(ins.a);
          regDefIdx.delete(ins.a + 1);
          regDefIdx.delete(ins.a + 2);
          const loopPc = ins.targetPc ?? (ins.pc + 1 + ins.d);
          const loopIdx = pcToIdx.get(loopPc);
          if (loopIdx !== undefined && loopIdx < endIdx && insns[loopIdx].opname === 'FORGLOOP') {
            const gloop = insns[loopIdx];
            const varCount = Math.max(1, (gloop.aux ?? 2) & 0xff);
            const forGExclude = new Set<number>([ins.a, ins.a + 1, ins.a + 2]);
            for (let v = 0; v < varCount; v++) forGExclude.add(ins.a + 3 + v);
            hoistBlockLiveLocals(i, i + 1, loopIdx + 1, loopIdx + 1, out, lvl, {
              excludeRegs: forGExclude,
              loopHeaderIdx: i + 1,
            });
            const isPairs = iterCode.startsWith('pairs(');
            const isIpairs = iterCode.startsWith('ipairs(');
            const inferIterValueHint = (ic: string): string => {
              if (/:GetPlayers\(\)\)?$/.test(ic) || /\b[Pp]layers\)?$/.test(ic)) return 'player';
              if (/:GetChildren\(\)\)?$/.test(ic) || /\b[Cc]hildren\)?$/.test(ic)) return 'child';
              if (/:GetDescendants\(\)\)?$/.test(ic)) return 'descendant';
              if (/:GetTagged\([^)]*\)\)?$/.test(ic)) return 'inst';
              return 'value';
            };
            const valHint = inferIterValueHint(iterCode);
            const hints = isPairs ? ['key', valHint] : isIpairs ? ['index', valHint] : varCount === 1 ? ['v'] : ['k', 'v'];
            const varNames: string[] = [];
            const hadVarNames: boolean[] = [];
            for (let v = 0; v < varCount; v++) {
              const varReg = ins.a + 3 + v;
              const dbgVar = findDebugLocalForDef(varReg, i + 1);
              let isUnusedFirstLoopVar = false;
              if (v === 0 && varCount >= 2 && !dbgVar?.name && (isPairs || isIpairs)) {
                let readInLoop = false;
                for (let lk = i + 1; lk < loopIdx; lk++) {
                  luauForEachReadReg(insns[lk], lk, multretEndAt, (rr) => {
                    if (rr === varReg) readInLoop = true;
                  });
                  if (readInLoop) break;
                }
                if (!readInLoop) isUnusedFirstLoopVar = true;
              }
              if (isUnusedFirstLoopVar) {
                hadVarNames.push(true);
                declaredLocals.set(varReg, '_');
                declaredLocalLvl.set(varReg, lvl + 1);
                regExpr.set(varReg, atomExpr('_', { kind: 'ident', isVarRef: true, regOrigin: varReg }));
                varNames.push('_');
              } else {
                const pref = dbgVar?.name ?? (env.opts.renamingType === 'SEMANTIC' ? hints[v] : undefined);
                hadVarNames.push(pref ? usedNames.has(pref) : false);
                const nm = buildSemanticName(
                  pref,
                  'v',
                  usedNames,
                  env.opts,
                  env.metrics
                );
                declaredLocals.set(varReg, nm);
                declaredLocalLvl.set(varReg, lvl + 1);
                regExpr.set(varReg, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: varReg }));
                varNames.push(nm);
              }
            }
            const exitPc = gloop.pc + gloop.width;
            const keepLoopVars = new Set<number>();
            for (let v = 0; v < varCount; v++) keepLoopVars.add(ins.a + 3 + v);
            releaseDeadLocalsAtEntry(i + 1, keepLoopVars);
            out.push(`${indent(lvl)}for ${varNames.join(', ')} in ${iterCode} do`);
            out.push(
              ...liftBlockScoped(i + 1, loopIdx, lvl + 1, [
                ...loopStack,
                { kind: 'forg', headerPc: insns[i + 1]?.pc ?? ins.pc + 1, latchPc: gloop.pc, continuePc: gloop.pc, exitPc },
              ])
            );
            out.push(`${indent(lvl)}end`);
            for (let v = 0; v < varCount; v++) {
              const r = ins.a + 3 + v;
              const wasCap = capturedRefRegs.has(r) || capturedValRegs.has(r) || wasCapturedByVal.has(r);
              releaseDeclaredLocal(r);
              if (!hadVarNames[v] && !wasCap) {
                usedNames.delete(varNames[v]);
              }
            }
            i = loopIdx + 1;
          } else {
            const msg = `Could not match ${ins.opname} at pc=${ins.pc} with FORGLOOP at pc=${loopPc}.`;
            env.diagnostics.push({
              severity: 'warning',
              code: 'UNRECONSTRUCTED_LOOP',
              message: msg,
              protoId: proto.id,
              pc: ins.pc,
              section: 'decompiler',
            });
            out.push(`${indent(lvl)}-- [unreconstructed ${ins.opname} pc=${ins.pc} -> loopPc=${loopPc}]`);
            i++;
          }
          break;
        }

        case 'JUMP':
        case 'JUMPX': {
          const targetPc = ins.targetPc;
          const activeLoop = loopStack[loopStack.length - 1];
          if (activeLoop && isLoopExitTarget(activeLoop, targetPc)) {
            env.metrics.breaksRecovered++;
            out.push(`${indent(lvl)}break`);
            i++;
          } else if (activeLoop && env.opts.virtualizeContinue && isLoopContinueTarget(activeLoop, targetPc)) {
            env.metrics.continuesRecovered++;
            out.push(`${indent(lvl)}continue`);
            i++;
          } else if (targetPc !== undefined) {
            const targetIdx = pcToIdx.get(targetPc);
            if (targetIdx !== undefined && targetIdx > i && targetIdx <= endIdx) {
              env.metrics.deadBranchesEliminated++;
              i = targetIdx;
            } else if (targetIdx !== i + 1) {
              env.diagnostics.push({
                severity: 'warning',
                code: 'UNRECONSTRUCTED_JUMP',
                message: `Unstructured ${ins.opname} at pc=${ins.pc} targeting pc=${targetPc}.`,
                protoId: proto.id,
                pc: ins.pc,
                section: 'decompiler',
              });
              out.push(`${indent(lvl)}-- [unreconstructed ${ins.opname} pc=${ins.pc} -> pc=${targetPc}]`);
              i++;
            } else {
              i++;
            }
          } else {
            i++;
          }
          break;
        }

        case 'JUMPBACK': {
          const targetPc = ins.targetPc;
          const activeLoop = loopStack[loopStack.length - 1];
          if (activeLoop && env.opts.virtualizeContinue && isLoopContinueTarget(activeLoop, targetPc)) {
            env.metrics.continuesRecovered++;
            out.push(`${indent(lvl)}continue`);
            i++;
          } else if (activeLoop && isLoopExitTarget(activeLoop, targetPc)) {
            env.metrics.breaksRecovered++;
            out.push(`${indent(lvl)}break`);
            i++;
          } else {
            env.diagnostics.push({
              severity: 'warning',
              code: 'UNSTRUCTURED_JUMPBACK',
              message: `Unstructured JUMPBACK at pc=${ins.pc} targeting pc=${targetPc ?? '?'}.`,
              protoId: proto.id,
              pc: ins.pc,
              section: 'decompiler',
            });
            out.push(`${indent(lvl)}-- [unstructured JUMPBACK -> pc=${targetPc ?? '?'}]`);
            i++;
          }
          break;
        }

        case 'JUMPIF': case 'JUMPIFNOT':
        case 'JUMPIFEQ': case 'JUMPIFLE': case 'JUMPIFLT':
        case 'JUMPIFNOTEQ': case 'JUMPIFNOTLE': case 'JUMPIFNOTLT':
        case 'JUMPXEQKNIL': case 'JUMPXEQKB': case 'JUMPXEQKN': case 'JUMPXEQKS': {
          const cond = evalLuauJumpCondition(ins);
          const targetPc = ins.targetPc ?? (ins.pc + ins.width);
          const targetIdx = pcToIdx.get(targetPc) ?? endIdx;

          // Pattern 0: LOADB boolean expression idiom (`JUMPIF* -> +2; LOADB R, b1, C=1; LOADB R, b2, C=0`)
          // Evaluate BEFORE flushing open tables so boolean fields inside `{ a = x == y }` stay folded!
          if (
            targetIdx === i + 2 &&
            i + 2 < endIdx &&
            insns[i + 1].opname === 'LOADB' &&
            insns[i + 1].c === 1 &&
            insns[i + 2].opname === 'LOADB' &&
            insns[i + 2].c === 0 &&
            insns[i + 1].a === insns[i + 2].a
          ) {
            const destReg = insns[i + 1].a;
            const boolExprStr = insns[i + 1].b !== 0 ? cond.fallthroughCond : cond.jumpTakenCond;
            assignReg(destReg, atomExpr(boolExprStr, { kind: 'binary', prec: 40 }), i + 2, out, lvl);
            i += 3;
            continue;
          }

          // Helper: infer exact Lua/Luau precedence for a condition string at paren depth 0
          const condExprFromStr = (code: string, hasEffect = false, readsMutable = false): Expr => {
            const trimmed = code.trim();
            const prec = inferExprPrec(trimmed);
            const kind: Expr['kind'] = prec === 80 ? 'unary' : prec < 100 ? 'binary' : 'ident';
            return atomExpr(trimmed, { kind, prec, hasEffect, readsMutable });
          };

          // Transitive forward-jump closure starting at conditional jump `i` to find the exact join boundary
          // of any pure/expression short-circuit DAG without crossing into following statements or siblings.
          const findShortCircuitEndIdx = (): number | null => {
            if (targetIdx <= i + 1 || targetIdx > endIdx) return null;
            let limit = targetIdx;
            for (let k = i + 1; k < limit; k++) {
              if (allLoopHeaderIdxs.has(k) || backwardJumpTargetIdxs.has(k)) return null;
              const ki = insns[k];
              const kop = ki.opname;
              if (isLuauCondJump(kop) || kop === 'JUMP' || kop === 'JUMPX') {
                const tPc = ki.targetPc;
                const tIdx = tPc !== undefined ? pcToIdx.get(tPc) : undefined;
                if (tIdx === undefined || tIdx <= k || tIdx > endIdx) return null;
                if (tIdx > limit) limit = tIdx;
              } else if (
                kop === 'RETURN' ||
                kop === 'SETUPVAL' ||
                kop === 'SETGLOBAL' ||
                kop === 'FORNPREP' ||
                kop === 'FORNLOOP' ||
                kop === 'FORGPREP' ||
                kop === 'FORGPREP_NEXT' ||
                kop === 'FORGPREP_INEXT' ||
                kop === 'FORGLOOP' ||
                kop === 'JUMPBACK' ||
                kop === 'CLOSEUPVALS' ||
                kop === 'NEWCLOSURE' ||
                kop === 'DUPCLOSURE' ||
                ((kop === 'CALL' || kop === 'CALLFB') && (ki.c !== 2 || ki.b === 0)) ||
                (kop === 'GETVARARGS' && ki.b !== 2)
              ) {
                return null;
              }
            }
            return limit;
          };

          const scEndCandidate = findShortCircuitEndIdx();
          const liveAfterTopSlice =
            scEndCandidate !== null && scEndCandidate < insns.length ? liveIn[scEndCandidate] : new Set<number>();

          // General sandboxed short-circuit / expression-DAG lifter:
          // Evaluates [sIdx .. eIdx) without mutating live register state unless the entire expression matches.
          // Handles arbitrary nested `and`/`or` chains, jump-threaded outer joins, multi-guard conditions,
          // Luau `if-then-else` expressions, function/method calls, arithmetic, indexing, and temp tables.
          const tryLiftShortCircuitOrSlice = (
            sIdx: number,
            eIdx: number,
            outerJoinIdx: number,
            expectedDestReg: number,
            baseRegs: Map<number, Expr>,
            depth = 0
          ): { reg: number; expr: Expr; nextIdx: number; writtenRegs: Set<number> } | null => {
            if (depth > 12 || sIdx >= eIdx || eIdx > endIdx) return null;

            for (let k = sIdx + 1; k < eIdx; k++) {
              if (allLoopHeaderIdxs.has(k) || backwardJumpTargetIdxs.has(k)) return null;
            }

            const simRegs = new Map<number, Expr>(baseRegs);
            const simMethods = new Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>();
            const simTables = new Map<number, Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }>>();
            const writtenRegs = new Set<number>();

            const simGet = (r: number, regsMap: Map<number, Expr> = simRegs): Expr => {
              const ex = regsMap.get(r);
              if (ex) return ex;
              const loc = declaredLocals.get(r);
              if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
              return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
            };

            const simEvalCond = (
              jIns: DecodedInstruction,
              regsMap: Map<number, Expr> = simRegs
            ): { jumpTakenCond: string; fallthroughCond: string; hasEffect: boolean; readsMutable: boolean } => {
              return evalLuauJumpCondition(jIns, (r) => simGet(r, regsMap), false);
            };

            const checkWriteSafe = (r: number, destHint: number = expectedDestReg): boolean => {
              if (destHint >= 0 && r === destHint) return true;
              if (destHint < 0 && !declaredLocals.has(r) && !capturedRefRegs.has(r)) return true;
              // Any non-destination register written inside the expression slice MUST be dead after the whole slice
              // and not ref-captured (prevents mislifting multi-output `if a then x = 1; y = 2 end` as `a and a`!).
              return !liveAfterTopSlice.has(r) && !capturedRefRegs.has(r);
            };

            // Simulate a single non-jump expression instruction against a register map
            const simStepExpr = (
              ci: DecodedInstruction,
              regsMap: Map<number, Expr>,
              methodsMap: Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>,
              tablesMap: Map<number, Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }>>,
              destHint: number,
              wSet: Set<number>
            ): { ok: boolean; writtenReg: number; hasEffect: boolean; readsMutable: boolean } => {
              const fail = { ok: false, writtenReg: -1, hasEffect: false, readsMutable: false };
              switch (ci.opname) {
                case 'NOP':
                case 'PREPVARARGS':
                  return { ok: true, writtenReg: -1, hasEffect: false, readsMutable: false };
                case 'LOADNIL':
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, atomExpr('nil', { isConst: true, constVal: null }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                case 'LOADB':
                  if (ci.c !== 0 || !checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, atomExpr(ci.b !== 0 ? 'true' : 'false', { isConst: true, constVal: ci.b !== 0 }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                case 'LOADN':
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, atomExpr(formatNumber(ci.d, env.opts), { isConst: true, constVal: ci.d }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                case 'LOADK':
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, constantToExpr(proto.constants[ci.d], env.opts));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                case 'LOADKX':
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, constantToExpr(proto.constants[ci.aux ?? 0], env.opts));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                case 'MOVE': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const src = simGet(ci.b, regsMap);
                  regsMap.set(ci.a, src);
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(src.hasEffect), readsMutable: Boolean(src.readsMutable) };
                }
                case 'GETIMPORT': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const k = proto.constants[ci.d];
                  const path = k?.importPath?.join('.') ?? `K${ci.d}`;
                  regsMap.set(ci.a, atomExpr(path, { kind: 'global', calleeName: path }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                }
                case 'GETGLOBAL': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const k = proto.constants[ci.aux ?? 0];
                  const gname = k?.kind === 'string' ? String(k.value) : `G${ci.aux}`;
                  regsMap.set(ci.a, atomExpr(gname, { kind: 'global', calleeName: gname }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                }
                case 'GETUPVAL':
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, atomExpr(getUpvalName(ci.b), { kind: 'ident', isVarRef: true, readsMutable: true }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: true };
                case 'GETTABLEKS':
                case 'GETUDATAKS': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const tbl = simGet(ci.b, regsMap);
                  const kIdx = ci.opname === 'GETUDATAKS' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                  const keyK = proto.constants[kIdx];
                  const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                  const tblCode = wrapPrefixExpr(tbl);
                  const code = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
                  regsMap.set(ci.a, atomExpr(code, { kind: 'index', prec: 90, calleeName: code, hasEffect: tbl.hasEffect, readsMutable: true }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(tbl.hasEffect), readsMutable: true };
                }
                case 'GETTABLE': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const tbl = simGet(ci.b, regsMap);
                  const key = simGet(ci.c, regsMap);
                  regsMap.set(
                    ci.a,
                    atomExpr(`${wrapPrefixExpr(tbl)}[${key.code}]`, {
                      kind: 'index',
                      prec: 90,
                      hasEffect: Boolean(tbl.hasEffect || key.hasEffect),
                      readsMutable: true,
                    })
                  );
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(tbl.hasEffect || key.hasEffect), readsMutable: true };
                }
                case 'GETTABLEN': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const tbl = simGet(ci.b, regsMap);
                  regsMap.set(ci.a, atomExpr(`${wrapPrefixExpr(tbl)}[${ci.c + 1}]`, { kind: 'index', prec: 90, hasEffect: tbl.hasEffect, readsMutable: true }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(tbl.hasEffect), readsMutable: true };
                }
                case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
                case 'AND': case 'OR': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const opMap: Record<string, string> = {
                    ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^', IDIV: '//', AND: 'and', OR: 'or',
                  };
                  const e = foldBinary(opMap[ci.opname], simGet(ci.b, regsMap), simGet(ci.c, regsMap), env.opts, env.metrics);
                  regsMap.set(ci.a, e);
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(e.hasEffect), readsMutable: Boolean(e.readsMutable) };
                }
                case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
                case 'ANDK': case 'ORK': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const opMap: Record<string, string> = {
                    ADDK: '+', SUBK: '-', MULK: '*', DIVK: '/', MODK: '%', POWK: '^', IDIVK: '//', ANDK: 'and', ORK: 'or',
                  };
                  const e = foldBinary(opMap[ci.opname], simGet(ci.b, regsMap), constantToExpr(proto.constants[ci.c], env.opts), env.opts, env.metrics);
                  regsMap.set(ci.a, e);
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(e.hasEffect), readsMutable: Boolean(e.readsMutable) };
                }
                case 'SUBRK': case 'DIVRK': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const op = ci.opname === 'SUBRK' ? '-' : '/';
                  const e = foldBinary(op, constantToExpr(proto.constants[ci.b], env.opts), simGet(ci.c, regsMap), env.opts, env.metrics);
                  regsMap.set(ci.a, e);
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(e.hasEffect), readsMutable: Boolean(e.readsMutable) };
                }
                case 'CONCAT': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  let acc = simGet(ci.b, regsMap);
                  for (let r = ci.b + 1; r <= ci.c; r++) acc = foldBinary('..', acc, simGet(r, regsMap), env.opts, env.metrics);
                  regsMap.set(ci.a, acc);
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(acc.hasEffect), readsMutable: Boolean(acc.readsMutable) };
                }
                case 'NOT': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const rhs = simGet(ci.b, regsMap);
                  regsMap.set(ci.a, { kind: 'unary', code: `not ${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(rhs.hasEffect), readsMutable: Boolean(rhs.readsMutable) };
                }
                case 'MINUS': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const rhs = simGet(ci.b, regsMap);
                  const rhsCode = rhs.code.startsWith('-') ? `(${rhs.code})` : wrapIfLower(rhs, 80);
                  regsMap.set(ci.a, { kind: 'unary', code: `-${rhsCode}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(rhs.hasEffect), readsMutable: Boolean(rhs.readsMutable) };
                }
                case 'LENGTH': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const rhs = simGet(ci.b, regsMap);
                  regsMap.set(ci.a, { kind: 'unary', code: `#${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: true });
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: Boolean(rhs.hasEffect), readsMutable: true };
                }
                case 'NEWTABLE':
                case 'DUPTABLE': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const entries: Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }> = [];
                  if (ci.opname === 'DUPTABLE') {
                    const tmpl = proto.constants[ci.d];
                    if (tmpl?.tableConstantEntries) {
                      for (const ent of tmpl.tableConstantEntries) {
                        if (ent.valueConstIdx >= 0) {
                          const valExpr = constantToExpr(proto.constants[ent.valueConstIdx], env.opts);
                          const keyFmt = isValidIdent(ent.key) ? ent.key : `[${escapeLuaString(ent.key)}]`;
                          entries.push({ key: keyFmt, keyRaw: ent.key, val: valExpr.code });
                        }
                      }
                    }
                  }
                  tablesMap.set(ci.a, entries);
                  regsMap.set(ci.a, atomExpr(formatTableLiteral(entries, indent, lvl), { kind: 'table', prec: 100 }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                }
                case 'SETTABLEKS':
                case 'SETUDATAKS': {
                  const entries = tablesMap.get(ci.b);
                  if (!entries) return fail;
                  const val = simGet(ci.a, regsMap);
                  const kIdx = ci.opname === 'SETUDATAKS' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                  const keyK = proto.constants[kIdx];
                  const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                  const keyFmt = isValidIdent(keyStr) ? keyStr : `[${escapeLuaString(keyStr)}]`;
                  const entry = { key: keyFmt, keyRaw: keyStr, val: val.code, hasEffect: Boolean(val.hasEffect), readsMutable: Boolean(val.readsMutable) };
                  const exIdx = entries.findIndex((e) => e.keyRaw === keyStr);
                  if (exIdx !== -1) entries[exIdx] = entry;
                  else entries.push(entry);
                  regsMap.set(
                    ci.b,
                    atomExpr(formatTableLiteral(entries, indent, lvl), {
                      kind: 'table',
                      prec: 100,
                      hasEffect: entries.some((e) => e.hasEffect),
                      readsMutable: entries.some((e) => e.readsMutable),
                    })
                  );
                  wSet.add(ci.b);
                  return { ok: true, writtenReg: ci.b, hasEffect: Boolean(val.hasEffect), readsMutable: Boolean(val.readsMutable) };
                }
                case 'SETLIST': {
                  const entries = tablesMap.get(ci.a);
                  if (!entries || ci.c === 0) return fail;
                  const count = ci.c - 1;
                  for (let k = 0; k < count; k++) {
                    const e = simGet(ci.b + k, regsMap);
                    const isLastFixed = k === count - 1;
                    const needsTrunc =
                      isLastFixed && !e.singleReturn && (e.kind === 'call' || e.kind === 'methodCall' || e.kind === 'vararg');
                    entries.push({ val: needsTrunc ? `(${e.code})` : e.code, hasEffect: Boolean(e.hasEffect), readsMutable: Boolean(e.readsMutable) });
                  }
                  regsMap.set(
                    ci.a,
                    atomExpr(formatTableLiteral(entries, indent, lvl), {
                      kind: 'table',
                      prec: 100,
                      hasEffect: entries.some((e) => e.hasEffect),
                      readsMutable: entries.some((e) => e.readsMutable),
                    })
                  );
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: entries.some((e) => e.hasEffect), readsMutable: entries.some((e) => e.readsMutable) };
                }
                case 'NAMECALL':
                case 'NAMECALLUDATA': {
                  if (!checkWriteSafe(ci.a, destHint)) return fail;
                  const obj = simGet(ci.b, regsMap);
                  const kIdx = ci.opname === 'NAMECALLUDATA' ? (ci.aux ?? 0) & 0xffff : ci.aux ?? 0;
                  const methodK = proto.constants[kIdx];
                  const methodName = methodK?.kind === 'string' ? String(methodK.value) : `method_${kIdx}`;
                  const recvCode = wrapPrefixExpr(obj);
                  const calleeFull = `${recvCode}:${methodName}`;
                  methodsMap.set(ci.a, { calleeFull, objExpr: obj, methodName });
                  regsMap.set(ci.a, atomExpr(calleeFull, { kind: 'methodCall', prec: 90, calleeName: calleeFull, hasEffect: obj.hasEffect, readsMutable: obj.readsMutable }));
                  regsMap.set(ci.a + 1, obj);
                  wSet.add(ci.a);
                  wSet.add(ci.a + 1);
                  return { ok: true, writtenReg: -1, hasEffect: Boolean(obj.hasEffect), readsMutable: Boolean(obj.readsMutable) };
                }
                case 'CALL':
                case 'CALLFB': {
                  if (ci.c !== 2 || ci.b === 0 || !checkWriteSafe(ci.a, destHint)) return fail;
                  const mInfo = methodsMap.get(ci.a);
                  if (mInfo) methodsMap.delete(ci.a);
                  const fnE = mInfo
                    ? atomExpr(mInfo.calleeFull, { kind: 'methodCall', prec: 90, calleeName: mInfo.calleeFull })
                    : simGet(ci.a, regsMap);
                  const totalSlots = ci.b - 1;
                  const startOff = mInfo ? 2 : 1;
                  const cArgs: Expr[] = [];
                  for (let off = startOff; off <= totalSlots; off++) {
                    cArgs.push(simGet(ci.a + off, regsMap));
                  }
                  const calleeTxt = mInfo ? fnE.code : wrapPrefixExpr(fnE);
                  const fmtArgs = cArgs.map((a, idx) => {
                    const isLastFixed = idx === cArgs.length - 1;
                    if (isLastFixed && !a.singleReturn && (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')) {
                      return `(${a.code})`;
                    }
                    return a.code;
                  });
                  let cCode = `${calleeTxt}(${fmtArgs.join(', ')})`;
                  let sRet = Boolean(fnE.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnE.calleeName));
                  if (fnE.calleeName === 'string.format') {
                    sRet = true;
                    const resugared = tryResugarStringFormat(cArgs, env.opts);
                    if (resugared) cCode = resugared;
                  } else if (mInfo && mInfo.methodName === 'format' && mInfo.objExpr.isConst && typeof mInfo.objExpr.constVal === 'string') {
                    sRet = true;
                    const resugared = tryResugarStringFormat([mInfo.objExpr, ...cArgs], env.opts);
                    if (resugared) cCode = resugared;
                  }
                  regsMap.set(
                    ci.a,
                    atomExpr(cCode, {
                      kind: mInfo ? 'methodCall' : 'call',
                      prec: 90,
                      singleReturn: sRet,
                      calleeName: fnE.calleeName,
                      hasEffect: true,
                      readsMutable: true,
                    })
                  );
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: true, readsMutable: true };
                }
                case 'GETVARARGS':
                  if (ci.b !== 2 || !checkWriteSafe(ci.a, destHint)) return fail;
                  regsMap.set(ci.a, atomExpr('...', { kind: 'vararg', prec: 100 }));
                  wSet.add(ci.a);
                  return { ok: true, writtenReg: ci.a, hasEffect: false, readsMutable: false };
                default:
                  return fail;
              }
            };

            // Zero-duplication boolean condition DAG lifter:
            // Lifts any multi-jump boolean guard starting at `bStart` whose ONLY exits are `trueTarget` and `falseTarget`.
            const simLiftBoolCond = (
              bStart: number,
              trueTarget: number,
              falseTarget: number,
              inRegs: Map<number, Expr>,
              destHint: number,
              bDepth = 0
            ): { expr: Expr; regsAtTrue: Map<number, Expr>; regsAtFalse: Map<number, Expr>; wSet: Set<number> } | null => {
              if (bDepth > 10 || trueTarget === falseTarget) return null;
              const upper = Math.max(trueTarget, falseTarget);
              if (bStart >= upper || upper > outerJoinIdx) return null;

              const cRegs = new Map<number, Expr>(inRegs);
              const cMethods = new Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>();
              const cTables = new Map<number, Array<{ key?: string; keyRaw?: string; val: string; hasEffect?: boolean; readsMutable?: boolean }>>();
              const wSet = new Set<number>();

              let p = bStart;
              while (p < upper && !isLuauCondJump(insns[p].opname)) {
                const st = simStepExpr(insns[p], cRegs, cMethods, cTables, destHint, wSet);
                if (!st.ok) return null;
                p++;
              }
              if (p >= upper || !isLuauCondJump(insns[p].opname)) return null;

              const ji = insns[p];
              const takenIdx = ji.targetPc !== undefined ? pcToIdx.get(ji.targetPc) : undefined;
              const fallIdx = p + 1;
              if (takenIdx === undefined || takenIdx <= p || takenIdx > upper) return null;

              const jc = simEvalCond(ji, cRegs);
              const takenE = condExprFromStr(jc.jumpTakenCond, jc.hasEffect, jc.readsMutable);
              const fallE = condExprFromStr(jc.fallthroughCond, jc.hasEffect, jc.readsMutable);

              // Direct 1-jump match
              if (takenIdx === trueTarget && fallIdx === falseTarget) {
                return { expr: takenE, regsAtTrue: cRegs, regsAtFalse: cRegs, wSet };
              }
              if (takenIdx === falseTarget && fallIdx === trueTarget) {
                return { expr: fallE, regsAtTrue: cRegs, regsAtFalse: cRegs, wSet };
              }
              // Short-circuit AND chain: jump to falseTarget on false, fallthrough continues testing
              if (takenIdx === falseTarget && fallIdx < upper) {
                const rest = simLiftBoolCond(fallIdx, trueTarget, falseTarget, cRegs, destHint, bDepth + 1);
                if (rest) {
                  for (const r of rest.wSet) wSet.add(r);
                  return {
                    expr: foldBinary('and', fallE, rest.expr, env.opts, env.metrics),
                    regsAtTrue: rest.regsAtTrue,
                    regsAtFalse: cRegs,
                    wSet,
                  };
                }
              }
              // Short-circuit OR chain: jump to trueTarget on true, fallthrough continues testing
              if (takenIdx === trueTarget && fallIdx < upper) {
                const rest = simLiftBoolCond(fallIdx, trueTarget, falseTarget, cRegs, destHint, bDepth + 1);
                if (rest) {
                  for (const r of rest.wSet) wSet.add(r);
                  return {
                    expr: foldBinary('or', takenE, rest.expr, env.opts, env.metrics),
                    regsAtTrue: cRegs,
                    regsAtFalse: rest.regsAtFalse,
                    wSet,
                  };
                }
              }
              // Nested compound guard: `(A and B) or C` or `(A or B) and C`
              if (takenIdx > fallIdx && takenIdx < upper) {
                const subAnd = simLiftBoolCond(fallIdx, trueTarget, takenIdx, cRegs, destHint, bDepth + 1);
                if (subAnd) {
                  const restOr = simLiftBoolCond(takenIdx, trueTarget, falseTarget, cRegs, destHint, bDepth + 1);
                  if (restOr) {
                    for (const r of subAnd.wSet) wSet.add(r);
                    for (const r of restOr.wSet) wSet.add(r);
                    return {
                      expr: foldBinary('or', foldBinary('and', fallE, subAnd.expr, env.opts, env.metrics), restOr.expr, env.opts, env.metrics),
                      regsAtTrue: restOr.regsAtTrue,
                      regsAtFalse: restOr.regsAtFalse,
                      wSet,
                    };
                  }
                }
                const subOr = simLiftBoolCond(fallIdx, takenIdx, falseTarget, cRegs, destHint, bDepth + 1);
                if (subOr) {
                  const restAnd = simLiftBoolCond(takenIdx, trueTarget, falseTarget, cRegs, destHint, bDepth + 1);
                  if (restAnd) {
                    for (const r of subOr.wSet) wSet.add(r);
                    for (const r of restAnd.wSet) wSet.add(r);
                    return {
                      expr: foldBinary('and', foldBinary('or', takenE, subOr.expr, env.opts, env.metrics), restAnd.expr, env.opts, env.metrics),
                      regsAtTrue: restAnd.regsAtTrue,
                      regsAtFalse: restAnd.regsAtFalse,
                      wSet,
                    };
                  }
                }
              }
              return null;
            };

            let cur = sIdx;
            let lastWrittenReg = -1;
            let anyEffect = false;
            let anyMutable = false;

            while (cur < eIdx) {
              const ci = insns[cur];

              if (isLuauCondJump(ci.opname)) {
                const cTargetPc = ci.targetPc ?? (ci.pc + ci.width);
                const cTargetIdx = pcToIdx.get(cTargetPc);
                if (cTargetIdx === undefined || cTargetIdx <= cur + 1 || cTargetIdx > outerJoinIdx) return null;

                // Pattern SC-0: LOADB boolean idiom inside slice
                if (
                  cTargetIdx === cur + 2 &&
                  cur + 2 < eIdx &&
                  insns[cur + 1].opname === 'LOADB' &&
                  insns[cur + 1].c === 1 &&
                  insns[cur + 2].opname === 'LOADB' &&
                  insns[cur + 2].c === 0 &&
                  insns[cur + 1].a === insns[cur + 2].a
                ) {
                  const dReg = insns[cur + 1].a;
                  if (!checkWriteSafe(dReg)) return null;
                  const jc = simEvalCond(ci);
                  const bStr = insns[cur + 1].b !== 0 ? jc.fallthroughCond : jc.jumpTakenCond;
                  simRegs.set(dReg, condExprFromStr(bStr, jc.hasEffect, jc.readsMutable));
                  writtenRegs.add(dReg);
                  lastWrittenReg = dReg;
                  anyEffect = anyEffect || jc.hasEffect;
                  anyMutable = anyMutable || jc.readsMutable;
                  cur += 3;
                  continue;
                }

                // Collect candidate falseTarget splits for Pattern SC-1a / SC-1b:
                //   Candidate 1: direct `falseTarget = cTargetIdx` (e.g. `a and b or c`, `a and b and c or d`)
                //   Candidate 2: OR-guarded `trueTarget = cTargetIdx`, `falseTarget = target of insns[cTargetIdx - 1]` (e.g. `(a or b) and (c or d) or 5`)
                const scCandidates: Array<{ guardEndHint: number; falseTarget: number }> = [];
                if (cTargetIdx <= eIdx) {
                  scCandidates.push({ guardEndHint: cur + 1, falseTarget: cTargetIdx });
                  const preTrue = insns[cTargetIdx - 1];
                  if (preTrue && isLuauCondJump(preTrue.opname) && preTrue.targetPc !== undefined) {
                    const altFalse = pcToIdx.get(preTrue.targetPc);
                    if (altFalse !== undefined && altFalse > cTargetIdx && altFalse <= eIdx) {
                      scCandidates.push({ guardEndHint: cTargetIdx, falseTarget: altFalse });
                    }
                  }
                }

                let matchedCompound = false;
                for (const cand of scCandidates) {
                  const falseTarget = cand.falseTarget;
                  const tailJ = insns[falseTarget - 1];
                  if (!tailJ || tailJ.targetPc === undefined) continue;

                  // Pattern SC-1a: Compound `GUARD and MID or RHS` / `(GUARD) and RHS`
                  if (tailJ.opname === 'JUMPIF' || tailJ.opname === 'JUMPIFNOT') {
                    const joinIdx = pcToIdx.get(tailJ.targetPc);
                    const isNormalJoin = joinIdx !== undefined && joinIdx > falseTarget && joinIdx <= eIdx;
                    const isThreadedJoin =
                      joinIdx !== undefined &&
                      tailJ.opname === 'JUMPIF' &&
                      joinIdx === outerJoinIdx &&
                      falseTarget < eIdx &&
                      (expectedDestReg < 0 || tailJ.a === expectedDestReg);

                    if (isNormalJoin || isThreadedJoin) {
                      const destReg = tailJ.a;
                      if (expectedDestReg >= 0 && destReg !== expectedDestReg) continue;
                      if (!checkWriteSafe(destReg, destReg)) continue;

                      const rhsEnd = isNormalJoin ? joinIdx! : eIdx;
                      const nextOuterJoin = isNormalJoin ? joinIdx! : outerJoinIdx;

                      if (tailJ.opname === 'JUMPIFNOT') {
                        // `(A or B) and C` / `(A and B or C) and D`:
                        // Entire [cur .. falseTarget) is a boolean guard exiting to (true=falseTarget, false=joinIdx).
                        const boolGuard = simLiftBoolCond(cur, falseTarget, joinIdx!, simRegs, destReg, 0);
                        if (boolGuard) {
                          const rhsRes = tryLiftShortCircuitOrSlice(falseTarget, rhsEnd, nextOuterJoin, destReg, boolGuard.regsAtTrue, depth + 1);
                          if (rhsRes && rhsRes.reg === destReg) {
                            const fullExpr = foldBinary('and', boolGuard.expr, rhsRes.expr, env.opts, env.metrics);
                            simRegs.set(destReg, fullExpr);
                            writtenRegs.add(destReg);
                            for (const r of boolGuard.wSet) writtenRegs.add(r);
                            for (const r of rhsRes.writtenRegs) writtenRegs.add(r);
                            lastWrittenReg = destReg;
                            anyEffect = anyEffect || Boolean(fullExpr.hasEffect);
                            anyMutable = anyMutable || Boolean(fullExpr.readsMutable);
                            cur = rhsEnd;
                            matchedCompound = true;
                            break;
                          }
                        }
                      } else {
                        // `GUARD and MID or RHS`:
                        // Find all candidate guardEnd splits (preferring the widest multi-guard prefix jumping to falseTarget).
                        const guardEnds: number[] = [];
                        for (let g = falseTarget - 2; g >= cur; g--) {
                          const gi = insns[g];
                          if (isLuauCondJump(gi.opname) && gi.targetPc === insns[falseTarget]?.pc) {
                            guardEnds.push(g + 1);
                          }
                        }
                        if (!guardEnds.includes(cand.guardEndHint)) guardEnds.push(cand.guardEndHint);

                        for (const guardEnd of guardEnds) {
                          if (guardEnd >= falseTarget - 1) continue;
                          const guardRes = simLiftBoolCond(cur, guardEnd, falseTarget, simRegs, destReg, 0);
                          if (!guardRes) continue;
                          const midRes = tryLiftShortCircuitOrSlice(guardEnd, falseTarget - 1, nextOuterJoin, destReg, guardRes.regsAtTrue, depth + 1);
                          if (!midRes) continue;
                          const rhsRes = tryLiftShortCircuitOrSlice(falseTarget, rhsEnd, nextOuterJoin, destReg, guardRes.regsAtFalse, depth + 1);
                          if (!rhsRes) continue;

                          const leftCombined = foldBinary('and', guardRes.expr, midRes.expr, env.opts, env.metrics);
                          const fullExpr = foldBinary('or', leftCombined, rhsRes.expr, env.opts, env.metrics);
                          simRegs.set(destReg, fullExpr);
                          writtenRegs.add(destReg);
                          for (const r of guardRes.wSet) writtenRegs.add(r);
                          for (const r of midRes.writtenRegs) writtenRegs.add(r);
                          for (const r of rhsRes.writtenRegs) writtenRegs.add(r);
                          lastWrittenReg = destReg;
                          anyEffect = anyEffect || Boolean(fullExpr.hasEffect);
                          anyMutable = anyMutable || Boolean(fullExpr.readsMutable);
                          cur = rhsEnd;
                          matchedCompound = true;
                          break;
                        }
                        if (matchedCompound) break;
                      }
                    }
                  }

                  // Pattern SC-1b: Multi-instruction Luau `if cond then exprA else exprB` ternary
                  if (env.opts.ifExpressions && tailJ.opname === 'JUMP') {
                    const joinIdx = pcToIdx.get(tailJ.targetPc);
                    const isNormalJoin = joinIdx !== undefined && joinIdx > falseTarget && joinIdx <= eIdx;
                    const isThreadedJoin = joinIdx !== undefined && joinIdx === outerJoinIdx && falseTarget < eIdx;
                    if (isNormalJoin || isThreadedJoin) {
                      const rhsEnd = isNormalJoin ? joinIdx! : eIdx;
                      const nextOuterJoin = isNormalJoin ? joinIdx! : outerJoinIdx;
                      const guardEnds: number[] = [];
                      for (let g = falseTarget - 2; g >= cur; g--) {
                        const gi = insns[g];
                        if (isLuauCondJump(gi.opname) && gi.targetPc === insns[falseTarget]?.pc) {
                          guardEnds.push(g + 1);
                        }
                      }
                      if (!guardEnds.includes(cand.guardEndHint)) guardEnds.push(cand.guardEndHint);

                      for (const guardEnd of guardEnds) {
                        if (guardEnd >= falseTarget - 1) continue;
                        const guardRes = simLiftBoolCond(cur, guardEnd, falseTarget, simRegs, expectedDestReg, 0);
                        if (!guardRes) continue;
                        const thenRes = tryLiftShortCircuitOrSlice(guardEnd, falseTarget - 1, nextOuterJoin, expectedDestReg, guardRes.regsAtTrue, depth + 1);
                        if (!thenRes) continue;
                        const elseRes = tryLiftShortCircuitOrSlice(falseTarget, rhsEnd, nextOuterJoin, thenRes.reg, guardRes.regsAtFalse, depth + 1);
                        if (!elseRes || elseRes.reg !== thenRes.reg) continue;

                        const elseClause = elseRes.expr.code.startsWith('if ')
                          ? `else${elseRes.expr.code}`
                          : `else ${elseRes.expr.code}`;
                        const ternaryExpr = atomExpr(
                          `if ${guardRes.expr.code} then ${thenRes.expr.code} ${elseClause}`,
                          {
                            kind: 'binary',
                            prec: 10,
                            hasEffect: Boolean(guardRes.expr.hasEffect || thenRes.expr.hasEffect || elseRes.expr.hasEffect),
                            readsMutable: Boolean(guardRes.expr.readsMutable || thenRes.expr.readsMutable || elseRes.expr.readsMutable),
                          }
                        );
                        simRegs.set(thenRes.reg, ternaryExpr);
                        writtenRegs.add(thenRes.reg);
                        for (const r of guardRes.wSet) writtenRegs.add(r);
                        for (const r of thenRes.writtenRegs) writtenRegs.add(r);
                        for (const r of elseRes.writtenRegs) writtenRegs.add(r);
                        lastWrittenReg = thenRes.reg;
                        anyEffect = anyEffect || Boolean(ternaryExpr.hasEffect);
                        anyMutable = anyMutable || Boolean(ternaryExpr.readsMutable);
                        cur = rhsEnd;
                        matchedCompound = true;
                        break;
                      }
                      if (matchedCompound) break;
                    }
                  }
                }
                if (matchedCompound) continue;

                // Pattern SC-2: 2-way `lhs and rhs` / `lhs or rhs` (including jump-threaded `cTargetIdx === outerJoinIdx`)
                if (
                  (ci.opname === 'JUMPIF' || ci.opname === 'JUMPIFNOT') &&
                  checkWriteSafe(ci.a) &&
                  (expectedDestReg < 0 || ci.a === expectedDestReg)
                ) {
                  const isNormalTwoWay = cTargetIdx <= eIdx;
                  const isThreadedOr =
                    ci.opname === 'JUMPIF' &&
                    cTargetIdx === outerJoinIdx &&
                    expectedDestReg === ci.a &&
                    cur + 1 < eIdx;
                  if (isNormalTwoWay || isThreadedOr) {
                    const rhsEnd = isNormalTwoWay ? cTargetIdx : eIdx;
                    const rhsRes = tryLiftShortCircuitOrSlice(cur + 1, rhsEnd, outerJoinIdx, ci.a, simRegs, depth + 1);
                    if (rhsRes && rhsRes.reg === ci.a) {
                      const op = ci.opname === 'JUMPIF' ? 'or' : 'and';
                      const lhs = simGet(ci.a);
                      const combined = foldBinary(op, lhs, rhsRes.expr, env.opts, env.metrics);
                      simRegs.set(ci.a, combined);
                      writtenRegs.add(ci.a);
                      for (const r of rhsRes.writtenRegs) writtenRegs.add(r);
                      lastWrittenReg = ci.a;
                      anyEffect = anyEffect || Boolean(combined.hasEffect);
                      anyMutable = anyMutable || Boolean(combined.readsMutable);
                      cur = rhsEnd;
                      continue;
                    }
                  }
                }

                return null;
              }

              // Non-jump expression ops inside the slice
              const step = simStepExpr(ci, simRegs, simMethods, simTables, expectedDestReg, writtenRegs);
              if (!step.ok) return null;
              if (step.writtenReg >= 0) lastWrittenReg = step.writtenReg;
              if (step.hasEffect) anyEffect = true;
              if (step.readsMutable) anyMutable = true;
              cur++;
            }

            const finalReg = expectedDestReg >= 0 ? expectedDestReg : lastWrittenReg;
            if (finalReg < 0 || !simRegs.has(finalReg)) return null;
            if (!writtenRegs.has(finalReg)) return null;
            for (const wr of writtenRegs) {
              if (wr !== finalReg && (liveAfterTopSlice.has(wr) || capturedRefRegs.has(wr))) {
                return null;
              }
            }
            const outExpr = simRegs.get(finalReg)!;
            return {
              reg: finalReg,
              expr: {
                ...outExpr,
                hasEffect: Boolean(outExpr.hasEffect || anyEffect),
                readsMutable: Boolean(outExpr.readsMutable || anyMutable),
              },
              nextIdx: cur,
              writtenRegs,
            };
          };

          // Pattern SC (Short-circuit & multi-instruction ternary expressions):
          // Pattern SC (Short-circuit & multi-instruction ternary / boolean value DAG expressions):
          // Evaluate BEFORE flushing open tables so `{ x = a and bump(b) or bump(c) }` and `return a and bump(b) or bump(c)` reconstruct directly!
          {
            const dagRes = tryLiftValueDag(i, endIdx, -1);
            if (dagRes) {
              i = dagRes.nextIdx;
              continue;
            }
          }
          if (scEndCandidate !== null) {
            const scMatch = tryLiftShortCircuitOrSlice(i, scEndCandidate, scEndCandidate, -1, regExpr, 0);
            if (scMatch && scMatch.nextIdx === scEndCandidate) {
              // Preserve exact order: if any OTHER unmaterialized register has side effects before this short-circuit, snapshot it first!
              if (scMatch.expr.hasEffect) {
                snapshotDependentRegs(scMatch.reg, null, true, i, out, lvl, false);
              }
              // Release any dead scratch registers that were overwritten inside the expression slice
              for (const wr of scMatch.writtenRegs) {
                if (
                  wr !== scMatch.reg &&
                  declaredLocals.has(wr) &&
                  !liveAfterTopSlice.has(wr) &&
                  !capturedRefRegs.has(wr) &&
                  !hoistedLocals.has(wr)
                ) {
                  releaseDeclaredLocal(wr);
                }
              }
              // If `scMatch.reg` was a dead previously-declared scratch local (not live at `i`, not hoisted, not ref-captured)
              // and is not referenced by the newly lifted expression, release it so it can inline cleanly instead of mutating a stale temp!
              if (
                declaredLocals.has(scMatch.reg) &&
                (!liveIn[i].has(scMatch.reg) || isDeadLocalAtReuse(scMatch.reg, i, lvl, scMatch.expr.code)) &&
                !hoistedLocals.has(scMatch.reg) &&
                !capturedRefRegs.has(scMatch.reg) &&
                !exprReferencesIdent(scMatch.expr.code, declaredLocals.get(scMatch.reg)!)
              ) {
                releaseDeclaredLocal(scMatch.reg);
              }
              assignReg(scMatch.reg, scMatch.expr, scEndCandidate - 1, out, lvl);
              i = scEndCandidate;
              continue;
            }
          }

          flushAllOpenTables(out, lvl, true);
          // Flush any deferred side-effecting calls in registers BEFORE entering a conditional branch!
          snapshotDependentRegs(-1, null, true, i, out, lvl, false);

          if (env.opts.eliminateDeadBranches && cond.staticJumpTaken !== undefined) {
            env.metrics.deadBranchesEliminated++;
            if (cond.staticJumpTaken) {
              i = targetIdx;
            } else {
              const lastBeforeTarget = targetIdx - 1;
              if (lastBeforeTarget > i && insns[lastBeforeTarget].opname === 'JUMP' && insns[lastBeforeTarget].targetPc !== undefined) {
                const mergeIdx = pcToIdx.get(insns[lastBeforeTarget].targetPc!) ?? endIdx;
                out.push(...liftRange(i + 1, lastBeforeTarget, lvl, loopStack));
                i = mergeIdx;
              } else {
                i++;
              }
            }
            continue;
          }

          const activeLoop = loopStack[loopStack.length - 1];

          // Coalesce short-circuit `or` / `and` chains (`if c1 or c2 then ...` / `if c1 and c2 then ...` / `if (a and b) or c then ...`)
          const isTinyCondSetup = (opIns: DecodedInstruction) =>
            !declaredLocals.has(opIns.a) &&
            (opIns.opname === 'LOADN' ||
              opIns.opname === 'LOADK' ||
              opIns.opname === 'LOADKX' ||
              (opIns.opname === 'LOADB' && opIns.c === 0) ||
              opIns.opname === 'LOADNIL' ||
              opIns.opname === 'GETIMPORT' ||
              opIns.opname === 'GETGLOBAL' ||
              opIns.opname === 'GETUPVAL' ||
              opIns.opname === 'GETTABLEKS' ||
              opIns.opname === 'GETTABLE' ||
              opIns.opname === 'GETTABLEN' ||
              opIns.opname === 'LENGTH' ||
              opIns.opname === 'NOT' ||
              opIns.opname === 'MINUS');

          const evalCondStepInMap = (
            opIns: DecodedInstruction,
            cRegs: Map<number, Expr>,
            cMethods: Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>,
            liveAtTrue: Set<number>,
            liveAtFalse: Set<number>,
            liveAtStart: Set<number>
          ): boolean => {
            const getFromC = (r: number): Expr => {
              const ex = cRegs.get(r);
              if (ex) return ex;
              const loc = declaredLocals.get(r);
              if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
              return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
            };
            const canWriteCondScratch = (r: number, allowReusedScratch = false): boolean => {
              if (capturedRefRegs.has(r) || hoistedLocals.has(r)) return false;
              if (liveAtTrue.has(r) || liveAtFalse.has(r)) return false;
              if (declaredLocals.has(r) && (liveAtStart.has(r) || !allowReusedScratch)) return false;
              return true;
            };
            switch (opIns.opname) {
              case 'NOP':
              case 'PREPVARARGS':
                return true;
              case 'LOADNIL':
                if (!canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, atomExpr('nil', { isConst: true, constVal: null }));
                return true;
              case 'LOADB':
                if (opIns.c !== 0 || !canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, atomExpr(opIns.b !== 0 ? 'true' : 'false', { isConst: true, constVal: opIns.b !== 0 }));
                return true;
              case 'LOADN':
                if (!canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, atomExpr(formatNumber(opIns.d, env.opts), { isConst: true, constVal: opIns.d }));
                return true;
              case 'LOADK':
                if (!canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, constantToExpr(proto.constants[opIns.d], env.opts));
                return true;
              case 'LOADKX':
                if (!canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, constantToExpr(proto.constants[opIns.aux ?? 0], env.opts));
                return true;
              case 'MOVE':
                if (!canWriteCondScratch(opIns.a, true)) return false;
                cRegs.set(opIns.a, getFromC(opIns.b));
                return true;
              case 'GETIMPORT': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const k = proto.constants[opIns.d];
                const path = k?.importPath?.join('.') ?? `K${opIns.d}`;
                cRegs.set(opIns.a, atomExpr(path, { kind: 'global', calleeName: path }));
                return true;
              }
              case 'GETGLOBAL': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const k = proto.constants[opIns.aux ?? 0];
                const gname = k?.kind === 'string' ? String(k.value) : `G${opIns.aux}`;
                cRegs.set(opIns.a, atomExpr(gname, { kind: 'global', calleeName: gname }));
                return true;
              }
              case 'GETUPVAL':
                if (!canWriteCondScratch(opIns.a)) return false;
                cRegs.set(opIns.a, atomExpr(getUpvalName(opIns.b), { kind: 'ident', isVarRef: true, readsMutable: true }));
                return true;
              case 'GETTABLEKS':
              case 'GETUDATAKS': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const tbl = getFromC(opIns.b);
                const kIdx = opIns.opname === 'GETUDATAKS' ? (opIns.aux ?? 0) & 0xffff : opIns.aux ?? 0;
                const keyK = proto.constants[kIdx];
                const keyStr = keyK?.kind === 'string' ? String(keyK.value) : String(keyK?.value ?? '');
                const tblCode = wrapPrefixExpr(tbl);
                const code = isValidIdent(keyStr) ? `${tblCode}.${keyStr}` : `${tblCode}[${escapeLuaString(keyStr)}]`;
                cRegs.set(opIns.a, atomExpr(code, { kind: 'index', prec: 90, calleeName: code, hasEffect: tbl.hasEffect, readsMutable: true }));
                return true;
              }
              case 'GETTABLE': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const tbl = getFromC(opIns.b);
                const key = getFromC(opIns.c);
                cRegs.set(opIns.a, atomExpr(`${wrapPrefixExpr(tbl)}[${key.code}]`, { kind: 'index', prec: 90, hasEffect: Boolean(tbl.hasEffect || key.hasEffect), readsMutable: true }));
                return true;
              }
              case 'GETTABLEN': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const tbl = getFromC(opIns.b);
                cRegs.set(opIns.a, atomExpr(`${wrapPrefixExpr(tbl)}[${opIns.c + 1}]`, { kind: 'index', prec: 90, hasEffect: tbl.hasEffect, readsMutable: true }));
                return true;
              }
              case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
              case 'AND': case 'OR': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const opMap: Record<string, string> = {
                  ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^', IDIV: '//', AND: 'and', OR: 'or',
                };
                cRegs.set(opIns.a, foldBinary(opMap[opIns.opname], getFromC(opIns.b), getFromC(opIns.c), env.opts, env.metrics));
                return true;
              }
              case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK':
              case 'ANDK': case 'ORK': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const opMap: Record<string, string> = {
                  ADDK: '+', SUBK: '-', MULK: '*', DIVK: '/', MODK: '%', POWK: '^', IDIVK: '//', ANDK: 'and', ORK: 'or',
                };
                cRegs.set(opIns.a, foldBinary(opMap[opIns.opname], getFromC(opIns.b), constantToExpr(proto.constants[opIns.c], env.opts), env.opts, env.metrics));
                return true;
              }
              case 'SUBRK': case 'DIVRK': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const op = opIns.opname === 'SUBRK' ? '-' : '/';
                cRegs.set(opIns.a, foldBinary(op, constantToExpr(proto.constants[opIns.b], env.opts), getFromC(opIns.c), env.opts, env.metrics));
                return true;
              }
              case 'NOT': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const rhs = getFromC(opIns.b);
                cRegs.set(opIns.a, { kind: 'unary', code: `not ${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                return true;
              }
              case 'MINUS': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const rhs = getFromC(opIns.b);
                const rhsCode = rhs.code.startsWith('-') ? `(${rhs.code})` : wrapIfLower(rhs, 80);
                cRegs.set(opIns.a, { kind: 'unary', code: `-${rhsCode}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: rhs.readsMutable });
                return true;
              }
              case 'LENGTH': {
                if (!canWriteCondScratch(opIns.a)) return false;
                const rhs = getFromC(opIns.b);
                cRegs.set(opIns.a, { kind: 'unary', code: `#${wrapIfLower(rhs, 80)}`, prec: 80, hasEffect: rhs.hasEffect, readsMutable: true });
                return true;
              }
              case 'NAMECALL':
              case 'NAMECALLUDATA': {
                if (!canWriteCondScratch(opIns.a, true) || !canWriteCondScratch(opIns.a + 1, true)) return false;
                const obj = getFromC(opIns.b);
                const kIdx = opIns.opname === 'NAMECALLUDATA' ? (opIns.aux ?? 0) & 0xffff : opIns.aux ?? 0;
                const methodK = proto.constants[kIdx];
                const methodName = methodK?.kind === 'string' ? String(methodK.value) : `method_${kIdx}`;
                const recvCode = wrapPrefixExpr(obj);
                const calleeFull = `${recvCode}:${methodName}`;
                cMethods.set(opIns.a, { calleeFull, objExpr: obj, methodName });
                cRegs.set(opIns.a, atomExpr(calleeFull, { kind: 'methodCall', prec: 90, calleeName: calleeFull, hasEffect: obj.hasEffect, readsMutable: obj.readsMutable }));
                cRegs.set(opIns.a + 1, obj);
                return true;
              }
              case 'CALL':
              case 'CALLFB': {
                if (opIns.c !== 2 || opIns.b === 0 || !canWriteCondScratch(opIns.a, true)) return false;
                const mInfo = cMethods.get(opIns.a);
                if (mInfo) cMethods.delete(opIns.a);
                const fnE = mInfo
                  ? atomExpr(mInfo.calleeFull, { kind: 'methodCall', prec: 90, calleeName: mInfo.calleeFull })
                  : getFromC(opIns.a);
                const totalSlots = opIns.b - 1;
                const startOff = mInfo ? 2 : 1;
                const cArgs: Expr[] = [];
                for (let off = startOff; off <= totalSlots; off++) {
                  cArgs.push(getFromC(opIns.a + off));
                }
                const calleeTxt = mInfo ? fnE.code : wrapPrefixExpr(fnE);
                const fmtArgs = cArgs.map((a, idx) => {
                  const isLastFixed = idx === cArgs.length - 1;
                  if (isLastFixed && !a.singleReturn && (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')) {
                    return `(${a.code})`;
                  }
                  return a.code;
                });
                const cCode = `${calleeTxt}(${fmtArgs.join(', ')})`;
                const sRet = Boolean(fnE.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnE.calleeName));
                cRegs.set(opIns.a, atomExpr(cCode, { kind: mInfo ? 'methodCall' : 'call', prec: 90, singleReturn: sRet, calleeName: fnE.calleeName, hasEffect: true, readsMutable: true }));
                return true;
              }
              default:
                return false;
            }
          };

          const coalesceBranchCond = (
            startJIdx: number,
            maxEndIdx: number
          ): { condStr: string; bodyStartIdx: number; falseTargetPc: number; falseTargetIdx: number } => {
            const firstIns = insns[startJIdx];
            const firstCond = evalLuauJumpCondition(firstIns);
            const firstTargetPc = firstIns.targetPc ?? firstIns.pc + firstIns.width;
            const firstTargetIdx = pcToIdx.get(firstTargetPc) ?? maxEndIdx;

            const liveAtStart = startJIdx < insns.length ? liveIn[startJIdx] : new Set<number>();

            // General recursive boolean condition DAG solver over [startJIdx .. bStart) with exits ONLY to (bStart, fIdx)
            const trySolveCondDag = (bStart: number, fIdx: number): string | null => {
              if (bStart <= startJIdx || bStart >= fIdx || fIdx > maxEndIdx) return null;
              for (let k = startJIdx + 1; k < bStart; k++) {
                if (allLoopHeaderIdxs.has(k) || backwardJumpTargetIdxs.has(k)) return null;
              }
              // Last instruction before `bStart` must be a conditional jump targeting `fIdx` (or `bStart`)
              const lastBeforeBody = insns[bStart - 1];
              if (!lastBeforeBody || !isLuauCondJump(lastBeforeBody.opname)) return null;
              // Never swallow a value-producing short-circuit (`a and b or c`) whose destination register is live at `bStart` or `fIdx`!
              const liveAtTrue = bStart < insns.length ? liveIn[bStart] : new Set<number>();
              const liveAtFalse = fIdx < insns.length ? liveIn[fIdx] : new Set<number>();
              for (let k = startJIdx; k < bStart; k++) {
                const ki = insns[k];
                if ((ki.opname === 'JUMPIF' || ki.opname === 'JUMPIFNOT') && ki.targetPc !== undefined) {
                  const ktIdx = pcToIdx.get(ki.targetPc);
                  if (ktIdx === fIdx && liveAtFalse.has(ki.a) && !liveAtStart.has(ki.a)) return null;
                  if (ktIdx === bStart && liveAtTrue.has(ki.a) && !liveAtStart.has(ki.a)) return null;
                }
              }

              type CNode =
                | { kind: 'bool'; val: boolean; code: string; prec: number; hasEffect: boolean; nodeId: number }
                | { kind: 'expr'; code: string; prec: number; hasEffect: boolean; nodeId: number };

              const mkCBool = (val: boolean, nodeId: number): CNode => ({
                kind: 'bool',
                val,
                code: val ? 'true' : 'false',
                prec: 100,
                hasEffect: false,
                nodeId,
              });
              const mkCAtom = (code: string, hasEffect: boolean, nodeId: number): CNode => {
                const trimmed = code.trim();
                return { kind: 'expr', code: trimmed, prec: inferExprPrec(trimmed), hasEffect, nodeId };
              };
              const mkCAnd = (a: CNode, b: CNode, nodeId: number): CNode => {
                if (a.kind === 'bool') return a.val ? b : mkCBool(false, nodeId);
                if (b.kind === 'bool') return b.val ? a : mkCBool(false, nodeId);
                const lStr = a.prec < 30 ? `(${a.code})` : a.code;
                const rStr = b.prec < 30 ? `(${b.code})` : b.code;
                return { kind: 'expr', code: `${lStr} and ${rStr}`, prec: 30, hasEffect: Boolean(a.hasEffect || b.hasEffect), nodeId };
              };
              const mkCOr = (a: CNode, b: CNode, nodeId: number): CNode => {
                if (a.kind === 'bool') return a.val ? mkCBool(true, nodeId) : b;
                if (b.kind === 'bool') return b.val ? mkCBool(true, nodeId) : a;
                const lStr = a.prec < 20 ? `(${a.code})` : a.code;
                const rStr = b.prec < 20 ? `(${b.code})` : b.code;
                return { kind: 'expr', code: `${lStr} or ${rStr}`, prec: 20, hasEffect: Boolean(a.hasEffect || b.hasEffect), nodeId };
              };

              const evalCondAt = (pIdx: number, inRegs: Map<number, Expr>, depth: number): CNode | null => {
                if (depth > 14) return null;
                if (pIdx === bStart) return mkCBool(true, bStart);
                if (pIdx === fIdx) return mkCBool(false, fIdx);
                if (pIdx < startJIdx || pIdx > bStart) return null;

                const cRegs = new Map<number, Expr>(inRegs);
                const cMethods = new Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>();
                let p = pIdx;
                while (p < bStart && !isLuauCondJump(insns[p].opname)) {
                  if (!evalCondStepInMap(insns[p], cRegs, cMethods, liveAtTrue, liveAtFalse, liveAtStart)) {
                    return null;
                  }
                  p++;
                }
                if (p >= bStart || !isLuauCondJump(insns[p].opname)) return null;

                const ji = insns[p];
                const tPc = ji.targetPc;
                const tIdx = tPc !== undefined ? pcToIdx.get(tPc) : undefined;
                if (tIdx === undefined || tIdx <= p) return null;
                if (tIdx !== bStart && tIdx !== fIdx && (tIdx <= p || tIdx >= bStart)) return null;

                const jc = evalLuauJumpCondition(ji, (r) => {
                  const ex = cRegs.get(r);
                  if (ex) return ex;
                  const loc = declaredLocals.get(r);
                  if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
                  return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
                }, true);

                const takenC = mkCAtom(jc.jumpTakenCond, jc.hasEffect, -1);
                const fallC = mkCAtom(jc.fallthroughCond, jc.hasEffect, -1);

                // Direct terminal exits
                if (tIdx === bStart && p + 1 === fIdx) return { ...takenC, nodeId: pIdx };
                if (tIdx === fIdx && p + 1 === bStart) return { ...fallC, nodeId: pIdx };
                if (tIdx === fIdx) {
                  const rest = evalCondAt(p + 1, cRegs, depth + 1);
                  return rest ? mkCAnd(fallC, rest, pIdx) : null;
                }
                if (tIdx === bStart) {
                  const rest = evalCondAt(p + 1, cRegs, depth + 1);
                  return rest ? mkCOr(takenC, rest, pIdx) : null;
                }

                // Internal jump target `tIdx` inside `(p, bStart)`:
                // Try factoring `(A and B) or C` (where sub-guard `[p+1 .. tIdx)` exits to `(true=bStart, false=tIdx)`)
                // or `(A or B) and C` (where sub-guard `[p+1 .. tIdx)` exits to `(true=tIdx, false=fIdx)`)
                const evalSubGuard = (subStart: number, subTrue: number, subFalse: number, subRegs: Map<number, Expr>, sDepth: number): CNode | null => {
                  if (sDepth > 10 || subStart >= Math.min(subTrue, subFalse) && subStart !== subTrue && subStart !== subFalse) {
                    // continue below
                  }
                  if (subStart === subTrue) return mkCBool(true, subTrue);
                  if (subStart === subFalse) return mkCBool(false, subFalse);
                  if (subStart >= bStart) return null;
                  const sRegs = new Map<number, Expr>(subRegs);
                  const sMethods = new Map<number, { calleeFull: string; objExpr: Expr; methodName: string }>();
                  let sp = subStart;
                  while (sp < bStart && !isLuauCondJump(insns[sp].opname)) {
                    if (!evalCondStepInMap(insns[sp], sRegs, sMethods, liveAtTrue, liveAtFalse, liveAtStart)) return null;
                    sp++;
                  }
                  if (sp >= bStart || !isLuauCondJump(insns[sp].opname)) return null;
                  const sji = insns[sp];
                  const stIdx = sji.targetPc !== undefined ? pcToIdx.get(sji.targetPc) : undefined;
                  if (stIdx === undefined || stIdx <= sp) return null;
                  const sjc = evalLuauJumpCondition(sji, (r) => {
                    const ex = sRegs.get(r);
                    if (ex) return ex;
                    const loc = declaredLocals.get(r);
                    if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r, readsMutable: capturedRefRegs.has(r) });
                    return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
                  }, true);
                  const sTaken = mkCAtom(sjc.jumpTakenCond, sjc.hasEffect, -1);
                  const sFall = mkCAtom(sjc.fallthroughCond, sjc.hasEffect, -1);
                  if (stIdx === subTrue && sp + 1 === subFalse) return sTaken;
                  if (stIdx === subFalse && sp + 1 === subTrue) return sFall;
                  if (stIdx === subFalse && sp + 1 < Math.max(subTrue, subFalse)) {
                    const rNode = evalSubGuard(sp + 1, subTrue, subFalse, sRegs, sDepth + 1);
                    return rNode ? mkCAnd(sFall, rNode, subStart) : null;
                  }
                  if (stIdx === subTrue && sp + 1 < Math.max(subTrue, subFalse)) {
                    const rNode = evalSubGuard(sp + 1, subTrue, subFalse, sRegs, sDepth + 1);
                    return rNode ? mkCOr(sTaken, rNode, subStart) : null;
                  }
                  return null;
                };

                const subAnd = evalSubGuard(p + 1, bStart, tIdx, cRegs, depth + 1);
                if (subAnd) {
                  const tailOr = evalCondAt(tIdx, cRegs, depth + 1);
                  if (tailOr) {
                    return mkCOr(mkCAnd(fallC, subAnd, -1), tailOr, pIdx);
                  }
                }
                const subOr = evalSubGuard(p + 1, tIdx, fIdx, cRegs, depth + 1);
                if (subOr) {
                  const tailAnd = evalCondAt(tIdx, cRegs, depth + 1);
                  if (tailAnd) {
                    return mkCAnd(mkCOr(takenC, subOr, -1), tailAnd, pIdx);
                  }
                }
                return null;
              };

              const res = evalCondAt(startJIdx, regExpr, 0);
              if (!res || res.kind === 'bool') return null;
              return res.code;
            };

            // Enumerate candidate `(bStart, fIdx)` pairs reachable from the condition header
            const candidateBodyStarts: number[] = [];
            // 1. Walk forward through consecutive condition jumps/setups to find candidate `bStart`s
            {
              let scan = startJIdx;
              let maxInternalTarget = firstTargetIdx;
              while (scan < maxEndIdx && scan <= startJIdx + 24) {
                if (scan > startJIdx && (allLoopHeaderIdxs.has(scan) || backwardJumpTargetIdxs.has(scan))) break;
                const si = insns[scan];
                if (isLuauCondJump(si.opname)) {
                  const stIdx = si.targetPc !== undefined ? pcToIdx.get(si.targetPc) : undefined;
                  if (stIdx !== undefined && stIdx > scan && stIdx <= maxEndIdx) {
                    if (stIdx > maxInternalTarget) maxInternalTarget = stIdx;
                    if (scan + 1 <= maxInternalTarget && !candidateBodyStarts.includes(scan + 1)) {
                      candidateBodyStarts.push(scan + 1);
                    }
                  } else {
                    break;
                  }
                }
                scan++;
              }
            }
            // Prefer widest valid condition header (largest `bStart`) so compound conditions are fully coalesced!
            candidateBodyStarts.sort((a, b) => b - a);

            for (const bStart of candidateBodyStarts) {
              const lastJ = insns[bStart - 1];
              if (!lastJ || !isLuauCondJump(lastJ.opname) || lastJ.targetPc === undefined) continue;
              const fIdx = pcToIdx.get(lastJ.targetPc);
              if (fIdx === undefined || fIdx <= bStart || fIdx > maxEndIdx) continue;
              const solved = trySolveCondDag(bStart, fIdx);
              if (solved !== null) {
                return {
                  condStr: solved,
                  bodyStartIdx: bStart,
                  falseTargetPc: lastJ.targetPc,
                  falseTargetIdx: fIdx,
                };
              }
            }

            return {
              condStr: firstCond.fallthroughCond,
              bodyStartIdx: startJIdx + 1,
              falseTargetPc: firstTargetPc,
              falseTargetIdx: firstTargetIdx,
            };
          };

          // Rule 3.3 helper: convert a short 1-3 simple-statement tail before loop latch into `if cond then ... end`
          // instead of `if not cond then continue end`, while keeping `if i == 6 then continue end` at loop tops.
          const tryFoldShortContinueGuard = (condStr: string, bodyStart: number, tailEnd: number): boolean => {
            if (!activeLoop || bodyStart >= tailEnd || tailEnd - bodyStart > 18) return false;
            for (let k = bodyStart; k < tailEnd; k++) {
              const kop = insns[k].opname;
              if (
                allLoopHeaderIdxs.has(k) ||
                backwardJumpTargetIdxs.has(k) ||
                isLuauCondJump(kop) ||
                kop === 'FORNPREP' ||
                kop === 'FORGPREP' ||
                kop === 'FORGPREP_NEXT' ||
                kop === 'FORGPREP_INEXT' ||
                kop === 'JUMPBACK' ||
                ((kop === 'JUMP' || kop === 'JUMPX') && !isLoopExitTarget(activeLoop, insns[k].targetPc))
              ) {
                return false;
              }
            }
            const savedNames = new Set(usedNames);
            const savedMetrics = { ...env.metrics };
            const savedDiagLen = env.diagnostics.length;
            const savedScope = snapshotLexicalScope();
            const rollback = () => {
              usedNames.clear();
              for (const n of savedNames) usedNames.add(n);
              Object.assign(env.metrics, savedMetrics);
              env.diagnostics.length = savedDiagLen;
              restoreLexicalScope(savedScope);
            };
            const tailLines = liftBlockScoped(bodyStart, tailEnd, lvl + 1, loopStack);
            const stmtPad = indent(lvl + 1);
            const topStmtCount = tailLines.filter((l) => l.startsWith(stmtPad) && !l.startsWith(indent(lvl + 2))).length;
            const hasNestedControlOrUnrec = tailLines.some((l) =>
              /^\s*(?:if\b|for\b|while\b|repeat\b|elseif\b|else\b|continue\b|--\s*\[un)/.test(l)
            );
            if (tailLines.length === 0 || tailLines.length > 5 || topStmtCount === 0 || topStmtCount > 3 || hasNestedControlOrUnrec) {
              rollback();
              return false;
            }
            const lastTrim = tailLines[tailLines.length - 1].trim();
            const endsWithBreakOrReturn = lastTrim === 'break' || lastTrim === 'return' || lastTrim.startsWith('return ');
            const looksLikeTopContinueGuard =
              condStr.startsWith('not ') ||
              (out.length === 0 && /^[A-Za-z_]\w*\s*~=\s*[^~=<>\n]+$/.test(condStr));
            if (!endsWithBreakOrReturn && looksLikeTopContinueGuard) {
              rollback();
              return false;
            }
            out.push(`${indent(lvl)}if ${condStr} then`);
            out.push(...tailLines);
            out.push(`${indent(lvl)}end`);
            return true;
          };

          // Direct conditional break / continue jump emitted by Luau optimizer (`if cond then break/continue end`)
          if (activeLoop && isLoopExitTarget(activeLoop, targetPc)) {
            env.metrics.breaksRecovered++;
            out.push(`${indent(lvl)}if ${cond.jumpTakenCond} then`);
            out.push(`${indent(lvl + 1)}break`);
            out.push(`${indent(lvl)}end`);
            i++;
            continue;
          }
          if (activeLoop && env.opts.virtualizeContinue && isLoopContinueTarget(activeLoop, targetPc)) {
            if (targetIdx === endIdx || insns[endIdx]?.pc === targetPc) {
              const scSnap = snapshotLexicalScope();
              const branchCont = coalesceBranchCond(i, endIdx);
              if (tryFoldShortContinueGuard(branchCont.condStr, branchCont.bodyStartIdx, endIdx)) {
                i = endIdx;
                continue;
              }
              restoreLexicalScope(scSnap);
            }
            env.metrics.continuesRecovered++;
            out.push(`${indent(lvl)}if ${cond.jumpTakenCond} then`);
            out.push(`${indent(lvl + 1)}continue`);
            out.push(`${indent(lvl)}end`);
            i++;
            continue;
          }

          // Direct conditional early-return jump (e.g. `-O2` inlined short-circuit jumping directly to trailing `RETURN R`)
          if (targetIdx >= endIdx && targetIdx < insns.length && insns[targetIdx].opname === 'RETURN') {
            const retIns = insns[targetIdx];
            const retCnt = retIns.b === 0 ? -1 : retIns.b - 1;
            if (retCnt === 0) {
              out.push(`${indent(lvl)}if ${cond.jumpTakenCond} then`);
              out.push(`${indent(lvl + 1)}return`);
              out.push(`${indent(lvl)}end`);
              i++;
              continue;
            }
            if (retCnt === 1) {
              const rv = getReg(retIns.a);
              const isMultiCap = rv.kind === 'call' || rv.kind === 'methodCall' || rv.kind === 'vararg';
              const rvCode = isMultiCap && !rv.singleReturn ? `(${rv.code})` : rv.code;
              out.push(`${indent(lvl)}if ${cond.jumpTakenCond} then`);
              out.push(`${indent(lvl + 1)}return ${rvCode}`);
              out.push(`${indent(lvl)}end`);
              i++;
              continue;
            }
          }

          // 2-instruction conditional break / continue (`JUMPIF* -> +2; JUMP/JUMPBACK -> continue/exit`)
          if (
            activeLoop &&
            targetIdx === i + 2 &&
            (insns[i + 1].opname === 'JUMP' || insns[i + 1].opname === 'JUMPBACK')
          ) {
            const jmpTarget = insns[i + 1].targetPc;
            if (isLoopContinueTarget(activeLoop, jmpTarget)) {
              if (env.opts.virtualizeContinue) {
                const jmpTargetIdx = jmpTarget !== undefined ? pcToIdx.get(jmpTarget) : undefined;
                if (
                  (jmpTargetIdx === endIdx || insns[endIdx]?.pc === jmpTarget) &&
                  tryFoldShortContinueGuard(cond.jumpTakenCond, targetIdx, endIdx)
                ) {
                  i = endIdx;
                  continue;
                }
                env.metrics.continuesRecovered++;
                out.push(`${indent(lvl)}if ${cond.fallthroughCond} then`);
                out.push(`${indent(lvl + 1)}continue`);
                out.push(`${indent(lvl)}end`);
                i = targetIdx;
                continue;
              }
            } else if (isLoopExitTarget(activeLoop, jmpTarget)) {
              env.metrics.breaksRecovered++;
              out.push(`${indent(lvl)}if ${cond.fallthroughCond} then`);
              out.push(`${indent(lvl + 1)}break`);
              out.push(`${indent(lvl)}end`);
              i = targetIdx;
              continue;
            }
          }

          const branch = coalesceBranchCond(i, endIdx);
          let bodyStartIdx = branch.bodyStartIdx;
          let falseTargetIdx = branch.falseTargetIdx;

          let lastInThen = falseTargetIdx - 1;

          // Multi-statement short-circuit fallback (e.g. `-O2` inlined a call inside `a and bump(b) or bump(c)`):
          // `if a then <stmts computing R>; JUMPIF R -> join; else <stmts computing R>; join:`
          if (
            lastInThen >= bodyStartIdx &&
            falseTargetIdx < endIdx &&
            (insns[lastInThen].opname === 'JUMPIF' || insns[lastInThen].opname === 'JUMPIFNOT') &&
            insns[lastInThen].targetPc !== undefined
          ) {
            const scTail = insns[lastInThen];
            const scJoinIdx = pcToIdx.get(scTail.targetPc!);
            // Verify no jump inside `[bodyStartIdx .. lastInThen)` or `[falseTargetIdx .. scJoinIdx)` escapes `scJoinIdx`!
            let hasEscapingJump = false;
            if (scJoinIdx !== undefined) {
              for (let k = bodyStartIdx; k < scJoinIdx; k++) {
                if (k === lastInThen) continue;
                const ki = insns[k];
                if ((isLuauCondJump(ki.opname) || ki.opname === 'JUMP' || ki.opname === 'JUMPX') && ki.targetPc !== undefined) {
                  const ktIdx = pcToIdx.get(ki.targetPc);
                  if (ktIdx === undefined || ktIdx > scJoinIdx || (k < lastInThen && ktIdx > falseTargetIdx)) {
                    hasEscapingJump = true;
                    break;
                  }
                }
              }
            }
            if (!hasEscapingJump && scJoinIdx !== undefined && scJoinIdx > falseTargetIdx && scJoinIdx <= endIdx) {
              const destReg = scTail.a;
              const joinIsDirectReturn =
                scTail.opname === 'JUMPIF' &&
                scJoinIdx < insns.length &&
                insns[scJoinIdx].opname === 'RETURN' &&
                insns[scJoinIdx].a === destReg &&
                insns[scJoinIdx].b === 2;

              if (joinIsDirectReturn) {
                // Clean early-return form with zero synthetic phi temp:
                // `if a then <stmts>; if val then return val end end` followed by normal fallthrough into RHS!
                out.push(`${indent(lvl)}if ${branch.condStr} then`);
                const scDirectSnap = snapshotLexicalScope();
                const midBody = liftRange(bodyStartIdx, lastInThen, lvl + 1, loopStack);
                const midVal = getReg(destReg);
                out.push(...midBody);
                if (midVal.hasEffect) {
                  const resName = buildSemanticName('result', 'v', usedNames, env.opts, env.metrics);
                  out.push(`${indent(lvl + 1)}local ${resName} = ${midVal.code}`);
                  out.push(`${indent(lvl + 1)}if ${resName} then`);
                  out.push(`${indent(lvl + 2)}return ${resName}`);
                  out.push(`${indent(lvl + 1)}end`);
                } else {
                  out.push(`${indent(lvl + 1)}if ${midVal.code} then`);
                  out.push(`${indent(lvl + 2)}return ${midVal.code}`);
                  out.push(`${indent(lvl + 1)}end`);
                }
                out.push(`${indent(lvl)}end`);
                restoreLexicalScope(scDirectSnap);
                i = falseTargetIdx;
                continue;
              }

              hoistBlockLiveLocals(i, i, scJoinIdx, scJoinIdx, out, lvl, {
                excludeRegs: new Set([destReg]),
              });
              if (isDeadLocalAtReuse(destReg, i, lvl)) {
                releaseDeclaredLocal(destReg);
              }
              const wasAlreadyDeclared = declaredLocals.has(destReg);
              if (!wasAlreadyDeclared) {
                const nm = buildSemanticName('result', 'v', usedNames, env.opts, env.metrics);
                declaredLocals.set(destReg, nm);
                declaredLocalLvl.set(destReg, lvl);
                hoistedLocals.add(destReg);
                regExpr.set(destReg, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: destReg, readsMutable: capturedRefRegs.has(destReg) }));
                out.push(`${indent(lvl)}local ${nm}`);
              }
              const destName = declaredLocals.get(destReg)!;
              if (scTail.opname === 'JUMPIF') {
                // `a and <mid-stmts -> destName> or <rhs-stmts -> destName>`
                // CRITICAL: If `destName` was already declared (reused register!), it may hold a stale truthy
                // value from a prior subexpression. Track whether the mid branch actually produced a truthy result
                // so a false `branch.condStr` NEVER skips `<rhs-stmts>` and duplicates the stale value!
                if (wasAlreadyDeclared) {
                  const matchedName = buildSemanticName('matched', 'v', usedNames, env.opts, env.metrics);
                  out.push(`${indent(lvl)}local ${matchedName} = false`);
                  out.push(`${indent(lvl)}if ${branch.condStr} then`);
                  out.push(...liftBlockScoped(bodyStartIdx, lastInThen, lvl + 1, loopStack));
                  out.push(`${indent(lvl + 1)}if ${destName} then`);
                  out.push(`${indent(lvl + 2)}${matchedName} = true`);
                  out.push(`${indent(lvl + 1)}end`);
                  out.push(`${indent(lvl)}end`);
                  out.push(`${indent(lvl)}if not ${matchedName} then`);
                  out.push(...liftBlockScoped(falseTargetIdx, scJoinIdx, lvl + 1, loopStack));
                  out.push(`${indent(lvl)}end`);
                } else {
                  out.push(`${indent(lvl)}if ${branch.condStr} then`);
                  out.push(...liftBlockScoped(bodyStartIdx, lastInThen, lvl + 1, loopStack));
                  out.push(`${indent(lvl)}end`);
                  out.push(`${indent(lvl)}if not ${destName} then`);
                  out.push(...liftBlockScoped(falseTargetIdx, scJoinIdx, lvl + 1, loopStack));
                  out.push(`${indent(lvl)}end`);
                }
              } else {
                // `(a or <mid-stmts -> destName>) and <rhs-stmts -> destName>`
                const passName = buildSemanticName('pass', 'v', usedNames, env.opts, env.metrics);
                out.push(`${indent(lvl)}local ${passName} = true`);
                out.push(`${indent(lvl)}if ${branch.condStr} then`);
                out.push(...liftBlockScoped(bodyStartIdx, lastInThen, lvl + 1, loopStack));
                out.push(`${indent(lvl + 1)}if not ${destName} then`);
                out.push(`${indent(lvl + 2)}${passName} = false`);
                out.push(`${indent(lvl + 1)}end`);
                out.push(`${indent(lvl)}end`);
                out.push(`${indent(lvl)}if ${passName} then`);
                out.push(...liftBlockScoped(falseTargetIdx, scJoinIdx, lvl + 1, loopStack));
                out.push(`${indent(lvl)}end`);
              }
              i = scJoinIdx;
              continue;
            }
          }

          const thenEndsWithJump =
            lastInThen >= bodyStartIdx &&
            insns[lastInThen].opname === 'JUMP' &&
            insns[lastInThen].targetPc !== undefined &&
            insns[lastInThen].targetPc! > insns[lastInThen].pc &&
            (!activeLoop ||
              (!isLoopExitTarget(activeLoop, insns[lastInThen].targetPc) &&
                insns[lastInThen].targetPc !== activeLoop.latchPc &&
                insns[lastInThen].targetPc !== activeLoop.continuePc));

          const thenJumpsToLatch =
            lastInThen >= bodyStartIdx &&
            insns[lastInThen].opname === 'JUMP' &&
            Boolean(activeLoop && isLoopContinueTarget(activeLoop, insns[lastInThen].targetPc)) &&
            !allLoopHeaderIdxs.has(falseTargetIdx);

          if (thenEndsWithJump || thenJumpsToLatch) {
            const mergePc = insns[lastInThen].targetPc!;
            const mergeIdx = Math.min(endIdx, pcToIdx.get(mergePc) ?? endIdx);

            // Pre-declare any local written inside the if/elseif/else branches and read after mergeIdx,
            // and materialize any outer live expressions that could be invalidated inside the branches!
            const didMatPriorIfElse = hoistBlockLiveLocals(i, i, mergeIdx, mergeIdx, out, lvl);
            const finalIfElseBranch = didMatPriorIfElse ? coalesceBranchCond(i, endIdx) : branch;
            bodyStartIdx = finalIfElseBranch.bodyStartIdx;
            falseTargetIdx = finalIfElseBranch.falseTargetIdx;
            lastInThen = falseTargetIdx - 1;

            out.push(`${indent(lvl)}if ${finalIfElseBranch.condStr} then`);
            out.push(...liftBlockScoped(bodyStartIdx, lastInThen, lvl + 1, loopStack));

            const ifElseOuterSnap = snapshotLexicalScope();
            let cursor = falseTargetIdx;
            while (cursor < mergeIdx) {
              restoreLexicalScope(ifElseOuterSnap);
              let condCursor = cursor;
              const setupScratchRegs = new Map<number, Expr | undefined>();
              while (
                condCursor < mergeIdx &&
                condCursor < cursor + 3 &&
                !allLoopHeaderIdxs.has(condCursor) &&
                !backwardJumpTargetIdxs.has(condCursor) &&
                isTinyCondSetup(insns[condCursor])
              ) {
                const setup = insns[condCursor];
                const pure = evalPureLuauExpr(setup);
                if (pure) {
                  if (!setupScratchRegs.has(pure.reg)) setupScratchRegs.set(pure.reg, regExpr.get(pure.reg));
                  regExpr.set(pure.reg, pure.expr);
                }
                condCursor++;
              }

              if (
                condCursor < mergeIdx &&
                !allLoopHeaderIdxs.has(condCursor) &&
                !backwardJumpTargetIdxs.has(condCursor) &&
                isLuauCondJump(insns[condCursor].opname)
              ) {
                const eBranch = coalesceBranchCond(condCursor, mergeIdx);
                for (const [sr, prevEx] of setupScratchRegs.entries()) {
                  if (prevEx !== undefined) regExpr.set(sr, prevEx);
                  else regExpr.delete(sr);
                }
                const eTargetIdx = Math.min(mergeIdx, eBranch.falseTargetIdx);
                const eLast = eTargetIdx - 1;
                const eEndsJump =
                  eLast >= eBranch.bodyStartIdx &&
                  insns[eLast].opname === 'JUMP' &&
                  insns[eLast].targetPc === mergePc;

                let scratchUsedInBody = false;
                for (const sr of setupScratchRegs.keys()) {
                  if (eBranch.bodyStartIdx < insns.length && liveIn[eBranch.bodyStartIdx].has(sr)) {
                    scratchUsedInBody = true;
                    break;
                  }
                }
                if (!scratchUsedInBody && (eEndsJump || eTargetIdx === mergeIdx)) {
                  out.push(`${indent(lvl)}elseif ${eBranch.condStr} then`);
                  out.push(...liftBlockScoped(eBranch.bodyStartIdx, eEndsJump ? eLast : eTargetIdx, lvl + 1, loopStack));
                  cursor = eTargetIdx;
                  continue;
                }
              } else {
                for (const [sr, prevEx] of setupScratchRegs.entries()) {
                  if (prevEx !== undefined) regExpr.set(sr, prevEx);
                  else regExpr.delete(sr);
                }
              }

              restoreLexicalScope(ifElseOuterSnap);
              const elseLines = liftBlockScoped(cursor, mergeIdx, lvl + 1, loopStack);
              if (elseLines.length > 0) {
                // Collapse `else\n    if cond then ... end\nend` into idiomatic `elseif cond then ... end`
                const innerPad = indent(lvl + 1);
                let isSingleNestedIf =
                  elseLines.length >= 2 &&
                  elseLines[0].startsWith(`${innerPad}if `) &&
                  elseLines[0].endsWith(' then') &&
                  elseLines[elseLines.length - 1] === `${innerPad}end`;
                if (isSingleNestedIf) {
                  for (let el = 1; el < elseLines.length - 1; el++) {
                    if (elseLines[el] === `${innerPad}end`) {
                      isSingleNestedIf = false;
                      break;
                    }
                  }
                }
                if (isSingleNestedIf) {
                  out.push(`${indent(lvl)}elseif ${elseLines[0].slice(innerPad.length + 3)}`);
                  for (let el = 1; el < elseLines.length - 1; el++) {
                    out.push(elseLines[el].startsWith('    ') ? elseLines[el].slice(4) : elseLines[el]);
                  }
                } else {
                  out.push(`${indent(lvl)}else`);
                  out.push(...elseLines);
                }
              }
              cursor = mergeIdx;
            }
            restoreLexicalScope(ifElseOuterSnap);

            if (activeLoop && declaredLocals.size > 0) {
              env.metrics.syntheticPhiTempsAvoided++;
            }

            out.push(`${indent(lvl)}end`);
            i = mergeIdx;
            continue;
          }

          // Never silently emit an empty `if cond then end` when a forward jump escapes `endIdx`!
          let clampedTarget = Math.min(falseTargetIdx, endIdx);
          if (clampedTarget <= bodyStartIdx && falseTargetIdx > endIdx) {
            env.diagnostics.push({
              severity: 'warning',
              code: 'UNRECONSTRUCTED_JUMP',
              message: `Conditional jump ${ins.opname} at pc=${ins.pc} escapes block end (target pc=${branch.falseTargetPc}).`,
              protoId: proto.id,
              pc: ins.pc,
              section: 'decompiler',
            });
            out.push(`${indent(lvl)}-- [unreconstructed branch: if ${cond.jumpTakenCond} then goto pc_${branch.falseTargetPc} end]`);
            i = bodyStartIdx;
            break;
          }

          // Clean `if cond then ... end` (including early-return guards without swallowing following statements!)
          const didMatPrior = hoistBlockLiveLocals(i, i, clampedTarget, clampedTarget, out, lvl);
          const finalBranch = didMatPrior ? coalesceBranchCond(i, endIdx) : branch;
          bodyStartIdx = finalBranch.bodyStartIdx;
          falseTargetIdx = finalBranch.falseTargetIdx;
          clampedTarget = Math.min(falseTargetIdx, endIdx);
          const thenBodyLines = liftBlockScoped(bodyStartIdx, clampedTarget, lvl + 1, loopStack);
          if (thenBodyLines.length > 0 || cond.staticJumpTaken === undefined) {
            out.push(`${indent(lvl)}if ${finalBranch.condStr} then`);
            out.push(...thenBodyLines);
            out.push(`${indent(lvl)}end`);
          }
          i = clampedTarget;
          break;
        }

        case 'RETURN': {
          const retCount = ins.b === 0 ? -1 : ins.b - 1;
          if (retCount === 0) {
            // Only suppress the implicit trailing RETURN 0, 1 at the very end of the proto — NEVER inside an early-return branch!
            if (i < insns.length - 1) out.push(`${indent(lvl)}return`);
          } else if (retCount === 1) {
            if (openTables.has(ins.a)) flushOpenTable(ins.a, out, lvl);
            const val = getReg(ins.a);
            let code = val.code;
            const isMultiCapable = val.kind === 'call' || val.kind === 'methodCall' || val.kind === 'vararg';
            if (isMultiCapable) {
              if (val.singleReturn && env.opts.pruneReturnParens) {
                env.metrics.returnParensPruned++;
              } else {
                code = `(${code})`;
              }
            }
            out.push(`${indent(lvl)}return ${code}`);
          } else if (retCount > 1) {
            // Preserve exact evaluation order across multi-value returns ONLY when a later return slot
            // was actually evaluated BEFORE an earlier slot (dp > dq >= 0) with side-effect/mutable conflict.
            // Never trigger on normal left-to-right (dp < dq) order!
            let needsOrderSnapshot = false;
            for (let q = 1; q < retCount && !needsOrderSnapshot; q++) {
              const rq = ins.a + q;
              const eq = regExpr.get(rq);
              if (!eq || eq.isConst || (!eq.hasEffect && !eq.readsMutable)) continue;
              const dq = regDefIdx.get(rq) ?? -1;
              if (dq < 0) continue;
              for (let p = 0; p < q; p++) {
                const rp = ins.a + p;
                const ep = getReg(rp);
                if (ep.isConst) continue;
                const dp = regDefIdx.get(rp) ?? -1;
                if (dp > dq && (ep.hasEffect || (eq.hasEffect && ep.readsMutable) || (ep.hasEffect && eq.readsMutable))) {
                  needsOrderSnapshot = true;
                  break;
                }
              }
            }
            if (needsOrderSnapshot) {
              snapshotDependentRegs(-1, null, true, i - 1, out, lvl, false);
            }
            const vals: string[] = [];
            for (let r = 0; r < retCount; r++) {
              if (openTables.has(ins.a + r)) flushOpenTable(ins.a + r, out, lvl);
              const v = getReg(ins.a + r);
              const isLast = r === retCount - 1;
              const isMultiCapable = v.kind === 'call' || v.kind === 'methodCall' || v.kind === 'vararg';
              vals.push(isLast && isMultiCapable && !v.singleReturn ? `(${v.code})` : v.code);
            }
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          } else {
            // MULTRET return (`RETURN A, 0`): return R[A] .. R[multretReg]!
            const endR = multretReg !== null && multretReg >= ins.a ? multretReg : ins.a;
            if (endR > ins.a) {
              let needsOrderSnapshot = false;
              for (let rq = ins.a + 1; rq <= endR && !needsOrderSnapshot; rq++) {
                if (rq === multretReg) continue;
                const eq = regExpr.get(rq);
                if (!eq || eq.isConst || (!eq.hasEffect && !eq.readsMutable)) continue;
                const dq = regDefIdx.get(rq) ?? -1;
                if (dq < 0) continue;
                for (let rp = ins.a; rp < rq; rp++) {
                  const ep = getReg(rp);
                  if (ep.isConst) continue;
                  const dp = regDefIdx.get(rp) ?? -1;
                  if (dp > dq && (ep.hasEffect || (eq.hasEffect && ep.readsMutable) || (ep.hasEffect && eq.readsMutable))) {
                    needsOrderSnapshot = true;
                    break;
                  }
                }
              }
              if (needsOrderSnapshot) {
                snapshotDependentRegs(-1, null, true, i - 1, out, lvl, false);
              }
            }
            const vals: string[] = [];
            for (let r = ins.a; r <= endR; r++) {
              if (openTables.has(r)) flushOpenTable(r, out, lvl);
              vals.push(getReg(r).code);
            }
            multretReg = null;
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          }
          i++;
          break;
        }

        default:
          env.diagnostics.push({
            severity: 'warning',
            code: 'UNHANDLED_OPCODE',
            message: `Unhandled Luau opcode ${ins.opname} (A=${ins.a} B=${ins.b} C=${ins.c}) at pc=${ins.pc}.`,
            protoId: proto.id,
            pc: ins.pc,
            section: 'decompiler',
          });
          out.push(`${indent(lvl)}-- [unhandled op ${ins.opname} A=${ins.a} B=${ins.b} C=${ins.c}]`);
          i++;
          break;
      }
    }

    return out;
  }

  const sig = `${paramSigParts.join(', ')}${proto.isVararg ? (paramSigParts.length ? ', ...' : '...') : ''}`;
  if (isTopLevel) {
    if (proto.numParams > 0) {
      const body = liftRange(0, insns.length, indentLevel + 1, []);
      return [
        `${indent(indentLevel)}local function main(${sig})`,
        ...body,
        `${indent(indentLevel)}end`,
        `${indent(indentLevel)}return main(...)`,
      ];
    }
    return liftRange(0, insns.length, indentLevel, []);
  }

  const header = `function(${sig})`;
  const body: string[] = [];
  if (env.opts.lineInfoMode !== 'NONE' && proto.lineDefined > 0) {
    body.push(`${indent(indentLevel + 1)}-- line: ${proto.lineDefined}`);
  }
  if (env.opts.upvalueComments && inheritedUpvalues.length > 0) {
    body.push(`${indent(indentLevel + 1)}-- upvalues: ${inheritedUpvalues.map((u) => `${u.name} (${u.mode})`).join(', ')}`);
  }
  body.push(...liftRange(0, insns.length, indentLevel + 1, []));
  return [header, ...body, `${indent(indentLevel)}end`];
}

// Decompile Lua 5.1 proto cleanly with O(N) capture analysis & extended opcodes (SELF, TAILCALL, TFORLOOP, VARARG, SETLIST, TEST)
function decompileLua51Proto(
  proto: ParsedProto,
  env: LiftEnv,
  indentLevel: number,
  inheritedUpvalues: UpvalueBinding[],
  isTopLevel: boolean
): string[] {
  const insns = proto.instructions;
  const indent = (lvl: number) => '    '.repeat(lvl);
  const usedNames = new Set<string>();
  const regExpr = new Map<number, Expr>();
  const declaredLocals = new Map<number, string>();
  const localProtoMap = new Map<number, number>();
  const pendingMethodSelf = new Map<number, string>();

  const paramNames: string[] = [];
  for (let p = 0; p < proto.numParams; p++) {
    const dbg = env.opts.useDebugLocals ? proto.localVars.find((lv) => lv.reg === p && lv.startPc === 0)?.name : undefined;
    const pname = dbg && isValidIdent(dbg)
      ? dbg
      : env.opts.renamingType === 'SEMANTIC' && proto.numParams <= 4
        ? buildSemanticName(['a', 'b', 'c', 'd'][p], 'p', usedNames, env.opts, env.metrics)
        : buildSemanticName(undefined, 'p', usedNames, env.opts, env.metrics);
    usedNames.add(pname);
    paramNames.push(pname);
    declaredLocals.set(p, pname);
    regExpr.set(p, atomExpr(pname, { kind: 'ident', isVarRef: true, regOrigin: p }));
  }

  // O(N) precomputation of captured registers and loop-carried locals
  const capturedRegs = new Set<number>();
  const loopCarriedDefs = new Set<string>();
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname === 'CLOSURE') {
      const childId = proto.childProtos[ins.bx ?? 0];
      const cp = env.chunk.protos[childId];
      if (cp) {
        for (let u = 1; u <= cp.numUpvalues && i + u < insns.length; u++) {
          const cap = insns[i + u];
          if (cap.opname === 'MOVE') capturedRegs.add(cap.b);
        }
      }
    } else if (ins.opname === 'FORPREP' && ins.targetPc !== undefined) {
      const loopEnd = ins.targetPc;
      for (let j = i + 1; j < Math.min(loopEnd, insns.length); j++) {
        const w = insns[j];
        if (['ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'MOVE', 'LOADK'].includes(w.opname)) {
          for (let k = i - 1; k >= 0; k--) {
            if (insns[k].a === w.a && !['FORPREP', 'SETGLOBAL', 'SETTABLE'].includes(insns[k].opname)) {
              loopCarriedDefs.add(`${k}:${w.a}`);
              break;
            }
          }
        }
      }
    }
  }

  function getReg(r: number): Expr {
    const e = regExpr.get(r);
    if (e) return e;
    const loc = declaredLocals.get(r);
    if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r });
    return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
  }

  function getRK(rk: number): Expr {
    if (rk >= 256) return constantToExpr(proto.constants[rk - 256], env.opts);
    return getReg(rk);
  }

  function getUpvalName(idx: number): string {
    if (inheritedUpvalues[idx]) return inheritedUpvalues[idx].name;
    if (env.opts.useDebugLocals && proto.upvalueNames[idx]) return proto.upvalueNames[idx];
    return `upval_${idx}`;
  }

  function assignReg(reg: number, expr: Expr, idx: number, out: string[], lvl: number, forceLocal = false) {
    const existing = declaredLocals.get(reg);
    if (existing) {
      out.push(`${indent(lvl)}${existing} = ${expr.code}`);
      regExpr.set(reg, atomExpr(existing, { kind: 'ident', isVarRef: true, regOrigin: reg }));
      return;
    }

    if (forceLocal || capturedRegs.has(reg) || loopCarriedDefs.has(`${idx}:${reg}`) || expr.kind === 'table' || expr.kind === 'function') {
      const dbg = env.opts.useDebugLocals ? proto.localVars.find((lv) => lv.reg === reg)?.name : undefined;
      let hint = dbg ?? inferSemanticHintFromExpr(expr);
      if (!hint && env.opts.renamingType === 'SEMANTIC' && expr.isConst && typeof expr.constVal === 'number') {
        hint = 'total';
      }
      const fallback = expr.kind === 'table' ? 't' : expr.kind === 'function' ? 'fn' : typeof expr.constVal === 'number' ? 'n' : 'v';
      const name = buildSemanticName(hint, fallback, usedNames, env.opts, env.metrics);
      declaredLocals.set(reg, name);
      if (expr.kind === 'function' && expr.code.startsWith('function(')) {
        out.push(`${indent(lvl)}local function ${name}${expr.code.slice('function'.length)}`);
      } else if (expr.isConst && expr.constVal === null) {
        out.push(`${indent(lvl)}local ${name}`);
      } else {
        out.push(`${indent(lvl)}local ${name} = ${expr.code}`);
      }
      regExpr.set(reg, atomExpr(name, { kind: 'ident', isVarRef: true, regOrigin: reg }));
      return;
    }

    regExpr.set(reg, expr);
  }

  function liftRange(startIdx: number, endIdx: number, lvl: number): string[] {
    const out: string[] = [];
    let i = startIdx;
    let multretReg: number | null = null;

    while (i < endIdx) {
      const ins = insns[i];
      switch (ins.opname) {
        case 'LOADK':
          assignReg(ins.a, constantToExpr(proto.constants[ins.bx ?? 0], env.opts), i, out, lvl);
          i++;
          break;
        case 'LOADNIL':
          for (let r = ins.a; r <= ins.b; r++) {
            assignReg(r, atomExpr('nil', { isConst: true, constVal: null }), i, out, lvl);
          }
          i++;
          break;
        case 'LOADBOOL':
          assignReg(ins.a, atomExpr(ins.b !== 0 ? 'true' : 'false', { isConst: true, constVal: ins.b !== 0 }), i, out, lvl);
          i += ins.c !== 0 ? 2 : 1;
          break;
        case 'MOVE':
          assignReg(ins.a, getReg(ins.b), i, out, lvl);
          if (localProtoMap.has(ins.b)) localProtoMap.set(ins.a, localProtoMap.get(ins.b)!);
          i++;
          break;
        case 'GETGLOBAL': {
          const k = proto.constants[ins.bx ?? 0];
          const gname = k?.kind === 'string' ? String(k.value) : `G${ins.bx}`;
          env.imports.add(gname);
          assignReg(ins.a, atomExpr(gname, { kind: 'global', calleeName: gname }), i, out, lvl);
          i++;
          break;
        }
        case 'SETGLOBAL': {
          const k = proto.constants[ins.bx ?? 0];
          const gname = k?.kind === 'string' ? String(k.value) : `G${ins.bx}`;
          out.push(`${indent(lvl)}${gname} = ${getReg(ins.a).code}`);
          i++;
          break;
        }
        case 'GETUPVAL':
          assignReg(ins.a, atomExpr(getUpvalName(ins.b), { kind: 'ident', isVarRef: true }), i, out, lvl);
          i++;
          break;
        case 'SETUPVAL':
          out.push(`${indent(lvl)}${getUpvalName(ins.b)} = ${getReg(ins.a).code}`);
          i++;
          break;
        case 'GETTABLE': {
          const tbl = getReg(ins.b);
          const key = getRK(ins.c);
          const code =
            key.isConst && typeof key.constVal === 'string' && isValidIdent(key.constVal)
              ? `${tbl.code}.${key.constVal}`
              : `${tbl.code}[${key.code}]`;
          assignReg(ins.a, atomExpr(code, { kind: 'index', prec: 90 }), i, out, lvl);
          i++;
          break;
        }
        case 'SELF': {
          const obj = getReg(ins.b);
          const key = getRK(ins.c);
          const methodName = key.isConst && typeof key.constVal === 'string' ? key.constVal : key.code;
          const calleeFull = `${obj.code}:${methodName}`;
          pendingMethodSelf.set(ins.a, calleeFull);
          regExpr.set(ins.a, atomExpr(calleeFull, { kind: 'methodCall', prec: 90, calleeName: calleeFull }));
          regExpr.set(ins.a + 1, obj);
          i++;
          break;
        }
        case 'NEWTABLE': {
          const tblReg = ins.a;
          const entries: Array<{ key?: string; val: string }> = [];
          let j = i + 1;
          if (env.opts.foldTableLiterals) {
            while (j < endIdx) {
              if (insns[j].opname === 'SETTABLE' && insns[j].a === tblReg) {
                const st = insns[j];
                const kExpr = getRK(st.b);
                const vExpr = getRK(st.c);
                if (kExpr.isConst && typeof kExpr.constVal === 'string' && isValidIdent(kExpr.constVal)) {
                  entries.push({ key: kExpr.constVal, val: vExpr.code });
                } else {
                  entries.push({ key: `[${kExpr.code}]`, val: vExpr.code });
                }
                j++;
                continue;
              }
              if (insns[j].opname === 'SETLIST' && insns[j].a === tblReg) {
                const count = insns[j].b;
                for (let k = 1; k <= count; k++) entries.push({ val: getReg(tblReg + k).code });
                j++;
                continue;
              }
              break;
            }
          }
          let code = '{}';
          if (entries.length > 0) {
            env.metrics.tablesFolded++;
            const inner = entries.map((e) => (e.key ? `${indent(lvl + 1)}${e.key} = ${e.val},` : `${indent(lvl + 1)}${e.val},`));
            code = `{\n${inner.join('\n')}\n${indent(lvl)}}`;
          }
          assignReg(tblReg, atomExpr(code, { kind: 'table', prec: 100 }), i, out, lvl, true);
          i = j;
          break;
        }
        case 'SETTABLE': {
          const tbl = getReg(ins.a);
          const kExpr = getRK(ins.b);
          const vExpr = getRK(ins.c);
          const lhs =
            kExpr.isConst && typeof kExpr.constVal === 'string' && isValidIdent(kExpr.constVal)
              ? `${tbl.code}.${kExpr.constVal}`
              : `${tbl.code}[${kExpr.code}]`;
          out.push(`${indent(lvl)}${lhs} = ${vExpr.code}`);
          i++;
          break;
        }
        case 'VARARG': {
          if (ins.b === 0) {
            regExpr.set(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }));
            multretReg = ins.a;
          } else if (ins.b === 2) {
            assignReg(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }), i, out, lvl);
          } else if (ins.b > 2) {
            const count = ins.b - 1;
            const names: string[] = [];
            for (let r = 0; r < count; r++) {
              const targetR = ins.a + r;
              const nm = buildSemanticName(undefined, 'arg', usedNames, env.opts, env.metrics);
              declaredLocals.set(targetR, nm);
              regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR }));
              names.push(nm);
            }
            out.push(`${indent(lvl)}local ${names.join(', ')} = ...`);
          }
          i++;
          break;
        }
        case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': {
          const opMap: Record<string, string> = { ADD: '+', SUB: '-', MUL: '*', DIV: '/', MOD: '%', POW: '^' };
          assignReg(ins.a, foldBinary(opMap[ins.opname], getRK(ins.b), getRK(ins.c), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }
        case 'UNM':
          assignReg(ins.a, { kind: 'unary', code: `-${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'NOT':
          assignReg(ins.a, { kind: 'unary', code: `not ${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'LEN':
          assignReg(ins.a, { kind: 'unary', code: `#${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'CONCAT': {
          let acc = getReg(ins.b);
          for (let r = ins.b + 1; r <= ins.c; r++) acc = foldBinary('..', acc, getReg(r), env.opts, env.metrics);
          assignReg(ins.a, acc, i, out, lvl);
          i++;
          break;
        }
        case 'CLOSURE': {
          const childId = proto.childProtos[ins.bx ?? 0];
          const child = childId !== undefined ? env.chunk.protos[childId] : undefined;
          const captures: UpvalueBinding[] = [];
          let j = i + 1;
          if (child) {
            for (let u = 0; u < child.numUpvalues && j < endIdx; u++, j++) {
              const cap = insns[j];
              if (cap.opname === 'MOVE') {
                captures.push({ name: declaredLocals.get(cap.b) ?? getReg(cap.b).code, mode: 'ref' });
              } else {
                captures.push({ name: getUpvalName(cap.b), mode: 'upval' });
              }
            }
            const fnLines = decompileLua51Proto(child, env, lvl, captures, false);
            localProtoMap.set(ins.a, child.id);
            assignReg(ins.a, atomExpr(fnLines.join('\n'), { kind: 'function', prec: 100, protoId: child.id }), i, out, lvl, true);
          }
          i = j;
          break;
        }
        case 'FORPREP': {
          const init = getReg(ins.a);
          const limit = getReg(ins.a + 1);
          const step = getReg(ins.a + 2);
          const loopIdx = ins.targetPc ?? (i + 1 + ins.d);
          const idxName = buildSemanticName(env.opts.renamingType === 'SEMANTIC' ? 'i' : undefined, 'i', usedNames, env.opts, env.metrics);
          declaredLocals.set(ins.a + 3, idxName);
          regExpr.set(ins.a + 3, atomExpr(idxName, { kind: 'ident', isVarRef: true, regOrigin: ins.a + 3 }));
          const omitStep = env.opts.numericForStepSugaring && step.isConst && step.constVal === 1;
          out.push(`${indent(lvl)}for ${idxName} = ${init.code}, ${limit.code}${omitStep ? '' : `, ${step.code}`} do`);
          out.push(...liftRange(i + 1, loopIdx, lvl + 1));
          out.push(`${indent(lvl)}end`);
          declaredLocals.delete(ins.a + 3);
          i = loopIdx + 1;
          break;
        }
        case 'EQ': case 'LT': case 'LE': case 'TEST': {
          let condStr: string;
          if (ins.opname === 'TEST') {
            const val = getReg(ins.a);
            condStr = ins.c === 0 ? invertCondition(val.code, true) : val.code;
          } else {
            const lhs = getRK(ins.b);
            const rhs = getRK(ins.c);
            const baseOp: '==' | '<' | '<=' = ins.opname === 'EQ' ? '==' : ins.opname === 'LT' ? '<' : '<=';
            const pair = formatLuauComparisonPair(lhs, rhs, baseOp, ins.a !== 0);
            condStr = pair.jumpTakenCond;
          }
          if (i + 1 < endIdx && insns[i + 1].opname === 'JMP') {
            const jmp = insns[i + 1];
            const falseIdx = Math.min(endIdx, jmp.targetPc ?? i + 2);
            const lastInThen = falseIdx - 1;
            const hasElse = lastInThen > i + 1 && insns[lastInThen].opname === 'JMP';
            if (hasElse) {
              const mergeIdx = Math.min(endIdx, insns[lastInThen].targetPc ?? endIdx);
              out.push(`${indent(lvl)}if ${condStr} then`);
              out.push(...liftRange(i + 2, lastInThen, lvl + 1));
              out.push(`${indent(lvl)}else`);
              out.push(...liftRange(falseIdx, mergeIdx, lvl + 1));
              out.push(`${indent(lvl)}end`);
              i = mergeIdx;
            } else {
              out.push(`${indent(lvl)}if ${condStr} then`);
              out.push(...liftRange(i + 2, falseIdx, lvl + 1));
              out.push(`${indent(lvl)}end`);
              i = falseIdx;
            }
          } else {
            i++;
          }
          break;
        }
        case 'CALL':
        case 'TAILCALL': {
          const isMethod = pendingMethodSelf.has(ins.a);
          const fnExpr = getReg(ins.a);
          const startArg = isMethod ? 2 : 1;
          const args: Expr[] = [];
          if (ins.b === 0) {
            if (multretReg !== null && multretReg >= ins.a + startArg) {
              for (let r = ins.a + startArg; r <= multretReg; r++) args.push(getReg(r));
            }
            multretReg = null;
          } else {
            const argCount = ins.b - 1;
            for (let aIdx = startArg; aIdx <= argCount; aIdx++) args.push(getReg(ins.a + aIdx));
          }
          pendingMethodSelf.delete(ins.a);
          const formattedArgs = args.map((a, idx) =>
            ins.b !== 0 && idx === args.length - 1 && !a.singleReturn && (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')
              ? `(${a.code})`
              : a.code
          );
          const callCode = `${fnExpr.code}(${formattedArgs.join(', ')})`;

          if (ins.opname === 'TAILCALL') {
            out.push(`${indent(lvl)}return ${callCode}`);
            i += insns[i + 1]?.opname === 'RETURN' ? 2 : 1;
            break;
          }

          let singleRet = Boolean(fnExpr.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnExpr.calleeName));
          if (localProtoMap.has(ins.a)) {
            if (env.returnArities.get(localProtoMap.get(ins.a)!) === 1) singleRet = true;
          }
          const retCount = ins.c === 0 ? -1 : ins.c - 1;
          if (retCount === -1) {
            regExpr.set(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, singleReturn: false, calleeName: fnExpr.calleeName }));
            multretReg = ins.a;
          } else if (retCount === 0) {
            out.push(`${indent(lvl)}${callCode}`);
          } else if (retCount === 1) {
            assignReg(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, singleReturn: singleRet, calleeName: fnExpr.calleeName }), i, out, lvl);
          } else {
            const names: string[] = [];
            for (let r = 0; r < retCount; r++) {
              const targetR = ins.a + r;
              const nm = buildSemanticName(undefined, 'v', usedNames, env.opts, env.metrics);
              declaredLocals.set(targetR, nm);
              regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR }));
              names.push(nm);
            }
            out.push(`${indent(lvl)}local ${names.join(', ')} = ${callCode}`);
          }
          i++;
          break;
        }
        case 'RETURN': {
          const retCount = ins.b === 0 ? -1 : ins.b - 1;
          if (retCount === 0) {
            if (i < endIdx - 1) out.push(`${indent(lvl)}return`);
          } else if (retCount === 1) {
            const val = getReg(ins.a);
            let code = val.code;
            const isMultiCapable = val.kind === 'call' || val.kind === 'methodCall' || val.kind === 'vararg';
            if (isMultiCapable && val.singleReturn && env.opts.pruneReturnParens) {
              env.metrics.returnParensPruned++;
            } else if (isMultiCapable && !val.singleReturn) {
              code = `(${code})`;
            }
            out.push(`${indent(lvl)}return ${code}`);
          } else if (retCount > 1) {
            const vals: string[] = [];
            for (let r = 0; r < retCount; r++) {
              const v = getReg(ins.a + r);
              const isLast = r === retCount - 1;
              const isMultiCapable = v.kind === 'call' || v.kind === 'methodCall' || v.kind === 'vararg';
              vals.push(isLast && isMultiCapable && !v.singleReturn ? `(${v.code})` : v.code);
            }
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          } else {
            const endR = multretReg !== null && multretReg >= ins.a ? multretReg : ins.a;
            const vals: string[] = [];
            for (let r = ins.a; r <= endR; r++) vals.push(getReg(r).code);
            multretReg = null;
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          }
          i++;
          break;
        }
        default:
          i++;
          break;
      }
    }
    return out;
  }

  if (isTopLevel) {
    return liftRange(0, insns.length, indentLevel);
  }
  const sig = `${paramNames.join(', ')}${proto.isVararg ? (paramNames.length ? ', ...' : '...') : ''}`;
  const body: string[] = [];
  if (env.opts.lineInfoMode !== 'NONE' && proto.lineDefined > 0) {
    body.push(`${indent(indentLevel + 1)}-- line: ${proto.lineDefined}`);
  }
  if (env.opts.upvalueComments && inheritedUpvalues.length > 0) {
    body.push(`${indent(indentLevel + 1)}-- upvalues: ${inheritedUpvalues.map((u) => `${u.name} (${u.mode})`).join(', ')}`);
  }
  body.push(...liftRange(0, insns.length, indentLevel + 1));
  return [`function(${sig})`, ...body, `${indent(indentLevel)}end`];
}

// Full Lua 5.4 bytecode lifter (_ENV upvalue resolution, LOADI/ADDI/bitwise/RETURN0/RETURN1/FORPREP/TFORCALL/table folding)
function decompileLua54Proto(
  proto: ParsedProto,
  env: LiftEnv,
  indentLevel: number,
  inheritedUpvalues: UpvalueBinding[],
  isTopLevel: boolean
): string[] {
  const insns = proto.instructions;
  const indent = (lvl: number) => '    '.repeat(lvl);
  const usedNames = new Set<string>();
  const regExpr = new Map<number, Expr>();
  const declaredLocals = new Map<number, string>();
  const localProtoMap = new Map<number, number>();
  const pendingMethodSelf = new Map<number, string>();

  const paramNames: string[] = [];
  for (let p = 0; p < proto.numParams; p++) {
    const dbg = env.opts.useDebugLocals ? proto.localVars.find((lv) => lv.reg === p && lv.startPc === 0)?.name : undefined;
    const pname = dbg && isValidIdent(dbg)
      ? dbg
      : env.opts.renamingType === 'SEMANTIC' && proto.numParams <= 4
        ? buildSemanticName(['a', 'b', 'c', 'd'][p], 'p', usedNames, env.opts, env.metrics)
        : buildSemanticName(undefined, 'p', usedNames, env.opts, env.metrics);
    usedNames.add(pname);
    paramNames.push(pname);
    declaredLocals.set(p, pname);
    regExpr.set(p, atomExpr(pname, { kind: 'ident', isVarRef: true, regOrigin: p }));
  }

  // O(N) pre-analysis: identify loop-carried locals & captured registers in Lua 5.4
  const capturedRegs = new Set<number>();
  const loopCarriedDefs = new Set<string>();
  const loopSpans: Array<{ headerIdx: number; endIdx: number }> = [];

  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.opname === 'CLOSURE') {
      const childId = proto.childProtos[ins.bx ?? 0];
      const child = childId !== undefined ? env.chunk.protos[childId] : undefined;
      if (child?.upvalueDescriptors) {
        for (const desc of child.upvalueDescriptors) {
          if (desc.instack) capturedRegs.add(desc.idx);
        }
      }
    } else if (ins.opname === 'FORPREP' && ins.targetPc !== undefined && ins.targetPc > i) {
      loopSpans.push({ headerIdx: i, endIdx: ins.targetPc });
    } else if (ins.opname === 'TFORPREP' && ins.targetPc !== undefined && ins.targetPc > i) {
      loopSpans.push({ headerIdx: i, endIdx: ins.targetPc + 1 });
    } else if (ins.opname === 'JMP' && ins.targetPc !== undefined && ins.targetPc < i) {
      loopSpans.push({ headerIdx: ins.targetPc, endIdx: i });
    }
  }

  // Find registers written inside loops that were initialized prior to the loop header
  const lastWriteBefore = new Int32Array(256).fill(-1);
  const lua54NonWrite = new Set([
    'VARARGPREP', 'SETTABUP', 'SETTABLE', 'SETI', 'SETFIELD', 'SETUPVAL', 'MMBIN', 'MMBINI', 'MMBINK',
    'CLOSE', 'TBC', 'JMP', 'EQ', 'LT', 'LE', 'EQK', 'EQI', 'LTI', 'LEI', 'GTI', 'GEI', 'TEST',
    'RETURN', 'RETURN0', 'RETURN1', 'FORPREP', 'FORLOOP', 'TFORPREP', 'TFORCALL', 'TFORLOOP', 'SETLIST', 'EXTRAARG',
  ]);
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (lua54NonWrite.has(ins.opname)) continue;
    const prev = lastWriteBefore[ins.a];
    if (prev !== -1) {
      for (const sp of loopSpans) {
        if (prev < sp.headerIdx && i >= sp.headerIdx && i <= sp.endIdx) {
          loopCarriedDefs.add(`${prev}:${ins.a}`);
          break;
        }
      }
    }
    lastWriteBefore[ins.a] = i;
  }

  function getReg(r: number): Expr {
    const e = regExpr.get(r);
    if (e) return e;
    const loc = declaredLocals.get(r);
    if (loc) return atomExpr(loc, { kind: 'ident', isVarRef: true, regOrigin: r });
    return atomExpr(`v${r}`, { kind: 'ident', isVarRef: true, regOrigin: r });
  }

  function getRK54(idx: number, kFlag: number): Expr {
    return kFlag !== 0 ? constantToExpr(proto.constants[idx], env.opts) : getReg(idx);
  }

  function getUpvalName(uIdx: number): string {
    if (inheritedUpvalues[uIdx]) return inheritedUpvalues[uIdx].name;
    if (env.opts.useDebugLocals && proto.upvalueNames[uIdx]) return proto.upvalueNames[uIdx];
    if (isTopLevel && uIdx === 0) return '_ENV';
    return `upval_${uIdx}`;
  }

  function assignReg(reg: number, expr: Expr, idx: number, out: string[], lvl: number, forceLocal = false) {
    const existing = declaredLocals.get(reg);
    if (existing) {
      out.push(`${indent(lvl)}${existing} = ${expr.code}`);
      regExpr.set(reg, atomExpr(existing, { kind: 'ident', isVarRef: true, regOrigin: reg }));
      return;
    }

    if (forceLocal || capturedRegs.has(reg) || loopCarriedDefs.has(`${idx}:${reg}`) || expr.kind === 'table' || expr.kind === 'function') {
      const dbg = env.opts.useDebugLocals ? proto.localVars.find((lv) => lv.reg === reg)?.name : undefined;
      let hint = dbg ?? inferSemanticHintFromExpr(expr);
      if (!hint && env.opts.renamingType === 'SEMANTIC' && expr.isConst && typeof expr.constVal === 'number') {
        hint = 'total';
      }
      const fallback = expr.kind === 'table' ? 't' : expr.kind === 'function' ? 'fn' : typeof expr.constVal === 'number' ? 'n' : 'v';
      const name = buildSemanticName(hint, fallback, usedNames, env.opts, env.metrics);
      declaredLocals.set(reg, name);
      if (expr.kind === 'function' && expr.code.startsWith('function(')) {
        out.push(`${indent(lvl)}local function ${name}${expr.code.slice('function'.length)}`);
      } else if (expr.isConst && expr.constVal === null) {
        out.push(`${indent(lvl)}local ${name}`);
      } else {
        out.push(`${indent(lvl)}local ${name} = ${expr.code}`);
      }
      regExpr.set(reg, atomExpr(name, { kind: 'ident', isVarRef: true, regOrigin: reg }));
      return;
    }

    regExpr.set(reg, expr);
  }

  function liftRange(startIdx: number, endIdx: number, lvl: number): string[] {
    const out: string[] = [];
    let i = startIdx;
    let multretReg: number | null = null;

    while (i < endIdx) {
      const ins = insns[i];
      const kFlag = ins.aux ?? 0;

      switch (ins.opname) {
        case 'VARARGPREP':
        case 'MMBIN':
        case 'MMBINI':
        case 'MMBINK':
        case 'CLOSE':
        case 'TBC':
        case 'EXTRAARG':
          i++;
          break;

        case 'MOVE':
          assignReg(ins.a, getReg(ins.b), i, out, lvl);
          if (localProtoMap.has(ins.b)) localProtoMap.set(ins.a, localProtoMap.get(ins.b)!);
          i++;
          break;

        case 'LOADI':
        case 'LOADF':
          assignReg(ins.a, atomExpr(formatNumber(ins.d, env.opts), { isConst: true, constVal: ins.d }), i, out, lvl);
          i++;
          break;

        case 'LOADK':
          assignReg(ins.a, constantToExpr(proto.constants[ins.bx ?? 0], env.opts), i, out, lvl);
          i++;
          break;

        case 'LOADFALSE':
          assignReg(ins.a, atomExpr('false', { isConst: true, constVal: false }), i, out, lvl);
          i++;
          break;

        case 'LFALSESKIP':
          assignReg(ins.a, atomExpr('false', { isConst: true, constVal: false }), i, out, lvl);
          i += 2;
          break;

        case 'LOADTRUE':
          assignReg(ins.a, atomExpr('true', { isConst: true, constVal: true }), i, out, lvl);
          i++;
          break;

        case 'LOADNIL':
          for (let r = ins.a; r <= ins.a + ins.b; r++) {
            assignReg(r, atomExpr('nil', { isConst: true, constVal: null }), i, out, lvl);
          }
          i++;
          break;

        case 'GETUPVAL':
          assignReg(ins.a, atomExpr(getUpvalName(ins.b), { kind: 'ident', isVarRef: true }), i, out, lvl);
          i++;
          break;

        case 'SETUPVAL':
          out.push(`${indent(lvl)}${getUpvalName(ins.b)} = ${getReg(ins.a).code}`);
          i++;
          break;

        case 'GETTABUP': {
          const upName = getUpvalName(ins.b);
          const keyK = proto.constants[ins.c];
          const keyStr = keyK?.kind === 'string' ? String(keyK.value) : `K${ins.c}`;
          if (upName === '_ENV' && isValidIdent(keyStr)) {
            env.imports.add(keyStr);
            assignReg(ins.a, atomExpr(keyStr, { kind: 'global', calleeName: keyStr }), i, out, lvl);
          } else {
            const code = isValidIdent(keyStr) ? `${upName}.${keyStr}` : `${upName}[${escapeLuaString(keyStr)}]`;
            assignReg(ins.a, atomExpr(code, { kind: 'index', prec: 90, calleeName: code }), i, out, lvl);
          }
          i++;
          break;
        }

        case 'SETTABUP': {
          const upName = getUpvalName(ins.a);
          const keyK = proto.constants[ins.b];
          const keyStr = keyK?.kind === 'string' ? String(keyK.value) : `K${ins.b}`;
          const val = getRK54(ins.c, kFlag);
          const lhs = upName === '_ENV' && isValidIdent(keyStr)
            ? keyStr
            : isValidIdent(keyStr)
              ? `${upName}.${keyStr}`
              : `${upName}[${escapeLuaString(keyStr)}]`;
          out.push(`${indent(lvl)}${lhs} = ${val.code}`);
          i++;
          break;
        }

        case 'GETTABLE':
          assignReg(ins.a, atomExpr(`${getReg(ins.b).code}[${getReg(ins.c).code}]`, { kind: 'index', prec: 90 }), i, out, lvl);
          i++;
          break;

        case 'GETI':
          assignReg(ins.a, atomExpr(`${getReg(ins.b).code}[${ins.c}]`, { kind: 'index', prec: 90 }), i, out, lvl);
          i++;
          break;

        case 'GETFIELD': {
          const tbl = getReg(ins.b);
          const keyK = proto.constants[ins.c];
          const keyStr = keyK?.kind === 'string' ? String(keyK.value) : `K${ins.c}`;
          const code = isValidIdent(keyStr) ? `${tbl.code}.${keyStr}` : `${tbl.code}[${escapeLuaString(keyStr)}]`;
          assignReg(ins.a, atomExpr(code, { kind: 'index', prec: 90, calleeName: code }), i, out, lvl);
          i++;
          break;
        }

        case 'SELF': {
          const obj = getReg(ins.b);
          const key = getRK54(ins.c, kFlag);
          const methodName = key.isConst && typeof key.constVal === 'string' ? key.constVal : key.code;
          const calleeFull = `${obj.code}:${methodName}`;
          pendingMethodSelf.set(ins.a, calleeFull);
          regExpr.set(ins.a, atomExpr(calleeFull, { kind: 'methodCall', prec: 90, calleeName: calleeFull }));
          regExpr.set(ins.a + 1, obj);
          i++;
          break;
        }

        case 'NEWTABLE': {
          const tblReg = ins.a;
          const entries: Array<{ key?: string; val: string }> = [];
          let j = i + 1;
          // Lua 5.4 always emits an EXTRAARG word immediately after NEWTABLE
          if (j < endIdx && insns[j].opname === 'EXTRAARG') j++;
          if (env.opts.foldTableLiterals) {
            while (j < endIdx) {
              const cur = insns[j];
              const curK = cur.aux ?? 0;
              if (cur.opname === 'SETFIELD' && cur.a === tblReg) {
                const keyK = proto.constants[cur.b];
                const kStr = keyK?.kind === 'string' ? String(keyK.value) : `K${cur.b}`;
                const vExpr = getRK54(cur.c, curK);
                entries.push({ key: isValidIdent(kStr) ? kStr : `[${escapeLuaString(kStr)}]`, val: vExpr.code });
                j++;
                continue;
              }
              if (cur.opname === 'SETI' && cur.a === tblReg) {
                entries.push({ val: getRK54(cur.c, curK).code });
                j++;
                continue;
              }
              if (cur.opname === 'SETLIST' && cur.a === tblReg) {
                for (let k = 1; k <= cur.b; k++) entries.push({ val: getReg(tblReg + k).code });
                j++;
                continue;
              }
              break;
            }
          }
          let code = '{}';
          if (entries.length > 0) {
            env.metrics.tablesFolded++;
            const allArray = entries.every((e) => !e.key);
            if (allArray && entries.length <= 6) {
              code = `{ ${entries.map((e) => e.val).join(', ')} }`;
            } else {
              const inner = entries.map((e) => (e.key ? `${indent(lvl + 1)}${e.key} = ${e.val},` : `${indent(lvl + 1)}${e.val},`));
              code = `{\n${inner.join('\n')}\n${indent(lvl)}}`;
            }
          }
          assignReg(tblReg, atomExpr(code, { kind: 'table', prec: 100 }), i, out, lvl, true);
          i = j;
          break;
        }

        case 'SETTABLE':
          out.push(`${indent(lvl)}${getReg(ins.a).code}[${getReg(ins.b).code}] = ${getRK54(ins.c, kFlag).code}`);
          i++;
          break;

        case 'SETI':
          out.push(`${indent(lvl)}${getReg(ins.a).code}[${ins.b}] = ${getRK54(ins.c, kFlag).code}`);
          i++;
          break;

        case 'SETFIELD': {
          const tbl = getReg(ins.a);
          const keyK = proto.constants[ins.b];
          const kStr = keyK?.kind === 'string' ? String(keyK.value) : `K${ins.b}`;
          const lhs = isValidIdent(kStr) ? `${tbl.code}.${kStr}` : `${tbl.code}[${escapeLuaString(kStr)}]`;
          out.push(`${indent(lvl)}${lhs} = ${getRK54(ins.c, kFlag).code}`);
          i++;
          break;
        }

        case 'ADDI': {
          const sC = ins.c - 128;
          const op = sC < 0 ? '-' : '+';
          const rhs = atomExpr(formatNumber(Math.abs(sC), env.opts), { isConst: true, constVal: Math.abs(sC) });
          assignReg(ins.a, foldBinary(op, getReg(ins.b), rhs, env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'SHRI':
        case 'SHLI': {
          const sC = ins.c - 128;
          const op = ins.opname === 'SHRI' ? '>>' : '<<';
          const rhs = atomExpr(formatNumber(sC, env.opts), { isConst: true, constVal: sC });
          assignReg(ins.a, foldBinary(op, getReg(ins.b), rhs, env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'ADDK': case 'SUBK': case 'MULK': case 'MODK': case 'POWK': case 'DIVK': case 'IDIVK':
        case 'BANDK': case 'BORK': case 'BXORK': {
          const opMap: Record<string, string> = {
            ADDK: '+', SUBK: '-', MULK: '*', MODK: '%', POWK: '^', DIVK: '/', IDIVK: '//',
            BANDK: '&', BORK: '|', BXORK: '~',
          };
          assignReg(ins.a, foldBinary(opMap[ins.opname], getReg(ins.b), constantToExpr(proto.constants[ins.c], env.opts), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'ADD': case 'SUB': case 'MUL': case 'MOD': case 'POW': case 'DIV': case 'IDIV':
        case 'BAND': case 'BOR': case 'BXOR': case 'SHL': case 'SHR': {
          const opMap: Record<string, string> = {
            ADD: '+', SUB: '-', MUL: '*', MOD: '%', POW: '^', DIV: '/', IDIV: '//',
            BAND: '&', BOR: '|', BXOR: '~', SHL: '<<', SHR: '>>',
          };
          assignReg(ins.a, foldBinary(opMap[ins.opname], getReg(ins.b), getReg(ins.c), env.opts, env.metrics), i, out, lvl);
          i++;
          break;
        }

        case 'UNM':
          assignReg(ins.a, { kind: 'unary', code: `-${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'BNOT':
          assignReg(ins.a, { kind: 'unary', code: `~${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'NOT':
          assignReg(ins.a, { kind: 'unary', code: `not ${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'LEN':
          assignReg(ins.a, { kind: 'unary', code: `#${wrapIfLower(getReg(ins.b), 80)}`, prec: 80 }, i, out, lvl);
          i++;
          break;
        case 'CONCAT': {
          let acc = getReg(ins.a);
          for (let r = ins.a + 1; r < ins.a + ins.b; r++) {
            acc = foldBinary('..', acc, getReg(r), env.opts, env.metrics);
          }
          assignReg(ins.a, acc, i, out, lvl);
          i++;
          break;
        }

        case 'CLOSURE': {
          const childId = proto.childProtos[ins.bx ?? 0];
          const child = childId !== undefined ? env.chunk.protos[childId] : undefined;
          if (child) {
            const captures: UpvalueBinding[] = (child.upvalueDescriptors ?? []).map((desc) => {
              if (desc.instack) {
                return { name: declaredLocals.get(desc.idx) ?? getReg(desc.idx).code, mode: 'ref' };
              }
              return { name: getUpvalName(desc.idx), mode: 'upval' };
            });
            const fnLines = decompileLua54Proto(child, env, lvl, captures, false);
            localProtoMap.set(ins.a, child.id);
            assignReg(ins.a, atomExpr(fnLines.join('\n'), { kind: 'function', prec: 100, protoId: child.id }), i, out, lvl, true);
          }
          i++;
          break;
        }

        case 'FORPREP': {
          const init = getReg(ins.a);
          const limit = getReg(ins.a + 1);
          const step = getReg(ins.a + 2);
          const loopIdx = ins.targetPc ?? (i + 1 + ins.d);
          const idxName = buildSemanticName(env.opts.renamingType === 'SEMANTIC' ? 'i' : undefined, 'i', usedNames, env.opts, env.metrics);
          declaredLocals.set(ins.a + 3, idxName);
          regExpr.set(ins.a + 3, atomExpr(idxName, { kind: 'ident', isVarRef: true, regOrigin: ins.a + 3 }));
          const omitStep = env.opts.numericForStepSugaring && step.isConst && step.constVal === 1;
          out.push(`${indent(lvl)}for ${idxName} = ${init.code}, ${limit.code}${omitStep ? '' : `, ${step.code}`} do`);
          out.push(...liftRange(i + 1, loopIdx, lvl + 1));
          out.push(`${indent(lvl)}end`);
          declaredLocals.delete(ins.a + 3);
          i = loopIdx + 1;
          break;
        }

        case 'TFORPREP': {
          const tforCallIdx = ins.targetPc ?? (i + 1 + ins.d);
          const iterCode = getReg(ins.a).code;
          const varCount = insns[tforCallIdx]?.opname === 'TFORCALL' ? Math.max(1, insns[tforCallIdx].c) : 2;
          const hints = iterCode.startsWith('ipairs(') ? ['index', 'value'] : ['key', 'value'];
          const varNames: string[] = [];
          for (let v = 0; v < varCount; v++) {
            const nm = buildSemanticName(env.opts.renamingType === 'SEMANTIC' ? hints[v] : undefined, 'v', usedNames, env.opts, env.metrics);
            declaredLocals.set(ins.a + 4 + v, nm);
            regExpr.set(ins.a + 4 + v, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: ins.a + 4 + v }));
            varNames.push(nm);
          }
          out.push(`${indent(lvl)}for ${varNames.join(', ')} in ${iterCode} do`);
          out.push(...liftRange(i + 1, tforCallIdx, lvl + 1));
          out.push(`${indent(lvl)}end`);
          for (let v = 0; v < varCount; v++) declaredLocals.delete(ins.a + 4 + v);
          i = tforCallIdx + 2; // skip TFORCALL + TFORLOOP
          break;
        }

        case 'EQ': case 'LT': case 'LE': case 'EQK': case 'EQI': case 'LTI': case 'LEI': case 'GTI': case 'GEI': case 'TEST': {
          let condStr = '';
          const lhs = getReg(ins.a);
          if (ins.opname === 'TEST') {
            condStr = kFlag === 0 ? lhs.code : invertCondition(lhs.code);
          } else {
            let rhs: Expr;
            let baseOp = '==';
            if (ins.opname === 'EQ' || ins.opname === 'LT' || ins.opname === 'LE') {
              rhs = getReg(ins.b);
              baseOp = ins.opname === 'EQ' ? '==' : ins.opname === 'LT' ? '<' : '<=';
            } else if (ins.opname === 'EQK') {
              rhs = constantToExpr(proto.constants[ins.b], env.opts);
              baseOp = '==';
            } else {
              const sB = ins.b - 128;
              rhs = atomExpr(formatNumber(sB, env.opts), { isConst: true, constVal: sB });
              baseOp = ins.opname === 'EQI' ? '==' : ins.opname === 'LTI' ? '<' : ins.opname === 'LEI' ? '<=' : ins.opname === 'GTI' ? '>' : '>=';
            }
            const swapped = swapConstantComparison(lhs, rhs, baseOp, baseOp);
            const raw = `${swapped.left.code} ${swapped.opTaken} ${swapped.right.code}`;
            condStr = kFlag === 0 ? raw : invertCondition(raw);
          }

          if (i + 1 < endIdx && insns[i + 1].opname === 'JMP') {
            const jmp = insns[i + 1];
            const falseIdx = Math.min(endIdx, jmp.targetPc ?? i + 2);
            const lastInThen = falseIdx - 1;
            const hasElse = lastInThen > i + 1 && insns[lastInThen].opname === 'JMP';
            if (hasElse) {
              const mergeIdx = Math.min(endIdx, insns[lastInThen].targetPc ?? endIdx);
              out.push(`${indent(lvl)}if ${condStr} then`);
              out.push(...liftRange(i + 2, lastInThen, lvl + 1));
              out.push(`${indent(lvl)}else`);
              out.push(...liftRange(falseIdx, mergeIdx, lvl + 1));
              out.push(`${indent(lvl)}end`);
              i = mergeIdx;
            } else {
              out.push(`${indent(lvl)}if ${condStr} then`);
              out.push(...liftRange(i + 2, falseIdx, lvl + 1));
              out.push(`${indent(lvl)}end`);
              i = falseIdx;
            }
          } else {
            i++;
          }
          break;
        }

        case 'CALL':
        case 'TAILCALL': {
          const isMethod = pendingMethodSelf.has(ins.a);
          const fnExpr = getReg(ins.a);
          const startArg = isMethod ? 2 : 1;
          const args: Expr[] = [];
          if (ins.b === 0) {
            if (multretReg !== null && multretReg >= ins.a + startArg) {
              for (let r = ins.a + startArg; r <= multretReg; r++) args.push(getReg(r));
            }
            multretReg = null;
          } else {
            const argCount = ins.b - 1;
            for (let aIdx = startArg; aIdx <= argCount; aIdx++) args.push(getReg(ins.a + aIdx));
          }
          pendingMethodSelf.delete(ins.a);
          const formattedArgs = args.map((a, idx) =>
            ins.b !== 0 && idx === args.length - 1 && !a.singleReturn && (a.kind === 'call' || a.kind === 'methodCall' || a.kind === 'vararg')
              ? `(${a.code})`
              : a.code
          );
          const callCode = `${fnExpr.code}(${formattedArgs.join(', ')})`;

          if (ins.opname === 'TAILCALL') {
            out.push(`${indent(lvl)}return ${callCode}`);
            i += insns[i + 1]?.opname === 'RETURN' ? 2 : 1;
            break;
          }

          if (insns[i + 1]?.opname === 'TFORPREP' && insns[i + 1].a === ins.a) {
            regExpr.set(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, calleeName: fnExpr.calleeName }));
            i++;
            break;
          }

          let singleRet = Boolean(fnExpr.calleeName && KNOWN_SINGLE_RETURN_CALLS.has(fnExpr.calleeName));
          if (localProtoMap.has(ins.a)) {
            if (env.returnArities.get(localProtoMap.get(ins.a)!) === 1) singleRet = true;
          }
          const retCount = ins.c === 0 ? -1 : ins.c - 1;
          if (retCount === -1) {
            regExpr.set(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, singleReturn: false, calleeName: fnExpr.calleeName }));
            multretReg = ins.a;
          } else if (retCount === 0) {
            out.push(`${indent(lvl)}${callCode}`);
          } else if (retCount === 1) {
            assignReg(ins.a, atomExpr(callCode, { kind: 'call', prec: 90, singleReturn: singleRet, calleeName: fnExpr.calleeName }), i, out, lvl);
          } else {
            const names: string[] = [];
            for (let r = 0; r < retCount; r++) {
              const targetR = ins.a + r;
              const nm = buildSemanticName(undefined, 'v', usedNames, env.opts, env.metrics);
              declaredLocals.set(targetR, nm);
              regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR }));
              names.push(nm);
            }
            out.push(`${indent(lvl)}local ${names.join(', ')} = ${callCode}`);
          }
          i++;
          break;
        }

        case 'VARARG': {
          if (ins.c === 0) {
            regExpr.set(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }));
            multretReg = ins.a;
          } else if (ins.c === 2) {
            assignReg(ins.a, atomExpr('...', { kind: 'vararg', prec: 100 }), i, out, lvl);
          } else if (ins.c > 2) {
            const count = ins.c - 1;
            const names: string[] = [];
            for (let r = 0; r < count; r++) {
              const targetR = ins.a + r;
              const nm = buildSemanticName(undefined, 'arg', usedNames, env.opts, env.metrics);
              declaredLocals.set(targetR, nm);
              regExpr.set(targetR, atomExpr(nm, { kind: 'ident', isVarRef: true, regOrigin: targetR }));
              names.push(nm);
            }
            out.push(`${indent(lvl)}local ${names.join(', ')} = ...`);
          }
          i++;
          break;
        }

        case 'RETURN0':
          if (i < endIdx - 1) out.push(`${indent(lvl)}return`);
          i++;
          break;

        case 'RETURN1': {
          const val = getReg(ins.a);
          let code = val.code;
          const isMultiCapable = val.kind === 'call' || val.kind === 'methodCall' || val.kind === 'vararg';
          if (isMultiCapable && val.singleReturn && env.opts.pruneReturnParens) {
            env.metrics.returnParensPruned++;
          } else if (isMultiCapable && !val.singleReturn) {
            code = `(${code})`;
          }
          out.push(`${indent(lvl)}return ${code}`);
          i++;
          break;
        }

        case 'RETURN': {
          const retCount = ins.b === 0 ? -1 : ins.b - 1;
          if (retCount === 0) {
            if (i < endIdx - 1) out.push(`${indent(lvl)}return`);
          } else if (retCount === 1) {
            const val = getReg(ins.a);
            let code = val.code;
            const isMultiCapable = val.kind === 'call' || val.kind === 'methodCall' || val.kind === 'vararg';
            if (isMultiCapable && val.singleReturn && env.opts.pruneReturnParens) {
              env.metrics.returnParensPruned++;
            } else if (isMultiCapable && !val.singleReturn) {
              code = `(${code})`;
            }
            out.push(`${indent(lvl)}return ${code}`);
          } else if (retCount > 1) {
            const vals: string[] = [];
            for (let r = 0; r < retCount; r++) {
              const v = getReg(ins.a + r);
              const isLast = r === retCount - 1;
              const isMultiCapable = v.kind === 'call' || v.kind === 'methodCall' || v.kind === 'vararg';
              vals.push(isLast && isMultiCapable && !v.singleReturn ? `(${v.code})` : v.code);
            }
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          } else {
            const endR = multretReg !== null && multretReg >= ins.a ? multretReg : ins.a;
            const vals: string[] = [];
            for (let r = ins.a; r <= endR; r++) vals.push(getReg(r).code);
            multretReg = null;
            out.push(`${indent(lvl)}return ${vals.join(', ')}`);
          }
          i++;
          break;
        }

        default:
          i++;
          break;
      }
    }
    return out;
  }

  if (isTopLevel) {
    return liftRange(0, insns.length, indentLevel);
  }
  const sig = `${paramNames.join(', ')}${proto.isVararg ? (paramNames.length ? ', ...' : '...') : ''}`;
  const body: string[] = [];
  if (env.opts.lineInfoMode !== 'NONE' && proto.lineDefined > 0) {
    body.push(`${indent(indentLevel + 1)}-- line: ${proto.lineDefined}`);
  }
  if (env.opts.upvalueComments && inheritedUpvalues.length > 0) {
    const visibleUpvals = inheritedUpvalues.filter((u) => u.name !== '_ENV');
    if (visibleUpvals.length > 0) {
      body.push(`${indent(indentLevel + 1)}-- upvalues: ${visibleUpvals.map((u) => `${u.name} (${u.mode})`).join(', ')}`);
    }
  }
  body.push(...liftRange(0, insns.length, indentLevel + 1));
  return [`function(${sig})`, ...body, `${indent(indentLevel)}end`];
}

export function buildDisassembly(chunk: ParsedChunk): DisassembledProto[] {
  return chunk.protos.map((p) => ({
    id: p.id,
    name: p.debugName || (p.id === chunk.mainProtoId ? '<main>' : `<proto_${p.id}>`),
    numParams: p.numParams,
    numUpvalues: p.numUpvalues,
    isVararg: p.isVararg,
    maxStackSize: p.maxStackSize,
    constants: p.constants.map((c, idx) => `K${idx}: ${formatConstantShort(c)}`),
    instructions: p.instructions.map((ins) => {
      let operands: string;
      if (chunk.dialect === 'luau') {
        operands = ins.aux !== undefined
          ? `A=${ins.a} B=${ins.b} C=${ins.c} D=${ins.d} AUX=0x${ins.aux.toString(16)}`
          : `A=${ins.a} B=${ins.b} C=${ins.c} D=${ins.d}`;
      } else if (chunk.dialect === 'lua54') {
        if (ins.opname === 'JMP') operands = `sJ=${ins.d}`;
        else if (['LOADI', 'LOADF'].includes(ins.opname)) operands = `A=${ins.a} sBx=${ins.d}`;
        else if (['LOADK', 'CLOSURE', 'FORPREP', 'FORLOOP', 'TFORPREP', 'TFORLOOP'].includes(ins.opname)) operands = `A=${ins.a} Bx=${ins.bx}`;
        else operands = `A=${ins.a} B=${ins.b} C=${ins.c}${ins.aux ? ' k=1' : ''}`;
      } else {
        operands = ins.bx !== undefined && ['LOADK', 'GETGLOBAL', 'SETGLOBAL', 'CLOSURE'].includes(ins.opname)
          ? `A=${ins.a} Bx=${ins.bx}`
          : ['JMP', 'FORLOOP', 'FORPREP'].includes(ins.opname)
            ? `A=${ins.a} sBx=${ins.d}`
            : `A=${ins.a} B=${ins.b} C=${ins.c}`;
      }
      return {
        pc: ins.pc,
        opname: ins.opname,
        operands,
        comment: ins.comment,
      };
    }),
  }));
}

function measureNestingDepth(lines: string[]): number {
  let maxDepth = 0;
  for (const line of lines) {
    if (!line.trim()) continue;
    const leadingSpaces = line.length - line.trimStart().length;
    const depth = Math.floor(leadingSpaces / 4);
    if (depth > maxDepth) maxDepth = depth;
  }
  return maxDepth;
}

export const REQUIRED_OPLIFT_HEADER = '-- https://oplift.ai.studio';

export function applyRequiredHeader(bodyLines: string[]): string {
  const filtered: string[] = [];
  for (const line of bodyLines) {
    if (line.trim() === REQUIRED_OPLIFT_HEADER) continue;
    filtered.push(line);
  }
  while (filtered.length > 0 && filtered[0].trim() === '') {
    filtered.shift();
  }
  while (filtered.length > 0 && filtered[filtered.length - 1].trim() === '') {
    filtered.pop();
  }
  if (filtered.length === 0) {
    return `${REQUIRED_OPLIFT_HEADER}\n\n`;
  }
  return `${REQUIRED_OPLIFT_HEADER}\n\n${filtered.join('\n')}\n`;
}

// Rule 3.4: Fold 3-statement swap / parallel-update patterns through a dead temp into multi-assignment:
//   `local t = b; b = a + b; a = t` -> `a, b = b, a + b`
//   `local t = p; p = q; q = t`     -> `p, q = q, p`
function foldSwapMultiAssignments(lines: string[]): string[] {
  const out = [...lines];
  const isIdent = (s: string) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
  const blockOpenerRe = /^(?:do|repeat|else)\b|\bthen$|\bdo$|function\s*(?:[A-Za-z_][A-Za-z0-9_.:]*)?\([^)]*\)(?:\s*:\s*[^\s]+)?$/;
  const blockCloserRe = /^(?:end|else|elseif\b|until\b)/;

  for (let i = 0; i + 2 < out.length; i++) {
    const m0 = out[i].match(/^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (!m0) continue;
    const [, pad, tempVar, rhs1] = m0;
    if (!isIdent(tempVar) || !isIdent(rhs1) || tempVar === rhs1) continue;

    if (!out[i + 1].startsWith(pad) || !out[i + 2].startsWith(pad)) continue;
    const s1 = out[i + 1].slice(pad.length);
    const s2 = out[i + 2].slice(pad.length);
    if (/^\s/.test(s1) || /^\s/.test(s2)) continue;

    const m1 = s1.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
    const m2 = s2.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (!m1 || !m2) continue;

    const [, target1, rhs2Raw] = m1;
    const [, target2, rhs3] = m2;
    const rhs2 = rhs2Raw.trim();
    if (target1 !== rhs1 || rhs3 !== tempVar) continue;
    if (target2 === target1 || target2 === tempVar) continue;
    if (exprReferencesIdent(rhs2, tempVar)) continue;
    if (/^(?:function\b|if\b)/.test(rhs2)) continue;

    // Verify `tempVar` is dead after line i + 2 until the enclosing block closes or redeclares `local tempVar`
    let depth = 0;
    let tempReadLater = false;
    for (let k = i + 3; k < out.length; k++) {
      const tr = out[k].trim();
      if (!tr || tr.startsWith('--')) continue;
      if (blockCloserRe.test(tr) && !/\bend$/.test(tr.replace(/^(?:end|else|elseif\b|until\b)\s*/, ''))) {
        if (depth === 0) break;
        if (tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) {
          depth--;
        }
      } else if (/^local\s+/.test(tr) && depth === 0) {
        const declNames = tr.slice(6).split('=')[0].split(',').map((s) => s.trim());
        if (declNames.includes(tempVar)) break;
      }
      if (exprReferencesIdent(tr, tempVar)) {
        tempReadLater = true;
        break;
      }
      if (blockOpenerRe.test(tr) && !/\bend$/.test(tr)) {
        depth++;
      } else if ((tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) && depth > 0) {
        depth--;
      }
    }
    if (tempReadLater) continue;

    out.splice(i, 3, `${pad}${target2}, ${target1} = ${target1}, ${rhs2}`);
  }
  return out;
}

// Rule 3.8: Leave 1 blank line between logical blocks (after functions, before and after loops, before trailing return),
// never right after block openers or right before `end`, and collapse multiple blank lines to 1.
function formatDecompiledLayout(lines: string[], opts: DecompileOptions): string[] {
  if (!opts.emitBlankLines) {
    return lines.filter((l) => l.trim().length > 0);
  }

  const isMultiLineOpener = (t: string): 'function' | 'loop' | 'other' | null => {
    if (!t || t.startsWith('--')) return null;
    if (t === 'do' || t === 'else') return 'other';
    if (t === 'repeat') return 'loop';
    if (/^(?:for|while)\b/.test(t) && /\bdo$/.test(t) && !/\bend$/.test(t)) return 'loop';
    if (/\bthen$/.test(t) && !/\bend$/.test(t)) return 'other';
    if (/\bdo$/.test(t) && !/\bend$/.test(t)) return 'other';
    if (/(?:^|\s|=|\(|,\s*)function(?:\s+[A-Za-z_][A-Za-z0-9_.:]*)?\([^)]*\)/.test(t) && !/\bend\b/.test(t)) {
      return 'function';
    }
    if (/\{$/.test(t)) return 'other';
    return null;
  };

  const isCloser = (t: string) =>
    t === 'end' ||
    t.startsWith('end,') ||
    t.startsWith('end)') ||
    t === 'else' ||
    t.startsWith('elseif ') ||
    t.startsWith('until ') ||
    t === '}' ||
    t === '},' ||
    t === '})';

  const isHeaderMeta = (t: string) => t.startsWith('-- line:') || t.startsWith('-- upvalues:');

  const cleaned: string[] = [];
  const blockStack: Array<{ kind: 'function' | 'loop' | 'other'; stmtCount: number }> = [{ kind: 'other', stmtCount: 0 }];

  const pushBlankIfNeeded = () => {
    if (cleaned.length === 0) return;
    const prev = cleaned[cleaned.length - 1].trim();
    if (prev === '' || isMultiLineOpener(prev) !== null || isHeaderMeta(prev) || prev.startsWith('-- ')) return;
    cleaned.push('');
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx];
    const t = raw.trim();

    if (t === '') {
      pushBlankIfNeeded();
      continue;
    }

    // Never leave a blank line right before a closer
    if (isCloser(t)) {
      while (cleaned.length > 0 && cleaned[cleaned.length - 1].trim() === '') {
        cleaned.pop();
      }
    }

    const openedKind = isMultiLineOpener(t);
    if (openedKind === 'loop' || (openedKind === 'function' && /^local\s+function\b|^function\s+[A-Za-z_]/.test(t))) {
      pushBlankIfNeeded();
    } else if ((t === 'return' || t.startsWith('return ')) && cleaned.length > 0) {
      const topBlock = blockStack[blockStack.length - 1];
      const prev = cleaned[cleaned.length - 1].trim();
      if (topBlock && (topBlock.stmtCount >= 2 || prev === 'end' || prev.startsWith('until '))) {
        pushBlankIfNeeded();
      }
    }

    cleaned.push(raw);

    // Maintain block stack & statement counters
    let closedKind: 'function' | 'loop' | 'other' | null = null;
    if (t === 'end' || t.startsWith('end,') || t.startsWith('end)') || t.startsWith('until ') || t === '}' || t === '},' || t === '})') {
      if (blockStack.length > 1) {
        closedKind = blockStack.pop()!.kind;
      }
      blockStack[blockStack.length - 1].stmtCount++;
    } else if (t === 'else' || t.startsWith('elseif ')) {
      blockStack[blockStack.length - 1].stmtCount = 0;
    } else if (openedKind !== null) {
      blockStack[blockStack.length - 1].stmtCount++;
      blockStack.push({ kind: openedKind, stmtCount: 0 });
    } else if (!t.startsWith('--')) {
      blockStack[blockStack.length - 1].stmtCount++;
    }

    // Blank line after closing `end` of a multi-line function or loop (or `until ...`), unless followed by a closer
    if (closedKind === 'function' || closedKind === 'loop') {
      let nextNonBlank = '';
      for (let k = idx + 1; k < lines.length; k++) {
        if (lines[k].trim() !== '') {
          nextNonBlank = lines[k].trim();
          break;
        }
      }
      if (nextNonBlank && !isCloser(nextNonBlank)) {
        cleaned.push('');
      }
    }
  }

  while (cleaned.length > 0 && cleaned[cleaned.length - 1].trim() === '') {
    cleaned.pop();
  }
  return cleaned;
}

export function decompileBytesDirect(
  bytes: Uint8Array,
  partialOpts?: Partial<DecompileOptions>,
  extras?: { includeDisassembly?: boolean }
): DecompileResult {
  const t0 = performance.now();
  const opts: DecompileOptions = { ...DEFAULT_DECOMPILE_OPTIONS, ...(partialOpts ?? {}) };
  const parsed = parseAnyBytecode(bytes, opts.autoDecodeRoblox227);
  const diagnostics: ParseDiagnostic[] = [...parsed.diagnostics];

  if (!parsed.chunk || parsed.chunk.protos.length === 0) {
    const errMsg = diagnostics[0]?.message ? `-- ${diagnostics[0].code}: ${diagnostics[0].message}` : '-- Failed to parse bytecode.';
    return {
      ok: false,
      source: applyRequiredHeader([errMsg]),
      dialect: parsed.dialect,
      version: parsed.chunk?.version,
      versionLabel: parsed.chunk?.versionLabel,
      encoding: parsed.chunk?.encoding,
      timingMs: Number((performance.now() - t0).toFixed(2)),
      diagnostics,
      imports: [],
      strings: parsed.chunk?.stringTable ?? [],
    };
  }

  const chunk = parsed.chunk;
  const returnArities = computeProtoReturnArities(chunk);
  const totalInsns = chunk.protos.reduce((acc, p) => acc + p.instructions.length, 0);

  const metrics: DecompileMetrics = {
    instructionCount: totalInsns,
    protoCount: chunk.protos.length,
    outputLines: 0,
    maxNestingDepth: 0,
    constantsFolded: 0,
    deadBranchesEliminated: 0,
    continuesRecovered: 0,
    breaksRecovered: 0,
    tablesFolded: 0,
    returnParensPruned: 0,
    syntheticPhiTempsAvoided: 0,
    semanticNamesInferred: 0,
  };

  const imports = new Set<string>();
  const env: LiftEnv = { chunk, opts, metrics, returnArities, imports, diagnostics };
  const mainProto = chunk.protos[chunk.mainProtoId];

  const rawLines =
    chunk.dialect === 'luau'
      ? decompileLuauProto(mainProto, env, 0, [], true)
      : chunk.dialect === 'lua54'
        ? decompileLua54Proto(mainProto, env, 0, [], true)
        : decompileLua51Proto(mainProto, env, 0, [], true);

  const flatRawLines = rawLines.flatMap((line) => line.split('\n'));
  const foldedLines = runReadabilityPasses(flatRawLines, opts);
  const formattedLines = formatDecompiledLayout(foldedLines, opts);

  const bodyLines: string[] = [];
  if (opts.emitHeader) {
    bodyLines.push(`-- Decompiled by OpLift (${chunk.versionLabel}, ${chunk.encoding})`);
  }
  bodyLines.push(...formattedLines);

  const source = applyRequiredHeader(bodyLines);
  const finalLines = source.split('\n');
  metrics.outputLines = finalLines.filter((l) => l.trim().length > 0).length;
  metrics.maxNestingDepth = measureNestingDepth(finalLines);

  const protosSummary = chunk.protos.map((p) => ({
    id: p.id,
    name: p.debugName || (p.id === chunk.mainProtoId ? '<main>' : `<proto_${p.id}>`),
    params: p.numParams,
    upvalues: p.numUpvalues,
    instructions: p.instructions.length,
    constants: p.constants.length,
    returnArity: returnArities.get(p.id) ?? 0,
  }));

  return {
    ok: true,
    source,
    dialect: chunk.dialect,
    version: chunk.version,
    versionLabel: chunk.versionLabel,
    encoding: chunk.encoding,
    timingMs: Number((performance.now() - t0).toFixed(2)),
    metrics,
    diagnostics,
    imports: Array.from(imports),
    strings: chunk.stringTable,
    protosSummary,
    disassembly: extras?.includeDisassembly ? buildDisassembly(chunk) : undefined,
  };
}

export function decompileBytecode(
  scriptInput: string,
  partialOpts?: Partial<DecompileOptions>,
  extras?: { includeDisassembly?: boolean }
): DecompileResult {
  const t0 = performance.now();
  const decoded = decodeInputBytes(scriptInput);
  if (decoded.error || !decoded.bytes) {
    const errMsg = decoded.error ? `-- ${decoded.error.code}: ${decoded.error.message}` : '-- Failed to decode input bytes.';
    return {
      ok: false,
      source: applyRequiredHeader([errMsg]),
      dialect: 'unknown',
      timingMs: Number((performance.now() - t0).toFixed(2)),
      diagnostics: [decoded.error!],
      imports: [],
      strings: [],
    };
  }
  return decompileBytesDirect(decoded.bytes, partialOpts, extras);
}

export function inspectBytecode(scriptInput: string): {
  ok: boolean;
  dialect: string;
  version?: number;
  versionLabel?: string;
  encoding?: string;
  rawByteLength?: number;
  headerInfo?: Record<string, string | number | boolean>;
  strings: string[];
  imports: string[];
  protosSummary?: DecompileResult['protosSummary'];
  diagnostics: ParseDiagnostic[];
  timingMs: number;
} {
  const t0 = performance.now();
  const decoded = decodeInputBytes(scriptInput);
  if (decoded.error || !decoded.bytes) {
    return {
      ok: false,
      dialect: 'unknown',
      strings: [],
      imports: [],
      diagnostics: [decoded.error!],
      timingMs: Number((performance.now() - t0).toFixed(2)),
    };
  }
  const parsed = parseAnyBytecode(decoded.bytes, true);
  if (!parsed.chunk) {
    return {
      ok: false,
      dialect: parsed.dialect,
      rawByteLength: decoded.bytes.length,
      strings: [],
      imports: [],
      diagnostics: parsed.diagnostics,
      timingMs: Number((performance.now() - t0).toFixed(2)),
    };
  }
  const chunk = parsed.chunk;
  const imports = new Set<string>();
  for (const p of chunk.protos) {
    for (const c of p.constants) {
      if (c.kind === 'import' && c.importPath) imports.add(c.importPath.join('.'));
    }
    if (chunk.dialect === 'lua51') {
      for (const ins of p.instructions) {
        if (ins.opname === 'GETGLOBAL') {
          const k = p.constants[ins.bx ?? 0];
          if (k?.kind === 'string') imports.add(String(k.value));
        }
      }
    } else if (chunk.dialect === 'lua54') {
      for (const ins of p.instructions) {
        if (ins.opname === 'GETTABUP' && ins.b === 0) {
          const k = p.constants[ins.c];
          if (k?.kind === 'string') imports.add(String(k.value));
        }
      }
    }
  }
  const arities = computeProtoReturnArities(chunk);
  return {
    ok: true,
    dialect: chunk.dialect,
    version: chunk.version,
    versionLabel: chunk.versionLabel,
    encoding: chunk.encoding,
    rawByteLength: chunk.rawByteLength,
    headerInfo: chunk.headerInfo,
    strings: chunk.stringTable,
    imports: Array.from(imports),
    protosSummary: chunk.protos.map((p) => ({
      id: p.id,
      name: p.debugName || (p.id === chunk.mainProtoId ? '<main>' : `<proto_${p.id}>`),
      params: p.numParams,
      upvalues: p.numUpvalues,
      instructions: p.instructions.length,
      constants: p.constants.length,
      returnArity: arities.get(p.id) ?? 0,
    })),
    diagnostics: parsed.diagnostics,
    timingMs: Number((performance.now() - t0).toFixed(2)),
  };
}
