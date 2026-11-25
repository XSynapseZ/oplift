import { useState } from 'react';
import { Play, Copy, Check, Code2, Binary, AlertTriangle } from 'lucide-react';
import type { CleanlinessScore, DecompileMetrics, DisassembledProto, ParseDiagnostic } from '../engine/types.ts';
import { LuauCodeBlock, LuauCodeEditor } from './LuauCodeBlock.tsx';

function formatDisassembly(disasm: string | DisassembledProto[] | undefined): string {
  if (!disasm) return '';
  if (typeof disasm === 'string') return disasm;
  return disasm
    .map((p) => {
      const hdr = `-- proto #${p.id} (${p.name || 'anonymous'}, params=${p.numParams}, upvals=${p.numUpvalues}, stack=${p.maxStackSize})`;
      const body = p.instructions
        .map((l) => `  ${String(l.pc).padStart(4, '0')}  ${l.opname.padEnd(16, ' ')} ${l.operands}${l.comment ? `  ; ${l.comment}` : ''}`)
        .join('\n');
      return `${hdr}\n${body}`;
    })
    .join('\n\n');
}

interface CompareResponse {
  ok: boolean;
  mode: 'source' | 'bytecode';
  compilerVersion?: string | null;
  optLevel?: number | null;
  debugLevel?: number | null;
  compiledBase64?: string;
  compiledBytes?: number;
  compileTimingMs?: number | null;
  compileError?: string;
  error?: string;
  oplift?: {
    ok: boolean;
    dialect: string;
    versionLabel?: string;
    encoding?: string;
    source?: string;
    disassembly?: string | DisassembledProto[];
    timingMs: number;
    metrics?: DecompileMetrics;
    diagnostics: ParseDiagnostic[];
    score: CleanlinessScore;
  };
  luaExpertV2?: {
    reachable: boolean;
    status: number;
    timingMs: number;
    output: string;
    score: CleanlinessScore;
  };
}

interface ComparePreset {
  id: string;
  label: string;
  source: string;
}

const COMPARE_PRESETS: ComparePreset[] = [
  {
    id: 'closures',
    label: 'Mutable Closures',
    source: `local function makeAccount(initial)
    local balance = initial
    local ops = 0

    local function logOp(delta)
        ops += 1
        balance += delta
        return balance
    end

    return {
        deposit = function(amount)
            if amount <= 0 then
                return false, balance
            end
            return true, logOp(amount)
        end,
        withdraw = function(amount)
            if amount <= 0 or amount > balance then
                return false, balance
            end
            return true, logOp(-amount)
        end,
        snapshot = function()
            return balance, ops
        end,
    }
end

local acc = makeAccount(100)
print(acc.deposit(45))
print(acc.withdraw(30))
print(acc.snapshot())`,
  },
  {
    id: 'loops',
    label: 'Continue / Repeat / While',
    source: `local function analyzeRange(limit)
    local sum = 0
    for i = 1, limit do
        if i % 3 == 0 then
            continue
        end
        if i * i > 180 then
            break
        end
        sum += i
    end

    local steps = 0
    local n = sum
    repeat
        if n % 2 == 0 then
            n //= 2
        else
            n = n * 3 + 1
        end
        steps += 1
    until n == 1 or steps >= 25

    return sum, steps, n
end

print(analyzeRange(20))`,
  },
  {
    id: 'metatable',
    label: 'Metatable OOP',
    source: `local Vec2 = {}
Vec2.__index = Vec2

function Vec2.new(x, y)
    return setmetatable({ x = x, y = y }, Vec2)
end

function Vec2:dot(other)
    return self.x * other.x + self.y * other.y
end

function Vec2.__add(a, b)
    return Vec2.new(a.x + b.x, a.y + b.y)
end

local a = Vec2.new(3, 4)
local b = Vec2.new(1, -2)
local c = a + b
print(c.x, c.y, c:dot(a))`,
  },
  {
    id: 'fastcalls',
    label: 'bit32 & Ternary',
    source: `local function pack(value, flags)
    local clamped = math.clamp(math.floor(value), 0, 255)
    local tag = if clamped >= 128 then "high" else "low"
    local packed = bit32.bor(bit32.lshift(clamped, 4), bit32.band(flags, 0xF))
    return tag, packed, bit32.rshift(packed, 4)
end

print(pack(190.8, 0x2B))`,
  },
  {
    id: 'lexical-scope',
    label: 'Lexical Scope & Branches',
    source: `local function computeBonus(mode, x, result)
    local picked = 10
    if mode == "boost" then
        local step = x * 2 + 1
        picked = step * 3
    elseif mode == "safe" then
        picked = x + 5
    end
    if picked > 25 then
        picked -= 4
    end
    local value = picked + result
    return value, picked
end

print(computeBonus("boost", 6, 100))
print(computeBonus("safe", 6, 100))
print(computeBonus("none", 6, 100))`,
  },
];

function scoreTone(score: number): string {
  if (score >= 85) return 'text-emerald-400';
  if (score >= 65) return 'text-amber-400';
  return 'text-red-400';
}

export function ComparisonPlayground() {
  const [mode, setMode] = useState<'source' | 'bytecode'>('source');
  const [sourceInput, setSourceInput] = useState<string>(COMPARE_PRESETS[0].source);
  const [bytecodeInput, setBytecodeInput] = useState<string>('');
  const [optLevel, setOptLevel] = useState<0 | 1 | 2>(1);
  const [debugLevel, setDebugLevel] = useState<0 | 1 | 2>(1);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<CompareResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [showDisasm, setShowDisasm] = useState<boolean>(false);
  const [copiedTarget, setCopiedTarget] = useState<'b64' | 'oplift' | 'v2' | null>(null);

  function copyText(text: string, target: 'b64' | 'oplift' | 'v2') {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopiedTarget(target);
    setTimeout(() => setCopiedTarget(null), 1600);
  }

  async function handleRunCompare() {
    const payloadInput = mode === 'source' ? sourceInput : bytecodeInput;
    if (!payloadInput.trim()) {
      setErrorMsg(mode === 'source' ? 'Enter Luau source code first.' : 'Paste Base64 or Hex bytecode first.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setShowDisasm(false);
    try {
      const res = await fetch('/api/v1/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          input: payloadInput,
          optLevel,
          debugLevel,
        }),
      });
      const data = (await res.json()) as CompareResponse;
      if (!data.ok) {
        setErrorMsg(data.compileError ?? data.error ?? `Comparison failed (HTTP ${res.status})`);
        setResult(null);
      } else {
        setResult(data);
        if (mode === 'source' && data.compiledBase64) {
          setBytecodeInput(data.compiledBase64);
        }
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Network error calling /api/v1/compare');
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-5">
      {/* Input & Compiler Controls */}
      <section className="panel-surface rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#202026] flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex items-center bg-[#0C0C0E] border border-[#202026] rounded-md p-0.5">
            <button
              type="button"
              onClick={() => setMode('source')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'source' ? 'bg-zinc-800 text-zinc-50' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Luau Source</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('bytecode')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                mode === 'bytecode' ? 'bg-zinc-800 text-zinc-50' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Bytecode</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {mode === 'source' && (
              <>
                <label className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
                  <span>Opt</span>
                  <select
                    value={optLevel}
                    onChange={(e) => setOptLevel(Number(e.target.value) as 0 | 1 | 2)}
                    className="bg-[#0C0C0E] border border-[#202026] rounded px-2 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-emerald-500"
                  >
                    <option value={0}>-O0</option>
                    <option value={1}>-O1</option>
                    <option value={2}>-O2</option>
                  </select>
                </label>

                <label className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
                  <span>Debug</span>
                  <select
                    value={debugLevel}
                    onChange={(e) => setDebugLevel(Number(e.target.value) as 0 | 1 | 2)}
                    className="bg-[#0C0C0E] border border-[#202026] rounded px-2 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-emerald-500"
                  >
                    <option value={0}>-g0</option>
                    <option value={1}>-g1</option>
                    <option value={2}>-g2</option>
                  </select>
                </label>
              </>
            )}

            {result?.ok && result.compiledBase64 && (
              <button
                type="button"
                onClick={() => copyText(result.compiledBase64 ?? '', 'b64')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#202026] hover:border-zinc-600 bg-[#0C0C0E] text-xs font-medium text-zinc-300 hover:text-zinc-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                title={result.compiledBytes ? `${result.compiledBytes} bytes compiled` : undefined}
              >
                {copiedTarget === 'b64' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedTarget === 'b64' ? 'Copied Base64' : `Copy Base64 (${result.compiledBytes ?? 0}B)`}</span>
              </button>
            )}

            <button
              type="button"
              disabled={loading}
              onClick={() => void handleRunCompare()}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 active:scale-[0.99] disabled:opacity-60 text-[#03120B] text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{loading ? 'Comparing…' : 'Compare'}</span>
            </button>
          </div>
        </div>

        {mode === 'source' && (
          <div className="px-4 py-2 border-b border-[#202026] bg-[#0C0C0E]/60 flex flex-wrap items-center gap-2">
            <span className="text-xs text-zinc-500 mr-1">Presets</span>
            {COMPARE_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => setSourceInput(preset.source)}
                className="px-2.5 py-1 rounded border border-[#202026] hover:border-zinc-600 bg-[#111114] text-xs text-zinc-300 hover:text-zinc-100 transition-colors whitespace-nowrap cursor-pointer"
              >
                {preset.label}
              </button>
            ))}
          </div>
        )}

        <div className="p-4">
          {mode === 'source' ? (
            <LuauCodeEditor
              value={sourceInput}
              onChange={setSourceInput}
              rows={11}
              placeholder="Write Luau source code here..."
            />
          ) : (
            <textarea
              value={bytecodeInput}
              onChange={(e) => setBytecodeInput(e.target.value)}
              spellCheck={false}
              rows={6}
              placeholder="Paste Base64 or Hex encoded Luau / Lua bytecode..."
              className="w-full code-well rounded-md p-3.5 text-xs font-mono text-zinc-100 leading-6 focus:border-emerald-500/70 focus:outline-none resize-y break-all"
            />
          )}
        </div>

        {errorMsg && (
          <div className="mx-4 mb-4 p-3.5 rounded-md bg-red-950/35 border border-red-900/70 flex items-start gap-2.5 text-xs text-red-200">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <pre className="font-mono whitespace-pre-wrap break-words flex-1">{errorMsg}</pre>
          </div>
        )}
      </section>

      {/* Side-by-Side Results */}
      {result?.ok && result.oplift && result.luaExpertV2 && (
        <section className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Left Pane: OpLift */}
          <div className="panel-surface rounded-lg overflow-hidden flex flex-col border-emerald-500/35">
            <div className="px-4 py-3 border-b border-[#202026] flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-zinc-50 truncate">OpLift</div>
                <div className="text-[11px] font-mono text-zinc-400 truncate tabular-nums">
                  {result.oplift.versionLabel ?? result.oplift.dialect} · {result.oplift.timingMs} ms
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <span className={`text-sm font-mono font-bold tabular-nums ${scoreTone(result.oplift.score.score)}`}>
                  {result.oplift.score.score}/100
                </span>
                <button
                  type="button"
                  onClick={() => copyText(result.oplift?.source ?? '', 'oplift')}
                  className="p-1.5 rounded border border-[#202026] hover:border-zinc-600 text-zinc-300 hover:text-zinc-100 cursor-pointer"
                  title="Copy OpLift output"
                >
                  {copiedTarget === 'oplift' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {result.oplift.disassembly && (
              <div className="px-4 py-2 border-b border-[#202026] flex items-center justify-between text-xs">
                <div className="flex items-center gap-4">
                  <button
                    type="button"
                    onClick={() => setShowDisasm(false)}
                    className={`font-medium cursor-pointer ${!showDisasm ? 'text-emerald-400' : 'text-zinc-400 hover:text-zinc-200'}`}
                  >
                    Decompiled
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowDisasm(true)}
                    className={`font-medium cursor-pointer ${showDisasm ? 'text-emerald-400' : 'text-zinc-400 hover:text-zinc-200'}`}
                  >
                    Disassembly
                  </button>
                </div>
                {result.oplift.metrics && (
                  <span className="font-mono text-[11px] tabular-nums text-zinc-500">
                    {result.oplift.metrics.instructionCount} insns · {result.oplift.metrics.protoCount} protos
                  </span>
                )}
              </div>
            )}

            <LuauCodeBlock
              code={
                showDisasm
                  ? formatDisassembly(result.oplift.disassembly)
                  : result.oplift.ok
                    ? (result.oplift.source ?? '')
                    : result.oplift.diagnostics.map((d) => `[${d.code}] ${d.message}`).join('\n') || 'Decompilation failed.'
              }
              language={showDisasm ? 'disasm' : result.oplift.ok ? 'luau' : 'plain'}
              showLineNumbers={!showDisasm && result.oplift.ok}
              className="flex-1 bg-[#0C0C0E] p-4 text-[13px] leading-[1.65] min-h-[340px] max-h-[640px] overflow-y-auto"
            />
          </div>

          {/* Right Pane: lua.expert v2 */}
          <div className="panel-surface rounded-lg overflow-hidden flex flex-col">
            <div className="px-4 py-3 border-b border-[#202026] flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-zinc-50 truncate">lua.expert v2</div>
                <div className="text-[11px] font-mono text-zinc-400 truncate tabular-nums">
                  HTTP {result.luaExpertV2.status || 'ERR'} · {result.luaExpertV2.timingMs} ms
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <span className={`text-sm font-mono font-bold tabular-nums ${scoreTone(result.luaExpertV2.score.score)}`}>
                  {result.luaExpertV2.score.score}/100
                </span>
                <button
                  type="button"
                  onClick={() => copyText(result.luaExpertV2?.output ?? '', 'v2')}
                  className="p-1.5 rounded border border-[#202026] hover:border-zinc-600 text-zinc-300 hover:text-zinc-100 cursor-pointer"
                  title="Copy lua.expert v2 output"
                >
                  {copiedTarget === 'v2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="px-4 py-2 border-b border-[#202026] flex items-center justify-between text-xs text-zinc-400">
              <span>api.lua.expert/v1/decompile</span>
              <span className="font-mono text-[11px] tabular-nums text-zinc-500">
                {result.luaExpertV2.score.lines} lines
              </span>
            </div>

            <LuauCodeBlock
              code={result.luaExpertV2.output || '-- Empty response'}
              language={result.luaExpertV2.status === 200 ? 'luau' : 'plain'}
              showLineNumbers={result.luaExpertV2.status === 200}
              className="flex-1 bg-[#0C0C0E] p-4 text-[13px] leading-[1.65] min-h-[340px] max-h-[640px] overflow-y-auto"
            />
          </div>
        </section>
      )}
    </div>
  );
}
