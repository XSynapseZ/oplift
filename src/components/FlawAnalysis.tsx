import { LuauCodeBlock } from './LuauCodeBlock.tsx';

interface FlawEntry {
  number: string;
  title: string;
  severity: 'High' | 'Medium';
  methodAnalyzed: string;
  observedV2: string;
  opliftFix: string;
  rootCause: string;
}

const VERIFIED_FLAWS: FlawEntry[] = [
  {
    number: '01',
    title: 'SSA Phi-Destruction Emits Bogus Temporaries and Dead Elseif Branches',
    severity: 'High',
    methodAnalyzed: 'SSA lifting & register coalescing (registerCoalescingThreshold: 190)',
    observedV2: `local v1\nif n1 % 2 == 0 then\n    v1 = n2 + n1\nelseif n1 <= 50 then\n    v1 = n2\nelse\n    break\nend\nn2 = v1`,
    opliftFix: `if i % 2 == 0 then\n    total += i\nelseif i > 50 then\n    break\nend`,
    rootCause:
      'When an outer loop accumulator is mutated in one branch and untouched in another that merges back to the loop latch, lua.expert v2 lowers the SSA phi node into a synthetic `local v1`, invents a dead `elseif n1 <= 50 then v1 = n2` copy branch, and destroys the `+=` compound assignment. OpLift tracks loop-carried mutable locals directly and mutates them in place without phi materialization.',
  },
  {
    number: '02',
    title: 'Continue Virtualization Fails on Standard Loop Guard Clauses',
    severity: 'High',
    methodAnalyzed: 'CFG latch detection (virtualizeContinue: true default)',
    observedV2: `for i = 1, 20 do\n    if i ~= 5 then\n        if i == 15 then\n            break\n        end\n        n1 += i * 2\n    end\nend`,
    opliftFix: `for i = 1, 20 do\n    if i == 5 then\n        continue\n    end\n    if i == 15 then\n        break\n    end\n    total += i * 2\nend`,
    rootCause:
      'Even with `virtualizeContinue: true` enabled by default, v2 treats a conditional skip around a jump-to-FORNLOOP as an inverted `if i ~= 5 then ... end` block instead of a guard-clause `continue`. In real game loops with 3–5 early guards, indentation balloons rapidly. OpLift matches conditional jumps over loop-latch targets first and emits flat `continue` guards.',
  },
  {
    number: '03',
    title: 'Early-Return If / Elseif / Else Ladders Get Inverted',
    severity: 'Medium',
    methodAnalyzed: 'Dominator-tree branch structuring',
    observedV2: `if v1 <= 10 then\n    if v1 < 0 then\n        return -v1, 0\n    end\n    return 0, 0\nend\nreturn v1 * 2, v1 + 1`,
    opliftFix: `if value > 10 then\n    return value * 2, value + 1\nelseif value < 0 then\n    return -value, 0\nelse\n    return 0, 0\nend`,
    rootCause:
      'Because Luau emits `JUMPIFLE` to jump past the `then` body when `value > 10` is false, v2’s branch structurer prefers the jump-taken condition when the fallthrough ends in `RETURN`, flipping `>` into `<=` and nesting the remaining ladder. OpLift preserves fallthrough condition order and walks sequential conditional headers into flat `elseif / else` chains.',
  },
  {
    number: '04',
    title: 'Lua 5.1 Table Constructors Remain Unfolded and Upvalue Modes Are Mislabeled',
    severity: 'Medium',
    methodAnalyzed: 'Multi-dialect Lua 5.x backend + upvalue comment emitter',
    observedV2: `local t1 = {}\nt1.a = 1\nt1.b = 2\nlocal function v1(p1)\n    -- upvalues: t1 (copy)\n    return t1.a + p1\nend`,
    opliftFix: `local config = {\n    a = 1,\n    b = 2,\n}\nlocal function handler(x)\n    -- upvalues: config (ref)\n    return config.a + x\nend`,
    rootCause:
      'In Lua 5.1, `NEWTABLE` followed by sequential `SETTABLE` writes is the compiler’s standard output for table literals, and `CLOSURE` followed by `MOVE` captures a shared mutable reference (not a value copy). v2 leaves the table unfolded and labels the capture `(copy)`. OpLift folds sequential initializers back into table literals and reports `(ref)` accurately.',
  },
  {
    number: '05',
    title: 'Redundant Parentheses on Provably Single-Return API Calls',
    severity: 'Medium',
    methodAnalyzed: 'Return expression emitter (`CALL C=2` + `RETURN B=2`)',
    observedV2: `return (game:GetService("Players"))\nreturn (string.format("HP: %d/%d (%s)", p1, p2, p3))\nreturn (v1(10))`,
    opliftFix: `return game:GetService("Players")\nreturn \`HP: {a}/{b} ({c})\`\nreturn handler(10)`,
    rootCause:
      'Luau emits `CALL C=2` before `RETURN B=2` whenever a single value is returned. Without return-arity awareness, v2 wraps every call in `return (...)` to guard against multi-return truncation. OpLift checks both a verified single-return stdlib/Roblox API table and static return arity across child protos, pruning parens only when provably safe.',
  },
  {
    number: '06',
    title: 'No Constant Folding Pass for Obfuscated Arithmetic',
    severity: 'Medium',
    methodAnalyzed: 'Expression lifter (no constant-folding option in v2 schema)',
    observedV2: `print((10 + 20) * 3)`,
    opliftFix: `print(90)`,
    rootCause:
      'v2 eliminates unreachable dead branches on constant jumps, but exposes no `foldConstants` pass, leaving synthetic obfuscator math intact. OpLift exposes `foldConstants` (on by default, toggleable per request) to collapse pure numeric and string concatenation expressions cleanly.',
  },
  {
    number: '07',
    title: 'Opaque HTTP 400 Errors, Text-Only API, and No Roblox *227 Decoding',
    severity: 'High',
    methodAnalyzed: 'Public API layer (`POST https://api.lua.expert/v1/decompile`)',
    observedV2: `HTTP 400 text/plain:\nProvided bytecode is not supported or isnt bytecode at all`,
    opliftFix: `Auto-decoded Roblox *227 via inverse *203 mod 256.\nOn truncated/RSB1/Zstd input: exact byteOffset, section, magic hex, and remediation hint.`,
    rootCause:
      'Roblox client `getscriptbytecode` dumps often encode opcodes as `(op * 227) & 0xff` or wrap chunks in RSB1/Zstd. v2 rejects all malformed, compressed, or `*227` payloads with the exact same 1-line error string, offers no JSON metadata or disassembly endpoint, and forces a promotional `-- https://lua.expert` banner onto every response.',
  },
];

export function FlawAnalysis() {
  return (
    <div className="space-y-6">
      <section className="space-y-1 border-b border-slate-800/80 pb-4">
        <h1 className="text-xl sm:text-2xl font-bold tracking-[-0.025em] text-slate-50">
          Flaw Analysis
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 max-w-2xl">
          Seven defects observed directly on live <code className="text-slate-200">api.lua.expert/v1/decompile</code> and how OpLift addresses each one.
        </p>
      </section>

      {/* Architecture summary */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="panel-surface rounded-lg p-4 space-y-1.5">
          <h2 className="text-sm font-semibold text-slate-100">01. Scoob / Medal Lineage</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            v2’s 19 options (<code className="text-slate-200">UNIQUE_VALUE_BASED</code>,{' '}
            <code className="text-slate-200">registerCoalescingThreshold</code>) point to an SSA coalescer and dominator-tree structurer.
          </p>
        </div>

        <div className="panel-surface rounded-lg p-4 space-y-1.5">
          <h2 className="text-sm font-semibold text-slate-100">02. Where v2 Excels</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Native backend handles very large scripts, unstructured CFGs, and Lua 5.2–5.4 / LuaJIT / MoonSharp chunks.
          </p>
        </div>

        <div className="panel-surface rounded-lg p-4 space-y-1.5">
          <h2 className="text-sm font-semibold text-slate-100">03. Where v2 Breaks Down</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Aggressive phi destruction adds synthetic locals and dead <code className="text-slate-200">elseif</code> copies; text-only API returns opaque 400 errors.
          </p>
        </div>
      </section>

      {/* 7 Verified Flaws List */}
      <section className="space-y-6">
        {VERIFIED_FLAWS.map((flaw) => (
          <article key={flaw.number} className="panel-surface rounded-lg p-5 space-y-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-800/80 pb-3">
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-100">
                  {flaw.number}. {flaw.title}
                </h3>
                <div className="text-xs text-slate-400">
                  Method: <span className="text-slate-300">{flaw.methodAnalyzed}</span>
                </div>
              </div>
              <span
                className={`text-xs font-mono font-medium ${
                  flaw.severity === 'High' ? 'text-red-400' : 'text-amber-400'
                }`}
              >
                Impact: {flaw.severity}
              </span>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">{flaw.rootCause}</p>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-red-400">Observed on live api.lua.expert/v1/decompile</div>
                <LuauCodeBlock
                  code={flaw.observedV2}
                  language={flaw.number === '07' ? 'plain' : 'luau'}
                  className="code-well rounded-md p-3.5 text-[13px] leading-[1.6]"
                />
              </div>
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-emerald-400">OpLift Output / Fix</div>
                <LuauCodeBlock
                  code={flaw.opliftFix}
                  language={flaw.number === '07' ? 'plain' : 'luau'}
                  className="code-well rounded-md p-3.5 text-[13px] leading-[1.6]"
                />
              </div>
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
