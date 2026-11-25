import { useState } from 'react';
import { RefreshCw, ArrowUpRight } from 'lucide-react';
import type { BenchmarkCase, CleanlinessScore, DecompileMetrics } from '../engine/types.ts';
import type { LandscapeDecompilerEntry, LandscapeScores } from '../engine/comparator.ts';
import { LuauCodeBlock } from './LuauCodeBlock.tsx';

export interface EvaluatedBenchmarkCase extends BenchmarkCase {
  oplift: {
    ok: boolean;
    status: number;
    source: string;
    timingMs: number;
    encoding?: string;
    metrics?: DecompileMetrics;
    score: CleanlinessScore;
  };
  luaExpertScore: CleanlinessScore;
}

interface BenchmarkSuiteProps {
  corpusSummary: {
    totalCases: number;
    opliftAverageScore: number;
    luaExpertV2AverageScore: number;
  };
  cases: EvaluatedBenchmarkCase[];
  landscape: LandscapeDecompilerEntry[];
  onLoadInPlayground: (bytecodeBase64: string) => void;
}

interface LiveCaseResult {
  loading: boolean;
  opliftSource?: string;
  opliftScore?: number;
  opliftMs?: number;
  v2Output?: string;
  v2Status?: number;
  v2Score?: number;
  v2Ms?: number;
  error?: string;
}

type MetricKey = 'overall' | keyof LandscapeScores;

const METRIC_OPTIONS: Array<{ key: MetricKey; label: string }> = [
  { key: 'overall', label: 'Overall' },
  { key: 'complexCfgRecovery', label: 'Complex CFG' },
  { key: 'luauOpcodeCoverage', label: 'Opcodes' },
  { key: 'outputCleanliness', label: 'Cleanliness' },
  { key: 'multiDialectSupport', label: 'Multi-Dialect' },
  { key: 'apiAndDiagnostics', label: 'API & Diag' },
  { key: 'throughputAndScale', label: 'Throughput' },
];

function getMetricValue(entry: LandscapeDecompilerEntry, metric: MetricKey): number {
  if (metric === 'overall') return entry.overallScore;
  return entry.scores[metric];
}

function scoreColor(score: number): string {
  if (score >= 85) return 'text-emerald-400';
  if (score >= 70) return 'text-amber-400';
  return 'text-red-400';
}

export function BenchmarkSuite({
  corpusSummary,
  cases,
  landscape,
  onLoadInPlayground,
}: BenchmarkSuiteProps) {
  const [activeMetric, setActiveMetric] = useState<MetricKey>('overall');
  const [expandedDecompiler, setExpandedDecompiler] = useState<string>('oplift-ours');
  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.id ?? '');
  const [liveRuns, setLiveRuns] = useState<Record<string, LiveCaseResult>>({});

  const activeCase = cases.find((c) => c.id === selectedCaseId) ?? cases[0];
  const sortedEntries = [...landscape].sort(
    (a, b) => getMetricValue(b, activeMetric) - getMetricValue(a, activeMetric)
  );
  const selectedEntry = landscape.find((e) => e.id === expandedDecompiler) ?? landscape[0];

  async function runLiveCheck(c: EvaluatedBenchmarkCase) {
    setLiveRuns((prev) => ({ ...prev, [c.id]: { loading: true } }));
    try {
      const res = await fetch('/api/v1/benchmark/live', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script: c.bytecodeBase64 }),
      });
      const data = await res.json();
      setLiveRuns((prev) => ({
        ...prev,
        [c.id]: {
          loading: false,
          opliftSource: data.oplift?.source,
          opliftScore: data.oplift?.score?.score,
          opliftMs: data.oplift?.timingMs,
          v2Output: data.luaExpertV2?.output,
          v2Status: data.luaExpertV2?.status,
          v2Score: data.luaExpertV2?.score?.score,
          v2Ms: data.luaExpertV2?.timingMs,
        },
      }));
    } catch (err) {
      setLiveRuns((prev) => ({
        ...prev,
        [c.id]: {
          loading: false,
          error: err instanceof Error ? err.message : 'Live verification failed',
        },
      }));
    }
  }

  return (
    <div className="space-y-8">
      {/* Section 1: Flat Onyx Leaderboard + Breakdown */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#202026] pb-4">
          <div className="space-y-0.5">
            <h1 className="text-xl font-bold tracking-[-0.025em] text-zinc-50">
              Benchmarks
            </h1>
            <p className="text-xs text-zinc-400">
              Weighted /100 evaluation across control flow, opcodes, cleanliness, dialect coverage, diagnostics, and throughput.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1 bg-[#0C0C0E] border border-[#202026] rounded-md p-1">
            {METRIC_OPTIONS.map((m) => (
              <button
                key={m.key}
                type="button"
                onClick={() => setActiveMetric(m.key)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeMetric === m.key
                    ? 'bg-emerald-500 text-[#03120B] font-semibold'
                    : 'text-zinc-400 hover:text-zinc-100'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        <div className="panel-surface rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#202026] bg-[#0C0C0E] text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                  <th className="py-3 px-4">Decompiler</th>
                  <th className="py-3 px-4 w-48">Score</th>
                  <th className="py-3 px-3 text-right">CFG</th>
                  <th className="py-3 px-3 text-right">Opcodes</th>
                  <th className="py-3 px-3 text-right">Cleanliness</th>
                  <th className="py-3 px-3 text-right">Dialects</th>
                  <th className="py-3 px-3 text-right">API</th>
                  <th className="py-3 px-4 text-right">Speed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#202026]">
                {sortedEntries.map((entry) => {
                  const isOurs = entry.id === 'oplift-ours';
                  const isSelected = expandedDecompiler === entry.id;
                  const metricVal = getMetricValue(entry, activeMetric);
                  return (
                    <tr
                      key={entry.id}
                      onClick={() => setExpandedDecompiler(entry.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-zinc-900/90'
                          : isOurs
                            ? 'bg-emerald-950/10 hover:bg-emerald-950/20'
                            : 'hover:bg-zinc-900/50'
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-zinc-100">{entry.name}</div>
                        <div className="text-[11px] text-zinc-500 mt-0.5">
                          {entry.runtime} · {entry.accessModel}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          <div className="flex-1 h-1.5 bg-[#0C0C0E] rounded-full overflow-hidden border border-[#202026]">
                            <div
                              className={`h-full rounded-full transition-all duration-300 ${
                                isOurs ? 'bg-emerald-500' : 'bg-zinc-500'
                              }`}
                              style={{ width: `${metricVal}%` }}
                            />
                          </div>
                          <span className={`font-mono font-semibold tabular-nums w-12 text-right ${scoreColor(metricVal)}`}>
                            {metricVal}/100
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.complexCfgRecovery}
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.luauOpcodeCoverage}
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.outputCleanliness}
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.multiDialectSupport}
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.apiAndDiagnostics}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-zinc-300">
                        {entry.scores.throughputAndScale}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {selectedEntry && (
            <div className="border-t border-[#202026] bg-[#0C0C0E] px-5 py-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-zinc-100">{selectedEntry.name}</div>
                  <div className="text-xs text-zinc-400 mt-0.5">{selectedEntry.verdict}</div>
                </div>
                <span className={`text-sm font-mono font-bold tabular-nums ${scoreColor(selectedEntry.overallScore)}`}>
                  {selectedEntry.overallScore}/100 overall
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 text-xs">
                <div>
                  <div className="text-emerald-400 font-medium mb-1">Strengths</div>
                  <ul className="space-y-1 text-zinc-400 list-disc pl-4">
                    {selectedEntry.honestStrengths.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="text-zinc-300 font-medium mb-1">Limitations</div>
                  <ul className="space-y-1 text-zinc-400 list-disc pl-4">
                    {selectedEntry.honestWeaknesses.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Section 2: Head-to-Head Corpus */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[#202026] pb-3">
          <div className="space-y-0.5">
            <h2 className="text-lg font-semibold text-zinc-50">
              Head-to-Head Corpus ({corpusSummary.totalCases} cases)
            </h2>
            <p className="text-xs text-zinc-400">
              Identical bytecode evaluated on OpLift and live <code className="text-zinc-300">api.lua.expert/v1/decompile</code>.
            </p>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono tabular-nums">
            <span className="text-zinc-400">
              OpLift Avg <strong className="text-emerald-400 ml-1">{corpusSummary.opliftAverageScore}/100</strong>
            </span>
            <span className="text-zinc-700" aria-hidden="true">·</span>
            <span className="text-zinc-400">
              lua.expert v2 Avg <strong className="text-amber-400 ml-1">{corpusSummary.luaExpertV2AverageScore}/100</strong>
            </span>
          </div>
        </div>

        <div className="panel-surface rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#202026] bg-[#0C0C0E] text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                  <th className="py-3 px-4">Test Case</th>
                  <th className="py-3 px-3">Dialect</th>
                  <th className="py-3 px-3">Focus</th>
                  <th className="py-3 px-3 text-right">OpLift</th>
                  <th className="py-3 px-3 text-right">lua.expert v2</th>
                  <th className="py-3 px-4 text-right">Diff</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#202026]">
                {cases.map((c) => {
                  const isSelected = activeCase?.id === c.id;
                  const live = liveRuns[c.id];
                  const ourVal = live?.opliftScore ?? c.oplift.score.score;
                  const v2Val = live?.v2Score ?? c.luaExpertScore.score;
                  return (
                    <tr
                      key={c.id}
                      onClick={() => setSelectedCaseId(c.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-zinc-900/90' : 'hover:bg-zinc-900/50'
                      }`}
                    >
                      <td className="py-3 px-4 font-medium text-zinc-100">{c.title}</td>
                      <td className="py-3 px-3 font-mono text-zinc-400">{c.dialect}</td>
                      <td className="py-3 px-3 text-zinc-300">{c.flawCategory}</td>
                      <td className={`py-3 px-3 text-right font-mono font-semibold tabular-nums ${scoreColor(ourVal)}`}>
                        {ourVal}/100
                      </td>
                      <td className={`py-3 px-3 text-right font-mono font-semibold tabular-nums ${scoreColor(v2Val)}`}>
                        {v2Val}/100
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="text-emerald-400 font-medium">
                          {isSelected ? 'Selected' : 'View'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {activeCase && (
          <div className="panel-surface rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#202026] flex flex-wrap items-center justify-between gap-4">
              <div className="space-y-0.5">
                <h3 className="text-sm font-semibold text-zinc-100">{activeCase.title}</h3>
                <p className="text-xs text-zinc-400">{activeCase.summary}</p>
              </div>
              <div className="flex items-center gap-2.5">
                <button
                  type="button"
                  disabled={liveRuns[activeCase.id]?.loading}
                  onClick={() => void runLiveCheck(activeCase)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#202026] hover:border-zinc-600 bg-[#0C0C0E] text-xs font-medium text-zinc-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${liveRuns[activeCase.id]?.loading ? 'animate-spin' : ''}`} />
                  <span>{liveRuns[activeCase.id]?.loading ? 'Querying…' : 'Verify Live'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => onLoadInPlayground(activeCase.bytecodeBase64)}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 active:scale-[0.99] text-[#03120B] text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <span>Open in Playground</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#202026]">
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-emerald-400">OpLift</span>
                  <span className="font-mono tabular-nums text-zinc-400">
                    {liveRuns[activeCase.id]?.opliftScore ?? activeCase.oplift.score.score}/100 ·{' '}
                    {liveRuns[activeCase.id]?.opliftMs ?? activeCase.oplift.timingMs} ms
                  </span>
                </div>
                <LuauCodeBlock
                  code={liveRuns[activeCase.id]?.opliftSource ?? activeCase.oplift.source}
                  language="luau"
                  showLineNumbers
                  className="code-well rounded-md p-4 text-[13px] leading-[1.65] min-h-[200px]"
                />
              </div>

              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-zinc-300">lua.expert v2</span>
                  <span className="font-mono tabular-nums text-zinc-400">
                    {liveRuns[activeCase.id]?.v2Score ?? activeCase.luaExpertScore.score}/100 · HTTP{' '}
                    {liveRuns[activeCase.id]?.v2Status ?? activeCase.luaExpertV2Status}
                    {liveRuns[activeCase.id]?.v2Ms ? ` · ${liveRuns[activeCase.id].v2Ms} ms` : ''}
                  </span>
                </div>
                <LuauCodeBlock
                  code={liveRuns[activeCase.id]?.v2Output ?? activeCase.luaExpertV2Output}
                  language="luau"
                  showLineNumbers
                  className="code-well rounded-md p-4 text-[13px] leading-[1.65] min-h-[200px]"
                />
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
