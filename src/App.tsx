import { useState, useEffect } from 'react';
import { Copy, Check } from 'lucide-react';
import { ApiPlayground } from './components/ApiPlayground.tsx';
import { ComparisonPlayground } from './components/ComparisonPlayground.tsx';
import { BenchmarkSuite } from './components/BenchmarkSuite.tsx';
import type { EvaluatedBenchmarkCase } from './components/BenchmarkSuite.tsx';
import { ApiReference } from './components/ApiReference.tsx';
import type { LandscapeDecompilerEntry } from './engine/comparator.ts';

type ActiveView = 'playground' | 'compare' | 'benchmarks' | 'docs';

interface BenchmarksResponse {
  ok: boolean;
  corpusSummary: {
    totalCases: number;
    opliftAverageScore: number;
    luaExpertV2AverageScore: number;
  };
  cases: EvaluatedBenchmarkCase[];
  landscape: LandscapeDecompilerEntry[];
}

export default function App() {
  const [view, setView] = useState<ActiveView>('playground');
  const [benchmarks, setBenchmarks] = useState<BenchmarksResponse | null>(null);
  const [loadingBenchmarks, setLoadingBenchmarks] = useState(true);
  const [playgroundScript, setPlaygroundScript] = useState<string | undefined>(undefined);
  const [copiedBridge, setCopiedBridge] = useState(false);

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';

  useEffect(() => {
    let active = true;
    fetch('/api/v1/benchmarks')
      .then((r) => r.json())
      .then((data: BenchmarksResponse) => {
        if (active && data.ok) {
          setBenchmarks(data);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoadingBenchmarks(false);
      });
    return () => {
      active = false;
    };
  }, []);

  function handleCopyBridgeUrl() {
    navigator.clipboard.writeText(`${origin}/decompile`).catch(() => {});
    setCopiedBridge(true);
    setTimeout(() => setCopiedBridge(false), 1800);
  }

  function handleOpenInPlayground(bytecodeBase64: string) {
    setPlaygroundScript(bytecodeBase64);
    setView('playground');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  return (
    <div className="min-h-screen bg-[#09090B] text-zinc-100 flex flex-col">
      <header className="sticky top-0 z-30 bg-[#09090B]/92 backdrop-blur-md border-b border-[#202026]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-8">
          <a
            href="#playground"
            onClick={(e) => {
              e.preventDefault();
              setView('playground');
            }}
            style={{ fontFamily: 'var(--font-display)' }}
            className="text-lg font-bold tracking-[-0.03em] text-zinc-50 hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            OpLift
          </a>

          <nav aria-label="Primary" className="flex items-center h-full gap-1 sm:gap-2 overflow-x-auto">
            {(
              [
                ['playground', 'Playground'],
                ['compare', 'Compare'],
                ['benchmarks', 'Benchmarks'],
                ['docs', 'API'],
              ] as Array<[ActiveView, string]>
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setView(key)}
                className={`relative h-full inline-flex items-center px-3 text-[13px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  view === key ? 'text-zinc-50' : 'text-zinc-400 hover:text-zinc-100'
                }`}
              >
                <span>{label}</span>
                {view === key && (
                  <span
                    aria-hidden="true"
                    className="absolute bottom-0 left-2.5 right-2.5 h-[2px] bg-emerald-500"
                  />
                )}
              </button>
            ))}
          </nav>

          <div className="shrink-0">
            <button
              type="button"
              onClick={handleCopyBridgeUrl}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-emerald-500 hover:bg-emerald-400 active:scale-[0.99] text-[#03120B] text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedBridge ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedBridge ? 'Copied /decompile' : 'Copy Bridge URL'}</span>
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {loadingBenchmarks && !benchmarks ? (
          <div className="space-y-4 py-12">
            <div className="h-8 w-56 bg-zinc-900 rounded animate-pulse" />
            <div className="h-72 w-full bg-zinc-900/70 border border-[#202026] rounded-lg animate-pulse" />
          </div>
        ) : (
          <>
            {view === 'playground' && (
              <ApiPlayground
                samples={benchmarks?.cases ?? []}
                origin={origin}
                initialScript={playgroundScript}
              />
            )}

            {view === 'compare' && <ComparisonPlayground />}

            {view === 'benchmarks' && benchmarks && (
              <BenchmarkSuite
                corpusSummary={benchmarks.corpusSummary}
                cases={benchmarks.cases}
                landscape={benchmarks.landscape}
                onLoadInPlayground={handleOpenInPlayground}
              />
            )}

            {view === 'docs' && <ApiReference origin={origin} />}
          </>
        )}
      </main>

      <footer className="border-t border-[#202026] py-4 mt-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-wrap items-center justify-between gap-4 text-xs text-zinc-500">
          <span>OpLift Luau Decompiler</span>
          <div className="flex items-center gap-5 font-mono">
            <a href="/api/v1/health" target="_blank" rel="noopener noreferrer" className="hover:text-zinc-200 transition-colors">
              /api/v1/health
            </a>
            <a href="/api/v1/openapi.json" target="_blank" rel="noopener noreferrer" className="hover:text-zinc-200 transition-colors">
              /api/v1/openapi.json
            </a>
            <a href="/script.lua" target="_blank" rel="noopener noreferrer" className="hover:text-zinc-200 transition-colors">
              /script.lua
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
