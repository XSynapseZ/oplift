import { useState, useEffect, useRef } from 'react';
import {
  Play,
  Copy,
  Check,
  Upload,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Terminal,
  FileCode2,
  AlertTriangle,
} from 'lucide-react';
import { DEFAULT_DECOMPILE_OPTIONS } from '../engine/types.ts';
import type { DecompileOptions, DecompileResult, BenchmarkCase } from '../engine/types.ts';
import { LuauCodeBlock } from './LuauCodeBlock.tsx';

type EndpointKey =
  | '/api/v1/decompile'
  | '/decompile'
  | '/api/v1/disassemble'
  | '/api/v1/inspect'
  | '/api/v1/benchmark/live';

type ResponseTab = 'source' | 'disassembly' | 'json' | 'diagnostics';
type SnippetLang = 'curl' | 'luau' | 'js' | 'python';

interface LiveComparePayload {
  ok: boolean;
  oplift: DecompileResult & { score: { score: number; issues: string[] } };
  luaExpertV2: {
    reachable: boolean;
    status: number;
    timingMs: number;
    output: string;
    score: { score: number; issues: string[] };
  };
}

interface ApiPlaygroundProps {
  samples: Array<BenchmarkCase & { oplift: { source: string } }>;
  origin: string;
  initialScript?: string;
}

export function ApiPlayground({ samples, origin, initialScript }: ApiPlaygroundProps) {
  const [endpoint, setEndpoint] = useState<EndpointKey>('/api/v1/decompile');
  const [selectedSampleId, setSelectedSampleId] = useState<string>(samples[0]?.id ?? '');
  const [scriptInput, setScriptInput] = useState<string>(initialScript ?? samples[0]?.bytecodeBase64 ?? '');
  const [options, setOptions] = useState<DecompileOptions>({ ...DEFAULT_DECOMPILE_OPTIONS });
  const [showOptions, setShowOptions] = useState(false);
  const [showSnippet, setShowSnippet] = useState(false);
  const [includeDisassembly, setIncludeDisassembly] = useState(true);
  const [snippetLang, setSnippetLang] = useState<SnippetLang>('curl');

  const [loading, setLoading] = useState(false);
  const [httpStatus, setHttpStatus] = useState<number | null>(null);
  const [roundtripMs, setRoundtripMs] = useState<number | null>(null);
  const [responseTab, setResponseTab] = useState<ResponseTab>('source');
  const [rawResponseText, setRawResponseText] = useState<string>('');
  const [parsedResult, setParsedResult] = useState<DecompileResult | null>(null);
  const [liveCompare, setLiveCompare] = useState<LiveComparePayload | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [copiedId, setCopiedId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!scriptInput && samples.length > 0) {
      setSelectedSampleId(samples[0].id);
      setScriptInput(samples[0].bytecodeBase64);
    }
  }, [samples, scriptInput]);

  useEffect(() => {
    if (initialScript) {
      setScriptInput(initialScript);
    }
  }, [initialScript]);

  const didAutoRun = useRef(false);
  useEffect(() => {
    if (!didAutoRun.current && scriptInput) {
      didAutoRun.current = true;
      void executeApiCall('/api/v1/decompile', scriptInput, options, true);
    }
  }, [scriptInput]);

  function copyText(id: string, text: string) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopiedId(id);
    setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1600);
  }

  async function executeApiCall(
    targetEndpoint: EndpointKey = endpoint,
    payloadScript: string = scriptInput,
    opts: DecompileOptions = options,
    withDisasm: boolean = includeDisassembly
  ) {
    setLoading(true);
    setErrorMsg(null);
    setLiveCompare(null);
    const t0 = performance.now();

    try {
      const bodyObj =
        targetEndpoint === '/api/v1/inspect' || targetEndpoint === '/api/v1/disassemble'
          ? { script: payloadScript, decompilerOptions: { autoDecodeRoblox227: opts.autoDecodeRoblox227 } }
          : targetEndpoint === '/decompile'
            ? { script: payloadScript, decompilerOptions: opts }
            : {
                script: payloadScript,
                decompilerOptions: opts,
                includeDisassembly: withDisasm,
              };

      const res = await fetch(targetEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: targetEndpoint === '/decompile' ? 'text/plain' : 'application/json',
        },
        body: JSON.stringify(bodyObj),
      });

      const elapsed = Math.round(performance.now() - t0);
      setHttpStatus(res.status);
      setRoundtripMs(elapsed);

      const contentType = res.headers.get('content-type') ?? '';
      if (contentType.includes('application/json')) {
        const json = await res.json();
        setRawResponseText(JSON.stringify(json, null, 2));
        if (targetEndpoint === '/api/v1/benchmark/live') {
          setLiveCompare(json as LiveComparePayload);
          setParsedResult((json as LiveComparePayload).oplift);
          setResponseTab('source');
        } else if (targetEndpoint === '/api/v1/disassemble') {
          setParsedResult({
            ok: Boolean(json.ok),
            dialect: json.dialect ?? 'unknown',
            version: json.version,
            versionLabel: json.versionLabel,
            encoding: json.encoding,
            timingMs: json.timingMs ?? elapsed,
            diagnostics: json.diagnostics ?? [],
            imports: [],
            strings: json.stringTable ?? [],
            disassembly: json.disassembly,
          });
          setResponseTab('disassembly');
        } else if (targetEndpoint === '/api/v1/inspect') {
          setParsedResult({
            ok: Boolean(json.ok),
            dialect: json.dialect ?? 'unknown',
            version: json.version,
            versionLabel: json.versionLabel,
            encoding: json.encoding,
            timingMs: json.timingMs ?? elapsed,
            diagnostics: json.diagnostics ?? [],
            imports: json.imports ?? [],
            strings: json.strings ?? [],
            protosSummary: json.protosSummary,
          });
          setResponseTab('diagnostics');
        } else {
          setParsedResult(json as DecompileResult);
          setResponseTab(json.ok ? 'source' : 'diagnostics');
        }
      } else {
        const text = await res.text();
        setRawResponseText(text);
        setParsedResult({
          ok: res.ok,
          source: res.ok ? text : undefined,
          dialect: (res.headers.get('x-oplift-dialect') as DecompileResult['dialect']) ?? 'luau',
          encoding: (res.headers.get('x-oplift-encoding') as DecompileResult['encoding']) ?? 'standard',
          timingMs: Number(res.headers.get('x-oplift-timing-ms')) || elapsed,
          diagnostics: res.ok
            ? []
            : [{ severity: 'error', code: `HTTP_${res.status}`, message: text }],
          imports: [],
          strings: [],
        });
        setResponseTab(res.ok ? 'source' : 'diagnostics');
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Request failed');
      setHttpStatus(0);
    } finally {
      setLoading(false);
    }
  }

  function handleSelectSample(id: string) {
    setSelectedSampleId(id);
    const found = samples.find((s) => s.id === id);
    if (found) {
      setScriptInput(found.bytecodeBase64);
      void executeApiCall(endpoint, found.bytecodeBase64, options, includeDisassembly);
    }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const buf = reader.result as ArrayBuffer;
      const bytes = new Uint8Array(buf);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      const b64 = btoa(binary);
      setSelectedSampleId('');
      setScriptInput(b64);
      void executeApiCall(endpoint, b64, options, includeDisassembly);
    };
    reader.readAsArrayBuffer(file);
  }

  function buildSnippet(): string {
    const fullUrl = `${origin}${endpoint}`;
    const shortB64 = scriptInput.length > 48 ? `${scriptInput.slice(0, 48)}...` : scriptInput;
    if (snippetLang === 'curl') {
      if (endpoint === '/decompile') {
        return `curl -X POST "${fullUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"${shortB64}"}'`;
      }
      return `curl -X POST "${fullUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"${shortB64}","includeDisassembly":true,"decompilerOptions":{"renamingType":"${options.renamingType}","foldConstants":${options.foldConstants},"autoDecodeRoblox227":${options.autoDecodeRoblox227}}}'`;
    }
    if (snippetLang === 'luau') {
      return `local HttpService = game:GetService("HttpService")\nlocal res = request({\n    Url = "${origin}/decompile",\n    Method = "POST",\n    Headers = { ["Content-Type"] = "application/json" },\n    Body = HttpService:JSONEncode({\n        script = crypt.base64encode(getscriptbytecode(targetScript)),\n        decompilerOptions = { renamingType = "${options.renamingType}", foldConstants = ${options.foldConstants} }\n    })\n})\nprint(res.Body)`;
    }
    if (snippetLang === 'js') {
      return `const res = await fetch("${fullUrl}", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({\n    script: base64Bytecode,\n    decompilerOptions: { renamingType: "${options.renamingType}", foldConstants: ${options.foldConstants} }\n  })\n});\nconst data = await res.${endpoint === '/decompile' ? 'text()' : 'json()'};`;
    }
    return `import requests\nres = requests.post("${fullUrl}", json={\n    "script": base64_bytecode,\n    "decompilerOptions": {"renamingType": "${options.renamingType}", "foldConstants": ${options.foldConstants ? 'True' : 'False'}}\n})\nprint(res.${endpoint === '/decompile' ? 'text' : 'json()'})`;
  }

  const toggleBoolOption = (key: keyof DecompileOptions) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <section className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
      {/* Left: Request Builder */}
      <div className="lg:col-span-6 panel-surface rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#202026] flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
            <h1 className="text-sm font-semibold text-zinc-100">Bytecode Input</h1>
          </div>

          <div className="flex items-center gap-2">
            <select
              aria-label="API Endpoint"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value as EndpointKey)}
              className="bg-[#0C0C0E] border border-[#202026] rounded-md px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:border-emerald-500 focus:outline-none"
            >
              <option value="/api/v1/decompile">/api/v1/decompile (JSON)</option>
              <option value="/decompile">/decompile (text/plain)</option>
              <option value="/api/v1/disassemble">/api/v1/disassemble</option>
              <option value="/api/v1/inspect">/api/v1/inspect</option>
              <option value="/api/v1/benchmark/live">/api/v1/benchmark/live</option>
            </select>

            <button
              type="button"
              disabled={loading}
              onClick={() => void executeApiCall()}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 active:scale-[0.99] disabled:opacity-50 text-[#03120B] text-xs font-semibold transition-all whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{loading ? 'Running…' : 'Decompile'}</span>
            </button>
          </div>
        </div>

        <div className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 flex-1 min-w-[220px]">
              <label htmlFor="sample-select" className="text-xs text-zinc-400 whitespace-nowrap">
                Sample
              </label>
              <select
                id="sample-select"
                value={selectedSampleId}
                onChange={(e) => handleSelectSample(e.target.value)}
                className="flex-1 bg-[#0C0C0E] border border-[#202026] rounded-md px-2.5 py-1.5 text-xs text-zinc-200 truncate focus:border-emerald-500 focus:outline-none"
              >
                {samples.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.title} ({s.dialect.toUpperCase()})
                  </option>
                ))}
                {!selectedSampleId && <option value="">Custom Bytecode</option>}
              </select>
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".luauc,.luac,.bin,.bc"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#202026] hover:border-zinc-600 bg-[#0C0C0E] text-xs text-zinc-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload binary</span>
            </button>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs text-zinc-400">
              <label htmlFor="bytecode-input">Base64 or Hex Bytecode</label>
              <button
                type="button"
                onClick={() => {
                  const truncated = scriptInput.slice(0, 24);
                  setSelectedSampleId('');
                  setScriptInput(truncated);
                  void executeApiCall(endpoint, truncated, options, includeDisassembly);
                }}
                className="text-zinc-400 hover:text-amber-300 text-xs transition-colors cursor-pointer"
              >
                Test truncated
              </button>
            </div>
            <textarea
              id="bytecode-input"
              rows={9}
              value={scriptInput}
              onChange={(e) => {
                setSelectedSampleId('');
                setScriptInput(e.target.value);
              }}
              placeholder="Paste Base64 Luau/Lua bytecode or 0x-prefixed hex..."
              className="code-input w-full code-well rounded-md p-3.5 text-xs text-zinc-200 leading-relaxed resize-y focus:border-emerald-500/70 focus:outline-none"
            />
          </div>

          {/* Collapsible Options */}
          <div className="border-t border-[#202026] pt-2.5">
            <button
              type="button"
              onClick={() => setShowOptions((v) => !v)}
              className="w-full flex items-center justify-between text-xs font-medium text-zinc-300 hover:text-zinc-100 py-1 cursor-pointer"
            >
              <span>Decompiler Options</span>
              {showOptions ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {showOptions && (
              <div className="mt-3 space-y-3 pt-1">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <label className="flex flex-col gap-1 text-xs text-zinc-400">
                    <span>renamingType</span>
                    <select
                      value={options.renamingType}
                      onChange={(e) =>
                        setOptions((prev) => ({
                          ...prev,
                          renamingType: e.target.value as DecompileOptions['renamingType'],
                        }))
                      }
                      className="bg-[#0C0C0E] border border-[#202026] rounded px-2 py-1.5 text-xs font-mono text-zinc-200 focus:border-emerald-500 focus:outline-none"
                    >
                      <option value="SEMANTIC">SEMANTIC</option>
                      <option value="UNIQUE_VALUE_BASED">UNIQUE_VALUE_BASED</option>
                      <option value="NONE">NONE</option>
                    </select>
                  </label>

                  <label className="flex items-center gap-2 text-xs text-zinc-300 pt-5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeDisassembly}
                      onChange={(e) => setIncludeDisassembly(e.target.checked)}
                      className="accent-emerald-500"
                    />
                    <span className="font-mono text-[11px]">includeDisassembly</span>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-zinc-300">
                  {(
                    [
                      ['emitTypeAnnotations', 'emitTypeAnnotations'],
                      ['ifExpressions', 'ifExpressions'],
                      ['tableFunctionSugaring', 'tableFunctionSugaring'],
                      ['foldConstants', 'foldConstants'],
                      ['eliminateDeadBranches', 'eliminateDeadBranches'],
                      ['virtualizeContinue', 'virtualizeContinue'],
                      ['foldTableLiterals', 'foldTableLiterals'],
                      ['pruneReturnParens', 'pruneReturnParens'],
                      ['autoDecodeRoblox227', 'autoDecodeRoblox227'],
                      ['compoundAssignments', 'compoundAssignments'],
                      ['resugarInterpolatedStrings', 'resugarInterpolatedStrings'],
                      ['numericForStepSugaring', 'numericForStepSugaring'],
                      ['upvalueComments', 'upvalueComments'],
                      ['useDebugLocals', 'useDebugLocals'],
                      ['emitHeader', 'emitHeader'],
                    ] as Array<[keyof DecompileOptions, string]>
                  ).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={Boolean(options[key])}
                        onChange={() => toggleBoolOption(key)}
                        className="accent-emerald-500"
                      />
                      <span className="font-mono text-[11px] truncate">{label}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Collapsible Code Snippet */}
          <div className="border-t border-[#202026] pt-2.5">
            <button
              type="button"
              onClick={() => setShowSnippet((v) => !v)}
              className="w-full flex items-center justify-between text-xs font-medium text-zinc-300 hover:text-zinc-100 py-1 cursor-pointer"
            >
              <span>Client Snippet</span>
              {showSnippet ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {showSnippet && (
              <div className="mt-2.5 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1 bg-[#0C0C0E] p-0.5 rounded-md border border-[#202026]">
                    {(['curl', 'luau', 'js', 'python'] as SnippetLang[]).map((lang) => (
                      <button
                        key={lang}
                        type="button"
                        onClick={() => setSnippetLang(lang)}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                          snippetLang === lang
                            ? 'bg-zinc-800 text-zinc-100'
                            : 'text-zinc-400 hover:text-zinc-200'
                        }`}
                      >
                        {lang === 'curl' ? 'cURL' : lang === 'luau' ? 'Luau' : lang === 'js' ? 'JS' : 'Python'}
                      </button>
                    ))}
                  </div>

                  <button
                    type="button"
                    onClick={() => copyText('snippet', buildSnippet())}
                    className="inline-flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                  >
                    {copiedId === 'snippet' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'snippet' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <LuauCodeBlock
                  code={buildSnippet()}
                  language={snippetLang === 'luau' ? 'luau' : 'plain'}
                  className="code-well rounded-md p-3.5 text-xs leading-relaxed"
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right: Output Viewer */}
      <div className="lg:col-span-6 panel-surface rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#202026] flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">Output</h2>
          </div>

          <div className="flex items-center gap-2.5 text-xs font-mono tabular-nums">
            {httpStatus !== null && (
              <span className={httpStatus === 200 ? 'text-emerald-400 font-medium' : 'text-red-400 font-medium'}>
                HTTP {httpStatus}
              </span>
            )}
            {roundtripMs !== null && (
              <>
                <span className="text-zinc-600" aria-hidden="true">·</span>
                <span className="text-zinc-400">{roundtripMs} ms</span>
              </>
            )}
            {parsedResult?.versionLabel && (
              <>
                <span className="text-zinc-600" aria-hidden="true">·</span>
                <span className="text-zinc-300">{parsedResult.versionLabel}</span>
              </>
            )}
            {parsedResult?.encoding === 'roblox-227' && (
              <>
                <span className="text-zinc-600" aria-hidden="true">·</span>
                <span className="text-amber-400">roblox-227</span>
              </>
            )}
          </div>
        </div>

        <div className="px-5 pt-3 border-b border-[#202026] flex items-center justify-between gap-4">
          <div className="flex items-center gap-5 overflow-x-auto">
            {(
              [
                ['source', 'Source'],
                ['disassembly', 'Disassembly'],
                ['json', 'Payload'],
                ['diagnostics', `Diagnostics (${parsedResult?.diagnostics.length ?? 0})`],
              ] as Array<[ResponseTab, string]>
            ).map(([tabKey, label]) => (
              <button
                key={tabKey}
                type="button"
                onClick={() => setResponseTab(tabKey)}
                className={`pb-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  responseTab === tabKey
                    ? 'border-emerald-400 text-zinc-100'
                    : 'border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {parsedResult?.source && responseTab === 'source' && (
            <button
              type="button"
              onClick={() => copyText('resp-src', parsedResult.source ?? '')}
              className="pb-2.5 text-xs text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedId === 'resp-src' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedId === 'resp-src' ? 'Copied' : 'Copy'}</span>
            </button>
          )}
        </div>

        <div className="p-5 min-h-[420px]">
          {errorMsg && (
            <div className="border border-red-900/60 bg-red-950/30 rounded-md p-3.5 text-xs text-red-300 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          {!errorMsg && liveCompare && responseTab === 'source' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-emerald-400">OpLift</span>
                  <span className="font-mono tabular-nums text-zinc-400">
                    {liveCompare.oplift.score.score}/100 · {liveCompare.oplift.timingMs} ms
                  </span>
                </div>
                <LuauCodeBlock
                  code={liveCompare.oplift.source || '(decompile failed)'}
                  language={liveCompare.oplift.source ? 'luau' : 'plain'}
                  showLineNumbers={Boolean(liveCompare.oplift.source)}
                  className="code-well rounded-md p-3.5 text-[13px] leading-[1.65]"
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-zinc-300">lua.expert v2</span>
                  <span className="font-mono tabular-nums text-zinc-400">
                    {liveCompare.luaExpertV2.score.score}/100 · HTTP {liveCompare.luaExpertV2.status} · {liveCompare.luaExpertV2.timingMs} ms
                  </span>
                </div>
                <LuauCodeBlock
                  code={liveCompare.luaExpertV2.output}
                  language={liveCompare.luaExpertV2.status === 200 ? 'luau' : 'plain'}
                  showLineNumbers={liveCompare.luaExpertV2.status === 200}
                  className="code-well rounded-md p-3.5 text-[13px] leading-[1.65]"
                />
              </div>
            </div>
          )}

          {!errorMsg && !liveCompare && responseTab === 'source' && (
            <>
              {parsedResult?.source ? (
                <LuauCodeBlock
                  code={parsedResult.source}
                  language="luau"
                  showLineNumbers
                  className="code-well rounded-md p-4 text-[13px] leading-[1.65] max-h-[640px] overflow-y-auto"
                />
              ) : (
                <div className="text-xs text-zinc-400 space-y-2 py-4">
                  <p>No decompiled source returned. Inspect Diagnostics for exact byte offsets.</p>
                  <button
                    type="button"
                    onClick={() => setResponseTab('diagnostics')}
                    className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 cursor-pointer"
                  >
                    <span>Open diagnostics</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </>
          )}

          {!errorMsg && responseTab === 'disassembly' && (
            <div className="space-y-4">
              {parsedResult?.disassembly && parsedResult.disassembly.length > 0 ? (
                parsedResult.disassembly.map((proto) => (
                  <div key={proto.id} className="space-y-2">
                    <div className="flex items-center justify-between text-xs text-zinc-400">
                      <span className="font-mono text-zinc-200 font-medium">
                        proto #{proto.id} {proto.name}
                      </span>
                      <span className="font-mono tabular-nums">
                        params={proto.numParams} · upvals={proto.numUpvalues} · maxstack={proto.maxStackSize}
                      </span>
                    </div>
                    <div className="code-well rounded-md overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="border-b border-[#202026] text-[11px] uppercase tracking-wider text-zinc-500">
                            <th className="py-2 px-3">PC</th>
                            <th className="py-2 px-3">Opcode</th>
                            <th className="py-2 px-3">Operands</th>
                            <th className="py-2 px-3">Resolved</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#202026]/80">
                          {proto.instructions.map((ins) => (
                            <tr key={ins.pc} className="hover:bg-zinc-900/60">
                              <td className="py-1.5 px-3 tabular-nums text-zinc-500">
                                {String(ins.pc).padStart(3, '0')}
                              </td>
                              <td className="py-1.5 px-3 text-emerald-400">{ins.opname}</td>
                              <td className="py-1.5 px-3 text-zinc-300">{ins.operands}</td>
                              <td className="py-1.5 px-3 text-zinc-400">{ins.comment ?? ''}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-zinc-400 py-4">
                  Enable <code className="text-zinc-300">includeDisassembly</code> or call{' '}
                  <code className="text-zinc-300">POST /api/v1/disassemble</code> to inspect proto instructions.
                </p>
              )}
            </div>
          )}

          {!errorMsg && responseTab === 'json' && (
            <LuauCodeBlock
              code={rawResponseText || '(Run a request to inspect raw response payload)'}
              language={rawResponseText.trimStart().startsWith('{') ? 'json' : 'plain'}
              className="code-well rounded-md p-4 text-xs max-h-[560px] leading-relaxed"
            />
          )}

          {!errorMsg && responseTab === 'diagnostics' && (
            <div className="space-y-4">
              {parsedResult?.diagnostics && parsedResult.diagnostics.length > 0 ? (
                <div className="space-y-2.5">
                  {parsedResult.diagnostics.map((d, idx) => (
                    <div
                      key={idx}
                      className={`border rounded-md p-3.5 text-xs space-y-1.5 ${
                        d.severity === 'error'
                          ? 'border-red-900/60 bg-red-950/20 text-red-200'
                          : d.severity === 'warning'
                            ? 'border-amber-900/60 bg-amber-950/20 text-amber-200'
                            : 'border-[#202026] bg-[#0C0C0E] text-zinc-300'
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2 font-mono">
                        <span className="font-semibold">{d.code}</span>
                        {d.section && <span className="text-zinc-400">· {d.section}</span>}
                        {d.byteOffset !== undefined && (
                          <span className="text-zinc-400">· offset 0x{d.byteOffset.toString(16)}</span>
                        )}
                      </div>
                      <p className="leading-relaxed">{d.message}</p>
                      {d.hint && <p className="text-zinc-400">Hint: {d.hint}</p>}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-zinc-400">No parser errors or warnings reported on this chunk.</p>
              )}

              {parsedResult && (parsedResult.imports.length > 0 || parsedResult.strings.length > 0) && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-3 border-t border-[#202026] text-xs">
                  <div>
                    <div className="text-zinc-400 font-medium mb-1.5">Resolved Imports ({parsedResult.imports.length})</div>
                    <div className="font-mono text-zinc-300 space-y-1">
                      {parsedResult.imports.length > 0
                        ? parsedResult.imports.map((imp) => <div key={imp}>{imp}</div>)
                        : <span className="text-zinc-500">None</span>}
                    </div>
                  </div>
                  <div>
                    <div className="text-zinc-400 font-medium mb-1.5">String Table ({parsedResult.strings.length})</div>
                    <div className="font-mono text-zinc-300 space-y-1 max-h-40 overflow-y-auto">
                      {parsedResult.strings.length > 0
                        ? parsedResult.strings.map((s, idx) => <div key={idx}>{JSON.stringify(s)}</div>)
                        : <span className="text-zinc-500">Empty</span>}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
