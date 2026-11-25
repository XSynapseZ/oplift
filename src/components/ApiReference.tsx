import { useState } from 'react';
import { Copy, Check, ExternalLink } from 'lucide-react';

interface ApiReferenceProps {
  origin: string;
}

export function ApiReference({ origin }: ApiReferenceProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  function copy(id: string, text: string) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopiedId(id);
    setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1600);
  }

  const endpoints = [
    {
      method: 'POST',
      path: '/decompile',
      returns: 'text/plain (or JSON)',
      purpose:
        'Drop-in endpoint for roblox-bridge, lua.expert v1/v2 clients, and self-hosted Medal clients. Accepts JSON {"script":"<base64>"}, raw base64 text/plain, or raw application/octet-stream bytecode.',
      example: `curl -X POST "${origin}/decompile" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64-luau-or-lua51>"}'`,
    },
    {
      method: 'POST',
      path: '/v1/decompile',
      returns: 'text/plain / application/json',
      purpose:
        'Path parity with api.lua.expert/v1/decompile. Supports all 19 lua.expert v2 decompilerOptions plus OpLift options (foldConstants, foldTableLiterals, pruneReturnParens, autoDecodeRoblox227).',
      example: `curl -X POST "${origin}/v1/decompile" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64>","decompilerOptions":{"renamingType":"SEMANTIC","foldConstants":true}}'`,
    },
    {
      method: 'POST',
      path: '/api/v1/decompile',
      returns: 'application/json',
      purpose:
        'Full reverse-engineering envelope: source, dialect, version, opcode encoding, resolved imports, string table, proto return arities, diagnostics, and optional disassembly.',
      example: `curl -X POST "${origin}/api/v1/decompile" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64>","includeDisassembly":true}'`,
    },
    {
      method: 'POST',
      path: '/api/v1/disassemble',
      returns: 'application/json',
      purpose:
        'Proto-by-proto instruction disassembly, constant pools, AUX word resolution, and jump targets without high-level structuring.',
      example: `curl -X POST "${origin}/api/v1/disassemble" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64>"}'`,
    },
    {
      method: 'POST',
      path: '/api/v1/inspect',
      returns: 'application/json',
      purpose:
        'Binary triage: detects magic header (Luau v3–v6, Roblox *227, Lua 5.1–5.4, LuaJIT, MoonSharp, RSB1/Zstd), string table, imports, and proto summaries.',
      example: `curl -X POST "${origin}/api/v1/inspect" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64>"}'`,
    },
    {
      method: 'POST',
      path: '/api/v1/batch',
      returns: 'application/json',
      purpose:
        'Decompile up to 25 scripts in one request with shared or per-script decompilerOptions.',
      example: `curl -X POST "${origin}/api/v1/batch" \\\n  -H "Content-Type: application/json" \\\n  -d '{"scripts":[{"id":"LocalScript1","script":"<base64>"}]}'`,
    },
    {
      method: 'POST',
      path: '/api/v1/benchmark/live',
      returns: 'application/json',
      purpose:
        'Executes OpLift and queries api.lua.expert/v1/decompile in parallel on the same bytecode.',
      example: `curl -X POST "${origin}/api/v1/benchmark/live" \\\n  -H "Content-Type: application/json" \\\n  -d '{"script":"<base64>"}'`,
    },
  ];

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-end justify-between gap-4 border-b border-[#202026] pb-4">
        <div className="space-y-0.5">
          <h1 className="text-xl font-bold tracking-[-0.025em] text-zinc-50">
            API Reference
          </h1>
          <p className="text-xs text-zinc-400">
            Plain-text bridge endpoints and structured JSON analysis routes.
          </p>
        </div>
        <a
          href="/api/v1/openapi.json"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 hover:text-emerald-300 whitespace-nowrap"
        >
          <span>OpenAPI 3.1 JSON</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </section>

      <section className="panel-surface rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">
            roblox-bridge Endpoint
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Paste <code className="text-zinc-200">{origin}/decompile</code> into Settings → Decompiler Endpoint (<code className="text-zinc-200">#cfg-decomp</code>).
          </p>
        </div>

        <div className="flex items-center justify-between gap-3 code-well rounded-md px-3.5 py-2.5">
          <code className="text-xs font-mono text-emerald-400 truncate">{origin}/decompile</code>
          <button
            type="button"
            onClick={() => copy('ref-bridge', `${origin}/decompile`)}
            className="inline-flex items-center gap-1 text-xs font-medium text-zinc-300 hover:text-zinc-100 whitespace-nowrap shrink-0 cursor-pointer"
          >
            {copiedId === 'ref-bridge' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedId === 'ref-bridge' ? 'Copied' : 'Copy Endpoint'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1 text-xs text-zinc-400">
          <div>
            <div className="text-zinc-200 font-medium">Accepted Bodies</div>
            <p className="mt-1">
              JSON (<code className="text-zinc-300">{'{"script":"..."}'}</code> /{' '}
              <code className="text-zinc-300">{'{"bytecode":"..."}'}</code>), raw base64{' '}
              <code className="text-zinc-300">text/plain</code>, or raw binary.
            </p>
          </div>
          <div>
            <div className="text-zinc-200 font-medium">Response Headers</div>
            <p className="mt-1">
              Returns <code className="text-zinc-300">200 OK</code> with{' '}
              <code className="text-zinc-300">X-OpLift-Dialect</code> and{' '}
              <code className="text-zinc-300">X-OpLift-Encoding</code>.
            </p>
          </div>
          <div>
            <div className="text-zinc-200 font-medium">Executor Helper</div>
            <p className="mt-1">
              Available at{' '}
              <a href="/script.lua" target="_blank" rel="noopener noreferrer" className="text-emerald-400 hover:underline font-mono">
                GET /script.lua
              </a>
              .
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-zinc-200">Endpoints</h2>
        <div className="space-y-3">
          {endpoints.map((ep) => (
            <div key={ep.path} className="panel-surface rounded-lg p-4 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 font-mono text-xs">
                  <span className="text-emerald-400 font-semibold">{ep.method}</span>
                  <span className="text-zinc-100 font-medium">{ep.path}</span>
                </div>
                <span className="text-xs font-mono text-zinc-500">{ep.returns}</span>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed">{ep.purpose}</p>
              <div className="relative">
                <pre className="code-well rounded-md p-3.5 text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed pr-20">
                  <code>{ep.example}</code>
                </pre>
                <button
                  type="button"
                  onClick={() => copy(ep.path, ep.example)}
                  className="absolute top-2.5 right-2.5 inline-flex items-center gap-1 text-[11px] text-zinc-300 hover:text-zinc-100 bg-[#111114] border border-[#202026] rounded px-2 py-1 cursor-pointer"
                >
                  {copiedId === ep.path ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedId === ep.path ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
