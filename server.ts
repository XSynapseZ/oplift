import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import {
  buildDisassembly,
  decompileBytecode,
  decompileBytesDirect,
  inspectBytecode,
} from './src/engine/decompiler.ts';
import { decodeInputBytes, parseAnyBytecode } from './src/engine/parser.ts';
import { getBenchmarkSuite } from './src/engine/assembler.ts';
import {
  ROBLOX_DECOMPILER_LANDSCAPE,
  scoreDecompiledOutput,
} from './src/engine/comparator.ts';
import { DEFAULT_DECOMPILE_OPTIONS } from './src/engine/types.ts';
import type { DecompileOptions } from './src/engine/types.ts';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const LUA_EXPERT_LIVE_URL = 'https://api.lua.expert/v1/decompile';
const LUAU_COMPILE_BIN = path.resolve(__dirname, 'bin', 'luau-compile');
const MAX_SOURCE_BYTES = 64 * 1024;

async function compileLuauSource(
  source: string,
  optLevel: 0 | 1 | 2,
  debugLevel: 0 | 1 | 2
): Promise<{ ok: true; bytes: Buffer; timingMs: number } | { ok: false; error: string; timingMs: number }> {
  if (!fs.existsSync(LUAU_COMPILE_BIN)) {
    return {
      ok: false,
      error: 'Real Luau compiler binary (bin/luau-compile) is not present on the server.',
      timingMs: 0,
    };
  }
  if (Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES) {
    return {
      ok: false,
      error: `Luau source exceeds maximum allowed size of ${MAX_SOURCE_BYTES / 1024} KB.`,
      timingMs: 0,
    };
  }

  const tmpPath = path.join(os.tmpdir(), `oplift_${crypto.randomUUID()}.luau`);
  const t0 = performance.now();
  try {
    try {
      const st = await fs.promises.stat(LUAU_COMPILE_BIN);
      if ((st.mode & 0o111) === 0) {
        await fs.promises.chmod(LUAU_COMPILE_BIN, 0o755);
      }
    } catch {
      // Ignore chmod error if binary is on a read-only filesystem
    }
    await fs.promises.writeFile(tmpPath, source, 'utf8');
    const { stdout } = await execFileAsync(
      LUAU_COMPILE_BIN,
      ['--binary', `-O${optLevel}`, `-g${debugLevel}`, '-t1', tmpPath],
      {
        encoding: 'buffer',
        timeout: 5000,
        maxBuffer: 4 * 1024 * 1024,
      }
    );
    const bytes = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
    const timingMs = Number((performance.now() - t0).toFixed(2));
    if (bytes.length === 0 || bytes[0] === 0) {
      const errText = bytes.length > 1 ? bytes.subarray(1).toString('utf8').trim() : 'Luau compiler produced empty or error bytecode.';
      return { ok: false, error: errText, timingMs };
    }
    return { ok: true, bytes, timingMs };
  } catch (err) {
    const timingMs = Number((performance.now() - t0).toFixed(2));
    const e = err as { stderr?: Buffer | string; stdout?: Buffer | string; message?: string };
    const stderrText = e.stderr ? e.stderr.toString('utf8').trim() : '';
    const stdoutErr =
      Buffer.isBuffer(e.stdout) && e.stdout.length > 1 && e.stdout[0] === 0
        ? e.stdout.subarray(1).toString('utf8').trim()
        : '';
    return {
      ok: false,
      error: stderrText || stdoutErr || e.message || 'Luau compilation failed.',
      timingMs,
    };
  } finally {
    await fs.promises.unlink(tmpPath).catch(() => {});
  }
}

const app = express();
app.disable('x-powered-by');

// Public stateless CORS middleware for callable API & roblox-bridge custom endpoint compatibility
function publicApiCors(req: Request, res: Response, next: NextFunction) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Requested-With');
  res.setHeader('X-Decompiler-Engine', 'OpLift');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

// Parse JSON, plain-text (raw base64/hex), and raw octet-stream (Medal / executor raw binary)
app.use(express.json({ limit: '4mb' }));
app.use(express.text({ type: ['text/plain', 'application/x-www-form-urlencoded'], limit: '4mb' }));
app.use(express.raw({ type: ['application/octet-stream', 'application/luau', 'application/lua'], limit: '4mb' }));

function sanitizeOptions(raw: unknown): Partial<DecompileOptions> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const src = raw as Record<string, unknown>;
  const out: Partial<DecompileOptions> = {};

  if (src.renamingType === 'SEMANTIC' || src.renamingType === 'UNIQUE_VALUE_BASED' || src.renamingType === 'NONE') {
    out.renamingType = src.renamingType;
  }
  if (src.lineInfoMode === 'FUNCTION_LEVEL' || src.lineInfoMode === 'FULL' || src.lineInfoMode === 'NONE') {
    out.lineInfoMode = src.lineInfoMode;
  }

  const boolKeys: Array<keyof DecompileOptions> = [
    'useDebugLocals',
    'ifExpressions',
    'virtualizeContinue',
    'resugarInterpolatedStrings',
    'compoundAssignments',
    'genericForSugaring',
    'tableFunctionSugaring',
    'numericForStepSugaring',
    'foldTableLiterals',
    'foldConstants',
    'eliminateDeadBranches',
    'pruneReturnParens',
    'autoDecodeRoblox227',
    'upvalueComments',
    'emitBlankLines',
    'emitHeader',
    'emitUtf8',
    'integralFloatsAsInts',
    'scientificNotation',
    'emitTypeAnnotations',
  ];

  for (const key of boolKeys) {
    if (typeof src[key] === 'boolean') {
      (out as Record<string, unknown>)[key] = src[key];
    }
  }
  return out;
}

// Extract script bytes or base64/hex string from JSON, raw text, or raw binary body
function extractPayload(req: Request): {
  kind: 'string' | 'bytes';
  str?: string;
  bytes?: Uint8Array;
  options: Partial<DecompileOptions>;
  includeDisassembly: boolean;
  requestedFormat?: 'json' | 'text';
} | { error: string } {
  const body = req.body;

  if (Buffer.isBuffer(body)) {
    if (body.length === 0) return { error: 'Empty binary body.' };
    // Check if the buffer actually holds ASCII base64/JSON text sent with octet-stream header
    const asText = body.toString('utf8').trim();
    if (asText.startsWith('{') && asText.endsWith('}')) {
      try {
        const parsed = JSON.parse(asText) as Record<string, unknown>;
        const scriptVal = parsed.script ?? parsed.bytecode ?? parsed.data;
        if (typeof scriptVal === 'string') {
          return {
            kind: 'string',
            str: scriptVal,
            options: sanitizeOptions(parsed.decompilerOptions ?? parsed.options),
            includeDisassembly: Boolean(parsed.includeDisassembly),
            requestedFormat: parsed.format === 'json' || parsed.format === 'text' ? parsed.format : undefined,
          };
        }
      } catch {
        // Not JSON; treat as raw bytecode
      }
    }
    const rawBytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    // If raw bytes do not start with a known binary/compressed bytecode header AND look like ASCII base64/hex, treat as string
    const looksLikeAsciiEncoded =
      asText.length >= 8 &&
      !/[\x00-\x08\x0e-\x1f\x7f-\xff]/.test(asText) &&
      (/^[A-Za-z0-9+/_=\s-]+$/.test(asText) || /^(0x)?[0-9a-fA-F\s,\\x]+$/i.test(asText));
    if (looksLikeAsciiEncoded && rawBytes[0] >= 0x20) {
      const decTest = decodeInputBytes(asText);
      if (decTest.bytes && decTest.bytes.length >= 2) {
        return {
          kind: 'string',
          str: asText,
          options: {},
          includeDisassembly: false,
        };
      }
    }
    return {
      kind: 'bytes',
      bytes: rawBytes,
      options: {},
      includeDisassembly: false,
    };
  }

  if (typeof body === 'string') {
    const trimmed = body.trim();
    if (!trimmed) return { error: 'Empty text body.' };
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        const scriptVal = parsed.script ?? parsed.bytecode ?? parsed.data;
        if (typeof scriptVal === 'string') {
          return {
            kind: 'string',
            str: scriptVal,
            options: sanitizeOptions(parsed.decompilerOptions ?? parsed.options),
            includeDisassembly: Boolean(parsed.includeDisassembly),
            requestedFormat: parsed.format === 'json' || parsed.format === 'text' ? parsed.format : undefined,
          };
        }
      } catch {
        // Fall through to raw base64/hex string
      }
    }
    return {
      kind: 'string',
      str: trimmed,
      options: {},
      includeDisassembly: false,
    };
  }

  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const obj = body as Record<string, unknown>;
    const scriptVal = obj.script ?? obj.bytecode ?? obj.data;
    if (typeof scriptVal !== 'string' || !scriptVal.trim()) {
      return { error: 'Missing string field "script" (base64 or hex bytecode).' };
    }
    return {
      kind: 'string',
      str: scriptVal,
      options: sanitizeOptions(obj.decompilerOptions ?? obj.options),
      includeDisassembly: Boolean(obj.includeDisassembly),
      requestedFormat: obj.format === 'json' || obj.format === 'text' ? obj.format : undefined,
    };
  }

  return { error: 'Unsupported request body. Send JSON {"script":"<base64>"}, raw base64 text, or raw binary bytecode.' };
}

// Unified decompile handler supporting both drop-in plain-text mode (lua.expert / roblox-bridge / Medal)
// and structured JSON envelope mode (/api/v1/decompile)
function handleDecompile(defaultFormat: 'text' | 'json') {
  return (req: Request, res: Response) => {
    const extracted = extractPayload(req);
    if ('error' in extracted) {
      if (defaultFormat === 'text') {
        res
          .status(400)
          .type('text/plain; charset=utf-8')
          .send(`-- https://oplift.ai.studio\n\n-- OpLift Error: ${extracted.error}\n`);
      } else {
        res.status(400).json({
          ok: false,
          source: `-- https://oplift.ai.studio\n\n-- OpLift Error: ${extracted.error}\n`,
          dialect: 'unknown',
          diagnostics: [{ severity: 'error', code: 'INVALID_REQUEST', message: extracted.error }],
          imports: [],
          strings: [],
        });
      }
      return;
    }

    const result =
      extracted.kind === 'bytes' && extracted.bytes
        ? decompileBytesDirect(extracted.bytes, extracted.options, {
            includeDisassembly: extracted.includeDisassembly,
          })
        : decompileBytecode(extracted.str ?? '', extracted.options, {
            includeDisassembly: extracted.includeDisassembly,
          });

    const accept = (req.headers.accept ?? '').toLowerCase();
    const wantsText =
      extracted.requestedFormat === 'text' ||
      (extracted.requestedFormat !== 'json' &&
        (defaultFormat === 'text' || (accept.includes('text/plain') && !accept.includes('application/json'))));

    if (!result.ok) {
      if (wantsText) {
        const first = result.diagnostics[0];
        const msg = first
          ? `-- ${first.code}: ${first.message}${first.hint ? ` Hint: ${first.hint}` : ''}`
          : '-- Failed to decompile bytecode.';
        res
          .status(400)
          .type('text/plain; charset=utf-8')
          .send(result.source ?? `-- https://oplift.ai.studio\n\n${msg}\n`);
      } else {
        res.status(400).json(result);
      }
      return;
    }

    if (wantsText) {
      res.setHeader('X-OpLift-Dialect', result.dialect);
      res.setHeader('X-OpLift-Encoding', result.encoding ?? 'standard');
      res.setHeader('X-OpLift-Timing-Ms', String(result.timingMs));
      res.status(200).type('text/plain; charset=utf-8').send(result.source ?? '-- https://oplift.ai.studio\n\n');
      return;
    }

    res.status(200).json(result);
  };
}

// Drop-in endpoints for roblox-bridge.rbx-bridge-9306.workers.dev, lua.expert v1/v2 clients, and Medal clients
app.options(['/decompile', '/v1/decompile', '/luau/decompile', '/api/v1/*splat', '/script.lua'], publicApiCors);
app.use(['/decompile', '/v1/decompile', '/luau/decompile', '/api/v1', '/script.lua'], publicApiCors);

app.post('/decompile', handleDecompile('text'));
app.post('/v1/decompile', handleDecompile('text'));
app.post('/luau/decompile', handleDecompile('text'));

// Full structured JSON API routes
app.post('/api/v1/decompile', handleDecompile('json'));

app.get('/api/v1/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'OpLift',
    version: '1.0.0',
    luauCompiler: {
      available: fs.existsSync(LUAU_COMPILE_BIN),
      release: '0.748',
      bytecodeVersion: 14,
    },
    dialects: {
      fullDecompile: ['luau-v3..v14', 'luau-roblox-227', 'lua-5.1', 'lua-5.4'],
      headerInspect: ['lua-5.2', 'lua-5.3', 'luajit', 'moonsharp'],
    },
    compatibleClients: [
      'roblox-bridge.rbx-bridge-9306.workers.dev (/decompile or /v1/decompile)',
      'lua.expert v1/v2 JSON ({ script, decompilerOptions })',
      'Self-hosted Medal raw binary / base64 POST',
    ],
    defaultOptions: DEFAULT_DECOMPILE_OPTIONS,
  });
});

app.post('/api/v1/disassemble', (req, res) => {
  const t0 = performance.now();
  const extracted = extractPayload(req);
  if ('error' in extracted) {
    res.status(400).json({ ok: false, error: extracted.error });
    return;
  }

  let bytes: Uint8Array;
  if (extracted.kind === 'bytes' && extracted.bytes) {
    bytes = extracted.bytes;
  } else {
    const dec = decodeInputBytes(extracted.str ?? '');
    if (dec.error || !dec.bytes) {
      res.status(400).json({ ok: false, diagnostics: [dec.error] });
      return;
    }
    bytes = dec.bytes;
  }

  const parsed = parseAnyBytecode(bytes, extracted.options.autoDecodeRoblox227 ?? true);
  if (!parsed.chunk) {
    res.status(400).json({
      ok: false,
      dialect: parsed.dialect,
      diagnostics: parsed.diagnostics,
      timingMs: Number((performance.now() - t0).toFixed(2)),
    });
    return;
  }

  res.json({
    ok: true,
    dialect: parsed.chunk.dialect,
    version: parsed.chunk.version,
    versionLabel: parsed.chunk.versionLabel,
    encoding: parsed.chunk.encoding,
    headerInfo: parsed.chunk.headerInfo,
    stringTable: parsed.chunk.stringTable,
    disassembly: buildDisassembly(parsed.chunk),
    diagnostics: parsed.diagnostics,
    timingMs: Number((performance.now() - t0).toFixed(2)),
  });
});

app.post('/api/v1/inspect', (req, res) => {
  const body = req.body as Record<string, unknown>;
  const scriptVal = typeof body === 'string' ? body : body?.script ?? body?.bytecode;
  if (typeof scriptVal !== 'string' || !scriptVal.trim()) {
    res.status(400).json({ ok: false, error: 'Missing string field "script".' });
    return;
  }
  const result = inspectBytecode(scriptVal);
  res.status(result.ok ? 200 : 400).json(result);
});

app.post('/api/v1/batch', (req, res) => {
  const t0 = performance.now();
  const body = req.body as Record<string, unknown>;
  if (!body || !Array.isArray(body.scripts)) {
    res.status(400).json({ ok: false, error: 'Expected JSON body {"scripts": [{"id": "...", "script": "<base64>"}], "decompilerOptions": {...}}.' });
    return;
  }
  if (body.scripts.length === 0 || body.scripts.length > 25) {
    res.status(400).json({ ok: false, error: 'Batch size must be between 1 and 25 scripts.' });
    return;
  }

  const sharedOpts = sanitizeOptions(body.decompilerOptions ?? body.options);
  const results = body.scripts.map((item: unknown, idx: number) => {
    const entry = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
    const id = typeof entry.id === 'string' ? entry.id : `script_${idx}`;
    const scriptStr = typeof entry.script === 'string' ? entry.script : '';
    const itemOpts = { ...sharedOpts, ...sanitizeOptions(entry.decompilerOptions) };
    const result = decompileBytecode(scriptStr, itemOpts, { includeDisassembly: false });
    return { id, ...result };
  });

  res.json({
    ok: true,
    count: results.length,
    succeeded: results.filter((r) => r.ok).length,
    totalTimingMs: Number((performance.now() - t0).toFixed(2)),
    results,
  });
});

app.get('/api/v1/benchmarks', (_req, res) => {
  const suite = getBenchmarkSuite();
  const evaluated = suite.map((c) => {
    const ours = decompileBytecode(c.bytecodeBase64, {}, { includeDisassembly: true });
    const ourScore = scoreDecompiledOutput(ours.source, ours.ok ? 200 : 400);
    const theirScore = scoreDecompiledOutput(c.luaExpertV2Output, c.luaExpertV2Status);
    return {
      ...c,
      oplift: {
        ok: ours.ok,
        status: ours.ok ? 200 : 400,
        source: ours.source ?? '',
        timingMs: ours.timingMs,
        encoding: ours.encoding,
        metrics: ours.metrics,
        diagnostics: ours.diagnostics,
        disassembly: ours.disassembly,
        score: ourScore,
      },
      luaExpertScore: theirScore,
    };
  });

  const avgOurs = evaluated.reduce((a, b) => a + b.oplift.score.score, 0) / evaluated.length;
  const avgV2 = evaluated.reduce((a, b) => a + b.luaExpertScore.score, 0) / evaluated.length;

  res.json({
    ok: true,
    corpusSummary: {
      totalCases: evaluated.length,
      opliftAverageScore: Number(avgOurs.toFixed(1)),
      luaExpertV2AverageScore: Number(avgV2.toFixed(1)),
    },
    cases: evaluated,
    landscape: ROBLOX_DECOMPILER_LANDSCAPE,
  });
});

// Live comparison against the hardcoded https://api.lua.expert/v1/decompile endpoint (strictly allowlisted, zero SSRF)
app.post('/api/v1/benchmark/live', async (req, res) => {
  const body = req.body as Record<string, unknown>;
  const scriptVal = typeof body?.script === 'string' ? body.script.trim() : '';
  if (!scriptVal) {
    res.status(400).json({ ok: false, error: 'Missing "script" field (base64 bytecode).' });
    return;
  }

  const opts = sanitizeOptions(body.decompilerOptions);
  const ours = decompileBytecode(scriptVal, opts, { includeDisassembly: true });
  const ourScore = scoreDecompiledOutput(ours.source, ours.ok ? 200 : 400);

  let luaExpertLive: {
    reachable: boolean;
    status: number;
    timingMs: number;
    output: string;
    score: ReturnType<typeof scoreDecompiledOutput>;
  };

  const t0 = performance.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12_000);
    const upstream = await fetch(LUA_EXPERT_LIVE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpLift-Benchmark/1.0',
      },
      body: JSON.stringify({ script: scriptVal }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await upstream.text();
    const elapsed = Number((performance.now() - t0).toFixed(1));
    luaExpertLive = {
      reachable: true,
      status: upstream.status,
      timingMs: elapsed,
      output: text,
      score: scoreDecompiledOutput(text, upstream.status),
    };
  } catch (err) {
    const elapsed = Number((performance.now() - t0).toFixed(1));
    luaExpertLive = {
      reachable: false,
      status: 0,
      timingMs: elapsed,
      output: err instanceof Error ? `Upstream request failed: ${err.message}` : 'Upstream unreachable',
      score: scoreDecompiledOutput(undefined, 0),
    };
  }

  res.json({
    ok: true,
    oplift: {
      ...ours,
      score: ourScore,
    },
    luaExpertV2: luaExpertLive,
  });
});

// Side-by-side Comparison Playground endpoint: accepts either Luau source (compiled via real Luau 0.660 binary)
// or pre-compiled Base64/Hex bytecode, then runs BOTH OpLift and live https://api.lua.expert/v1/decompile
app.post('/api/v1/compare', async (req, res) => {
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
  const mode: 'source' | 'bytecode' = body.mode === 'bytecode' ? 'bytecode' : 'source';
  const input = typeof body.input === 'string' ? body.input : typeof body.script === 'string' ? body.script : '';

  if (!input.trim()) {
    res.status(400).json({
      ok: false,
      error: mode === 'source' ? 'Provide Luau source code in "input".' : 'Provide Base64 or Hex bytecode in "input".',
    });
    return;
  }

  const rawOpt = Number(body.optLevel);
  const optLevel: 0 | 1 | 2 = rawOpt === 0 || rawOpt === 2 ? rawOpt : 1;
  const rawDbg = Number(body.debugLevel);
  const debugLevel: 0 | 1 | 2 = rawDbg === 0 || rawDbg === 2 ? rawDbg : 1;
  const opts = sanitizeOptions(body.decompilerOptions ?? body.options);

  let bytecodeBase64 = '';
  let compiledBytes = 0;
  let compileTimingMs: number | null = null;

  if (mode === 'source') {
    const compiled = await compileLuauSource(input, optLevel, debugLevel);
    if (!compiled.ok) {
      res.status(400).json({
        ok: false,
        mode,
        compileError: compiled.error,
        compileTimingMs: compiled.timingMs,
      });
      return;
    }
    bytecodeBase64 = compiled.bytes.toString('base64');
    compiledBytes = compiled.bytes.length;
    compileTimingMs = compiled.timingMs;
  } else {
    const decoded = decodeInputBytes(input.trim());
    if (decoded.error || !decoded.bytes) {
      res.status(400).json({
        ok: false,
        mode,
        error: decoded.error?.message ?? 'Invalid Base64 or Hex bytecode payload.',
      });
      return;
    }
    bytecodeBase64 = Buffer.from(decoded.bytes).toString('base64');
    compiledBytes = decoded.bytes.length;
  }

  const ours = decompileBytecode(bytecodeBase64, opts, { includeDisassembly: true });
  const ourScore = scoreDecompiledOutput(ours.source, ours.ok ? 200 : 400);

  let luaExpertLive: {
    reachable: boolean;
    status: number;
    timingMs: number;
    output: string;
    score: ReturnType<typeof scoreDecompiledOutput>;
  };

  const t0 = performance.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 14_000);
    const upstream = await fetch(LUA_EXPERT_LIVE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpLift-Compare/1.0',
      },
      body: JSON.stringify({ script: bytecodeBase64 }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await upstream.text();
    const elapsed = Number((performance.now() - t0).toFixed(1));
    luaExpertLive = {
      reachable: true,
      status: upstream.status,
      timingMs: elapsed,
      output: text,
      score: scoreDecompiledOutput(text, upstream.status),
    };
  } catch (err) {
    const elapsed = Number((performance.now() - t0).toFixed(1));
    luaExpertLive = {
      reachable: false,
      status: 0,
      timingMs: elapsed,
      output: err instanceof Error ? `Upstream request failed: ${err.message}` : 'Upstream unreachable',
      score: scoreDecompiledOutput(undefined, 0),
    };
  }

  res.json({
    ok: true,
    mode,
    compilerVersion: mode === 'source' ? 'Luau 0.748 (bytecode v14)' : null,
    optLevel: mode === 'source' ? optLevel : null,
    debugLevel: mode === 'source' ? debugLevel : null,
    compiledBase64: bytecodeBase64,
    compiledBytes,
    compileTimingMs,
    oplift: {
      ...ours,
      score: ourScore,
    },
    luaExpertV2: luaExpertLive,
  });
});

app.get('/api/v1/openapi.json', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    openapi: '3.1.0',
    info: {
      title: 'OpLift Bytecode Decompiler API',
      version: '1.0.0',
      description:
        'Callable Luau (v3–v14, standard, Roblox *227, RSB1/XOR-RSB1/Zstd compressed), Lua 5.1, and Lua 5.4 decompiler, disassembler, and inspector API. Drop-in compatible with roblox-bridge.rbx-bridge-9306.workers.dev and lua.expert v1/v2 clients.',
    },
    servers: [{ url: baseUrl }],
    paths: {
      '/decompile': {
        post: {
          summary: 'Drop-in plain-text decompiler (roblox-bridge / lua.expert / Medal compatible)',
          description:
            'Accepts JSON {"script":"<base64>"}, raw base64 text/plain, or raw application/octet-stream bytecode. Returns decompiled Luau/Lua as text/plain.',
          responses: { '200': { description: 'Plain text decompiled Luau/Lua source' } },
        },
      },
      '/v1/decompile': {
        post: {
          summary: 'Drop-in lua.expert v2 compatible endpoint (returns text/plain by default)',
          responses: { '200': { description: 'Plain text decompiled source' } },
        },
      },
      '/api/v1/decompile': {
        post: {
          summary: 'Full structured JSON decompilation with metrics, imports, diagnostics, and optional disassembly',
          responses: { '200': { description: 'Structured JSON envelope' } },
        },
      },
      '/api/v1/disassemble': {
        post: {
          summary: 'Proto-by-proto instruction disassembly & constant pool dump',
          responses: { '200': { description: 'Disassembled prototypes JSON' } },
        },
      },
      '/api/v1/inspect': {
        post: {
          summary: 'Fast binary header, dialect, encoding, string, and import triage',
          responses: { '200': { description: 'Chunk triage metadata' } },
        },
      },
      '/api/v1/batch': {
        post: {
          summary: 'Batch decompile up to 25 bytecode chunks in a single request',
          responses: { '200': { description: 'Array of per-script results' } },
        },
      },
      '/api/v1/benchmark/live': {
        post: {
          summary: 'Run OpLift side-by-side against live https://api.lua.expert/v1/decompile',
          responses: { '200': { description: 'Side-by-side outputs and cleanliness scores' } },
        },
      },
      '/api/v1/compare': {
        post: {
          summary: 'Compile Luau source with real Luau 0.748 (or accept Base64/Hex/RSB1 bytecode) and run OpLift vs live api.lua.expert/v1/decompile side-by-side',
          responses: { '200': { description: 'Compiled bytecode plus side-by-side decompilation outputs' } },
        },
      },
    },
  });
});

app.get('/script.lua', (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const helper = `-- OpLift Luau Executor Helper (Drop-in replacement for lua.expert/script.lua)
-- Also works directly in https://roblox-bridge.rbx-bridge-9306.workers.dev/ Settings -> Decompiler Endpoint:
--   ${origin}/decompile

local HttpService = game:GetService("HttpService")
local ENDPOINT = "${origin}/v1/decompile"

local req = (syn and syn.request) or http_request or request
assert(req, "Executor does not expose an HTTP request function")
assert(getscriptbytecode, "Executor does not expose getscriptbytecode")

local b64encode = (crypt and crypt.base64encode) or base64_encode or base64encode
assert(b64encode, "Executor does not expose a base64 encoder")

getgenv().decompile = function(targetScript, options)
    local bytecode = getscriptbytecode(targetScript)
    local payload = HttpService:JSONEncode({
        script = b64encode(bytecode),
        decompilerOptions = options or {
            renamingType = "SEMANTIC",
            foldConstants = true,
            autoDecodeRoblox227 = true,
        },
    })

    local response = req({
        Url = ENDPOINT,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "text/plain",
        },
        Body = payload,
    })

    if response.StatusCode ~= 200 then
        return "-- OpLift decompile error (" .. tostring(response.StatusCode) .. "): " .. tostring(response.Body)
    end
    return response.Body
end
`;
  res.status(200).type('text/plain; charset=utf-8').send(helper);
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*splat', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`OpLift API & Workbench listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
