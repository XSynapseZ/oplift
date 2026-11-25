import zlib from 'node:zlib';
import type { BytecodeDialect, ParseDiagnostic, ParsedChunk } from './types.ts';
import { LuauParseError, parseLuauBytecode } from './luauParser.ts';
import { parseLua5xBytecode } from './lua5xParser.ts';

const MAX_BYTECODE_BYTES = 4 * 1024 * 1024; // 4 MiB hard safety limit

export function decodeInputBytes(input: string): {
  bytes?: Uint8Array;
  inputFormat?: 'base64' | 'hex';
  error?: ParseDiagnostic;
} {
  let trimmed = input.replace(/^\uFEFF/, '').trim();
  // Strip matching outer quotes if user pasted a JSON/Lua string literal
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  if (!trimmed) {
    return {
      error: {
        severity: 'error',
        code: 'EMPTY_INPUT',
        message: 'Field "script" is empty. Supply base64-encoded or hex-encoded Lua/Luau bytecode.',
        section: 'request.script',
      },
    };
  }

  // Detect pure hex (optional 0x prefix, \x escapes, or whitespace-separated bytes)
  const hexCandidate = trimmed.replace(/\\x/gi, '').replace(/^0x/i, '').replace(/[\s,]+/g, '');
  const looksLikeHex =
    hexCandidate.length >= 8 &&
    hexCandidate.length % 2 === 0 &&
    /^[0-9a-fA-F]+$/.test(hexCandidate) &&
    (trimmed.includes(' ') ||
      trimmed.includes('\\x') ||
      trimmed.startsWith('0x') ||
      trimmed.startsWith('0X') ||
      /^1b4c7561/i.test(hexCandidate) ||
      /^0[3-9a-fA-F]0[0-4]/i.test(hexCandidate) ||
      /^1[0-4]0[1-4]/i.test(hexCandidate));

  if (looksLikeHex) {
    if (hexCandidate.length / 2 > MAX_BYTECODE_BYTES) {
      return {
        error: {
          severity: 'error',
          code: 'PAYLOAD_TOO_LARGE',
          message: `Bytecode exceeds maximum allowed size of ${MAX_BYTECODE_BYTES} bytes.`,
          section: 'request.script',
        },
      };
    }
    const bytes = new Uint8Array(hexCandidate.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexCandidate.slice(i * 2, i * 2 + 2), 16);
    }
    return { bytes, inputFormat: 'hex' };
  }

  // Decode base64 (strip whitespace / data-uri prefix if user pasted one)
  const b64Clean = trimmed.replace(/^data:[^;]+;base64,/i, '').replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(b64Clean)) {
    return {
      error: {
        severity: 'error',
        code: 'INVALID_BASE64',
        message: 'Input is neither valid base64 nor valid hexadecimal bytecode.',
        section: 'request.script',
        hint: 'Encode compiled .luauc / .luac binary bytes as base64 (or hex with 0x prefix).',
      },
    };
  }

  // Normalize URL-safe base64
  const normalized = b64Clean.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.length % 4 === 0 ? normalized : normalized + '='.repeat(4 - (normalized.length % 4));

  try {
    const buf = Buffer.from(padded, 'base64');
    if (buf.length > MAX_BYTECODE_BYTES) {
      return {
        error: {
          severity: 'error',
          code: 'PAYLOAD_TOO_LARGE',
          message: `Decoded bytecode (${buf.length} bytes) exceeds maximum allowed size of ${MAX_BYTECODE_BYTES} bytes.`,
          section: 'request.script',
        },
      };
    }
    return { bytes: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), inputFormat: 'base64' };
  } catch {
    return {
      error: {
        severity: 'error',
        code: 'BASE64_DECODE_FAILED',
        message: 'Failed to decode base64 script payload.',
        section: 'request.script',
      },
    };
  }
}

function isZstdMagic(b: Uint8Array, off = 0): boolean {
  return (
    b.length >= off + 4 &&
    b[off] === 0x28 &&
    b[off + 1] === 0xb5 &&
    b[off + 2] === 0x2f &&
    b[off + 3] === 0xfd
  );
}

function tryUnwrapCompressedBytecode(bytes: Uint8Array): {
  bytes: Uint8Array;
  container?: string;
} {
  const zstdDecompress = (zlib as unknown as { zstdDecompressSync?: (buf: Uint8Array) => Buffer }).zstdDecompressSync;

  // 1. Raw Zstd stream (28 b5 2f fd)
  if (isZstdMagic(bytes, 0) && zstdDecompress) {
    try {
      const out = zstdDecompress(bytes);
      if (out.length > 0 && out.length <= MAX_BYTECODE_BYTES) {
        return { bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength), container: 'zstd' };
      }
    } catch {
      // Fall through
    }
  }

  // 2. Plain Roblox RSB1 container: "RSB1" + uint32 LE uncompressedSize + zstd (or raw uncompressed) payload
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x53 &&
    bytes[2] === 0x42 &&
    bytes[3] === 0x31
  ) {
    if (isZstdMagic(bytes, 8) && zstdDecompress) {
      try {
        const out = zstdDecompress(bytes.subarray(8));
        if (out.length > 0 && out.length <= MAX_BYTECODE_BYTES) {
          return { bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength), container: 'rsb1-zstd' };
        }
      } catch {
        // Fall through
      }
    } else {
      const uncompSize =
        (bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>> 0;
      if (uncompSize === bytes.length - 8 && bytes[8] >= 3 && bytes[8] <= 20) {
        return { bytes: bytes.subarray(8), container: 'rsb1-raw' };
      }
    }
  }

  // 3. Roblox XOR-masked RSB1 container (ProtectedString / executor getscriptbytecode):
  //    encoded[i] = plain[i] ^ ((key[i & 3] + i * 41) & 0xff), where plain[0..3] == "RSB1" and plain[8..11] == Zstd magic
  if (bytes.length >= 16 && zstdDecompress) {
    const key0 = (bytes[0] ^ 0x52) & 0xff;
    const key1 = ((bytes[1] ^ 0x53) - 41) & 0xff;
    const key2 = ((bytes[2] ^ 0x42) - 82) & 0xff;
    const key3 = ((bytes[3] ^ 0x31) - 123) & 0xff;
    const key = [key0, key1, key2, key3];

    const u8 = (i: number) => (bytes[i] ^ ((key[i & 3] + i * 41) & 0xff)) & 0xff;
    if (u8(8) === 0x28 && u8(9) === 0xb5 && u8(10) === 0x2f && u8(11) === 0xfd) {
      const uncompSize = (u8(4) | (u8(5) << 8) | (u8(6) << 16) | (u8(7) << 24)) >>> 0;
      if (uncompSize > 0 && uncompSize <= MAX_BYTECODE_BYTES) {
        const unmasked = new Uint8Array(bytes.length - 8);
        for (let i = 8; i < bytes.length; i++) {
          unmasked[i - 8] = (bytes[i] ^ ((key[i & 3] + i * 41) & 0xff)) & 0xff;
        }
        try {
          const out = zstdDecompress(unmasked);
          if (out.length > 0 && out.length <= MAX_BYTECODE_BYTES) {
            return { bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength), container: 'rsb1-xor-zstd' };
          }
        } catch {
          // Not a valid XOR-RSB1 stream
        }
      }
    }
  }

  // 4. Gzip (1f 8b) or zlib (78 01 / 78 9c / 78 da) wrapped bytecode
  if (bytes.length >= 10 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    try {
      const out = zlib.gunzipSync(bytes, { maxOutputLength: MAX_BYTECODE_BYTES });
      if (out.length > 0) {
        return { bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength), container: 'gzip' };
      }
    } catch {
      // Fall through
    }
  }
  if (bytes.length >= 6 && bytes[0] === 0x78 && (bytes[1] === 0x01 || bytes[1] === 0x9c || bytes[1] === 0xda)) {
    try {
      const out = zlib.inflateSync(bytes, { maxOutputLength: MAX_BYTECODE_BYTES });
      if (out.length > 0) {
        return { bytes: new Uint8Array(out.buffer, out.byteOffset, out.byteLength), container: 'zlib' };
      }
    } catch {
      // Fall through
    }
  }

  return { bytes };
}

export function detectDialect(bytes: Uint8Array): { dialect: BytecodeDialect; magicHex: string } {
  const unwrapped = tryUnwrapCompressedBytecode(bytes).bytes;
  const magicHex = Array.from(unwrapped.subarray(0, Math.min(8, unwrapped.length)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');

  if (unwrapped.length >= 4 && unwrapped[0] === 0x1b && unwrapped[1] === 0x4c && unwrapped[2] === 0x75 && unwrapped[3] === 0x61) {
    const v = unwrapped[4];
    if (v === 0x51) return { dialect: 'lua51', magicHex };
    if (v === 0x52) return { dialect: 'lua52', magicHex };
    if (v === 0x53) return { dialect: 'lua53', magicHex };
    if (v === 0x54) return { dialect: 'lua54', magicHex };
    return { dialect: 'lua51', magicHex };
  }

  if (unwrapped.length >= 3 && unwrapped[0] === 0x1b && unwrapped[1] === 0x4c && unwrapped[2] === 0x4a) {
    return { dialect: 'luajit', magicHex };
  }

  // MoonSharp binary dump header starts with 0x1A 0x0D 0x23 0x1D ("MoonSharp" signature)
  if (unwrapped.length >= 4 && unwrapped[0] === 0x1a && unwrapped[1] === 0x0d && unwrapped[2] === 0x23 && unwrapped[3] === 0x1d) {
    return { dialect: 'moonsharp', magicHex };
  }

  // Luau bytecode version bytes 3..20 (and experimental 100)
  if (unwrapped.length >= 2 && ((unwrapped[0] >= 3 && unwrapped[0] <= 20) || unwrapped[0] === 100)) {
    return { dialect: 'luau', magicHex };
  }

  return { dialect: 'unknown', magicHex };
}

export function parseAnyBytecode(
  rawBytes: Uint8Array,
  autoDecodeRoblox227 = true
): { chunk?: ParsedChunk; dialect: BytecodeDialect; diagnostics: ParseDiagnostic[] } {
  const unwrapped = tryUnwrapCompressedBytecode(rawBytes);
  const bytes = unwrapped.bytes;
  const containerDiags: ParseDiagnostic[] = unwrapped.container
    ? [
        {
          severity: 'info',
          code: 'CONTAINER_DECOMPRESSED',
          message: `Unwrapped ${unwrapped.container} bytecode container (${rawBytes.length} -> ${bytes.length} bytes).`,
          byteOffset: 0,
          section: 'header',
        },
      ]
    : [];

  // Detect Luau compiler error blob (byte 0 == 0x00 followed by UTF-8 compiler error message)
  if (bytes.length >= 4 && bytes[0] === 0x00) {
    const errSlice = bytes.subarray(1, Math.min(bytes.length, 256));
    const printable = errSlice.every((b) => (b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09);
    if (printable) {
      const errText = Buffer.from(errSlice).toString('utf8').trim();
      return {
        dialect: 'luau',
        diagnostics: [
          {
            severity: 'error',
            code: 'LUAU_COMPILE_ERROR_BLOB',
            message: `Input is a Luau compile-error payload (version byte 0x00): ${errText}`,
            byteOffset: 0,
            section: 'header',
          },
        ],
      };
    }
  }

  const { dialect, magicHex } = detectDialect(bytes);

  try {
    if (dialect === 'luau') {
      const res = parseLuauBytecode(bytes, autoDecodeRoblox227);
      return { chunk: res.chunk, dialect: 'luau', diagnostics: [...containerDiags, ...res.diagnostics] };
    }
    if (dialect === 'lua51' || dialect === 'lua52' || dialect === 'lua53' || dialect === 'lua54') {
      const res = parseLua5xBytecode(bytes);
      return { chunk: res.chunk, dialect: res.chunk.dialect, diagnostics: [...containerDiags, ...res.diagnostics] };
    }
    if (dialect === 'luajit') {
      const ljVer = bytes[3] ?? 0;
      const flags = bytes[4] ?? 0;
      return {
        dialect: 'luajit',
        diagnostics: [
          {
            severity: 'warning',
            code: 'LUAJIT_HEADER_DETECTED',
            message: `Detected LuaJIT bytecode header (magic 1b 4c 4a, version ${ljVer}, flags 0x${flags.toString(16)}). Header inspection succeeded; full LuaJIT BC_x lifting is not enabled in this build.`,
            byteOffset: 0,
            section: 'header',
            hint: 'Full decompilation currently targets Luau (v3–v6, standard & Roblox *227), Lua 5.1, and Lua 5.4.',
          },
        ],
      };
    }
    if (dialect === 'moonsharp') {
      return {
        dialect: 'moonsharp',
        diagnostics: [
          {
            severity: 'warning',
            code: 'MOONSHARP_HEADER_DETECTED',
            message: 'Detected MoonSharp binary dump signature (1a 0d 23 1d). Header inspection succeeded; full MoonSharp IL lifting is not enabled in this build.',
            byteOffset: 0,
            section: 'header',
          },
        ],
      };
    }

    return {
      dialect: 'unknown',
      diagnostics: [
        {
          severity: 'error',
          code: 'UNRECOGNIZED_BYTECODE_MAGIC',
          message: `Unrecognized bytecode header [${magicHex}] (${bytes.length} bytes).`,
          byteOffset: 0,
          section: 'header',
          hint: 'Expected Luau bytecode (first byte 0x03–0x0e), Lua 5.x (1b 4c 75 61), or LuaJIT (1b 4c 4a).',
        },
      ],
    };
  } catch (err) {
    if (err instanceof LuauParseError) {
      return {
        dialect,
        diagnostics: [err.toDiagnostic()],
      };
    }
    return {
      dialect,
      diagnostics: [
        {
          severity: 'error',
          code: 'INTERNAL_PARSE_ERROR',
          message: err instanceof Error ? err.message : 'Unexpected parser failure.',
          section: 'parser',
        },
      ],
    };
  }
}
