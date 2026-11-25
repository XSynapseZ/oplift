import type { BenchmarkCase } from './types.ts';
import { LUAU_AUX_OPCODES } from './luauParser.ts';

function encodeVarint(n: number): number[] {
  const out: number[] = [];
  let v = n >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
  } while (v !== 0);
  return out;
}

function abc(op: number, a: number, b = 0, c = 0): number {
  return ((op & 0xff) | ((a & 0xff) << 8) | ((b & 0xff) << 16) | ((c & 0xff) << 24)) >>> 0;
}

function ad(op: number, a: number, d: number): number {
  return ((op & 0xff) | ((a & 0xff) << 8) | ((d & 0xffff) << 16)) >>> 0;
}

function pushU32(buf: number[], v: number) {
  buf.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
}

function pushF64(buf: number[], v: number) {
  const arr = new ArrayBuffer(8);
  new DataView(arr).setFloat64(0, v, true);
  const bytes = new Uint8Array(arr);
  for (let i = 0; i < 8; i++) buf.push(bytes[i]);
}

function pushU64(buf: number[], v: number) {
  pushU32(buf, v >>> 0);
  pushU32(buf, Math.floor(v / 0x100000000) >>> 0);
}

type LuauConstSpec =
  | [0]
  | [1, boolean]
  | [2, number]
  | [3, number] // 1-based string idx
  | [4, number] // import bitfield
  | [5, number[]] // table key indices
  | [6, number]; // closure proto id

interface LuauProtoSpec {
  maxStackSize?: number;
  numParams?: number;
  nups?: number;
  isVararg?: number;
  typeinfo?: number[];
  code: number[];
  consts?: LuauConstSpec[];
  childs?: number[];
}

export function buildLuauV6Chunk(
  strings: string[],
  protos: LuauProtoSpec[],
  mainId = 0,
  robloxEncode227 = false
): Uint8Array {
  const enc = new TextEncoder();
  const buf: number[] = [6, 3]; // version=6, typesVersion=3
  buf.push(...encodeVarint(strings.length));
  for (const s of strings) {
    const sb = enc.encode(s);
    buf.push(...encodeVarint(sb.length), ...sb);
  }
  buf.push(0); // end userdata types
  buf.push(...encodeVarint(protos.length));

  for (const p of protos) {
    buf.push(p.maxStackSize ?? 10, p.numParams ?? 0, p.nups ?? 0, p.isVararg ?? 0, 0);
    const ti = p.typeinfo ?? [];
    buf.push(...encodeVarint(ti.length), ...ti);

    const code = robloxEncode227 ? encodeRobloxOpcodes(p.code) : p.code;
    buf.push(...encodeVarint(code.length));
    for (const w of code) pushU32(buf, w);

    const consts = p.consts ?? [];
    buf.push(...encodeVarint(consts.length));
    for (const c of consts) {
      buf.push(c[0]);
      if (c[0] === 1) buf.push(c[1] ? 1 : 0);
      else if (c[0] === 2) pushF64(buf, c[1]);
      else if (c[0] === 3) buf.push(...encodeVarint(c[1]));
      else if (c[0] === 4) pushU32(buf, c[1]);
      else if (c[0] === 5) {
        buf.push(...encodeVarint(c[1].length));
        for (const k of c[1]) buf.push(...encodeVarint(k));
      } else if (c[0] === 6) {
        buf.push(...encodeVarint(c[1]));
      }
    }

    const childs = p.childs ?? [];
    buf.push(...encodeVarint(childs.length));
    for (const ch of childs) buf.push(...encodeVarint(ch));

    buf.push(...encodeVarint(0)); // lineDefined
    buf.push(...encodeVarint(0)); // debugName
    buf.push(0, 0); // hasLineInfo, hasDebugInfo
  }

  buf.push(...encodeVarint(mainId));
  return new Uint8Array(buf);
}

function encodeRobloxOpcodes(code: number[]): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < code.length) {
    const w = code[i];
    const op = w & 0xff;
    out.push(((w & ~0xff) | ((op * 227) & 0xff)) >>> 0);
    if (LUAU_AUX_OPCODES.has(op) && i + 1 < code.length) {
      out.push(code[i + 1]);
      i += 2;
    } else {
      i += 1;
    }
  }
  return out;
}

function l51Abx(op: number, a: number, bx: number): number {
  return ((op & 0x3f) | ((a & 0xff) << 6) | ((bx & 0x3ffff) << 14)) >>> 0;
}

function l51Abc(op: number, a: number, b: number, c: number): number {
  return ((op & 0x3f) | ((a & 0xff) << 6) | ((c & 0x1ff) << 14) | ((b & 0x1ff) << 23)) >>> 0;
}

function buildLua51TableClosureChunk(): Uint8Array {
  const enc = new TextEncoder();
  const buf: number[] = [0x1b, 0x4c, 0x75, 0x61, 0x51, 0, 1, 4, 8, 4, 8, 0];
  // main proto
  pushU64(buf, 0); // source
  pushU32(buf, 0); pushU32(buf, 0);
  buf.push(0, 0, 2, 6); // nups, numparams, is_vararg, maxstacksize
  const mainInsns = [
    l51Abc(10, 0, 0, 2),         // NEWTABLE R0
    l51Abc(9, 0, 256 + 0, 256 + 1), // SETTABLE R0["a"] = 1
    l51Abc(9, 0, 256 + 2, 256 + 3), // SETTABLE R0["b"] = 2
    l51Abx(36, 1, 0),            // CLOSURE R1, proto 0
    l51Abc(0, 0, 0, 0),          // MOVE R0 (upvalue ref)
    l51Abc(0, 2, 1, 0),          // MOVE R2, R1
    l51Abx(1, 3, 4),             // LOADK R3, 10
    l51Abc(28, 2, 2, 2),         // CALL R2(R3) -> 1 ret
    l51Abc(30, 2, 2, 0),         // RETURN R2, 1
  ];
  pushU32(buf, mainInsns.length);
  for (const w of mainInsns) pushU32(buf, w);
  pushU32(buf, 5);
  const pushStr = (s: string) => {
    const b = enc.encode(s + '\0');
    buf.push(4);
    pushU64(buf, b.length);
    buf.push(...b);
  };
  const pushNum = (n: number) => {
    buf.push(3);
    pushF64(buf, n);
  };
  pushStr('a'); pushNum(1); pushStr('b'); pushNum(2); pushNum(10);
  // 1 child proto
  pushU32(buf, 1);
  pushU64(buf, 0); pushU32(buf, 0); pushU32(buf, 0);
  buf.push(1, 1, 0, 4); // nups=1, numparams=1, is_vararg=0, maxstack=4
  const childInsns = [
    l51Abc(4, 1, 0, 0),          // GETUPVAL R1, 0
    l51Abc(6, 1, 1, 256 + 0),    // GETTABLE R1, R1, "a"
    l51Abc(12, 1, 1, 0),         // ADD R1, R1, R0
    l51Abc(30, 1, 2, 0),         // RETURN R1, 1
  ];
  pushU32(buf, childInsns.length);
  for (const w of childInsns) pushU32(buf, w);
  pushU32(buf, 1);
  pushStr('a');
  pushU32(buf, 0); pushU32(buf, 0); pushU32(buf, 0); pushU32(buf, 0);
  pushU32(buf, 0); pushU32(buf, 0); pushU32(buf, 0);
  return new Uint8Array(buf);
}

function encodeLua54VarInt(n: number): number[] {
  const out: number[] = [];
  let v = n >>> 0;
  out.push((v & 0x7f) | 0x80);
  v = Math.floor(v / 128);
  while (v > 0) {
    out.unshift(v & 0x7f);
    v = Math.floor(v / 128);
  }
  return out;
}

function l54Abc(op: number, a: number, b: number, c: number, k = 0): number {
  return ((op & 0x7f) | ((a & 0xff) << 7) | ((k & 1) << 15) | ((b & 0xff) << 16) | ((c & 0xff) << 24)) >>> 0;
}

function l54Abx(op: number, a: number, bx: number): number {
  return ((op & 0x7f) | ((a & 0xff) << 7) | ((bx & 0x1ffff) << 15)) >>> 0;
}

function l54Asbx(op: number, a: number, sbx: number): number {
  return l54Abx(op, a, sbx + 65535);
}

function buildLua54LoopBitwiseChunk(): Uint8Array {
  const enc = new TextEncoder();
  const buf: number[] = [
    0x1b, 0x4c, 0x75, 0x61, 0x54, 0x00, // \x1bLua 5.4 format 0
    0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a, // LUAC_DATA
    4, 8, 8,                            // insnSize=4, intSize=8, numSize=8
  ];
  pushU64(buf, 0x5678); // LUAC_INT
  pushF64(buf, 370.5);  // LUAC_NUM
  buf.push(1);          // top-level upvalue count (_ENV)

  // Main proto
  buf.push(...encodeLua54VarInt(0)); // source = ""
  buf.push(...encodeLua54VarInt(0)); // linedefined
  buf.push(...encodeLua54VarInt(0)); // lastlinedefined
  buf.push(0, 1, 8);                 // numparams=0, is_vararg=1, maxstacksize=8

  // local total = 0
  // for i = 1, 10 do
  //     total = total + (i & 3)
  // end
  // return total
  const insns = [
    l54Abc(81, 0, 0, 0),      // 0: VARARGPREP 0
    l54Asbx(1, 0, 0),         // 1: LOADI R0, 0       (total = 0)
    l54Asbx(1, 1, 1),         // 2: LOADI R1, 1       (init = 1)
    l54Asbx(1, 2, 10),        // 3: LOADI R2, 10      (limit = 10)
    l54Asbx(1, 3, 1),         // 4: LOADI R3, 1       (step = 1)
    l54Abx(74, 1, 4),         // 5: FORPREP R1, Bx=4  (FORLOOP at 5+1+4=10, exit at 11)
    l54Abc(29, 5, 4, 0),      // 6: BANDK R5, R4, K0(3)
    l54Abc(48, 4, 0, 13),     // 7: MMBINK (band metamethod marker)
    l54Abc(34, 0, 0, 5),      // 8: ADD R0, R0, R5
    l54Abc(46, 0, 5, 6),      // 9: MMBIN (add metamethod marker)
    l54Abx(73, 1, 5),         // 10: FORLOOP R1, Bx=5 (10+1-5=6)
    l54Abc(72, 0, 0, 0),      // 11: RETURN1 R0
  ];
  buf.push(...encodeLua54VarInt(insns.length));
  for (const w of insns) pushU32(buf, w);

  // Constants: K0 = int 3
  buf.push(...encodeLua54VarInt(1));
  buf.push(3); // LUA_VNUMINT
  pushU64(buf, 3);

  // Upvalues: 1 (_ENV)
  buf.push(...encodeLua54VarInt(1));
  buf.push(1, 0, 0); // instack=1, idx=0, kind=0

  // Child protos: 0
  buf.push(...encodeLua54VarInt(0));

  // Debug info: lineinfo=0, absline=0, locvars=0, upvalnames=1 ("_ENV")
  buf.push(...encodeLua54VarInt(0));
  buf.push(...encodeLua54VarInt(0));
  buf.push(...encodeLua54VarInt(0));
  buf.push(...encodeLua54VarInt(1));
  const envBytes = enc.encode('_ENV');
  buf.push(...encodeLua54VarInt(envBytes.length + 1), ...envBytes);

  return new Uint8Array(buf);
}

function buildLuau2000InsnStressChunk(): Uint8Array {
  // 500 unrolled arithmetic steps (~2,004 instruction words) to test O(N) liveness & throughput
  const code: number[] = [
    abc(65, 0),       // PREPVARARGS 0
    ad(4, 0, 1),      // LOADN R0, 1
  ];
  // 500 blocks x 4 words = 2000 words: ADDK R0, R0, K0(1); MULK R1, R0, K1(2); ADD R0, R0, R1; MODK R0, R0, K2(997)
  for (let step = 0; step < 500; step++) {
    code.push(abc(39, 0, 0, 0)); // ADDK R0, R0, K0(1)
    code.push(abc(41, 1, 0, 1)); // MULK R1, R0, K1(2)
    code.push(abc(33, 0, 0, 1)); // ADD R0, R0, R1
    code.push(abc(43, 0, 0, 2)); // MODK R0, R0, K2(997)
  }
  code.push(abc(22, 0, 2)); // RETURN R0, 1

  return buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 8,
      isVararg: 1,
      code,
      consts: [[2, 1], [2, 2], [2, 997]],
    }]
  );
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

// 8 verified head-to-head benchmark cases with exact bytecode & real captured live responses from https://api.lua.expert/v1/decompile
export function getBenchmarkSuite(): BenchmarkCase[] {
  // 1. While loop + modulo if/elseif/break (SSA phi-destruction bug in lua.expert v2)
  const caseWhilePhi = buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 8, isVararg: 1,
      code: [
        abc(65, 0),
        ad(4, 0, 0),
        ad(4, 1, 0),
        ad(4, 2, 100),
        ad(32, 0, 12), 2,
        abc(39, 0, 0, 0),
        abc(43, 2, 0, 1),
        ad(79, 2, 3), (2 | (1 << 31)) >>> 0,
        abc(33, 1, 1, 0),
        ad(23, 0, 4),
        ad(4, 2, 50),
        ad(28, 0, 2), 2,
        ad(23, 0, 1),
        ad(24, 0, -14),
        abc(22, 1, 2),
      ],
      consts: [[2, 1], [2, 2], [2, 0]],
    }]
  );

  // 2. Numeric for loop + continue + break + compound assign (continue virtualization failure in lua.expert v2)
  const caseContinue = buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 8, isVararg: 1,
      code: [
        abc(65, 0),
        ad(4, 0, 0),
        ad(4, 1, 20),
        ad(4, 2, 1),
        ad(4, 3, 1),
        ad(56, 1, 11),
        ad(79, 3, 2), (0 | (1 << 31)) >>> 0,
        ad(23, 0, 7),
        ad(79, 3, 2), (1 | (1 << 31)) >>> 0,
        ad(23, 0, 5),
        abc(41, 4, 3, 2),
        abc(33, 0, 0, 4),
        abc(0, 0),
        abc(0, 0),
        ad(57, 1, -11),
        abc(22, 0, 2),
      ],
      consts: [[2, 5], [2, 15], [2, 2]],
    }]
  );

  // 3. Early-return if/elseif/else ladder + short-circuit (branch inversion in lua.expert v2)
  const caseIfElseif = buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 8, numParams: 3, isVararg: 0,
      code: [
        abc(45, 3, 0, 1),
        abc(46, 3, 3, 2),
        ad(4, 4, 10),
        ad(28, 3, 4), 4,
        abc(41, 4, 3, 0),
        abc(39, 5, 3, 1),
        abc(22, 4, 3),
        ad(4, 4, 0),
        ad(32, 3, 4), 4,
        abc(51, 4, 3),
        ad(4, 5, 0),
        abc(22, 4, 3),
        ad(4, 4, 0),
        ad(4, 5, 0),
        abc(22, 4, 3),
      ],
      consts: [[2, 2], [2, 1]],
    }]
  );

  // 4. Lua 5.1 Table literal + closure capturing mutable local reference + single-return call
  const caseLua51 = buildLua51TableClosureChunk();

  // 5. Roblox game:GetService("Players") (redundant return parens in lua.expert v2)
  const caseGetService = buildLuauV6Chunk(
    ['game', 'GetService', 'Players'],
    [{
      maxStackSize: 8, isVararg: 1,
      code: [
        abc(65, 0),
        ad(12, 0, 3), ((1 << 30) | (0 << 20)) >>> 0,
        ad(5, 2, 2),
        abc(20, 0, 0, 0), 1,
        abc(21, 0, 3, 2),
        abc(22, 0, 2),
      ],
      consts: [[3, 1], [3, 2], [3, 3], [4, ((1 << 30) | (0 << 20)) >>> 0]],
    }]
  );

  // 6. string.format interpolation + single-return paren noise
  const caseStringFormat = buildLuauV6Chunk(
    ['string', 'format', 'HP: %d/%d (%s)', 'print'],
    [{
      maxStackSize: 10, numParams: 3, isVararg: 0,
      code: [
        ad(12, 3, 4), ((2 << 30) | (0 << 20) | (1 << 10)) >>> 0,
        ad(5, 4, 2),
        abc(6, 5, 0),
        abc(6, 6, 1),
        abc(6, 7, 2),
        abc(21, 3, 5, 2),
        abc(22, 3, 2),
      ],
      consts: [
        [3, 1], [3, 2], [3, 3], [3, 4],
        [4, ((2 << 30) | (0 << 20) | (1 << 10)) >>> 0],
      ],
    }]
  );

  // 7. Constant arithmetic + opaque predicate dead branch
  const caseOpaqueConst = buildLuauV6Chunk(
    ['print', 'dead_branch'],
    [{
      maxStackSize: 6, isVararg: 1,
      code: [
        abc(65, 0),
        ad(4, 0, 10),
        ad(4, 1, 20),
        abc(33, 2, 0, 1),
        ad(4, 3, 3),
        abc(35, 0, 2, 3),
        ad(4, 1, 1),
        ad(4, 2, 1),
        ad(30, 1, 5), 2,
        ad(12, 3, 2), ((1 << 30) | (0 << 20)) >>> 0,
        abc(6, 4, 0),
        abc(21, 3, 2, 1),
        ad(23, 0, 4),
        ad(12, 3, 2), ((1 << 30) | (0 << 20)) >>> 0,
        ad(5, 4, 1),
        abc(21, 3, 2, 1),
        abc(22, 0, 1),
      ],
      consts: [[3, 1], [3, 2], [4, ((1 << 30) | (0 << 20)) >>> 0]],
    }]
  );

  // 8. Roblox client-encoded (*227 mod 256) Luau v6 bytecode (rejected by lua.expert v2 with opaque 400!)
  const caseRoblox227 = buildLuauV6Chunk(
    ['game', 'GetService', 'Players'],
    [{
      maxStackSize: 8, isVararg: 1,
      code: [
        abc(65, 0),
        ad(12, 0, 3), ((1 << 30) | (0 << 20)) >>> 0,
        ad(5, 2, 2),
        abc(20, 0, 0, 0), 1,
        abc(21, 0, 3, 2),
        abc(22, 0, 2),
      ],
      consts: [[3, 1], [3, 2], [3, 3], [4, ((1 << 30) | (0 << 20)) >>> 0]],
    }],
    0,
    true // Roblox client *227 opcode encoding
  );

  // 9. Luau repeat...until + while true do with break
  const caseRepeatWhileTrue = buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 6, isVararg: 1,
      code: [
        abc(65, 0),         // 0: PREPVARARGS 0
        ad(4, 0, 0),        // 1: LOADN R0, 0
        abc(39, 0, 0, 0),   // 2: ADDK R0, R0, K0(1)
        ad(4, 1, 10),       // 3: LOADN R1, 10
        ad(29, 0, -3), 1,   // 4..5: JUMPIFLT R0, D=-3 -> pc 2, AUX=R1
        abc(39, 0, 0, 0),   // 6: ADDK R0, R0, K0(1)
        ad(4, 1, 20),       // 7: LOADN R1, 20
        ad(29, 0, 2), 1,    // 8..9: JUMPIFLT R0, D=2 -> pc 11, AUX=R1
        ad(23, 0, 1),       // 10: JUMP D=1 -> pc 12 (break)
        ad(24, 0, -6),      // 11: JUMPBACK D=-6 -> pc 6
        abc(22, 0, 2),      // 12: RETURN R0, 1
      ],
      consts: [[2, 1]],
    }]
  );

  // 10. Luau if-expression ternary + LOADB boolean materialization + Luau typeinfo parameter annotations
  const caseTernaryLoadbTypeinfo = buildLuauV6Chunk(
    [],
    [{
      maxStackSize: 8,
      numParams: 2,
      isVararg: 0,
      // typeinfo (Luau typesVersion=3): [typeSize=4, upvalTypes=0, localTypes=0, LBC_TYPE_FUNCTION=5, numParams=2, number=2, number=2]
      typeinfo: [4, 0, 0, 5, 2, 2, 2],
      code: [
        ad(28, 0, 3), 1,    // 0..1: JUMPIFLE R0, D=3 -> pc 4, AUX=R1
        abc(6, 2, 0),       // 2: MOVE R2, R0
        ad(23, 0, 1),       // 3: JUMP D=1 -> pc 5
        abc(6, 2, 1),       // 4: MOVE R2, R1
        ad(4, 3, 0),        // 5: LOADN R3, 0
        ad(28, 2, 2), 3,    // 6..7: JUMPIFLE R2, D=2 -> pc 9, AUX=R3
        abc(3, 3, 1, 1),    // 8: LOADB R3, true, C=1 (skip next)
        abc(3, 3, 0, 0),    // 9: LOADB R3, false, C=0
        abc(22, 2, 3),      // 10: RETURN R2, R3
      ],
      consts: [],
    }]
  );

  // 11. Luau SETLIST array literal + FORGPREP_INEXT (ipairs) generic loop
  const caseSetlistIpairs = buildLuauV6Chunk(
    ['ipairs'],
    [{
      maxStackSize: 10, isVararg: 1,
      code: [
        abc(65, 0),                                   // 0: PREPVARARGS 0
        ad(4, 0, 0),                                  // 1: LOADN R0, 0
        abc(53, 1, 0, 0), 3,                          // 2..3: NEWTABLE R1, aux=3
        ad(4, 2, 10),                                 // 4: LOADN R2, 10
        ad(4, 3, 20),                                 // 5: LOADN R3, 20
        ad(4, 4, 30),                                 // 6: LOADN R4, 30
        abc(55, 1, 2, 4), 1,                          // 7..8: SETLIST R1, B=2, C=4 (3 items), start=1
        ad(12, 2, 1), ((1 << 30) | (0 << 20)) >>> 0,  // 9..10: GETIMPORT R2, ipairs
        abc(6, 3, 1),                                 // 11: MOVE R3, R1
        abc(21, 2, 2, 4),                             // 12: CALL R2(R3) -> 3 vals
        ad(59, 2, 1),                                 // 13: FORGPREP_INEXT R2 -> pc 15
        abc(33, 0, 0, 6),                             // 14: ADD R0, R0, R6
        ad(58, 2, -2), 2,                             // 15..16: FORGLOOP R2 -> pc 14, vars=2
        abc(22, 0, 2),                                // 17: RETURN R0, 1
      ],
      consts: [[3, 1], [4, ((1 << 30) | (0 << 20)) >>> 0]],
    }]
  );

  // 12. Real Lua 5.4 bytecode (LOADI, BANDK, FORPREP/FORLOOP, RETURN1)
  const caseLua54 = buildLua54LoopBitwiseChunk();

  // 13. 2,000-instruction Luau v6 throughput stress test
  const caseStress2000 = buildLuau2000InsnStressChunk();

  return [
    {
      id: 'luau-while-phi',
      title: 'While Loop + Modulo If/Elseif/Break',
      dialect: 'luau',
      flawCategory: 'SSA Phi-Destruction Artifact',
      summary: 'Loop accumulator updated in one branch with an early break in the elseif branch.',
      bytecodeBase64: toBase64(caseWhilePhi),
      originalIntent: `local i = 0\nlocal total = 0\nwhile i < 100 do\n    i += 1\n    if i % 2 == 0 then\n        total += i\n    elseif i > 50 then\n        break\n    end\nend\nreturn total`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal n1 = 0\nlocal n2 = 0\nwhile n1 < 100 do\n    n1 += 1\n    local v1\n    if n1 % 2 == 0 then\n        v1 = n2 + n1\n    elseif n1 <= 50 then\n        v1 = n2\n    else\n        break\n    end\n    n2 = v1\nend\nreturn n2\n`,
      luaExpertV2FlawNotes: [
        'Materializes bogus SSA phi temporary `local v1` inside the hot loop.',
        'Fabricates a dead self-assignment branch `elseif n1 <= 50 then v1 = n2` instead of `elseif i > 50 then break`.',
        'Breaks compound assignment (`n2 += n1` degraded into `v1 = n2 + n1` + `n2 = v1`).',
      ],
    },
    {
      id: 'luau-for-continue-break',
      title: 'Numeric For Loop + Continue + Break',
      dialect: 'luau',
      flawCategory: 'Broken Continue Virtualization',
      summary: 'Standard guard-clause `if i == 5 then continue end` followed by `if i == 15 then break end`.',
      bytecodeBase64: toBase64(caseContinue),
      originalIntent: `local total = 0\nfor i = 1, 20 do\n    if i == 5 then\n        continue\n    end\n    if i == 15 then\n        break\n    end\n    total += i * 2\nend\nreturn total`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal n1 = 0\nfor i = 1, 20 do\n    if i ~= 5 then\n        if i == 15 then\n            break\n        end\n        n1 += i * 2\n    end\nend\nreturn n1\n`,
      luaExpertV2FlawNotes: [
        'Fails to emit `continue` despite `"virtualizeContinue": true` being enabled by default.',
        'Inverts the guard condition into `if i ~= 5 then ... end` and wraps the entire loop body in an extra nesting level.',
      ],
    },
    {
      id: 'luau-if-elseif-ladder',
      title: 'Short-Circuit + If/Elseif/Else Multi-Return',
      dialect: 'luau',
      flawCategory: 'Inverted Branch Ordering',
      summary: 'Function with `a and b or c` followed by a 3-way `if / elseif / else` early-return ladder.',
      bytecodeBase64: toBase64(caseIfElseif),
      originalIntent: `local function main(a, b, c)\n    local v1 = a and b or c\n    if v1 > 10 then\n        return v1 * 2, v1 + 1\n    elseif v1 < 0 then\n        return -v1, 0\n    else\n        return 0, 0\n    end\nend\nreturn main(...)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nreturn (function(p1, p2, p3)\n    local v1 = p1 and p2 or p3\n    if v1 <= 10 then\n        if v1 < 0 then\n            return -v1, 0\n        end\n        return 0, 0\n    end\n    return v1 * 2, v1 + 1\nend)(...)\n`,
      luaExpertV2FlawNotes: [
        'Inverts `if v1 > 10` into `if v1 <= 10`, pushing the primary return path to the bottom.',
        'Collapses `if / elseif / else` into nested `if` blocks with deeper indentation.',
      ],
    },
    {
      id: 'lua51-table-closure',
      title: 'Lua 5.1 Table Literal + Closure Upvalue Ref',
      dialect: 'lua51',
      flawCategory: 'Unfolded Table & Wrong Upvalue Mode',
      summary: 'Lua 5.1 table construction captured by a local closure returning a single value.',
      bytecodeBase64: toBase64(caseLua51),
      originalIntent: `local config = {\n    a = 1,\n    b = 2,\n}\nlocal function handler(x)\n    -- upvalues: config (ref)\n    return config.a + x\nend\nreturn handler(10)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal t1 = {}\nt1.a = 1\nt1.b = 2\nlocal function v1(p1)\n    -- upvalues: t1 (copy)\n    return t1.a + p1\nend\nreturn (v1(10))\n`,
      luaExpertV2FlawNotes: [
        'Fails to fold sequential `SETTABLE` initializers after `NEWTABLE` into `{ a = 1, b = 2 }`.',
        'Mislabeled Lua 5.1 shared reference capture (`MOVE`) as `-- upvalues: t1 (copy)`.',
        'Wraps `return (v1(10))` in unnecessary outer parens even though `v1` provably has return arity 1.',
      ],
    },
    {
      id: 'luau-getservice-parens',
      title: 'Roblox game:GetService("Players")',
      dialect: 'luau',
      flawCategory: 'Over-Parenthesized Known Single-Return API',
      summary: 'Most common Roblox Luau statement: retrieving a DataModel service via `NAMECALL`.',
      bytecodeBase64: toBase64(caseGetService),
      originalIntent: `return game:GetService("Players")`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nreturn (game:GetService("Players"))\n`,
      luaExpertV2FlawNotes: [
        'Wraps provably single-return `game:GetService("Players")` in noisy parentheses `return (...)`.',
        'Injects forced promotional `-- https://lua.expert` header banner with no disable option.',
      ],
    },
    {
      id: 'luau-string-format',
      title: 'string.format Resugaring & Return Cleanup',
      dialect: 'luau',
      flawCategory: 'Interpolation & Redundant Parens',
      summary: 'Standard `string.format("HP: %d/%d (%s)", a, b, c)` formatting call.',
      bytecodeBase64: toBase64(caseStringFormat),
      originalIntent: `local function main(a, b, c)\n    return \`HP: {a}/{b} ({c})\`\nend\nreturn main(...)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nreturn (function(p1, p2, p3)\n    return (string.format("HP: %d/%d (%s)", p1, p2, p3))\nend)(...)\n`,
      luaExpertV2FlawNotes: [
        'Wraps `string.format(...)` in unnecessary outer parens despite fixed single-return stdlib arity.',
        'Does not resugar simple `%d`/`%s` `string.format` calls even with `"resugarInterpolatedStrings": true`.',
      ],
    },
    {
      id: 'luau-opaque-const-fold',
      title: 'Constant Arithmetic + Opaque Predicate',
      dialect: 'luau',
      flawCategory: 'Missing Constant Folding Pass',
      summary: 'Obfuscated `(10 + 20) * 3` arithmetic guarded by an always-true `1 == 1` branch.',
      bytecodeBase64: toBase64(caseOpaqueConst),
      originalIntent: `print(90)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nprint((10 + 20) * 3)\n`,
      luaExpertV2FlawNotes: [
        'Eliminates the dead branch, but leaves pure constant arithmetic `(10 + 20) * 3` unfolded.',
        'Offers no `foldConstants` option for cleaning obfuscated math expressions.',
      ],
    },
    {
      id: 'luau-roblox-227-encoded',
      title: 'Roblox Client Opcode-Encoded (*227) Luau v6',
      dialect: 'luau',
      flawCategory: 'Opaque 400 Failure & No Client Encoding Support',
      summary: 'Live Roblox client `getscriptbytecode` encoding where every opcode byte is multiplied by 227 mod 256.',
      bytecodeBase64: toBase64(caseRoblox227),
      originalIntent: `return game:GetService("Players")`,
      luaExpertV2Status: 400,
      luaExpertV2Output: `HTTP 400: Provided bytecode is not supported or isnt bytecode at all`,
      luaExpertV2FlawNotes: [
        'Rejects Roblox client-encoded (`op * 227 mod 256`) bytecode outright with HTTP 400.',
        'Returns a completely opaque 1-line error with zero byte offset, header info, or remediation hint.',
      ],
    },
    {
      id: 'luau-repeat-while-true',
      title: 'Repeat...Until + While True With Break',
      dialect: 'luau',
      flawCategory: 'Double-Negated Until Condition',
      summary: 'Tests backward conditional `repeat...until` followed by `while true do ... if i >= 20 then break end`.',
      bytecodeBase64: toBase64(caseRepeatWhileTrue),
      originalIntent: `local i = 0\nrepeat\n    i += 1\nuntil i >= 10\nwhile true do\n    i += 1\n    if i >= 20 then\n        break\n    end\nend\nreturn i`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal n1 = 0\nrepeat\n    n1 += 1\nuntil not (n1 < 10)\nrepeat\n    n1 += 1\nuntil not (n1 < 20)\nreturn n1\n`,
      luaExpertV2FlawNotes: [
        'Emits double-negated `until not (n1 < 10)` and `until not (n1 < 20)` instead of simplified `until i >= 10`.',
        'Collapses `while true do ... if i >= 20 then break end` into a second negated `repeat...until` loop.',
      ],
    },
    {
      id: 'luau-ternary-loadb-typeinfo',
      title: 'Luau If-Expression + LOADB Boolean + TypeInfo',
      dialect: 'luau',
      flawCategory: 'Inverted Ternary, Negated LOADB & Stripped Types',
      summary: 'Typed function `(a: number, b: number)` returning a Luau `if` expression and a `LOADB`-materialized comparison.',
      bytecodeBase64: toBase64(caseTernaryLoadbTypeinfo),
      originalIntent: `local function main(a: number, b: number)\n    local value = if a > b then a else b\n    return value, value > 0\nend\nreturn main(...)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nreturn (function(p1, p2)\n    local v1 = if p1 <= p2 then p2 else p1\n    return v1, not (v1 <= 0)\nend)(...)\n`,
      luaExpertV2FlawNotes: [
        'Inverts the ternary condition to `if p1 <= p2 then p2 else p1` and emits `not (v1 <= 0)` instead of `v1 > 0`.',
        'Omits embedded Luau `typeinfo` parameter annotations `(a: number, b: number)` under default options.',
      ],
    },
    {
      id: 'luau-setlist-ipairs',
      title: 'SETLIST Array Literal + FORGPREP_INEXT (ipairs)',
      dialect: 'luau',
      flawCategory: 'Array Table Folding & Generic Iterator Loop',
      summary: 'Constructs `{ 10, 20, 30 }` via `NEWTABLE`+`SETLIST` and sums values with `for index, value in ipairs(...)`.',
      bytecodeBase64: toBase64(caseSetlistIpairs),
      originalIntent: `local total = 0\nlocal items = { 10, 20, 30 }\nfor index, value in ipairs(items) do\n    total += value\nend\nreturn total`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal t1 = {\n    10, 20, 30\n}\nlocal n1 = 0\nfor _, v1 in ipairs(t1) do\n    n1 += v1\nend\nreturn n1\n`,
      luaExpertV2FlawNotes: [
        'Handles `SETLIST` and `ipairs` cleanly (and elides unused index as `_`), with only generic `t1`/`n1`/`v1` names and the forced `-- https://lua.expert` header.',
      ],
    },
    {
      id: 'lua54-loop-bitwise',
      title: 'Lua 5.4 Bitwise AND + Numeric For + RETURN1',
      dialect: 'lua54',
      flawCategory: 'Lua 5.4 _ENV Noise & Top-Level Wrapper',
      summary: 'Real Lua 5.4 binary chunk using `LOADI`, `BANDK`, `MMBINK`, `FORPREP`/`FORLOOP`, and `RETURN1`.',
      bytecodeBase64: toBase64(caseLua54),
      originalIntent: `local total = 0\nfor i = 1, 10 do\n    total = total + (i & 3)\nend\nreturn total`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal _ = _ENV\nlocal function v1(...)\n    local v2 = 0\n    for i = 1, 10 do\n        v2 = v2 + (i & 3)\n    end\n    return v2\nend\nreturn v1(...)\n`,
      luaExpertV2FlawNotes: [
        'Emits dead `local _ = _ENV` statement and wraps the top-level chunk inside a synthetic `local function v1(...)` IIFE.',
      ],
    },
    {
      id: 'luau-2000-insn-stress',
      title: '2,000-Instruction O(N) Throughput Stress Chunk',
      dialect: 'luau',
      flawCategory: 'Large-Function Linear-Time Scaling (Trade-off)',
      summary: '2,003-instruction Luau v6 function measuring linear O(N) liveness speed vs remote API latency & expression folding.',
      bytecodeBase64: toBase64(caseStress2000),
      originalIntent: `-- 500 unrolled arithmetic+modulo stages (2,003 instructions)`,
      luaExpertV2Status: 200,
      luaExpertV2Output: `-- https://lua.expert\n\nlocal v1 = 1 + 1\n\nv1 = (v1 + v1 * 2) % 997 + 1\nv1 = (v1 + v1 * 2) % 997 + 1\n-- ... (500 folded lines total, 676.8 ms remote round-trip)\nreturn (v1 + v1 * 2) % 997\n`,
      luaExpertV2FlawNotes: [
        'Honest credit to v2: folds consecutive single-variable assignments into 506 compact lines (`v1 = (v1 + v1 * 2) % 997 + 1`), whereas OpLift keeps 3 compound-assign lines per stage (1,502 lines).',
        'OpLift completes the full 2,003-instruction lift locally in ~14–25 ms (O(N) backward liveness) vs 676.8 ms remote round-trip on api.lua.expert.',
      ],
    },
  ];
}
