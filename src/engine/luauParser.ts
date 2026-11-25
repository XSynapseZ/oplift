import type {
  ConstantValue,
  DecodedInstruction,
  LocalVarInfo,
  OpcodeEncoding,
  ParseDiagnostic,
  ParsedChunk,
  ParsedProto,
} from './types.ts';

export const LUAU_OPNAMES: readonly string[] = [
  'NOP', 'BREAK', 'LOADNIL', 'LOADB', 'LOADN', 'LOADK', 'MOVE',
  'GETGLOBAL', 'SETGLOBAL', 'GETUPVAL', 'SETUPVAL', 'CLOSEUPVALS',
  'GETIMPORT', 'GETTABLE', 'SETTABLE', 'GETTABLEKS', 'SETTABLEKS',
  'GETTABLEN', 'SETTABLEN', 'NEWCLOSURE', 'NAMECALL', 'CALL', 'RETURN',
  'JUMP', 'JUMPBACK', 'JUMPIF', 'JUMPIFNOT', 'JUMPIFEQ', 'JUMPIFLE',
  'JUMPIFLT', 'JUMPIFNOTEQ', 'JUMPIFNOTLE', 'JUMPIFNOTLT',
  'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW',
  'ADDK', 'SUBK', 'MULK', 'DIVK', 'MODK', 'POWK',
  'AND', 'OR', 'ANDK', 'ORK', 'CONCAT', 'NOT', 'MINUS', 'LENGTH',
  'NEWTABLE', 'DUPTABLE', 'SETLIST', 'FORNPREP', 'FORNLOOP', 'FORGLOOP',
  'FORGPREP_INEXT', 'FASTCALL3', 'FORGPREP_NEXT', 'NATIVECALL',
  'GETVARARGS', 'DUPCLOSURE', 'PREPVARARGS', 'LOADKX', 'JUMPX',
  'FASTCALL', 'COVERAGE', 'CAPTURE', 'SUBRK', 'DIVRK',
  'FASTCALL1', 'FASTCALL2', 'FASTCALL2K', 'FORGPREP',
  'JUMPXEQKNIL', 'JUMPXEQKB', 'JUMPXEQKN', 'JUMPXEQKS', 'IDIV', 'IDIVK',
  // Luau v7–v14 opcodes (Bytecode.h 0.748)
  'GETUDATAKS', 'SETUDATAKS', 'NAMECALLUDATA', 'NEWCLASSMEMBER',
  'CALLFB', 'CMPPROTO', 'FASTPCALL',
  // Experimental v100 class opcodes
  'NEWCLASS', 'CONSTRUCT', 'FINCONSTRUCT', 'GETPRIVATEFIELD', 'SETPRIVATEFIELD',
];

export const LUAU_AUX_OPCODES = new Set<number>([
  7,  // GETGLOBAL
  8,  // SETGLOBAL
  12, // GETIMPORT
  15, // GETTABLEKS
  16, // SETTABLEKS
  20, // NAMECALL
  27, // JUMPIFEQ
  28, // JUMPIFLE
  29, // JUMPIFLT
  30, // JUMPIFNOTEQ
  31, // JUMPIFNOTLE
  32, // JUMPIFNOTLT
  53, // NEWTABLE
  55, // SETLIST
  58, // FORGLOOP
  60, // FASTCALL3
  66, // LOADKX
  74, // FASTCALL2
  75, // FASTCALL2K
  77, // JUMPXEQKNIL
  78, // JUMPXEQKB
  79, // JUMPXEQKN
  80, // JUMPXEQKS
  83, // GETUDATAKS
  84, // SETUDATAKS
  85, // NAMECALLUDATA
  86, // NEWCLASSMEMBER
  87, // CALLFB
  88, // CMPPROTO
  90, // NEWCLASS
  91, // CONSTRUCT
  93, // GETPRIVATEFIELD
  94, // SETPRIVATEFIELD
]);

const JUMP_D_OPCODES = new Set<number>([
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  56, 57, 58, 59, 61, 76, 77, 78, 79, 80, 88,
]);

// Multiplicative inverse of 227 modulo 256: (227 * 203) % 256 === 1
const ROBLOX_OPCODE_INV = 203;

class BinaryReader {
  private view: DataView;
  public offset = 0;

  constructor(private bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  get length(): number {
    return this.bytes.length;
  }

  readU8(section: string): number {
    if (this.offset + 1 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Unexpected end of bytecode while reading uint8 in ${section} (expected 1 byte at offset 0x${this.offset.toString(16)}, total length ${this.bytes.length}).`,
        this.offset,
        section,
        'Ensure the full base64/binary chunk was captured without truncation.'
      );
    }
    return this.bytes[this.offset++];
  }

  readU32(section: string): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Unexpected end of bytecode while reading uint32 in ${section} (need 4 bytes at offset 0x${this.offset.toString(16)}, only ${this.remaining} remaining).`,
        this.offset,
        section,
        'Check whether the bytecode buffer was sliced or base64 padding was stripped.'
      );
    }
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }

  readI32(section: string): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Unexpected end of bytecode while reading int32 in ${section} (need 4 bytes at offset 0x${this.offset.toString(16)}, only ${this.remaining} remaining).`,
        this.offset,
        section
      );
    }
    const v = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return v;
  }

  readF64(section: string): number {
    if (this.offset + 8 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Unexpected end of bytecode while reading float64 in ${section} at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section
      );
    }
    const v = this.view.getFloat64(this.offset, true);
    this.offset += 8;
    return v;
  }

  readF32(section: string): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Unexpected end of bytecode while reading float32 in ${section} at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section
      );
    }
    const v = this.view.getFloat32(this.offset, true);
    this.offset += 4;
    return v;
  }

  readVarInt(section: string): number {
    let result = 0;
    let shift = 0;
    const startOffset = this.offset;
    for (let i = 0; i < 5; i++) {
      const b = this.readU8(section);
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        return result >>> 0;
      }
      shift += 7;
    }
    throw new LuauParseError(
      'INVALID_VARINT',
      `Malformed 5-byte varint in ${section} starting at offset 0x${startOffset.toString(16)}.`,
      startOffset,
      section
    );
  }

  readBytes(len: number, section: string): Uint8Array {
    if (len < 0 || this.offset + len > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_BYTECODE',
        `Declared length ${len} in ${section} exceeds remaining ${this.remaining} bytes at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section,
        'Bytecode may be truncated, compressed (zstd/lz4), or encrypted.'
      );
    }
    const slice = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }
}

export class LuauParseError extends Error {
  constructor(
    public code: string,
    message: string,
    public byteOffset: number,
    public section: string,
    public hint?: string,
    public protoId?: number,
    public pc?: number
  ) {
    super(message);
    this.name = 'LuauParseError';
  }

  toDiagnostic(): ParseDiagnostic {
    return {
      severity: 'error',
      code: this.code,
      message: this.message,
      byteOffset: this.byteOffset,
      section: this.section,
      protoId: this.protoId,
      pc: this.pc,
      hint: this.hint,
    };
  }
}

function decodeSigned16(v: number): number {
  return v >= 0x8000 ? v - 0x10000 : v;
}

function decodeSigned24(v: number): number {
  return v >= 0x800000 ? v - 0x1000000 : v;
}

function scoreInstructionStream(rawWords: number[], decodeOp: (op: number) => number): {
  valid: boolean;
  score: number;
  invalidOp?: { pc: number; rawOp: number; decodedOp: number };
} {
  let pc = 0;
  let score = 0;
  while (pc < rawWords.length) {
    const w = rawWords[pc];
    const rawOp = w & 0xff;
    const op = decodeOp(rawOp);
    if (op >= LUAU_OPNAMES.length) {
      return { valid: false, score: -1, invalidOp: { pc, rawOp, decodedOp: op } };
    }
    // High-confidence Luau anchor opcodes
    if (op === 65 && pc === 0) score += 25; // PREPVARARGS at pc 0
    if (op === 22) score += 12; // RETURN
    if (op === 12 || op === 21 || op === 87 || op === 5 || op === 4 || op === 6) score += 4;
    if (op === 20 || op === 15 || op === 16 || op === 83 || op === 84 || op === 85) score += 6;
    if (op === 56 || op === 57 || op === 58 || op === 76) score += 8;

    const hasAux = LUAU_AUX_OPCODES.has(op);
    if (hasAux && pc + 1 >= rawWords.length) {
      return { valid: false, score: -1, invalidOp: { pc, rawOp, decodedOp: op } };
    }
    pc += hasAux ? 2 : 1;
  }
  // Check last instruction is typically RETURN or JUMP/FORLOOP
  if (rawWords.length > 0) {
    let lastPc = 0;
    let cur = 0;
    while (cur < rawWords.length) {
      lastPc = cur;
      const op = decodeOp(rawWords[cur] & 0xff);
      cur += LUAU_AUX_OPCODES.has(op) ? 2 : 1;
    }
    const lastOp = decodeOp(rawWords[lastPc] & 0xff);
    if (lastOp === 22) score += 20;
  }
  return { valid: true, score };
}

function decodeLuauInstructions(
  rawWords: number[],
  constants: ConstantValue[],
  encoding: OpcodeEncoding,
  protoId: number
): DecodedInstruction[] {
  const decodeOp = encoding === 'roblox-227'
    ? (op: number) => (op * ROBLOX_OPCODE_INV) & 0xff
    : (op: number) => op;

  const out: DecodedInstruction[] = [];
  let pc = 0;
  while (pc < rawWords.length) {
    const word = rawWords[pc] >>> 0;
    const opcode = decodeOp(word & 0xff);
    if (opcode >= LUAU_OPNAMES.length) {
      throw new LuauParseError(
        'INVALID_OPCODE',
        `Unknown Luau opcode ${opcode} (raw byte 0x${(word & 0xff).toString(16)}) in proto #${protoId} at pc ${pc}.`,
        0,
        `proto[${protoId}].code[${pc}]`,
        'If this bytecode was dumped directly from Roblox client memory, enable autoDecodeRoblox227.',
        protoId,
        pc
      );
    }
    const opname = LUAU_OPNAMES[opcode];
    const a = (word >>> 8) & 0xff;
    const b = (word >>> 16) & 0xff;
    const c = (word >>> 24) & 0xff;
    const d = decodeSigned16((word >>> 16) & 0xffff);
    const e = decodeSigned24((word >>> 8) & 0xffffff);
    const hasAux = LUAU_AUX_OPCODES.has(opcode);
    let aux: number | undefined;
    if (hasAux) {
      if (pc + 1 >= rawWords.length) {
        throw new LuauParseError(
          'MISSING_AUX_WORD',
          `Instruction ${opname} in proto #${protoId} at pc ${pc} requires a trailing AUX word, but reached end of code stream.`,
          0,
          `proto[${protoId}].code[${pc}]`,
          undefined,
          protoId,
          pc
        );
      }
      aux = rawWords[pc + 1] >>> 0;
    }

    let targetPc: number | undefined;
    if (JUMP_D_OPCODES.has(opcode)) {
      targetPc = pc + 1 + d;
    } else if (opcode === 67) {
      // JUMPX
      targetPc = pc + 1 + e;
    } else if (opcode === 68 || opcode === 73 || opcode === 74 || opcode === 75 || opcode === 60 || opcode === 89) {
      // FASTCALL / FASTPCALL family: C holds skip offset
      if (opcode === 68 || opcode === 73 || opcode === 89) targetPc = pc + 1 + c;
    }

    let comment: string | undefined;
    if (opcode === 12 && aux !== undefined) {
      const k = constants[d];
      if (k?.importPath) comment = k.importPath.join('.');
    } else if ((opcode === 15 || opcode === 16 || opcode === 20) && aux !== undefined) {
      const k = constants[aux];
      if (k?.kind === 'string') comment = JSON.stringify(k.value);
    } else if ((opcode === 83 || opcode === 84 || opcode === 85) && aux !== undefined) {
      const k = constants[aux & 0xffff];
      if (k?.kind === 'string') comment = JSON.stringify(k.value);
    } else if (opcode === 5) {
      const k = constants[d];
      if (k) comment = formatConstantShort(k);
    } else if ((opcode === 79 || opcode === 80) && aux !== undefined) {
      const kIdx = aux & 0xffffff;
      const notFlag = (aux >>> 31) & 1;
      const k = constants[kIdx];
      comment = `${notFlag ? '~=' : '=='} ${k ? formatConstantShort(k) : `K${kIdx}`}`;
    } else if (targetPc !== undefined) {
      comment = `-> pc ${targetPc}`;
    }

    out.push({
      pc,
      word,
      aux,
      opcode,
      opname,
      a,
      b,
      c,
      d,
      e,
      targetPc,
      width: hasAux ? 2 : 1,
      comment,
    });
    pc += hasAux ? 2 : 1;
  }
  return out;
}

export function formatConstantShort(c: ConstantValue): string {
  switch (c.kind) {
    case 'nil': return 'nil';
    case 'boolean': return String(c.value);
    case 'number': return String(c.value);
    case 'string': return JSON.stringify(c.value);
    case 'import': return c.importPath ? c.importPath.join('.') : '<import>';
    case 'table': return `{${(c.tableKeys ?? []).join(', ')}}`;
    case 'closure': return `<proto #${c.closureProtoId}>`;
    case 'vector': return `vector(${(c.value as number[]).join(', ')})`;
  }
}

export function parseLuauBytecode(
  bytes: Uint8Array,
  autoDecodeRoblox227 = true
): { chunk: ParsedChunk; diagnostics: ParseDiagnostic[] } {
  const reader = new BinaryReader(bytes);
  const diagnostics: ParseDiagnostic[] = [];
  const decoder = new TextDecoder('utf-8', { fatal: false });

  const version = reader.readU8('header.version');
  if (version === 0) {
    const errText = decoder.decode(bytes.subarray(1));
    throw new LuauParseError(
      'LUAU_COMPILE_ERROR_CHUNK',
      `Bytecode version byte is 0, indicating a Luau compiler error payload rather than compiled bytecode: "${errText.slice(0, 120)}"`,
      0,
      'header.version',
      'The upstream Luau compiler returned a syntax error string instead of bytecode.'
    );
  }
  if ((version < 3 || version > 20) && version !== 100) {
    throw new LuauParseError(
      'UNSUPPORTED_LUAU_VERSION',
      `Unsupported Luau bytecode version ${version} at byte 0x00 (supported versions: 3 through 20).`,
      0,
      'header.version',
      'Verify the input is uncompressed Luau bytecode (v3-v14+) or Lua 5.x bytecode (starts with 0x1B 0x4C 0x75 0x61).'
    );
  }
  if (version > 14 && version !== 100) {
    diagnostics.push({
      severity: 'warning',
      code: 'NEWER_LUAU_VERSION',
      message: `Luau bytecode version v${version} is newer than v14; attempting v14-compatible parse.`,
      byteOffset: 0,
      section: 'header.version',
    });
  }

  let typesVersion = 0;
  if (version >= 4) {
    typesVersion = reader.readU8('header.typesVersion');
    if (typesVersion < 1 || typesVersion > 3) {
      diagnostics.push({
        severity: 'warning',
        code: 'UNUSUAL_TYPES_VERSION',
        message: `Unexpected Luau typesVersion=${typesVersion} for bytecode v${version}; continuing with v${typesVersion} layout.`,
        byteOffset: 1,
        section: 'header.typesVersion',
      });
    }
  }

  // String table
  const stringCount = reader.readVarInt('stringTable.count');
  if (stringCount > 200_000) {
    throw new LuauParseError(
      'EXCESSIVE_STRING_COUNT',
      `String table declares ${stringCount} entries at offset 0x${reader.offset.toString(16)}, exceeding safety limit.`,
      reader.offset,
      'stringTable.count',
      'Data is likely corrupted or not Luau bytecode.'
    );
  }
  const stringTable: string[] = [];
  for (let i = 0; i < stringCount; i++) {
    const len = reader.readVarInt(`stringTable[${i}].length`);
    const raw = reader.readBytes(len, `stringTable[${i}].bytes`);
    stringTable.push(decoder.decode(raw));
  }

  // Userdata type remapping (typesVersion >= 3)
  const userdataTypes = new Map<number, string>();
  if (typesVersion >= 3) {
    let idx = reader.readU8('userdataTypes.index');
    while (idx !== 0) {
      const nameIdx = reader.readVarInt('userdataTypes.name');
      if (nameIdx > 0 && nameIdx <= stringTable.length) {
        userdataTypes.set(idx, stringTable[nameIdx - 1]);
      }
      idx = reader.readU8('userdataTypes.index');
    }
  }

  const protoCount = reader.readVarInt('protos.count');
  if (protoCount === 0 || protoCount > 10_000) {
    throw new LuauParseError(
      'INVALID_PROTO_COUNT',
      `Declared prototype count ${protoCount} at offset 0x${reader.offset.toString(16)} is invalid.`,
      reader.offset,
      'protos.count'
    );
  }

  const rawProtos: Array<{
    id: number;
    maxStackSize: number;
    numParams: number;
    numUpvalues: number;
    isVararg: boolean;
    flags: number;
    rawCode: number[];
    constants: ConstantValue[];
    childProtos: number[];
    lineDefined: number;
    debugName: string;
    localVars: LocalVarInfo[];
    upvalueNames: string[];
    paramTypes: string[];
    codeStartOffset: number;
  }> = [];

  for (let pIdx = 0; pIdx < protoCount; pIdx++) {
    const sec = `proto[${pIdx}]`;
    let protoSize = 0;
    if (version >= 12) {
      protoSize = reader.readVarInt(`${sec}.protoSize`);
    }
    const protoStartOffset = reader.offset;
    const maxStackSize = reader.readU8(`${sec}.maxstacksize`);
    const numParams = reader.readU8(`${sec}.numparams`);
    const numUpvalues = reader.readU8(`${sec}.nups`);
    const isVararg = reader.readU8(`${sec}.is_vararg`) !== 0;

    let flags = 0;
    const paramTypes: string[] = [];
    if (version >= 4) {
      flags = reader.readU8(`${sec}.flags`);
      const typeInfoSize = reader.readVarInt(`${sec}.typeinfoSize`);
      if (typeInfoSize > 0) {
        const typeBytes = reader.readBytes(typeInfoSize, `${sec}.typeinfo`);
        // Decode Luau function parameter typeinfo (typesVersion >= 1):
        // Byte 0: typeSize (bytes in function signature), Byte 1: upvalTypesCount, Byte 2: localTypesCount
        // Signature bytes start with LBC_TYPE_FUNCTION (5), followed by numParams, then param type tags
        if (typeBytes.length >= 2) {
          const funcTypeLen = typeBytes[0];
          const sigStart = version >= 5 ? 3 : 1;
          if (funcTypeLen >= 2 && sigStart + funcTypeLen <= typeBytes.length && typeBytes[sigStart] === 5) {
            const pCount = typeBytes[sigStart + 1];
            const typeNameMap: Record<number, string> = {
              0: 'nil',
              1: 'boolean',
              2: 'number',
              3: 'string',
              4: 'any',
              5: 'any',
              6: 'thread',
              7: 'any',
              8: 'vector',
              10: 'buffer',
              15: 'any',
            };
            for (let pt = 0; pt < pCount && sigStart + 2 + pt < sigStart + funcTypeLen; pt++) {
              const rawTag = typeBytes[sigStart + 2 + pt];
              const isOptional = (rawTag & 0x80) !== 0;
              const baseTag = rawTag & 0x7f;
              const customUd = baseTag >= 64 ? userdataTypes.get(baseTag - 64 + 1) ?? userdataTypes.get(baseTag - 64) : undefined;
              const baseName = customUd ?? typeNameMap[baseTag] ?? 'any';
              paramTypes.push(isOptional && baseName !== 'any' && baseName !== 'nil' ? `${baseName}?` : baseName);
            }
          }
        }
      }
    }

    const codeSize = reader.readVarInt(`${sec}.codeSize`);
    if (codeSize > 500_000) {
      throw new LuauParseError(
        'EXCESSIVE_CODE_SIZE',
        `Proto #${pIdx} declares ${codeSize} instruction words, exceeding safety cap.`,
        reader.offset,
        `${sec}.codeSize`,
        undefined,
        pIdx
      );
    }
    const codeStartOffset = reader.offset;
    const rawCode: number[] = [];
    for (let i = 0; i < codeSize; i++) {
      rawCode.push(reader.readU32(`${sec}.code[${i}]`));
    }

    const constSize = reader.readVarInt(`${sec}.constSize`);
    const constants: ConstantValue[] = [];
    for (let k = 0; k < constSize; k++) {
      const ctype = reader.readU8(`${sec}.const[${k}].type`);
      switch (ctype) {
        case 0: // NIL
          constants.push({ kind: 'nil', value: null });
          break;
        case 1: // BOOLEAN
          constants.push({ kind: 'boolean', value: reader.readU8(`${sec}.const[${k}].bool`) !== 0 });
          break;
        case 2: // NUMBER
          constants.push({ kind: 'number', value: reader.readF64(`${sec}.const[${k}].number`) });
          break;
        case 3: { // STRING
          const sIdx = reader.readVarInt(`${sec}.const[${k}].stringIdx`);
          const strVal = sIdx > 0 && sIdx <= stringTable.length ? stringTable[sIdx - 1] : '';
          constants.push({ kind: 'string', value: strVal });
          break;
        }
        case 4: { // IMPORT
          const iid = reader.readU32(`${sec}.const[${k}].importId`);
          const count = (iid >>> 30) & 3;
          const id0 = (iid >>> 20) & 0x3ff;
          const id1 = (iid >>> 10) & 0x3ff;
          const id2 = iid & 0x3ff;
          const parts: string[] = [];
          const resolveK = (idx: number) => {
            const c = constants[idx];
            return c && c.kind === 'string' ? String(c.value) : `K${idx}`;
          };
          if (count >= 1) parts.push(resolveK(id0));
          if (count >= 2) parts.push(resolveK(id1));
          if (count >= 3) parts.push(resolveK(id2));
          constants.push({ kind: 'import', value: iid, importPath: parts });
          break;
        }
        case 5: { // TABLE
          const keysLen = reader.readVarInt(`${sec}.const[${k}].tableLen`);
          const keys: string[] = [];
          for (let j = 0; j < keysLen; j++) {
            const keyIdx = reader.readVarInt(`${sec}.const[${k}].tableKey[${j}]`);
            const c = constants[keyIdx];
            keys.push(c && c.kind === 'string' ? String(c.value) : `K${keyIdx}`);
          }
          constants.push({ kind: 'table', value: keys, tableKeys: keys });
          break;
        }
        case 6: { // CLOSURE
          const fid = reader.readVarInt(`${sec}.const[${k}].closureProtoId`);
          constants.push({ kind: 'closure', value: fid, closureProtoId: fid });
          break;
        }
        case 7: { // VECTOR (f32 x 4)
          const x = reader.readF32(`${sec}.const[${k}].vecX`);
          const y = reader.readF32(`${sec}.const[${k}].vecY`);
          const z = reader.readF32(`${sec}.const[${k}].vecZ`);
          const w = reader.readF32(`${sec}.const[${k}].vecW`);
          constants.push({ kind: 'vector', value: [x, y, z, w] });
          break;
        }
        case 8: { // TABLE_WITH_CONSTANTS (Luau v8+)
          const keysLen = reader.readVarInt(`${sec}.const[${k}].tableConstLen`);
          const keys: string[] = [];
          const entries: Array<{ key: string; valueConstIdx: number }> = [];
          for (let j = 0; j < keysLen; j++) {
            const keyIdx = reader.readVarInt(`${sec}.const[${k}].tableKey[${j}]`);
            const valConstIdx = reader.readI32(`${sec}.const[${k}].tableVal[${j}]`);
            const c = constants[keyIdx];
            const kName = c && c.kind === 'string' ? String(c.value) : `K${keyIdx}`;
            keys.push(kName);
            entries.push({ key: kName, valueConstIdx: valConstIdx });
          }
          constants.push({ kind: 'table', value: keys, tableKeys: keys, tableConstantEntries: entries });
          break;
        }
        case 9: { // INTEGER_DEPRECATED (8-byte int64)
          const lo = reader.readU32(`${sec}.const[${k}].i64Lo`);
          const hi = reader.readI32(`${sec}.const[${k}].i64Hi`);
          constants.push({ kind: 'number', value: hi * 4294967296 + lo });
          break;
        }
        case 10: { // CLASS_SHAPE (experimental Luau classes)
          const cnid = reader.readVarInt(`${sec}.const[${k}].classNameIdx`);
          const numPrivateFields = reader.readU8(`${sec}.const[${k}].numPrivateFields`);
          const numPrivateMethods = reader.readU8(`${sec}.const[${k}].numPrivateMethods`);
          const numProperties = reader.readVarInt(`${sec}.const[${k}].numProperties`);
          const numMethods = reader.readVarInt(`${sec}.const[${k}].numMethods`);
          const pubProps = Math.max(0, numProperties - numPrivateFields);
          const pubMethods = Math.max(0, numMethods - numPrivateMethods);
          const memberNames: string[] = [];
          for (let j = 0; j < pubProps + pubMethods; j++) {
            const mid = reader.readVarInt(`${sec}.const[${k}].member[${j}]`);
            const mc = constants[mid];
            memberNames.push(mc && mc.kind === 'string' ? String(mc.value) : `K${mid}`);
          }
          const cn = constants[cnid];
          constants.push({
            kind: 'table',
            value: cn && cn.kind === 'string' ? String(cn.value) : `Class_${cnid}`,
            tableKeys: memberNames,
          });
          break;
        }
        case 11: { // VECTORD (f64 x 4, Luau v13+)
          const x = reader.readF64(`${sec}.const[${k}].vecdX`);
          const y = reader.readF64(`${sec}.const[${k}].vecdY`);
          const z = reader.readF64(`${sec}.const[${k}].vecdZ`);
          const w = reader.readF64(`${sec}.const[${k}].vecdW`);
          constants.push({ kind: 'vector', value: [x, y, z, w] });
          break;
        }
        default:
          throw new LuauParseError(
            'UNKNOWN_CONSTANT_TYPE',
            `Unknown Luau constant tag ${ctype} in proto #${pIdx} constant #${k} at offset 0x${(reader.offset - 1).toString(16)}.`,
            reader.offset - 1,
            `${sec}.const[${k}]`,
            undefined,
            pIdx
          );
      }
    }

    // Resolve forward-referenced import paths if any import constant appeared before its string constants
    for (const c of constants) {
      if (c.kind === 'import' && typeof c.value === 'number') {
        const iid = c.value;
        const count = (iid >>> 30) & 3;
        const ids = [(iid >>> 20) & 0x3ff, (iid >>> 10) & 0x3ff, iid & 0x3ff];
        c.importPath = ids.slice(0, count).map((idx) => {
          const kc = constants[idx];
          return kc && kc.kind === 'string' ? String(kc.value) : `K${idx}`;
        });
      }
    }

    const childCount = reader.readVarInt(`${sec}.childCount`);
    const childProtos: number[] = [];
    for (let j = 0; j < childCount; j++) {
      childProtos.push(reader.readVarInt(`${sec}.child[${j}]`));
    }

    const lineDefined = reader.readVarInt(`${sec}.lineDefined`);
    const debugNameIdx = reader.readVarInt(`${sec}.debugName`);
    const debugName =
      debugNameIdx > 0 && debugNameIdx <= stringTable.length
        ? stringTable[debugNameIdx - 1]
        : '';

    const hasLineInfo = reader.readU8(`${sec}.hasLineInfo`);
    if (hasLineInfo !== 0) {
      const lineGapLog2 = reader.readU8(`${sec}.lineGapLog2`);
      const intervals = codeSize > 0 ? ((codeSize - 1) >> lineGapLog2) + 1 : 0;
      if (codeSize > 0) reader.readBytes(codeSize, `${sec}.lineInfo`);
      if (intervals > 0) reader.readBytes(intervals * 4, `${sec}.absLineInfo`);
    }

    const localVars: LocalVarInfo[] = [];
    const upvalueNames: string[] = [];
    const hasDebugInfo = reader.readU8(`${sec}.hasDebugInfo`);
    if (hasDebugInfo !== 0) {
      const localCount = reader.readVarInt(`${sec}.debugLocals.count`);
      for (let j = 0; j < localCount; j++) {
        const nameIdx = reader.readVarInt(`${sec}.debugLocals[${j}].name`);
        const startPc = reader.readVarInt(`${sec}.debugLocals[${j}].startPc`);
        const endPc = reader.readVarInt(`${sec}.debugLocals[${j}].endPc`);
        const reg = reader.readU8(`${sec}.debugLocals[${j}].reg`);
        localVars.push({
          name: nameIdx > 0 && nameIdx <= stringTable.length ? stringTable[nameIdx - 1] : `local_${reg}`,
          startPc,
          endPc,
          reg,
        });
      }
      const upvalCount = reader.readVarInt(`${sec}.debugUpvals.count`);
      for (let j = 0; j < upvalCount; j++) {
        const nameIdx = reader.readVarInt(`${sec}.debugUpvals[${j}].name`);
        upvalueNames.push(
          nameIdx > 0 && nameIdx <= stringTable.length ? stringTable[nameIdx - 1] : `upval_${j}`
        );
      }
    }

    if (version >= 11) {
      const feedbackVecSize = reader.readVarInt(`${sec}.feedbackVecSize`);
      for (let j = 0; j < feedbackVecSize; j++) {
        const slotType = reader.readU8(`${sec}.feedback[${j}].type`);
        if (slotType === 0 || slotType === 1) {
          reader.readVarInt(`${sec}.feedback[${j}].data`);
        }
      }
    }

    if (version >= 12) {
      // Per lvmload.cpp: jump to exact protoStartOffset + protoSize (covers cost varint64 and any trailing v12+ metadata)
      if (protoStartOffset + protoSize > reader.length) {
        throw new LuauParseError(
          'TRUNCATED_BYTECODE',
          `Proto #${pIdx} declared byte size ${protoSize} exceeds remaining input at offset 0x${protoStartOffset.toString(16)}.`,
          protoStartOffset,
          `${sec}.protoSize`,
          undefined,
          pIdx
        );
      }
      reader.offset = protoStartOffset + protoSize;
    }

    rawProtos.push({
      id: pIdx,
      maxStackSize,
      numParams,
      numUpvalues,
      isVararg,
      flags,
      rawCode,
      constants,
      childProtos,
      lineDefined,
      debugName,
      localVars,
      upvalueNames,
      paramTypes,
      codeStartOffset,
    });
  }

  const mainProtoId = reader.readVarInt('footer.mainProtoId');
  if (mainProtoId >= rawProtos.length) {
    throw new LuauParseError(
      'INVALID_MAIN_PROTO',
      `Main proto index ${mainProtoId} is out of range (only ${rawProtos.length} protos present).`,
      reader.offset,
      'footer.mainProtoId'
    );
  }

  if (reader.remaining > 0) {
    diagnostics.push({
      severity: 'info',
      code: 'TRAILING_BYTES',
      message: `${reader.remaining} trailing byte(s) found after mainProtoId at offset 0x${reader.offset.toString(16)}.`,
      byteOffset: reader.offset,
      section: 'footer',
    });
  }

  // Score standard vs Roblox *227 opcode encoding across all protos
  let stdValid = true;
  let stdScore = 0;
  let rbxValid = true;
  let rbxScore = 0;

  for (const p of rawProtos) {
    const s = scoreInstructionStream(p.rawCode, (op) => op);
    if (!s.valid) stdValid = false;
    else stdScore += s.score;

    const r = scoreInstructionStream(p.rawCode, (op) => (op * ROBLOX_OPCODE_INV) & 0xff);
    if (!r.valid) rbxValid = false;
    else rbxScore += r.score;
  }

  let encoding: OpcodeEncoding = 'standard';
  if ((!stdValid && rbxValid && autoDecodeRoblox227) || (rbxValid && stdValid && rbxScore > stdScore + 15 && autoDecodeRoblox227)) {
    encoding = 'roblox-227';
    diagnostics.push({
      severity: 'info',
      code: 'ROBLOX_227_AUTO_DECODED',
      message: 'Detected Roblox client opcode encoding (opcode * 227 mod 256); automatically inverted with multiplier 203.',
      section: 'opcodeDecoder',
    });
  } else if (!stdValid && rbxValid && !autoDecodeRoblox227) {
    throw new LuauParseError(
      'ROBLOX_227_ENCODING_DETECTED',
      'Bytecode uses Roblox client opcode encoding (op * 227 mod 256), but autoDecodeRoblox227 is disabled.',
      0,
      'opcodeDecoder',
      'Enable "autoDecodeRoblox227": true in decompilerOptions to decode Roblox client bytecode automatically.'
    );
  }

  const protos: ParsedProto[] = rawProtos.map((rp) => ({
    id: rp.id,
    maxStackSize: rp.maxStackSize,
    numParams: rp.numParams,
    numUpvalues: rp.numUpvalues,
    isVararg: rp.isVararg,
    flags: rp.flags,
    lineDefined: rp.lineDefined,
    debugName: rp.debugName,
    instructions: decodeLuauInstructions(rp.rawCode, rp.constants, encoding, rp.id),
    constants: rp.constants,
    childProtos: rp.childProtos,
    localVars: rp.localVars,
    upvalueNames: rp.upvalueNames,
    paramTypes: rp.paramTypes.length > 0 ? rp.paramTypes : undefined,
    codeLength: rp.rawCode.length,
    codeStartOffset: rp.codeStartOffset,
  }));

  return {
    chunk: {
      dialect: 'luau',
      version,
      versionLabel: `Luau v${version}${typesVersion ? ` (types v${typesVersion})` : ''}`,
      encoding,
      endianness: 'little',
      stringTable,
      protos,
      mainProtoId,
      rawByteLength: bytes.length,
      headerInfo: {
        bytecodeVersion: version,
        typesVersion,
        stringCount: stringTable.length,
        userdataTypes: userdataTypes.length,
        protoCount: protos.length,
        opcodeEncoding: encoding,
      },
    },
    diagnostics,
  };
}
