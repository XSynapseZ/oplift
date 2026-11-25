import type {
  BytecodeDialect,
  ConstantValue,
  DecodedInstruction,
  LocalVarInfo,
  ParseDiagnostic,
  ParsedChunk,
  ParsedProto,
} from './types.ts';
import { LuauParseError, formatConstantShort } from './luauParser.ts';

export const LUA51_OPNAMES: readonly string[] = [
  'MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETGLOBAL', 'GETTABLE',
  'SETGLOBAL', 'SETUPVAL', 'SETTABLE', 'NEWTABLE', 'SELF',
  'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'UNM', 'NOT', 'LEN', 'CONCAT',
  'JMP', 'EQ', 'LT', 'LE', 'TEST', 'TESTSET', 'CALL', 'TAILCALL', 'RETURN',
  'FORLOOP', 'FORPREP', 'TFORLOOP', 'SETLIST', 'CLOSE', 'CLOSURE', 'VARARG',
];

export const LUA54_OPNAMES: readonly string[] = [
  'MOVE', 'LOADI', 'LOADF', 'LOADK', 'LOADKX', 'LOADFALSE', 'LFALSESKIP', 'LOADTRUE', 'LOADNIL',
  'GETUPVAL', 'SETUPVAL', 'GETTABUP', 'GETTABLE', 'GETI', 'GETFIELD',
  'SETTABUP', 'SETTABLE', 'SETI', 'SETFIELD', 'NEWTABLE', 'SELF',
  'ADDI', 'ADDK', 'SUBK', 'MULK', 'MODK', 'POWK', 'DIVK', 'IDIVK',
  'BANDK', 'BORK', 'BXORK', 'SHRI', 'SHLI',
  'ADD', 'SUB', 'MUL', 'MOD', 'POW', 'DIV', 'IDIV',
  'BAND', 'BOR', 'BXOR', 'SHL', 'SHR',
  'MMBIN', 'MMBINI', 'MMBINK',
  'UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT', 'CLOSE', 'TBC', 'JMP',
  'EQ', 'LT', 'LE', 'EQK', 'EQI', 'LTI', 'LEI', 'GTI', 'GEI',
  'TEST', 'TESTSET', 'CALL', 'TAILCALL', 'RETURN', 'RETURN0', 'RETURN1',
  'FORLOOP', 'FORPREP', 'TFORPREP', 'TFORCALL', 'TFORLOOP', 'SETLIST',
  'CLOSURE', 'VARARG', 'VARARGPREP', 'EXTRAARG',
];

const LUA51_JUMP_OPCODES = new Set<number>([22, 31, 32]); // JMP, FORLOOP, FORPREP

class Lua5xReader {
  private view: DataView;
  public offset = 0;

  constructor(
    private bytes: Uint8Array,
    public littleEndian = true,
    public intSize = 4,
    public sizeTSize = 8,
    public insnSize = 4,
    public numberSize = 8
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  readU8(section: string): number {
    if (this.offset + 1 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_LUA5X',
        `Unexpected EOF reading byte in ${section} at offset 0x${this.offset.toString(16)} (total ${this.bytes.length} bytes).`,
        this.offset,
        section
      );
    }
    return this.bytes[this.offset++];
  }

  readU32(section: string): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_LUA5X',
        `Unexpected EOF reading uint32 in ${section} at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section
      );
    }
    const v = this.view.getUint32(this.offset, this.littleEndian);
    this.offset += 4;
    return v;
  }

  readInt(section: string): number {
    if (this.intSize === 4) {
      if (this.offset + 4 > this.bytes.length) {
        throw new LuauParseError('TRUNCATED_LUA5X', `EOF reading int32 in ${section}.`, this.offset, section);
      }
      const v = this.view.getInt32(this.offset, this.littleEndian);
      this.offset += 4;
      return v;
    }
    throw new LuauParseError('UNSUPPORTED_INT_SIZE', `Unsupported Lua int size ${this.intSize}.`, this.offset, section);
  }

  readInt64Number(section: string): number {
    if (this.offset + 8 > this.bytes.length) {
      throw new LuauParseError('TRUNCATED_LUA5X', `EOF reading int64 in ${section}.`, this.offset, section);
    }
    const v = this.view.getBigInt64(this.offset, this.littleEndian);
    this.offset += 8;
    return Number(v);
  }

  readSizeT(section: string): number {
    if (this.sizeTSize === 4) return this.readU32(section);
    if (this.sizeTSize === 8) {
      if (this.offset + 8 > this.bytes.length) {
        throw new LuauParseError('TRUNCATED_LUA5X', `EOF reading size_t(64) in ${section}.`, this.offset, section);
      }
      const lo = this.view.getUint32(this.offset, this.littleEndian);
      const hi = this.view.getUint32(this.offset + 4, this.littleEndian);
      this.offset += 8;
      return this.littleEndian ? hi * 0x100000000 + lo : lo * 0x100000000 + hi;
    }
    throw new LuauParseError('UNSUPPORTED_SIZET', `Unsupported size_t width ${this.sizeTSize}.`, this.offset, section);
  }

  readNumber(section: string): number {
    if (this.numberSize === 8) {
      if (this.offset + 8 > this.bytes.length) {
        throw new LuauParseError('TRUNCATED_LUA5X', `EOF reading lua_Number in ${section}.`, this.offset, section);
      }
      const v = this.view.getFloat64(this.offset, this.littleEndian);
      this.offset += 8;
      return v;
    }
    if (this.numberSize === 4) {
      if (this.offset + 4 > this.bytes.length) {
        throw new LuauParseError('TRUNCATED_LUA5X', `EOF reading float32 in ${section}.`, this.offset, section);
      }
      const v = this.view.getFloat32(this.offset, this.littleEndian);
      this.offset += 4;
      return v;
    }
    throw new LuauParseError('UNSUPPORTED_NUMBER_SIZE', `Unsupported lua_Number size ${this.numberSize}.`, this.offset, section);
  }

  readBytes(len: number, section: string): Uint8Array {
    if (len < 0 || this.offset + len > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_LUA5X',
        `Declared length ${len} in ${section} exceeds remaining ${this.remaining} bytes at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section
      );
    }
    const slice = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  readLua51String(section: string, decoder: TextDecoder): string {
    const len = this.readSizeT(`${section}.len`);
    if (len === 0) return '';
    if (len > 10_000_000 || this.offset + len > this.bytes.length) {
      throw new LuauParseError(
        'TRUNCATED_LUA5X',
        `Lua 5.1 string length ${len} in ${section} exceeds remaining ${this.remaining} bytes at offset 0x${this.offset.toString(16)}.`,
        this.offset,
        section
      );
    }
    const raw = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    const trimmed = raw[raw.length - 1] === 0 ? raw.subarray(0, raw.length - 1) : raw;
    return decoder.decode(trimmed);
  }

  // Official Lua 5.4 loadUnsigned: 7-bit big-endian chunks where MSB=1 marks the FINAL byte!
  readLua54VarInt(section: string): number {
    let x = 0;
    for (let i = 0; i < 10; i++) {
      const b = this.readU8(section);
      x = x * 128 + (b & 0x7f);
      if ((b & 0x80) !== 0) return x;
    }
    throw new LuauParseError('INVALID_LUA54_VARINT', `Malformed Lua 5.4 varint in ${section}.`, this.offset, section);
  }

  readLua54String(section: string, decoder: TextDecoder): string {
    const size = this.readLua54VarInt(`${section}.size`);
    if (size === 0) return '';
    const strLen = size - 1; // Lua 5.4 stores length + 1 (no NUL terminator)
    if (strLen === 0) return '';
    const raw = this.readBytes(strLen, `${section}.bytes`);
    return decoder.decode(raw);
  }
}

function parseLua54Bytecode(bytes: Uint8Array): { chunk: ParsedChunk; diagnostics: ParseDiagnostic[] } {
  const diagnostics: ParseDiagnostic[] = [];
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const reader = new Lua5xReader(bytes, true, 4, 8, 4, 8);
  reader.offset = 6; // skip \x1bLua\x54\x00

  // Verify LUAC_DATA: 0x19 0x93 \r \n 0x1a \n
  const luacData = reader.readBytes(6, 'lua54.header.luacData');
  const expectedData = [0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 6; i++) {
    if (luacData[i] !== expectedData[i]) {
      throw new LuauParseError(
        'INVALID_LUA54_HEADER',
        `Lua 5.4 LUAC_DATA mismatch at byte ${6 + i} (got 0x${luacData[i].toString(16)}, expected 0x${expectedData[i].toString(16)}).`,
        6 + i,
        'lua54.header.luacData'
      );
    }
  }

  const insnSize = reader.readU8('lua54.header.insnSize');
  const intSize = reader.readU8('lua54.header.intSize');
  const numSize = reader.readU8('lua54.header.numSize');
  reader.insnSize = insnSize;
  reader.numberSize = numSize;

  const luacInt = intSize === 8 ? reader.readInt64Number('lua54.header.luacInt') : reader.readInt('lua54.header.luacInt');
  const luacNum = reader.readNumber('lua54.header.luacNum');
  if (luacInt !== 0x5678) {
    diagnostics.push({
      severity: 'warning',
      code: 'LUA54_LUAC_INT_MISMATCH',
      message: `Expected LUAC_INT=0x5678, found 0x${luacInt.toString(16)}.`,
      section: 'lua54.header',
    });
  }
  const topUpvalues = reader.readU8('lua54.topUpvalues');

  const protos: ParsedProto[] = [];
  const stringSet = new Set<string>();

  function readProto(depth: number): number {
    if (depth > 64) {
      throw new LuauParseError('PROTO_DEPTH_EXCEEDED', 'Lua 5.4 nested proto depth exceeded 64.', reader.offset, 'lua54.proto');
    }
    const protoId = protos.length;
    const placeholder: ParsedProto = {
      id: protoId,
      maxStackSize: 0,
      numParams: 0,
      numUpvalues: 0,
      isVararg: false,
      flags: 0,
      lineDefined: 0,
      debugName: '',
      instructions: [],
      constants: [],
      childProtos: [],
      localVars: [],
      upvalueNames: [],
      upvalueDescriptors: [],
      codeLength: 0,
    };
    protos.push(placeholder);

    const sec = `lua54.proto[${protoId}]`;
    const sourceName = reader.readLua54String(`${sec}.source`, decoder);
    const lineDefined = reader.readLua54VarInt(`${sec}.lineDefined`);
    reader.readLua54VarInt(`${sec}.lastLineDefined`);
    const numParams = reader.readU8(`${sec}.numparams`);
    const isVararg = reader.readU8(`${sec}.is_vararg`) !== 0;
    const maxStackSize = reader.readU8(`${sec}.maxstacksize`);

    const codeLen = reader.readLua54VarInt(`${sec}.codeLen`);
    if (codeLen > 500_000) {
      throw new LuauParseError('EXCESSIVE_CODE_SIZE', `Lua 5.4 proto #${protoId} codeLen ${codeLen} exceeds limit.`, reader.offset, sec);
    }
    const rawWords: number[] = [];
    for (let i = 0; i < codeLen; i++) rawWords.push(reader.readU32(`${sec}.code[${i}]`));

    const constLen = reader.readLua54VarInt(`${sec}.constLen`);
    const constants: ConstantValue[] = [];
    for (let k = 0; k < constLen; k++) {
      const tag = reader.readU8(`${sec}.const[${k}].tag`);
      if (tag === 0) {
        constants.push({ kind: 'nil', value: null });
      } else if (tag === 1) {
        constants.push({ kind: 'boolean', value: false });
      } else if (tag === 17) { // LUA_VTRUE = 1 | (1 << 4)
        constants.push({ kind: 'boolean', value: true });
      } else if (tag === 3) { // LUA_VNUMINT
        const v = intSize === 8 ? reader.readInt64Number(`${sec}.const[${k}].int`) : reader.readInt(`${sec}.const[${k}].int`);
        constants.push({ kind: 'number', value: v });
      } else if (tag === 19) { // LUA_VNUMFLT = 3 | (1 << 4)
        constants.push({ kind: 'number', value: reader.readNumber(`${sec}.const[${k}].flt`) });
      } else if (tag === 4 || tag === 20) { // LUA_VSHRSTR / LUA_VLNGSTR
        const s = reader.readLua54String(`${sec}.const[${k}].str`, decoder);
        stringSet.add(s);
        constants.push({ kind: 'string', value: s });
      } else {
        throw new LuauParseError(
          'UNKNOWN_LUA54_CONST',
          `Unknown Lua 5.4 constant tag 0x${tag.toString(16)} in proto #${protoId} const #${k}.`,
          reader.offset - 1,
          `${sec}.const[${k}]`
        );
      }
    }

    const upvalCount = reader.readLua54VarInt(`${sec}.upvalCount`);
    const upvalueDescriptors: Array<{ instack: boolean; idx: number; kind: number }> = [];
    for (let u = 0; u < upvalCount; u++) {
      const instack = reader.readU8(`${sec}.upval[${u}].instack`) !== 0;
      const idx = reader.readU8(`${sec}.upval[${u}].idx`);
      const kind = reader.readU8(`${sec}.upval[${u}].kind`);
      upvalueDescriptors.push({ instack, idx, kind });
    }

    const childCount = reader.readLua54VarInt(`${sec}.childCount`);
    const childProtos: number[] = [];
    for (let c = 0; c < childCount; c++) {
      childProtos.push(readProto(depth + 1));
    }

    // Debug section
    const lineInfoLen = reader.readLua54VarInt(`${sec}.lineInfoLen`);
    if (lineInfoLen > 0) reader.readBytes(lineInfoLen, `${sec}.lineInfo`);

    const absLineLen = reader.readLua54VarInt(`${sec}.absLineLen`);
    for (let i = 0; i < absLineLen; i++) {
      reader.readLua54VarInt(`${sec}.absLine[${i}].pc`);
      reader.readLua54VarInt(`${sec}.absLine[${i}].line`);
    }

    const locVarLen = reader.readLua54VarInt(`${sec}.locVarLen`);
    const localVars: LocalVarInfo[] = [];
    for (let i = 0; i < locVarLen; i++) {
      const name = reader.readLua54String(`${sec}.locVar[${i}].name`, decoder);
      const startPc = reader.readLua54VarInt(`${sec}.locVar[${i}].startPc`);
      const endPc = reader.readLua54VarInt(`${sec}.locVar[${i}].endPc`);
      localVars.push({ name, startPc, endPc, reg: i });
    }

    const upvalNamesLen = reader.readLua54VarInt(`${sec}.upvalNamesLen`);
    const upvalueNames: string[] = [];
    for (let i = 0; i < upvalNamesLen; i++) {
      upvalueNames.push(reader.readLua54String(`${sec}.upvalName[${i}]`, decoder));
    }

    const instructions: DecodedInstruction[] = rawWords.map((word, pc) => {
      const opcode = word & 0x7f;
      if (opcode >= LUA54_OPNAMES.length) {
        throw new LuauParseError(
          'INVALID_LUA54_OPCODE',
          `Invalid Lua 5.4 opcode ${opcode} in proto #${protoId} at pc ${pc}.`,
          0,
          `${sec}.code[${pc}]`,
          undefined,
          protoId,
          pc
        );
      }
      const opname = LUA54_OPNAMES[opcode];
      const a = (word >>> 7) & 0xff;
      const kFlag = (word >>> 15) & 1;
      const b = (word >>> 16) & 0xff;
      const c = (word >>> 24) & 0xff;
      const bx = (word >>> 15) & 0x1ffff; // 17 bits
      const sbx = bx - 65535;
      const sj = ((word >>> 7) & 0x1ffffff) - 16777215; // 25-bit signed jump for OP_JMP

      let targetPc: number | undefined;
      let d = sbx;
      if (opname === 'JMP') {
        d = sj;
        targetPc = pc + 1 + sj;
      } else if (opname === 'FORPREP' || opname === 'TFORPREP') {
        targetPc = pc + 1 + bx;
        d = bx;
      } else if (opname === 'FORLOOP' || opname === 'TFORLOOP') {
        targetPc = pc + 1 - bx;
        d = -bx;
      }

      let comment: string | undefined;
      if (opname === 'LOADK' && constants[bx]) comment = formatConstantShort(constants[bx]);
      else if ((opname === 'GETTABUP' || opname === 'GETFIELD') && constants[c]) comment = formatConstantShort(constants[c]);
      else if (opname === 'SETTABUP' && constants[b]) comment = formatConstantShort(constants[b]);
      else if (opname === 'LOADI') comment = String(sbx);
      else if (targetPc !== undefined) comment = `-> pc ${targetPc}`;

      return {
        pc,
        word,
        opcode,
        opname,
        a,
        b,
        c,
        d,
        bx,
        aux: kFlag, // store Lua 5.4 k-flag in aux slot for condition/RK helpers
        targetPc,
        width: 1 as const,
        comment,
      };
    });

    placeholder.maxStackSize = maxStackSize;
    placeholder.numParams = numParams;
    placeholder.numUpvalues = upvalCount;
    placeholder.isVararg = isVararg;
    placeholder.lineDefined = lineDefined;
    placeholder.debugName = sourceName;
    placeholder.instructions = instructions;
    placeholder.constants = constants;
    placeholder.childProtos = childProtos;
    placeholder.localVars = localVars;
    placeholder.upvalueNames = upvalueNames;
    placeholder.upvalueDescriptors = upvalueDescriptors;
    placeholder.codeLength = rawWords.length;

    return protoId;
  }

  const mainProtoId = readProto(0);

  return {
    chunk: {
      dialect: 'lua54',
      version: 0x54,
      versionLabel: 'Lua 5.4',
      encoding: 'standard',
      endianness: 'little',
      stringTable: Array.from(stringSet),
      protos,
      mainProtoId,
      rawByteLength: bytes.length,
      headerInfo: {
        insnSize,
        intSize,
        numSize,
        luacInt: `0x${luacInt.toString(16)}`,
        luacNum,
        topUpvalues,
        protoCount: protos.length,
      },
    },
    diagnostics,
  };
}

export function parseLua5xBytecode(bytes: Uint8Array): {
  chunk: ParsedChunk;
  diagnostics: ParseDiagnostic[];
} {
  const diagnostics: ParseDiagnostic[] = [];
  const decoder = new TextDecoder('utf-8', { fatal: false });

  if (bytes.length < 12) {
    throw new LuauParseError(
      'TRUNCATED_LUA5X_HEADER',
      `Lua 5.x chunk is only ${bytes.length} bytes; a valid Lua header requires at least 12 bytes.`,
      bytes.length,
      'header'
    );
  }

  if (bytes[0] !== 0x1b || bytes[1] !== 0x4c || bytes[2] !== 0x75 || bytes[3] !== 0x61) {
    throw new LuauParseError('INVALID_LUA_MAGIC', 'Missing 0x1B "Lua" signature at offset 0x00.', 0, 'header');
  }

  const verByte = bytes[4];
  const format = bytes[5];

  if (verByte === 0x54) {
    return parseLua54Bytecode(bytes);
  }

  let dialect: BytecodeDialect = 'lua51';
  let versionLabel = 'Lua 5.1';
  if (verByte === 0x51) {
    dialect = 'lua51';
    versionLabel = 'Lua 5.1';
  } else if (verByte === 0x52) {
    dialect = 'lua52';
    versionLabel = 'Lua 5.2';
  } else if (verByte === 0x53) {
    dialect = 'lua53';
    versionLabel = 'Lua 5.3';
  } else {
    throw new LuauParseError(
      'UNSUPPORTED_LUA_VERSION',
      `Unsupported Lua bytecode version byte 0x${verByte.toString(16)} at offset 0x04.`,
      4,
      'header.version',
      'Supported standard Lua versions are 5.1 (0x51), 5.2 (0x52), 5.3 (0x53), and 5.4 (0x54).'
    );
  }

  if (verByte !== 0x51) {
    diagnostics.push({
      severity: 'warning',
      code: 'LUA5X_PARTIAL_HEADER_MODE',
      message: `Detected ${versionLabel} header (0x${verByte.toString(16)}). Full instruction lifting is verified for Luau v3–v6, Lua 5.1, and Lua 5.4; ${versionLabel} is currently header-inspection only.`,
      byteOffset: 4,
      section: 'header',
      hint: 'Submit Luau v3–v6, Lua 5.1, or Lua 5.4 bytecode for full source recovery.',
    });
    return {
      chunk: {
        dialect,
        version: verByte,
        versionLabel,
        encoding: 'standard',
        endianness: 'little',
        stringTable: [],
        protos: [],
        mainProtoId: 0,
        rawByteLength: bytes.length,
        headerInfo: { versionByte: `0x${verByte.toString(16)}`, format, rawBytes: bytes.length },
      },
      diagnostics,
    };
  }

  // Full Lua 5.1 parser
  const endianByte = bytes[6];
  const littleEndian = endianByte === 1;
  const intSize = bytes[7];
  const sizeTSize = bytes[8];
  const insnSize = bytes[9];
  const numberSize = bytes[10];
  const integralFlag = bytes[11];

  const reader = new Lua5xReader(bytes, littleEndian, intSize, sizeTSize, insnSize, numberSize);
  reader.offset = 12;

  const protos: ParsedProto[] = [];
  const stringSet = new Set<string>();

  function readProto(depth: number): number {
    if (depth > 64) {
      throw new LuauParseError('PROTO_DEPTH_EXCEEDED', 'Nested function depth exceeded 64.', reader.offset, 'proto');
    }
    const protoId = protos.length;
    const placeholder: ParsedProto = {
      id: protoId,
      maxStackSize: 0,
      numParams: 0,
      numUpvalues: 0,
      isVararg: false,
      flags: 0,
      lineDefined: 0,
      debugName: '',
      instructions: [],
      constants: [],
      childProtos: [],
      localVars: [],
      upvalueNames: [],
      codeLength: 0,
    };
    protos.push(placeholder);

    const sec = `lua51.proto[${protoId}]`;
    const sourceName = reader.readLua51String(`${sec}.source`, decoder);
    const lineDefined = reader.readInt(`${sec}.lineDefined`);
    reader.readInt(`${sec}.lastLineDefined`);
    const numUpvalues = reader.readU8(`${sec}.nups`);
    const numParams = reader.readU8(`${sec}.numparams`);
    const isVararg = reader.readU8(`${sec}.is_vararg`) !== 0;
    const maxStackSize = reader.readU8(`${sec}.maxstacksize`);

    const codeLen = reader.readInt(`${sec}.codeLen`);
    if (codeLen < 0 || codeLen > 500_000) {
      throw new LuauParseError('INVALID_CODE_LEN', `Invalid Lua 5.1 instruction count ${codeLen}.`, reader.offset, sec);
    }
    const rawWords: number[] = [];
    for (let i = 0; i < codeLen; i++) rawWords.push(reader.readU32(`${sec}.code[${i}]`));

    const constLen = reader.readInt(`${sec}.constLen`);
    const constants: ConstantValue[] = [];
    for (let k = 0; k < constLen; k++) {
      const tag = reader.readU8(`${sec}.const[${k}].tag`);
      if (tag === 0) constants.push({ kind: 'nil', value: null });
      else if (tag === 1) constants.push({ kind: 'boolean', value: reader.readU8(`${sec}.const[${k}].bool`) !== 0 });
      else if (tag === 3) constants.push({ kind: 'number', value: reader.readNumber(`${sec}.const[${k}].num`) });
      else if (tag === 4) {
        const s = reader.readLua51String(`${sec}.const[${k}].str`, decoder);
        stringSet.add(s);
        constants.push({ kind: 'string', value: s });
      } else {
        throw new LuauParseError('UNKNOWN_LUA51_CONST', `Unknown Lua 5.1 constant tag ${tag}.`, reader.offset - 1, `${sec}.const[${k}]`);
      }
    }

    const childCount = reader.readInt(`${sec}.childCount`);
    const childProtos: number[] = [];
    for (let c = 0; c < childCount; c++) childProtos.push(readProto(depth + 1));

    const lineInfoLen = reader.readInt(`${sec}.lineInfoLen`);
    for (let i = 0; i < lineInfoLen; i++) reader.readInt(`${sec}.lineInfo[${i}]`);

    const locVarsLen = reader.readInt(`${sec}.locVarsLen`);
    const localVars: LocalVarInfo[] = [];
    for (let i = 0; i < locVarsLen; i++) {
      const name = reader.readLua51String(`${sec}.locVars[${i}].name`, decoder);
      const startPc = reader.readInt(`${sec}.locVars[${i}].startPc`);
      const endPc = reader.readInt(`${sec}.locVars[${i}].endPc`);
      localVars.push({ name, startPc, endPc, reg: i });
    }

    const upvalLen = reader.readInt(`${sec}.upvalLen`);
    const upvalueNames: string[] = [];
    for (let i = 0; i < upvalLen; i++) upvalueNames.push(reader.readLua51String(`${sec}.upvals[${i}]`, decoder));

    const instructions: DecodedInstruction[] = rawWords.map((word, pc) => {
      const opcode = word & 0x3f;
      if (opcode >= LUA51_OPNAMES.length) {
        throw new LuauParseError('INVALID_LUA51_OPCODE', `Invalid Lua 5.1 opcode ${opcode} at proto #${protoId} pc ${pc}.`, 0, `${sec}.code[${pc}]`, undefined, protoId, pc);
      }
      const opname = LUA51_OPNAMES[opcode];
      const a = (word >>> 6) & 0xff;
      const c = (word >>> 14) & 0x1ff;
      const b = (word >>> 23) & 0x1ff;
      const bx = (word >>> 14) & 0x3ffff;
      const sbx = bx - 131071;

      let targetPc: number | undefined;
      if (LUA51_JUMP_OPCODES.has(opcode)) targetPc = pc + 1 + sbx;

      let comment: string | undefined;
      if ((opcode === 1 || opcode === 5 || opcode === 7) && constants[bx]) comment = formatConstantShort(constants[bx]);
      else if (targetPc !== undefined) comment = `-> pc ${targetPc}`;

      return { pc, word, opcode, opname, a, b, c, d: sbx, bx, targetPc, width: 1 as const, comment };
    });

    placeholder.maxStackSize = maxStackSize;
    placeholder.numParams = numParams;
    placeholder.numUpvalues = numUpvalues;
    placeholder.isVararg = isVararg;
    placeholder.lineDefined = lineDefined;
    placeholder.debugName = sourceName;
    placeholder.instructions = instructions;
    placeholder.constants = constants;
    placeholder.childProtos = childProtos;
    placeholder.localVars = localVars;
    placeholder.upvalueNames = upvalueNames;
    placeholder.codeLength = rawWords.length;

    return protoId;
  }

  const mainProtoId = readProto(0);

  return {
    chunk: {
      dialect: 'lua51',
      version: 0x51,
      versionLabel: 'Lua 5.1',
      encoding: 'standard',
      endianness: littleEndian ? 'little' : 'big',
      stringTable: Array.from(stringSet),
      protos,
      mainProtoId,
      rawByteLength: bytes.length,
      headerInfo: {
        format,
        endianness: littleEndian ? 'little' : 'big',
        intSize,
        sizeTSize,
        insnSize,
        numberSize,
        integralNumbers: integralFlag !== 0,
        protoCount: protos.length,
      },
    },
    diagnostics,
  };
}
