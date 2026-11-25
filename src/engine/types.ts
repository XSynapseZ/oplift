export type BytecodeDialect =
  | 'luau'
  | 'lua51'
  | 'lua52'
  | 'lua53'
  | 'lua54'
  | 'luajit'
  | 'moonsharp'
  | 'unknown';

export type OpcodeEncoding = 'standard' | 'roblox-227';

export type RenamingType = 'SEMANTIC' | 'UNIQUE_VALUE_BASED' | 'NONE';

export type LineInfoMode = 'FUNCTION_LEVEL' | 'FULL' | 'NONE';

export interface DecompileOptions {
  renamingType: RenamingType;
  useDebugLocals: boolean;
  ifExpressions: boolean;
  virtualizeContinue: boolean;
  resugarInterpolatedStrings: boolean;
  compoundAssignments: boolean;
  genericForSugaring: boolean;
  tableFunctionSugaring: boolean;
  numericForStepSugaring: boolean;
  foldTableLiterals: boolean;
  foldConstants: boolean;
  eliminateDeadBranches: boolean;
  pruneReturnParens: boolean;
  autoDecodeRoblox227: boolean;
  upvalueComments: boolean;
  emitBlankLines: boolean;
  emitHeader: boolean;
  emitUtf8: boolean;
  integralFloatsAsInts: boolean;
  scientificNotation: boolean;
  lineInfoMode: LineInfoMode;
  emitTypeAnnotations: boolean;
}

export const DEFAULT_DECOMPILE_OPTIONS: DecompileOptions = {
  renamingType: 'SEMANTIC',
  useDebugLocals: true,
  ifExpressions: true,
  virtualizeContinue: true,
  resugarInterpolatedStrings: true,
  compoundAssignments: true,
  genericForSugaring: true,
  tableFunctionSugaring: true,
  numericForStepSugaring: true,
  foldTableLiterals: true,
  foldConstants: true,
  eliminateDeadBranches: true,
  pruneReturnParens: true,
  autoDecodeRoblox227: true,
  upvalueComments: false,
  emitBlankLines: true,
  emitHeader: false,
  emitUtf8: true,
  integralFloatsAsInts: true,
  scientificNotation: false,
  lineInfoMode: 'NONE',
  emitTypeAnnotations: true,
};

export interface ConstantValue {
  kind: 'nil' | 'boolean' | 'number' | 'string' | 'import' | 'table' | 'closure' | 'vector';
  value: unknown;
  importPath?: string[];
  tableKeys?: string[];
  tableConstantEntries?: Array<{ key: string; valueConstIdx: number }>;
  closureProtoId?: number;
}

export interface DecodedInstruction {
  pc: number;
  word: number;
  aux?: number;
  opcode: number;
  opname: string;
  a: number;
  b: number;
  c: number;
  d: number; // signed 16-bit for Luau AD, or sBx for Lua 5.x
  bx?: number; // unsigned 18-bit for Lua 5.x ABx
  e?: number; // signed 24-bit for Luau E
  targetPc?: number;
  width: 1 | 2;
  comment?: string;
}

export interface LocalVarInfo {
  name: string;
  startPc: number;
  endPc: number;
  reg: number;
}

export interface ParsedProto {
  id: number;
  maxStackSize: number;
  numParams: number;
  numUpvalues: number;
  isVararg: boolean;
  flags: number;
  lineDefined: number;
  debugName: string;
  instructions: DecodedInstruction[];
  constants: ConstantValue[];
  childProtos: number[];
  localVars: LocalVarInfo[];
  upvalueNames: string[];
  paramTypes?: string[];
  upvalueDescriptors?: Array<{ instack: boolean; idx: number; kind: number }>;
  codeLength: number;
  codeStartOffset?: number;
}

export interface ParsedChunk {
  dialect: BytecodeDialect;
  version: number;
  versionLabel: string;
  encoding: OpcodeEncoding;
  endianness: 'little' | 'big';
  stringTable: string[];
  protos: ParsedProto[];
  mainProtoId: number;
  rawByteLength: number;
  headerInfo: Record<string, string | number | boolean>;
}

export interface ParseDiagnostic {
  severity: 'error' | 'warning' | 'info';
  code: string;
  message: string;
  byteOffset?: number;
  section?: string;
  protoId?: number;
  pc?: number;
  hint?: string;
}

export interface DecompileMetrics {
  instructionCount: number;
  protoCount: number;
  outputLines: number;
  maxNestingDepth: number;
  constantsFolded: number;
  deadBranchesEliminated: number;
  continuesRecovered: number;
  breaksRecovered: number;
  tablesFolded: number;
  returnParensPruned: number;
  syntheticPhiTempsAvoided: number;
  semanticNamesInferred: number;
}

export interface DisassembledProto {
  id: number;
  name: string;
  numParams: number;
  numUpvalues: number;
  isVararg: boolean;
  maxStackSize: number;
  constants: string[];
  instructions: Array<{
    pc: number;
    opname: string;
    operands: string;
    comment?: string;
  }>;
}

export interface DecompileResult {
  ok: boolean;
  source?: string;
  dialect: BytecodeDialect;
  version?: number;
  versionLabel?: string;
  encoding?: OpcodeEncoding;
  timingMs: number;
  metrics?: DecompileMetrics;
  diagnostics: ParseDiagnostic[];
  imports: string[];
  strings: string[];
  protosSummary?: Array<{
    id: number;
    name: string;
    params: number;
    upvalues: number;
    instructions: number;
    constants: number;
    returnArity: number | 'variadic';
  }>;
  disassembly?: DisassembledProto[];
}

export interface CleanlinessScore {
  score: number;
  lines: number;
  maxNestingDepth: number;
  syntheticPhiTemps: number;
  deadElseifAssignments: number;
  invertedGuardCount: number;
  unfoldedTableInits: number;
  redundantReturnParens: number;
  unfoldedConstArithmetic: number;
  forcedWatermarkLines: number;
  hasSemanticNames: boolean;
  issues: string[];
}

export interface BenchmarkCase {
  id: string;
  title: string;
  dialect: 'luau' | 'lua51' | 'lua54';
  flawCategory: string;
  summary: string;
  bytecodeBase64: string;
  originalIntent: string;
  luaExpertV2Output: string;
  luaExpertV2Status: number;
  luaExpertV2FlawNotes: string[];
}
