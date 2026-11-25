import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { decompileBytesDirect, decompileBytecode } from '../src/engine/decompiler.ts';
import { getBenchmarkSuite } from '../src/engine/assembler.ts';
import { parseLuauBytecode } from '../src/engine/luauParser.ts';
import { scoreDecompiledOutput } from '../src/engine/comparator.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const LUAU_COMPILE = path.join(ROOT, 'bin', 'luau-compile');
const LUAU_EXEC = path.join(ROOT, 'bin', 'luau');

interface CompileMode {
  label: string;
  flags: string[];
}

const COMPILE_MODES: CompileMode[] = [
  { label: '-O0 -g1', flags: ['-O0', '-g1'] },
  { label: '-O1 -g1', flags: ['-O1', '-g1'] },
  { label: '-O2 -g2', flags: ['-O2', '-g2'] },
  { label: '-O2 -g0', flags: ['-O2', '-g0'] },
];

interface RuntimeRegressionCase {
  id: string;
  category:
    | 'issue1-short-circuit'
    | 'issue2-statement-order'
    | 'issue3-lexical-scope'
    | 'issue4-logical-in-arithmetic'
    | 'issue5-multret-and-game-patterns'
    | 'rules-correctness-and-readability';
  description: string;
  source: string;
  checkStructure?: (decompiled: string, modeTag: string) => string | null;
}

const REGRESSION_CASES: RuntimeRegressionCase[] = [
  {
    id: 'issue1_short_circuit_and_or_side_effects',
    category: 'issue1-short-circuit',
    description: 'Short-circuit a and bump(b) or bump(c) plus nested/chained/guard variants and exact call counts',
    source: `local calls = {}

local function bump(tag, val)
    calls[#calls + 1] = tag
    return val
end

local function reset()
    calls = {}
end

local function trace()
    return table.concat(calls, ",")
end

local function pickBasic(a, b, c)
    return a and bump("b", b) or bump("c", c)
end

local function pickNot(a, b, c)
    return not a and bump("b", b) or bump("c", c)
end

local function pickMultiGuard(a, b, c, d)
    return a and b and bump("c", c) or bump("d", d)
end

local function pickCmpGuard(x, b, c)
    return (x == 1) and bump("b", b) or bump("c", c)
end

local function pickChained(a, b, c, d, e)
    return a and bump("b", b) or c and bump("d", d) or bump("e", e)
end

local function pickOrAnd(a, b, c)
    return (a or bump("b", b)) and bump("c", c)
end

local function pickSideEffectGuard(a, b, c)
    return bump("a", a) and bump("b", b) or bump("c", c)
end

local function pickTwoWayAnd(a, b)
    return a and bump("b", b)
end

local function pickTwoWayOr(a, b)
    return a or bump("b", b)
end

local function pickNestedOr(a, b, c)
    return a and (b or bump("c", c))
end

local function check(name, fn, ...)
    reset()
    local r = fn(...)
    print(name, tostring(r), trace())
end

check("basic_T_T", pickBasic, true, 10, 20)
check("basic_T_F", pickBasic, true, false, 20)
check("basic_T_nil", pickBasic, true, nil, 20)
check("basic_F_T", pickBasic, false, 10, 20)
check("not_F_T", pickNot, false, 11, 22)
check("not_T_T", pickNot, true, 11, 22)
check("not_F_F", pickNot, false, false, 22)
check("multi_TT_T", pickMultiGuard, true, true, 30, 40)
check("multi_TF_T", pickMultiGuard, true, false, 30, 40)
check("multi_TT_F", pickMultiGuard, true, true, false, 40)
check("cmp_eq", pickCmpGuard, 1, "hit", "miss")
check("cmp_ne", pickCmpGuard, 2, "hit", "miss")
check("chain_1", pickChained, true, "B", true, "D", "E")
check("chain_2", pickChained, false, "B", true, "D", "E")
check("chain_3", pickChained, true, false, false, "D", "E")
check("chain_4", pickChained, true, false, true, "D", "E")
check("orand_T", pickOrAnd, true, "B", "C")
check("orand_F_T", pickOrAnd, false, "B", "C")
check("orand_F_F", pickOrAnd, false, false, "C")
check("seg_T_T", pickSideEffectGuard, true, 7, 8)
check("seg_T_F", pickSideEffectGuard, true, false, 8)
check("seg_F_T", pickSideEffectGuard, false, 7, 8)
check("and2_T", pickTwoWayAnd, true, 99)
check("and2_F", pickTwoWayAnd, false, 99)
check("or2_T", pickTwoWayOr, 55, 99)
check("or2_F", pickTwoWayOr, false, 99)
check("nest_T_T", pickNestedOr, true, 1, 2)
check("nest_T_F", pickNestedOr, true, false, 2)
check("nest_F_F", pickNestedOr, false, false, 2)
`,
  },
  {
    id: 'issue1_short_circuit_multiret_and_closure_state',
    category: 'issue1-short-circuit',
    description: 'Short-circuit operands calling multi-return functions and mutating captured closure state',
    source: `local function makeSelector()
    local count = 0
    local log = {}

    local function bump(tag, v1, v2)
        count += 1
        log[#log + 1] = tag .. ":" .. tostring(count)
        return v1, v2
    end

    local function selectVal(flag, a, b)
        return flag and bump("left", a, a and a * 10 or -1) or bump("right", b, b * 10)
    end

    local function selectSingle(flag, a, b)
        local x = flag and bump("L", a, 111) or bump("R", b, 222)
        return x, count
    end

    local function dump()
        return count, table.concat(log, "|")
    end

    return selectVal, selectSingle, dump
end

local sel, sel1, dump = makeSelector()
local r1, r2 = sel(true, 5, 9)
print("sel_T_5", tostring(r1), tostring(r2), dump())
local r3, r4 = sel(true, false, 9)
print("sel_T_F", tostring(r3), tostring(r4), dump())
local r5, r6 = sel(false, 5, 9)
print("sel_F", tostring(r5), tostring(r6), dump())
local s1, c1 = sel1(true, 3, 4)
local s2, c2 = sel1(false, 3, 4)
local s3, c3 = sel1(true, nil, 4)
print("single", tostring(s1), c1, tostring(s2), c2, tostring(s3), c3, dump())
`,
  },
  {
    id: 'issue1_short_circuit_o2_inlined_and_reset',
    category: 'issue1-short-circuit',
    description: 'O2-inlined short-circuit branches mutating captured table with table reset between calls',
    source: `local log = {}

local function bump(v)
    log[#log + 1] = tostring(v)
    return v
end

local function pick(a, b, c)
    return a and bump(b) or bump(c)
end

local r1 = pick(true, 10, 20)
print("r1", tostring(r1), table.concat(log, ","))
log = {}
local r2 = pick(true, false, 20)
print("r2", tostring(r2), table.concat(log, ","))
log = {}
local r3 = pick(false, 10, 20)
print("r3", tostring(r3), table.concat(log, ","))
`,
  },
  {
    id: 'issue2_closure_statement_execution_order',
    category: 'issue2-statement-order',
    description: 'Exact Test 10 closure operation ordering: add, multiply, second closure add, reset',
    source: `local function makeAccount(start)
    local value = start
    local history = {}

    return function(op, amount)
        if op == "add" then
            value += amount
        elseif op == "multiply" then
            value *= amount
        elseif op == "reset" then
            value = amount
        end
        history[#history + 1] = op .. "=" .. tostring(value)
        return value, table.concat(history, ";")
    end
end

local function runSequence()
    local first = makeAccount(5)
    local second = makeAccount(1)

    local a = first("add", 3)
    local b = first("multiply", 2)
    local c = second("add", 10)
    local d = first("reset", 7)

    return a, b, c, d, d - a, b + c
end

local function runReversedReturn()
    local first = makeAccount(4)
    local second = makeAccount(2)

    local a = first("add", 3)
    local b = first("multiply", 2)
    local c = second("add", 10)
    local d = first("reset", 7)

    return d, c, b, a
end

print("seq", runSequence())
print("rev", runReversedReturn())
`,
  },
  {
    id: 'issue2_deferred_expr_and_table_order',
    category: 'issue2-statement-order',
    description: 'Side-effecting calls wrapped in binary expressions, open table literals, and mixed consumers',
    source: `local function makeCounter(seed)
    local n = seed
    local trace = {}
    return function(op, x)
        if op == "add" then
            n += x
        elseif op == "mul" then
            n *= x
        elseif op == "sub" then
            n -= x
        end
        trace[#trace + 1] = op .. ":" .. tostring(n)
        return n
    end, function()
        return n, table.concat(trace, ",")
    end
end

local function testWrappedBinary()
    local act, inspect = makeCounter(2)
    local x = act("add", 3) + 0
    local y = act("mul", 4) + 100
    local z = act("sub", 5) * 2
    local finalVal, logStr = inspect()
    return x, y, z, finalVal, logStr
end

local function testOpenTableCalls()
    local act, inspect = makeCounter(1)
    local snapshot = {
        first = act("add", 5),
        second = act("mul", 3),
        third = act("sub", 2),
    }
    local after = act("add", 10)
    local finalVal, logStr = inspect()
    return snapshot.third, snapshot.first, snapshot.second, after, finalVal, logStr
end

local function testMutatedUpvalueRead()
    local state = 10
    local function step(delta)
        state = state * 2 + delta
        return state
    end
    local before = state
    local s1 = step(1)
    local mid = state
    local s2 = step(3)
    local after = state
    return after, mid, before, s2, s1
end

print("wrapped", testWrappedBinary())
print("table", testOpenTableCalls())
print("upval", testMutatedUpvalueRead())
`,
  },
  {
    id: 'issue3_if_scope_sequential_and_calls',
    category: 'issue3-lexical-scope',
    description: 'Locals assigned inside if/elseif/else, sequential ifs, method calls, and early-return branches used in local value = v + result',
    source: `local calcObj = {
    scale = 3,
}
function calcObj:compute(n)
    return n * self.scale + 2
end

local function doublePlus(x)
    return x * 2 + 1
end

local function sequentialIfs(a, b, result)
    local picked = 10
    if a > 0 then
        picked = doublePlus(a)
    end
    if b > 0 then
        picked = calcObj:compute(b) + picked
    end
    local value = picked + result
    return value, picked
end

local function ladderWithCalls(mode, x, result)
    local chosen
    if mode == "double" then
        chosen = doublePlus(x)
    elseif mode == "method" then
        chosen = calcObj:compute(x)
    else
        chosen = x - 5
    end
    local value = chosen + result
    return value
end

local function earlyReturnBranch(ok, x, result)
    local chosen
    if ok then
        chosen = doublePlus(x)
    else
        return -999
    end
    local value = chosen + result
    return value
end

print("seq1", sequentialIfs(4, 2, 100))
print("seq2", sequentialIfs(4, 0, 100))
print("seq3", sequentialIfs(0, 2, 100))
print("seq4", sequentialIfs(0, 0, 100))
print("lad1", ladderWithCalls("double", 7, 50))
print("lad2", ladderWithCalls("method", 7, 50))
print("lad3", ladderWithCalls("other", 7, 50))
print("ear1", earlyReturnBranch(true, 6, 40))
print("ear2", earlyReturnBranch(false, 6, 40))
`,
  },
  {
    id: 'issue3_outer_expr_snapshot_and_nested_if',
    category: 'issue3-lexical-scope',
    description: 'Outer unmaterialized expressions surviving past mutating if-blocks plus deeply nested if scopes',
    source: `local function snapshotAcrossIf(state, flag, result)
    local beforeX = state.x
    local beforeSum = state.x + state.y
    if flag then
        state.x = state.x + 100
        state.y = state.y * 2
        local innerOnly = state.x - state.y
        if innerOnly > 0 then
            state.tag = "pos"
        else
            state.tag = "neg"
        end
    end
    local value = beforeX + beforeSum + result
    return value, state.x, state.y, state.tag
end

local function nestedIfScopes(a, b, c, result)
    local outerVal = 1
    if a then
        local branchTmp = 5
        if b then
            outerVal = branchTmp * 10
        else
            if c then
                outerVal = branchTmp + 7
            else
                outerVal = branchTmp + 2
            end
        end
    else
        local siblingTmp = 9
        if c then
            outerVal = siblingTmp * 3
        end
    end
    local value = outerVal + result
    return value
end

local s1 = { x = 4, y = 9, tag = "init" }
print("snapT", snapshotAcrossIf(s1, true, 10))
local s2 = { x = 4, y = 9, tag = "init" }
print("snapF", snapshotAcrossIf(s2, false, 10))
print("nest1", nestedIfScopes(true, true, false, 3))
print("nest2", nestedIfScopes(true, false, true, 3))
print("nest3", nestedIfScopes(true, false, false, 3))
print("nest4", nestedIfScopes(false, false, true, 3))
print("nest5", nestedIfScopes(false, false, false, 3))
`,
  },
  {
    id: 'issue3_multiret_table_and_varargs_scope',
    category: 'issue3-lexical-scope',
    description: 'Mixed outer/inner multi-return CALL, GETVARARGS, and branch-constructed tables referenced after end',
    source: `local function pairFn(n)
    return n > 0, n * 4 + 1
end

local function mixedMultiReturn(flag, n, result)
    local payload = 0
    if flag then
        local ok, computed = pairFn(n)
        if ok then
            payload = computed
        else
            payload = -computed
        end
    end
    local value = payload + result
    return value
end

local function directMultiReturnOuter(flag, n, result)
    local status, outVal = false, 5
    if flag then
        status, outVal = pairFn(n)
    end
    local value = outVal + result
    return status, value
end

local function branchTables(mode, result)
    local cfg
    if mode == 1 then
        cfg = { weight = 3, bias = 4 }
    elseif mode == 2 then
        cfg = { weight = 6, bias = 2 }
    else
        cfg = { weight = 1, bias = 9 }
    end
    local value = cfg.weight * 10 + cfg.bias + result
    return value
end

local function varargsInBranch(flag, result, ...)
    local first, second = 1, 2
    if flag then
        local a, b = ...
        first = a or 10
        second = b or 20
    end
    local value = first + second + result
    return value
end

print("mmr1", mixedMultiReturn(true, 5, 100))
print("mmr2", mixedMultiReturn(true, -2, 100))
print("mmr3", mixedMultiReturn(false, 5, 100))
print("dmr1", directMultiReturnOuter(true, 4, 20))
print("dmr2", directMultiReturnOuter(false, 4, 20))
print("tbl1", branchTables(1, 5))
print("tbl2", branchTables(2, 5))
print("tbl3", branchTables(3, 5))
print("varg1", varargsInBranch(true, 100, 7, 8))
print("varg2", varargsInBranch(true, 100, 7))
print("varg3", varargsInBranch(false, 100, 7, 8))
`,
  },
  {
    id: 'issue3_loop_and_high_register_pressure_scope',
    category: 'issue3-lexical-scope',
    description: 'Locals written inside while/repeat/for loops and high-register-pressure functions (r20+) read outside blocks',
    source: `local function highRegPressure(flagA, flagB, flagC, items, result)
    local a1, a2, a3, a4 = 1, 2, 3, 4
    local b1, b2, b3, b4 = 5, 6, 7, 8
    local c1, c2, c3, c4 = 9, 10, 11, 12
    local d1, d2, d3, d4 = 13, 14, 15, 16
    local e1, e2, e3, e4 = 17, 18, 19, 20
    local checksum = a1 + a2 + a3 + a4 + b1 + b2 + b3 + b4 + c1 + c2 + c3 + c4 + d1 + d2 + d3 + d4 + e1 + e2 + e3 + e4

    local chosen = 0
    if flagA then
        local step = checksum % 17
        if flagB then
            chosen = step * 3 + 1
        else
            chosen = step + 5
        end
    elseif flagC then
        chosen = checksum // 10
    end

    local found = -1
    for i = 1, #items do
        local cur = items[i]
        if cur > chosen then
            found = cur
            break
        end
    end

    local w = 0
    local idx = 1
    while idx <= #items do
        if items[idx] % 2 == 0 then
            w += items[idx]
        end
        idx += 1
    end

    local rAcc = 1
    local k = 1
    repeat
        if k % 2 == 1 then
            rAcc += k * 2
        end
        k += 1
    until k > 4

    local value = chosen + found + w + rAcc + result
    return value, chosen, found, w, rAcc
end

local list = { 3, 8, 15, 22, 41 }
print("hrp1", highRegPressure(true, true, false, list, 1000))
print("hrp2", highRegPressure(true, false, false, list, 1000))
print("hrp3", highRegPressure(false, false, true, list, 1000))
print("hrp4", highRegPressure(false, false, false, list, 1000))
`,
  },
  {
    id: 'issue3_void_call_register_reuse_and_callees',
    category: 'issue3-lexical-scope',
    description: 'Void statement calls inside branches reusing the same register as a subsequent outer-live local assignment plus upval/table callee calls',
    source: `local events = {}
local function note(msg)
    events[#events + 1] = msg
end

local ops = {
    triple = function(x)
        return x * 3
    end,
}

local function makeRunner(offset)
    local function upvalCalc(x)
        return x * 5 + offset
    end

    return function(mode, x, result)
        local chosen
        if mode == 1 then
            note("m1:" .. tostring(x))
            chosen = upvalCalc(x)
        elseif mode == 2 then
            note("m2:" .. tostring(x))
            chosen = ops.triple(x)
        elseif mode == 3 then
            note("m3:" .. tostring(x))
            local tmp = x + 4
            note("m3b:" .. tostring(tmp))
            chosen = tmp * 2
        else
            note("default")
            chosen = 1
        end
        local value = chosen + result
        return value, chosen
    end
end

local run = makeRunner(7)
print("r1", run(1, 4, 100))
print("r2", run(2, 4, 100))
print("r3", run(3, 4, 100))
print("r4", run(4, 4, 100))
print("ev", table.concat(events, "|"))
`,
  },
  {
    id: 'issue4_chained_logical_in_arithmetic_and_register_reuse',
    category: 'issue4-logical-in-arithmetic',
    description: 'Multi-term chained logical expressions inside arithmetic (with side effects, register reuse, -O2 inlining, and scoped accumulation) must never duplicate additions or reuse stale register values',
    source: `local state = 0
local function bump(k)
    state += k
    return state
end

local function double(n)
    return n * 2
end

local function sumFourCalls(a, b, c, d)
    local result = (a and bump(2) or bump(3))
        + (b and bump(4) or bump(5))
        + (c and bump(1) or bump(6))
        + (d and bump(7) or bump(2))
    return result, state
end

local function sumFourPure(a, b, c, d)
    local result = (a and double(6) or double(4))
        + (b and double(8) or double(10))
        + (c and double(5) or double(3))
        + (d and double(2) or double(7))
    local total = 0
    for i = 1, 4 do
        total += i * 2
    end
    local scoped
    if result > 30 then
        local bonus = result + total
        scoped = bonus + result
    else
        scoped = result
    end
    return result, total, scoped
end

print("c4", sumFourCalls(true, false, true, false))
print("p4a", sumFourPure(true, false, false, false))
print("p4b", sumFourPure(false, true, false, true))
`,
  },
  {
    id: 'issue4_nested_jump_threaded_logical_dags',
    category: 'issue4-logical-in-arithmetic',
    description: 'Nested jump-threaded short-circuit DAGs, multi-guard comparisons/table accesses, and if-expressions inside arithmetic must preserve exact expression trees and precedence',
    source: `local function nestedLogical(a, b, c, d, e, f, g)
    local r1 = (a and (b and 10 or 12) or 14) + (b and (c and 8 or 6) or 4) + (c and 20 or 18) + (d and 16 or 12)
    local r2 = ((a or b) and (c or d) or 5) + ((b and c) or (d and e) or 7) + ((a and e) or (c and f) or 11)
    local r3 = (if a then (b and c or d) else (e and f or g)) + (a and 10 or 20)
    return r1, r2, r3
end

local function guardedAndTable(x, y, z, t)
    local r1 = (x > 0 and y > 0 and 12 or x > 0 and 8 or 4) + (z > 0 and 20 or 10)
    local r2 = ((x > 3 and y > 2) and 16 or (z == 0) and 24 or 32) + ((x < 10 or y < 0) and 16 or 8)
    local r3 = (t.a and t.b or t.c) + (t.d or t.e or 10) + ((t.a and t.d) and t.b or t.e)
    return r1, r2, r3
end

print("nl1", nestedLogical(true, false, 9, 14, 16, 18, 22))
print("nl2", nestedLogical(false, 12, false, 14, 16, 18, 22))
print("nl3", nestedLogical(true, 11, 13, 14, 16, 18, 22))
print("nl4", nestedLogical(false, false, false, 14, false, 18, 22))
local tbl = { a = true, b = 12, c = 4, d = false, e = 18 }
print("gt1", guardedAndTable(5, 4, 1, tbl))
print("gt2", guardedAndTable(1, 1, 0, tbl))
print("gt3", guardedAndTable(15, 5, 1, tbl))
`,
  },
  {
    id: 'issue4_operator_precedence_prefix_parens_and_setlist_trunc',
    category: 'issue4-logical-in-arithmetic',
    description: 'Exponentiation vs unary minus, comparison on logical expressions, prefix parens on (a or b).x / [1] / :m() / (x), and fixed-count SETLIST multi-return truncation',
    source: `local function pair(x)
    return x, x * 10, x * 100
end

local function precAndPrefix(a, b, c, t1, t2, f1, f2)
    local p1 = (-a) ^ 2 + -(a ^ 2) + (a ^ b) ^ c + a ^ (b ^ c)
    local p2 = ((a > 0 or b > 0) == true) and 7 or 3
    local v1 = (t1 or t2).val
    local v2 = (t1 or t2)[1]
    local v3 = (t1 or t2):get(3)
    local v4 = (f1 or f2)(10)
    local tSingle = { (pair(2)) }
    local tExpand = { pair(2) }
    local tTailSingle = { 1, (pair(3)) }
    local tTailExpand = { 1, pair(3) }
    return p1, p2, v1, v2, v3, v4, #tSingle, #tExpand, #tTailSingle, #tTailExpand
end

local obj = { val = 10, [1] = 20, get = function(self, k) return self.val + k end }
print("pp", precAndPrefix(2, 3, 2, nil, obj, false, function(x) return x + 5 end))
`,
  },
  {
    id: 'issue5_test17_multret_unpack_select',
    category: 'issue5-multret-and-game-patterns',
    description: 'Test 17 multret preservation for table.unpack(packed, 1/2, packed.n) and select(2, ...) in return lists with nil holes',
    source: `local function choose(mode, ...)
    local packed = table.pack(...)
    if mode == 1 then
        return "m1", table.unpack(packed, 1, packed.n)
    elseif mode == 2 then
        return "m2", table.unpack(packed, 2, packed.n)
    end
    return "fb", select(2, ...)
end

local function chooseCount(mode, ...)
    local packed = table.pack(...)
    if mode == 1 then
        return packed.n, table.unpack(packed, 1, packed.n)
    elseif mode == 2 then
        return packed.n - 1, table.unpack(packed, 2, packed.n)
    end
    return select("#", ...), select(2, ...)
end

local function chooseDirect(mode, ...)
    local packed = table.pack(...)
    if mode == 1 then
        return table.unpack(packed, 1, packed.n)
    elseif mode == 2 then
        return table.unpack(packed, 2, packed.n)
    end
    return select(2, ...)
end

local function sumAll(...)
    local n = select("#", ...)
    local s = 0
    for i = 1, n do
        local v = select(i, ...)
        if type(v) == "number" then
            s += v
        elseif v == nil then
            s += 100
        else
            s += 1
        end
    end
    return n, s
end

print("A1", sumAll(choose(1, 10, nil, 30, nil, 50)))
print("A2", sumAll(choose(2, 10, nil, 30, nil, 50)))
print("A3", sumAll(choose(3, 10, nil, 30, nil, 50)))
print("B1", sumAll(chooseCount(1, 10, nil, 30, nil, 50)))
print("B2", sumAll(chooseCount(2, 10, nil, 30, nil, 50)))
print("B3", sumAll(chooseCount(3, 10, nil, 30, nil, 50)))
print("C1", sumAll(chooseDirect(1, 10, nil, 30, nil, 50)))
print("C2", sumAll(chooseDirect(2, 10, nil, 30, nil, 50)))
print("C3", sumAll(chooseDirect(3, 10, nil, 30, nil, 50)))
`,
  },
  {
    id: 'issue5_multret_matrix_tables_calls_locals',
    category: 'issue5-multret-and-game-patterns',
    description: 'Multret across RETURN prefixes (upvalue/global/side-effect/ternary), SETLIST C=0 (>16 elements), CALL B=0, (...) truncation, and multi-local assignment',
    source: `local gTag = "G"

local function makeRunner(upPrefix)
    local count = 0
    local function bump(tag)
        count += 1
        return tag .. ":" .. tostring(count)
    end
    local function run(mode, ...)
        local packed = table.pack(...)
        if mode == 1 then
            return packed.n, table.unpack(packed, 1, packed.n)
        elseif mode == 2 then
            return upPrefix, table.unpack(packed, 2, packed.n)
        elseif mode == 3 then
            return gTag, select(2, ...)
        elseif mode == 4 then
            return bump("hit"), select("#", ...), table.unpack(packed, 1, packed.n)
        elseif mode == 5 then
            return (if packed.n > 2 then "big" else "small"), select(2, ...)
        elseif mode == 6 then
            return (table.unpack(packed, 1, packed.n))
        elseif mode == 7 then
            return (select(2, ...))
        elseif mode == 8 then
            return "lit", ...
        else
            return packed.n, ...
        end
    end
    return run, function() return count end
end

local function packTable(...)
    local packed = table.pack(...)
    local t1 = { packed.n, table.unpack(packed, 1, packed.n) }
    local t2 = { "head", (table.unpack(packed, 1, packed.n)), "tail" }
    local t3 = { packed.n, select(2, ...) }
    local t4 = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, table.unpack(packed, 1, packed.n) }
    return #t1, t1[1], t1[3], #t2, t2[2], t2[3], #t3, t3[1], t3[3], #t4, t4[19]
end

local function callArgs(a, b, ...)
    local packed = table.pack(...)
    local function sink(...)
        local n = select("#", ...)
        local sum = 0
        for i = 1, n do
            local v = select(i, ...)
            if type(v) == "number" then sum += v elseif v == nil then sum += 100 else sum += 1 end
        end
        return n, sum
    end
    local n1, s1 = sink(a, table.unpack(packed, 1, packed.n))
    local n2, s2 = sink(b, select(2, ...))
    local n3, s3 = sink(packed.n, (table.unpack(packed, 1, packed.n)), 99)
    return n1, s1, n2, s2, n3, s3
end

local function multiLocalAssign(...)
    local packed = table.pack(...)
    local a, b, c = table.unpack(packed, 1, packed.n)
    local x, y, z = select(2, ...)
    local p, q, r = ...
    return tostring(a), tostring(b), tostring(c), tostring(x), tostring(y), tostring(z), tostring(p), tostring(q), tostring(r)
end

local function collect(...)
    local n = select("#", ...)
    local out = { tostring(n) }
    for i = 1, n do
        local v = select(i, ...)
        out[#out + 1] = tostring(v)
    end
    return table.concat(out, ",")
end

local r, getCount = makeRunner("UP")
for m = 1, 9 do
    print("R" .. m, collect(r(m, 10, nil, 30, nil, 50)))
end
print("CNT", getCount())
print("PT", packTable(10, nil, 30, 40))
print("CA", callArgs("x", 7, 10, nil, 30))
print("ML", multiLocalAssign(11, 22, 33, 44))
`,
  },
  {
    id: 'issue5_game_net_packet_codec',
    category: 'issue5-multret-and-game-patterns',
    description: 'Realistic packet codec exercising jump-threaded FORNPREP inside elseif, nested for loops, bit32, and multret table.unpack(out, 1, count)',
    source: `local function writeU16(buf, v)
    buf[#buf + 1] = bit32.band(bit32.rshift(v, 8), 0xFF)
    buf[#buf + 1] = bit32.band(v, 0xFF)
end

local function readU16(buf, pos)
    return bit32.bor(bit32.lshift(buf[pos], 8), buf[pos + 1]), pos + 2
end

local function encodePayload(opcode, flags, ...)
    local packed = table.pack(...)
    local buf = {
        bit32.band(opcode, 0xFF),
        bit32.bor(bit32.lshift(bit32.band(flags, 0x0F), 4), bit32.band(packed.n, 0x0F)),
    }
    for i = 1, packed.n do
        local v = packed[i]
        if v == nil then
            buf[#buf + 1] = 0
        elseif type(v) == "number" then
            buf[#buf + 1] = 1
            writeU16(buf, math.clamp(math.floor(v), 0, 65535))
        elseif type(v) == "string" then
            buf[#buf + 1] = 2
            buf[#buf + 1] = #v
            for j = 1, #v do
                buf[#buf + 1] = string.byte(v, j)
            end
        elseif type(v) == "boolean" then
            buf[#buf + 1] = v and 3 or 4
        end
    end
    return buf
end

local function decodePayload(buf)
    local opcode = buf[1]
    local meta = buf[2]
    local flags = bit32.extract(meta, 4, 4)
    local count = bit32.extract(meta, 0, 4)
    local pos = 3
    local out = table.create(count)
    for i = 1, count do
        local tag = buf[pos]
        pos += 1
        if tag == 0 then
            out[i] = nil
        elseif tag == 1 then
            local num
            num, pos = readU16(buf, pos)
            out[i] = num
        elseif tag == 2 then
            local len = buf[pos]
            pos += 1
            local chars = {}
            for j = 1, len do
                chars[j] = string.char(buf[pos + j - 1])
            end
            pos += len
            out[i] = table.concat(chars)
        elseif tag == 3 then
            out[i] = true
        elseif tag == 4 then
            out[i] = false
        end
    end
    return opcode, flags, table.unpack(out, 1, count)
end

local raw = encodePayload(0x4A, 5, 1024, nil, "Spawn", true, nil, 77)
local op, fl, a, b, c, d, e, f = decodePayload(raw)
print("PKT", #raw, op, fl, tostring(a), tostring(b), tostring(c), tostring(d), tostring(e), tostring(f))
`,
  },
  {
    id: 'issue5_game_inventory_loot_fsm',
    category: 'issue5-multret-and-game-patterns',
    description: 'Nested table catalog literal + dead local scratch release under -O0 + repeat-until/while/ipairs/break/continue loot wave FSM',
    source: `local LOOT_CATALOG = {
    { id = "sword_iron", weight = 40, rarity = 1, tags = { "melee", "starter" } },
    { id = "bow_oak", weight = 25, rarity = 1, tags = { "ranged", "wood" } },
    { id = "staff_ember", weight = 15, rarity = 2, tags = { "magic", "fire" } },
    { id = "shield_aegis", weight = 12, rarity = 3, tags = { "armor", "block" } },
    { id = "ring_void", weight = 8, rarity = 4, tags = { "trinket", "shadow" } },
}

local function makeRng(seed)
    local s = seed
    return function(limit)
        s = (s * 1664525 + 1013904223) % 4294967296
        return (s % limit) + 1
    end
end

local function simulateWaves(seed)
    local roll = makeRng(seed)
    local bag = {}
    local wave = 0
    local score = 0
    repeat
        wave += 1
        local tries = 0
        while tries < 4 do
            tries += 1
            if wave == 2 and tries == 2 then
                continue
            end
            local totalWeight = 0
            for _, item in ipairs(LOOT_CATALOG) do
                if item.rarity <= wave + 1 then
                    totalWeight += item.weight
                end
            end
            local target = roll(totalWeight)
            local cursor = 0
            local picked = nil
            for _, item in ipairs(LOOT_CATALOG) do
                if item.rarity <= wave + 1 then
                    cursor += item.weight
                    if target <= cursor then
                        picked = item
                        break
                    end
                end
            end
            if picked then
                bag[picked.id] = (bag[picked.id] or 0) + 1
                score += picked.rarity * tries + #picked.tags
                if picked.rarity >= 3 then
                    break
                end
            end
        end
    until wave >= 4 or score >= 50
    local summary = {}
    for k, v in pairs(bag) do
        summary[#summary + 1] = k .. "=" .. tostring(v)
    end
    table.sort(summary)
    return wave, score, table.concat(summary, ",")
end

print("W1", simulateWaves(1337))
print("W2", simulateWaves(9001))
`,
  },
  {
    id: 'issue5_game_nested_loops_xpcall_and_closures',
    category: 'issue5-multret-and-game-patterns',
    description: 'Nested while + repeat-until + numeric/generic for loops, closures capturing ref vs per-iteration value upvalues, xpcall, interpolated strings, and method multret forwarding',
    source: `local Store = {}
Store.__index = Store

function Store.new(prefix, ...)
    return setmetatable({
        prefix = prefix,
        data = table.pack(...),
    }, Store)
end

function Store:UnpackRange(fromIdx)
    return self.prefix, table.unpack(self.data, fromIdx or 1, self.data.n)
end

function Store:Inspect(mode, ...)
    if mode == "fwd" then
        return self:UnpackRange(2)
    elseif mode == "xp" then
        local ok, a, b, c = xpcall(function(x, ...)
            if x < 0 then error("neg", 0) end
            return x * 2, select(2, ...)
        end, function(err)
            return "CAUGHT:" .. tostring(err)
        end, ...)
        return ok, tostring(a), tostring(b), tostring(c)
    end
    return \`prefix={self.prefix},n={self.data.n},extra={select("#", ...)}\`, select(1, ...)
end

local function runEngine(limit)
    local total = 0
    local callbacks = {}
    local phase = 0
    while phase < limit do
        phase += 1
        local round = 0
        repeat
            round += 1
            if phase == 2 and round == 2 then
                continue
            end
            for step = 1, 3 do
                local capturedPhase = phase
                local capturedRound = round
                if step == 2 and phase == 3 then
                    break
                end
                callbacks[#callbacks + 1] = function(mul)
                    total += (capturedPhase * 10 + capturedRound + step) * mul
                    return total
                end
            end
        until round >= 3 or phase >= 4
    end
    local outs = {}
    for i, cb in callbacks do
        outs[i] = tostring(cb((i % 2) + 1))
    end
    return total, #callbacks, table.concat(outs, ",")
end

local function tally(...)
    local n = select("#", ...)
    local s = 0
    for i = 1, n do
        local v = select(i, ...)
        if type(v) == "number" then s += v elseif v == nil then s += 100 else s += #tostring(v) end
    end
    return n, s
end

local st = Store.new("INV", 10, nil, 30, nil, 50)
print("ST1", tally(st:UnpackRange(1)))
print("ST2", tally(st:Inspect("fwd")))
print("ST3", st:Inspect("xp", 7, "alpha", "beta"))
print("ST4", st:Inspect("xp", -1, "ignored"))
print("ST5", tally(st:Inspect("other", 11, nil, 22)))
print("ENG", runEngine(4))
`,
  },
  {
    id: 'rule2_1_2_2_copies_closures_and_shadowing',
    category: 'rules-correctness-and-readability',
    description: 'Rule 2.1 & 2.2: separate mutated copies, per-pass loop closure captures, and shadowed do-block locals',
    source: `local function copyAndShadow(seed)
    local a = seed + 3
    local b = a
    a += 1

    local snapshot = {}
    local live = 0
    for i = 1, 3 do
        live += i
        local frozen = live
        snapshot[i] = function()
            return frozen, live
        end
    end

    local value = seed * 2
    do
        local value = value + 10
        print("SHADOW_INNER", value)
    end

    local f1, l1 = snapshot[1]()
    local f2, l2 = snapshot[2]()
    local f3, l3 = snapshot[3]()
    return a, b, f1, l1, f2, l2, f3, l3, value
end

print("R21", copyAndShadow(5))
print("R21B", copyAndShadow(9))
`,
  },
  {
    id: 'rule2_3_2_4_short_circuit_and_multret_tails',
    category: 'rules-correctness-and-readability',
    description: 'Rule 2.3 & 2.4: preserve a and b or c when b can be false/nil, and keep ..., select("#", ...), table.pack(f()), and tail multret intact',
    source: `local function pair(x, y)
    return x, y, x + y
end

local function pick(a, b, c)
    return a and b or c
end

local function forward(tag, ...)
    local argc = select("#", ...)
    local packed = table.pack(pair(argc, 10))
    return tag, argc, packed[1], packed[2], packed[3], ...
end

print("SC1", pick(true, false, 99))
print("SC2", pick(true, nil, 88))
print("SC3", pick(false, true, 77))
print("MR1", forward("A", 1, nil, 3))
print("MR2", forward("B"))
`,
  },
  {
    id: 'rule3_readability_naming_swaps_loops_and_layout',
    category: 'rules-correctness-and-readability',
    description: 'Rule 3.1-3.8: dead local separation, constant-right comparisons, short-tail if vs continue, swap/fib folding, while-true vs repeat, clean params/names/ops',
    source: `local function splitDeadAndLoops(push)
    local sumA = 0
    for j = 10, 1, -2 do
        sumA += j
    end
    push(sumA)

    local sumB = 0
    for j = 1, 5 do
        sumB += j
    end
    push(sumB)
end

local function fibAndSwap(n, p, q)
    local a, b = 0, 1
    for i = 1, n do
        a, b = b, a + b
    end
    return a, b, q, p
end

local function loopsAndGuards(flag, x, limit, tbl, key, stepFn, push)
    local empty
    local ok = not flag
    if 8 <= x and 50 < limit then
        tbl.n += 5
        tbl[key] -= 1
    end

    local total = 0
    for i = 1, 4 do
        for j = 1, 4 do
            if i * j == 12 then
                total += i + j
                break
            end
        end
    end

    local skipped = 0
    for k = 1, 10 do
        if k == 6 then
            continue
        end
        skipped += k
    end

    local n = 0
    while true do
        n += 1
        local res = stepFn(n)
        if res == "stop" then
            break
        end
        push(res)
    end

    local r = 0
    repeat
        r += 1
        push(r)
    until r >= 3

    return empty, ok, total, skipped, tbl.n, tbl[key]
end

local items = {}
local function push(v)
    items[#items + 1] = v
end

splitDeadAndLoops(push)
print("FIB", fibAndSwap(7, "left", "right"))
print("LGS", loopsAndGuards(false, 12, 75, { n = 3, k = 10 }, "k", function(n) return n >= 3 and "stop" or n * 10 end, push))
print("ITEMS", table.concat(items, ","))
`,
    checkStructure: (src: string, modeTag: string) => {
      if (/\b(?:total|value|counter|worker)\d+\b/.test(src)) {
        return 'Disallowed numeric suffix on weak semantic name (e.g. total2/value2)';
      }
      if (/\b\d+\s*(?:<=|>=|<|>)\s*[A-Za-z_]/.test(src)) {
        return 'Constant appeared on LHS of comparison';
      }
      if (/\bnot\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)/.test(src)) {
        return 'Redundant parens around simple identifier after `not`';
      }
      if (/local\s+[A-Za-z_]\w*\s*=\s*nil\b/.test(src)) {
        return 'Redundant `= nil` on local declaration';
      }
      if (modeTag === '-O1 -g1') {
        if (!src.includes('n1, n2 = n2, n1 + n2') && !src.includes('a, b = b, a + b')) {
          return 'Expected Fibonacci multi-assignment folding in -O1 -g1';
        }
        if (/for\s+\w+\s*=\s*1,\s*4\s+do\n\s+for\s+\w+\s*=\s*1,\s*4\s+do\n\s+if\s+[^=\n]*~=\s*12\s+then\n\s+continue/.test(src)) {
          return 'Short break tail in inner loop emitted `continue` instead of `if i * j == 12 then ... break end`';
        }
        if (!/if\s+\w+\s*==\s*6\s+then\s*\n\s*continue/.test(src)) {
          return 'Expected `if i == 6 then continue end` to be preserved at top of loop';
        }
        if (!src.includes('while true do')) {
          return 'Expected `while true do` loop shape to be preserved';
        }
        if (!src.includes('repeat') || !/until\s+\w+\s*>=\s*3/.test(src)) {
          return 'Expected `repeat ... until` loop shape to be preserved';
        }
        if (!src.includes('tbl.n += 5') && !/\.n\s*\+=\s*5/.test(src)) {
          return 'Expected `.n += 5` compound assignment on table field';
        }
        if (!/\[[^\]]+\]\s*-=\s*1/.test(src)) {
          return 'Expected `[key] -= 1` compound assignment on bracket table field';
        }
      }
      return null;
    },
  },
  {
    id: 'sample_full_idiomatic_parities',
    category: 'issue5-multret-and-game-patterns',
    description: 'Full Chris benchmark sample: closures, varargs, Vec2 metatable, primes, interpolation, pcall error table, evens repeat-until, coroutine.wrap, Players loop',
    source: `local game = {
    GetService = function(_, name)
        return {
            GetPlayers = function()
                return {
                    {
                        Name = "Ada",
                        Character = {
                            WaitForChild = function(_, child)
                                return {
                                    WalkSpeed = 16,
                                    Died = {
                                        Connect = function(_, cb)
                                            cb()
                                            return "conn:" .. child
                                        end,
                                    },
                                }
                            end,
                        },
                    },
                    {
                        Name = "Lin",
                        Character = nil,
                    },
                }
            end,
        }
    end,
}

local Players = game:GetService("Players")

local function makeCounter(init: number, step: number)
    local cur = init
    local function inc()
        cur += step
        return cur
    end
    local function reset()
        cur = init
    end
    return inc, reset
end

local function sumAll(...)
    local total = 0
    for i = 1, select("#", ...) do
        total += select(i, ...)
    end
    return total, table.pack(...).n
end

local Vec2 = {}
Vec2.__index = Vec2

function Vec2.__call(self, key)
    return self[key]
end

function Vec2.__add(a, b)
    return setmetatable({ x = a.x + b.x, y = a.y + b.y }, Vec2)
end

function Vec2.new(x: number, y: number)
    return setmetatable({ x = x, y = y }, Vec2)
end

function Vec2.len(self)
    return math.sqrt(self.x ^ 2 + self.y ^ 2)
end

local function primes(limit: number)
    local out = {}
    for i = 2, limit do
        local isPrime = true
        for j = 2, math.floor(math.sqrt(i)) do
            if i % j == 0 then
                isPrime = false
                break
            end
        end
        if isPrime then
            out[#out + 1] = i
        end
    end
    for i = #out, 1, -2 do
        if out[i] > 40 then
            out[i] = nil
        end
    end
    return out
end

local function describe(n: number)
    local sign = if n < 0 then "neg" else "pos"
    local parity = if n % 2 == 0 then "even" else "odd"
    return \`{n}:{sign}:{parity}\`
end

local function risky(x: number)
    if x < 0 then
        error({ code = 400, msg = "neg" })
    end
    return x * 10
end

local function evens(list)
    local i = 0
    return function()
        repeat
            i += 1
        until list[i] == nil or list[i] % 2 == 0
        return list[i]
    end
end

local co = coroutine.wrap(function()
    for i = 1, 3 do
        coroutine.yield(i * i)
    end
end)

local inc, reset = makeCounter(10, 3)
print(inc(), inc(), reset(), inc())
print(sumAll(1, 2, 3, 4))
print((Vec2.new(3, 4) + Vec2.new(1, 1)):len(), Vec2.new(1, 2)("x"))
local p = primes(50)
local pbuf = {}
for k = 1, 16 do
    pbuf[#pbuf + 1] = tostring(p[k])
end
print(table.concat(pbuf, ","))
print(describe(7), describe(-3), describe(12))
local ok1, res1 = pcall(risky, 5)
local ok2, err2 = pcall(risky, -1)
print(ok1, res1, ok2, type(err2), err2.code, err2.msg)
for v in evens({ 1, 3, 4, 7, 8, 10 }) do
    print(v)
end
print(co(), co(), co(), co())

local list = Players:GetPlayers()
for _, player in ipairs(list) do
    local char = player.Character
    if char then
        local hum = char:WaitForChild("Humanoid")
        local conn = hum.Died:Connect(function()
            print(player.Name .. " died")
        end)
        print(hum.WalkSpeed, conn)
    end
end
`,
    checkStructure: (src: string, modeTag: string) => {
      if (/:\s*(?:table|userdata|function)\b/.test(src)) {
        return 'Emitted invalid Luau type annotation (`: table`, `: userdata`, or `: function`)';
      }
      if (/--\s*upvalues:.*\(upval\)/.test(src)) {
        return 'Upvalue annotation used `(upval)` instead of `(val)` or `(ref)`';
      }
      if (src.includes('while true do')) {
        return 'repeat-until loop collapsed into `while true do`';
      }
      if (modeTag === '-O1 -g1') {
        if (!src.includes('return setmetatable({ x = a.x + b.x, y = a.y + b.y }, mt)')) {
          return 'Expected Vec2.__add to inline table literal in setmetatable';
        }
        if (!src.includes('for v in evens({ 1, 3, 4, 7, 8, 10 }) do')) {
          return 'Expected `for v in evens({ 1, 3, 4, 7, 8, 10 }) do` in -O1 -g1';
        }
        if (!src.includes('print(co(), co(), co(), co())')) {
          return 'Expected `print(co(), co(), co(), co())` without redundant v4/v5/v6 snapshots';
        }
        if (/local\s+walkSpeed\b/.test(src)) {
          return 'Unexpected dead local `walkSpeed` from NAMECALL self register leak';
        }
      }
      return null;
    },
  },
  {
    id: 'sec1_repeat_until_done_boolean_dag',
    category: 'sec1-boolean-correctness',
    description: 'Boolean reconstruction in loop exits: repeat local done = tries >= 3 or (found ~= nil and found[1] == 1); tries += 1 until done',
    source: `local function testRepeatDone(found)
    local tries = 0
    repeat
        local done = tries >= 3 or (found ~= nil and found[1] == 1)
        tries += 1
    until done
    return tries
end

local function testRepeatComplex(a, b, c)
    local n = 0
    repeat
        local stop = n >= 2 or (a and b ~= nil and b.ok == true and c > 0)
        n += 1
    until stop
    return n
end

print("nil", testRepeatDone(nil))
print("zero", testRepeatDone({ 0 }))
print("one", testRepeatDone({ 1 }))
print("two", testRepeatDone({ 2 }))
print("c1", testRepeatComplex(true, nil, 0))
print("c2", testRepeatComplex(true, { ok = true }, 5))
print("c3", testRepeatComplex(false, { ok = true }, 5))
`,
  },
  {
    id: 'sec1_nan_and_metamethod_comparison_inversion',
    category: 'sec1-boolean-correctness',
    description: 'Comparison inversion safety with NaN (0/0) and __lt/__le metamethods',
    source: `local nan = 0 / 0
local function checkNan(x, y)
    local a = not (x < y)
    local b = not (x <= y)
    local c = not (x > y)
    local d = not (x >= y)
    local e = not (x == y)
    local f = not (x ~= y)
    local br = "F"
    if not (x < y) then
        br = "T"
    end
    return a, b, c, d, e, f, br
end

local mt = {
    __lt = function(u, v)
        return false
    end,
    __le = function(u, v)
        return false
    end,
}
local o1 = setmetatable({ v = 10 }, mt)
local o2 = setmetatable({ v = 5 }, mt)

print("nan1", checkNan(nan, 1))
print("nan2", checkNan(1, nan))
print("nan3", checkNan(nan, nan))
print("num", checkNan(2, 5))
print("meta", checkNan(o1, o2))
`,
  },
  {
    id: 'sec1_demorgan_short_circuit_and_side_effects',
    category: 'sec1-boolean-correctness',
    description: 'De Morgan rewrites preserving exact short-circuit evaluation order and side effects',
    source: `local trace = {}
local function hit(tag, val)
    trace[#trace + 1] = tag
    return val
end

local function runDeMorgan(a, b, c, d)
    trace = {}
    local r1 = not (hit("A", a) or hit("B", b))
    local r2 = not (hit("C", c) and hit("D", d))
    local br1 = "else1"
    if not (hit("E", a) and hit("F", b)) then
        br1 = "then1"
    end
    local br2 = "else2"
    if not (hit("G", c) or hit("H", d)) then
        br2 = "then2"
    end
    return r1, r2, br1, br2, table.concat(trace, ",")
end

print(runDeMorgan(true, false, true, false))
print(runDeMorgan(false, true, false, true))
print(runDeMorgan(false, false, true, true))
print(runDeMorgan(nil, "x", "y", nil))
`,
  },
  {
    id: 'sec1_and_or_falsy_middle_and_compound_dags',
    category: 'sec1-boolean-correctness',
    description: 'a and b or c with falsy b must never collapse to if-expression; compound boolean DAGs in locals and branches',
    source: `local function ternaryFalsy(a, b, c)
    return a and b or c
end

local function compoundBoolDag(a, b, c, d)
    local x = (a == 1 or b == 2) and (c == 3 or d == 4)
    local y = (a == 1 and b == 2) or (c == 3 and d == 4)
    local z = "no"
    if (a == 1 and b == 2) or c == 3 then
        z = "yes"
    end
    return x, y, z
end

print("f1", ternaryFalsy(true, false, "fallback"))
print("f2", ternaryFalsy(true, nil, "fallback"))
print("f3", ternaryFalsy(true, 0, "fallback"))
print("f4", ternaryFalsy(false, "mid", "fallback"))
print("f5", ternaryFalsy(true, false, false))
print("f6", ternaryFalsy(true, nil, false))

for _, a in ipairs({ 0, 1 }) do
    for _, b in ipairs({ 0, 2 }) do
        for _, c in ipairs({ 0, 3 }) do
            for _, d in ipairs({ 0, 4 }) do
                print(a, b, c, d, compoundBoolDag(a, b, c, d))
            end
        end
    end
end
`,
  },
];

function encodeCompiledLuauAsRoblox227(bytes: Uint8Array): Uint8Array {
  const parsed = parseLuauBytecode(bytes, false);
  if (!parsed.chunk) throw new Error('parseLuauBytecode failed while encoding *227 test input');
  const out = new Uint8Array(bytes);
  for (const proto of parsed.chunk.protos) {
    if (proto.codeStartOffset === undefined) {
      throw new Error(`Proto ${proto.id} missing codeStartOffset`);
    }
    for (const ins of proto.instructions) {
      const bytePos = proto.codeStartOffset + ins.pc * 4;
      out[bytePos] = (out[bytePos] * 227) & 0xff;
    }
  }
  const verify = parseLuauBytecode(out, true);
  if (verify.chunk?.encoding !== 'roblox-227') {
    throw new Error(`Expected roblox-227 encoding after transform, got ${verify.chunk?.encoding}`);
  }
  return out;
}

function compileLuau(source: string, flags: string[]): Uint8Array {
  const tmpPath = path.join(os.tmpdir(), `oplift_reg_${crypto.randomUUID()}.luau`);
  fs.writeFileSync(tmpPath, source, 'utf8');
  try {
    const out = execFileSync(LUAU_COMPILE, ['--binary', ...flags, '-t1', tmpPath], {
      maxBuffer: 8 * 1024 * 1024,
    });
    if (out.length === 0 || out[0] === 0) {
      throw new Error(`luau-compile failed: ${out.subarray(1).toString('utf8')}`);
    }
    return new Uint8Array(out);
  } finally {
    fs.unlinkSync(tmpPath);
  }
}

function runLuau(source: string): string {
  const tmpPath = path.join(os.tmpdir(), `oplift_run_${crypto.randomUUID()}.luau`);
  fs.writeFileSync(tmpPath, source, 'utf8');
  try {
    return execFileSync(LUAU_EXEC, [tmpPath], {
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } finally {
    fs.unlinkSync(tmpPath);
  }
}

/**
 * Extract all global variable names (GETGLOBAL / GETIMPORT root) from compiled Luau source
 * using `luau-compile --text`. Any synthetic local (e.g. v25) that escapes its lexical block
 * compiles as a global reference in Luau and will appear here even if runtime doesn't crash.
 */
function extractReferencedGlobals(source: string): Set<string> {
  const tmpPath = path.join(os.tmpdir(), `oplift_globals_${crypto.randomUUID()}.luau`);
  fs.writeFileSync(tmpPath, source, 'utf8');
  try {
    const text = execFileSync(LUAU_COMPILE, ['--text', '-O0', '-g0', tmpPath], {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
    });
    const globals = new Set<string>();
    for (const line of text.split('\n')) {
      const mGlobal = line.match(/\b(?:GETGLOBAL|SETGLOBAL)\s+R\d+\s+K\d+\s+\['([^']+)'\]/);
      if (mGlobal) globals.add(mGlobal[1]);
      const mImport = line.match(/\bGETIMPORT\s+R\d+\s+\d+\s+\[([A-Za-z_][A-Za-z0-9_]*)/);
      if (mImport) globals.add(mImport[1]);
    }
    return globals;
  } finally {
    fs.unlinkSync(tmpPath);
  }
}

function hasEmptyIfBlock(src: string): boolean {
  return /\bif\b[^\n]*\bthen\s*\n\s*(?:else(?:if\b[^\n]*\bthen)?\s*\n\s*)?end\b/.test(src);
}

function hasUnreconstructedMarker(src: string): boolean {
  return /\[unhandled|UNRECONSTRUCTED|unreconstructed/i.test(src);
}

function hasValidRequiredHeader(src: string | undefined): boolean {
  if (!src) return false;
  if (!src.startsWith('-- https://oplift.ai.studio\n\n')) return false;
  const matches = src.match(/-- https:\/\/oplift\.ai\.studio/g) ?? [];
  return matches.length === 1;
}

function main() {
  if (!fs.existsSync(LUAU_COMPILE) || !fs.existsSync(LUAU_EXEC)) {
    console.error('Missing official Luau binaries in ./bin/luau-compile or ./bin/luau');
    process.exit(1);
  }

  let passed = 0;
  let failed = 0;

  // Rule 1 check on failed / empty bytecode inputs
  const invalidChecks = [
    { name: 'header/empty-string', res: decompileBytecode('') },
    { name: 'header/invalid-bytes', res: decompileBytesDirect(new Uint8Array([0, 1, 2, 3])) },
  ];
  for (const chk of invalidChecks) {
    if (!hasValidRequiredHeader(chk.res.source)) {
      failed++;
      console.error(`FAIL ${chk.name}: missing or malformed required header in error output`);
    } else {
      passed++;
      console.log(`PASS ${chk.name} (required header present on failure output)`);
    }
  }

  console.log('\n=== OpLift Runtime Regression Suite (Issues 1 - 5, Rules 1 - 3 & Real Compiled Luau) ===');
  for (const tc of REGRESSION_CASES) {
    const expectedStdout = runLuau(tc.source);
    const originalGlobals = extractReferencedGlobals(tc.source);
    for (const mode of COMPILE_MODES) {
      const baseBytes = compileLuau(tc.source, mode.flags);
      const variants: Array<{ tag: string; bytes: Uint8Array }> = [{ tag: mode.label, bytes: baseBytes }];
      if (tc.category === 'issue5-multret-and-game-patterns' && mode.label === '-O2 -g0') {
        variants.push({ tag: `${mode.label} *227`, bytes: encodeCompiledLuauAsRoblox227(baseBytes) });
      }
      for (const variant of variants) {
        const label = `${tc.id} [${variant.tag}]`;
        try {
          const res = decompileBytesDirect(variant.bytes, {}, { includeDisassembly: false });
          if (!res.ok || !res.source) {
            throw new Error(`Decompile failed: ${res.diagnostics.map((d) => d.message).join('; ')}`);
          }
          const validHdr = hasValidRequiredHeader(res.source);
          const emptyIf = hasEmptyIfBlock(res.source);
          const unrec = hasUnreconstructedMarker(res.source);
          const decompiledGlobals = extractReferencedGlobals(res.source);
          const leakedGlobals = [...decompiledGlobals].filter((g) => !originalGlobals.has(g));
          const actualStdout = runLuau(res.source);
          const score = scoreDecompiledOutput(res.source, 200);
          const structErr = tc.checkStructure ? tc.checkStructure(res.source, variant.tag) : null;

          if (!validHdr) {
            failed++;
            console.error(`FAIL ${label}: missing or duplicate '-- https://oplift.ai.studio' header`);
            console.error(`  decompiled:\n${res.source}`);
          } else if (actualStdout !== expectedStdout) {
            failed++;
            console.error(`FAIL ${label}: runtime output mismatch`);
            console.error(`  expected:\n${expectedStdout}`);
            console.error(`  actual:\n${actualStdout}`);
            console.error(`  decompiled:\n${res.source}`);
          } else if (leakedGlobals.length > 0) {
            failed++;
            console.error(`FAIL ${label}: out-of-scope local(s) leaked as globals: ${leakedGlobals.join(', ')}`);
            console.error(`  decompiled:\n${res.source}`);
          } else if (emptyIf) {
            failed++;
            console.error(`FAIL ${label}: emitted empty if block`);
            console.error(`  decompiled:\n${res.source}`);
          } else if (unrec) {
            failed++;
            console.error(`FAIL ${label}: emitted unreconstructed marker`);
            console.error(`  decompiled:\n${res.source}`);
          } else if (structErr) {
            failed++;
            console.error(`FAIL ${label}: structural rule failure: ${structErr}`);
            console.error(`  decompiled:\n${res.source}`);
          } else {
            passed++;
            console.log(`PASS ${label} (score=${score.score}/100, stdout=${actualStdout.trim().split('\n').length} lines)`);
          }
        } catch (err) {
          failed++;
          console.error(`FAIL ${label}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }
  }

  console.log('\n=== Built-in Benchmark Corpus Smoke Check ===');
  const corpus = getBenchmarkSuite();
  for (const c of corpus) {
    const res = decompileBytecode(c.bytecodeBase64, {}, { includeDisassembly: false });
    const score = scoreDecompiledOutput(res.source, res.ok ? 200 : 400);
    const validHdr = hasValidRequiredHeader(res.source);
    const emptyIf = res.source ? hasEmptyIfBlock(res.source) : false;
    const unrec = res.source ? hasUnreconstructedMarker(res.source) : false;
    if (!res.ok || !res.source || !validHdr || emptyIf || unrec) {
      failed++;
      console.error(`FAIL corpus/${c.id}: ok=${res.ok} validHdr=${validHdr} emptyIf=${emptyIf} unrec=${unrec}`);
    } else {
      passed++;
      console.log(`PASS corpus/${c.id} (score=${score.score}/100)`);
    }
  }

  console.log(`\nSummary: ${passed} passed, ${failed} failed.`);
  if (failed > 0) {
    process.exit(1);
  }
}

main();
