import type { DecompileOptions } from '../types.ts';

/**
 * Pure post-structuring readability passes on decompiled Luau lines.
 *
 * Each pass is a pure, typed transformation that preserves exact runtime
 * semantics while eliminating synthetic bytecode artifacts:
 *   1. `removeSelfAssignmentsPass`: strips dead `x = x` self-assignments.
 *   2. `foldSwapMultiAssignmentsPass`: folds 3-line temp swap/update patterns
 *      (`local tmp = a; a = b; b = expr(tmp)` -> `a, b = b, expr(a)`).
 *   3. `liftStateMachineLoopsPass`: lifts `while true do` state-machine
 *      dispatchers (`if state == "done" then break end`) into
 *      `while state ~= "done" do` with clean `if/elseif` branches.
 *   4. `inlineSingleUseTempsPass`: inlines adjacent single-use `local vN = expr`
 *      temps into the immediately following statement when evaluation order and
 *      side effects are provably preserved (e.g. `local v1 = t1; local v2 = #t1 + 1; v1[v2] = x`
 *      -> `t1[#t1 + 1] = x`, `local v4 = isEven(10); print(v4, ...)` -> `print(isEven(10), ...)`).
 */

function countIdentOccurrences(code: string, ident: string): number {
  const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?<![A-Za-z0-9_.])${escaped}(?![A-Za-z0-9_])`, 'g');
  return (code.match(re) ?? []).length;
}

function referencesIdent(code: string, ident: string): boolean {
  return countIdentOccurrences(code, ident) > 0;
}

/**
 * Pass 1: Strip dead self-assignments (`v = v`) that can remain after register-copy merging.
 */
export function removeSelfAssignmentsPass(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    const m = line.match(/^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)$/);
    if (m && m[2] === m[3]) {
      continue;
    }
    out.push(line);
  }
  return out;
}

/**
 * Pass 2: Fold 3-line swap / simultaneous update sequences:
 *   `local tmp = a`
 *   `a = b`
 *   `b = <expr using tmp>`
 * into `a, b = b, <expr with tmp replaced by a>` when `tmp` is dead afterwards.
 */
export function foldSwapMultiAssignmentsPass(lines: string[]): string[] {
  const out = [...lines];
  const isIdent = (s: string) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
  const blockOpenerRe = /^(?:do|repeat|else)\b|\bthen$|\bdo$|function\s*(?:[A-Za-z_][A-Za-z0-9_.:]*)?\([^)]*\)(?:\s*:\s*[^\s]+)?$/;
  const blockCloserRe = /^(?:end|else|elseif\b|until\b)/;

  for (let i = 0; i + 2 < out.length; i++) {
    const m0 = out[i].match(/^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (!m0) continue;
    const [, pad, tempVar, rhs1] = m0;
    if (!isIdent(tempVar) || !isIdent(rhs1) || tempVar === rhs1) continue;

    if (!out[i + 1].startsWith(pad) || !out[i + 2].startsWith(pad)) continue;
    const s1 = out[i + 1].slice(pad.length);
    const s2 = out[i + 2].slice(pad.length);
    if (/^\s/.test(s1) || /^\s/.test(s2)) continue;

    const m1 = s1.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
    const m2 = s2.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (!m1 || !m2) continue;

    const [, target1, rhs2Raw] = m1;
    const [, target2, rhs3] = m2;
    const rhs2 = rhs2Raw.trim();
    if (target1 !== rhs1 || rhs3 !== tempVar) continue;
    if (target2 === target1 || target2 === tempVar) continue;
    if (referencesIdent(rhs2, tempVar)) continue;
    if (/^(?:function\b|if\b)/.test(rhs2)) continue;

    let depth = 0;
    let tempReadLater = false;
    for (let k = i + 3; k < out.length; k++) {
      const tr = out[k].trim();
      if (!tr || tr.startsWith('--')) continue;
      if (blockCloserRe.test(tr) && !/\bend$/.test(tr.replace(/^(?:end|else|elseif\b|until\b)\s*/, ''))) {
        if (depth === 0) break;
        if (tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) {
          depth--;
        }
      } else if (/^local\s+/.test(tr) && depth === 0) {
        const declNames = tr
          .slice(6)
          .split('=')[0]
          .split(',')
          .map((s) => s.trim());
        if (declNames.includes(tempVar)) break;
      }
      if (referencesIdent(tr, tempVar)) {
        tempReadLater = true;
        break;
      }
      if (blockOpenerRe.test(tr) && !/\bend$/.test(tr)) {
        depth++;
      } else if ((tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) && depth > 0) {
        depth--;
      }
    }
    if (tempReadLater) continue;

    out.splice(i, 3, `${pad}${target2}, ${target1} = ${target1}, ${rhs2}`);
  }
  return out;
}

/**
 * Pass 3: Lift `while true do` state-machine dispatch loops where the first statement inside
 * the loop is `if <state> == <doneVal> then break end` (or the final `else` branch breaks when
 * `<state> == <doneVal>`), converting them to `while <state> ~= <doneVal> do`.
 */
export function liftStateMachineLoopsPass(lines: string[]): string[] {
  const out = [...lines];
  for (let i = 0; i + 4 < out.length; i++) {
    const mWhile = out[i].match(/^(\s*)while true do$/);
    if (!mWhile) continue;
    const pad = mWhile[1];
    const innerPad = `${pad}    `;

    // Pattern A:
    //   while true do
    //       if state == "done" then
    //           break
    //       end
    //       ...
    const mIf = out[i + 1]?.match(new RegExp(`^${innerPad}if\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*==\\s*("[^"]*"|\\d+|true|false|nil)\\s+then$`));
    if (
      mIf &&
      out[i + 2] === `${innerPad}    break` &&
      out[i + 3] === `${innerPad}end`
    ) {
      out[i] = `${pad}while ${mIf[1]} ~= ${mIf[2]} do`;
      out.splice(i + 1, 3);
      continue;
    }

    // Pattern B:
    //   while true do
    //       if state == "done" then
    //           break
    //       elseif ...
    if (
      mIf &&
      out[i + 2] === `${innerPad}    break` &&
      out[i + 3]?.startsWith(`${innerPad}elseif `)
    ) {
      out[i] = `${pad}while ${mIf[1]} ~= ${mIf[2]} do`;
      out[i + 3] = `${innerPad}if ${out[i + 3].slice(`${innerPad}elseif `.length)}`;
      out.splice(i + 1, 2);
      continue;
    }
  }
  return out;
}

/**
 * Pass 4: Inline single-use synthetic temp variables (`local vN = ...`, `local tN = ...`)
 * when consumed exactly once on the immediately following line and dead afterwards:
 *   - `local v1 = t1; local v2 = #t1 + 1; v1[v2] = val` -> `t1[#t1 + 1] = val`
 *   - `local v1 = expr; return v1` -> `return expr`
 */
export function inlineSingleUseTempsPass(lines: string[]): string[] {
  const out = [...lines];
  const blockCloserRe = /^(?:end|else|elseif\b|until\b)/;
  const blockOpenerRe = /\b(?:then|do|repeat)$|(?:^|\s|=|\()function\b/;

  const isDeadAfter = (startIdx: number, varName: string): boolean => {
    let depth = 0;
    for (let k = startIdx; k < out.length; k++) {
      const tr = out[k].trim();
      if (!tr || tr.startsWith('--')) continue;
      if (blockCloserRe.test(tr) && !/\bend$/.test(tr.replace(/^(?:end|else|elseif\b|until\b)\s*/, ''))) {
        if (depth === 0) break;
        if (tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) {
          depth--;
        }
      } else if (/^local\s+/.test(tr) && depth === 0) {
        const declNames = tr
          .slice(6)
          .split('=')[0]
          .split(',')
          .map((s) => s.trim());
        if (declNames.includes(varName)) break;
      }
      if (referencesIdent(tr, varName)) return false;
      if (blockOpenerRe.test(tr) && !/\bend$/.test(tr)) {
        depth++;
      } else if ((tr === 'end' || tr.startsWith('end,') || tr.startsWith('end)') || tr.startsWith('until ')) && depth > 0) {
        depth--;
      }
    }
    return true;
  };

  // Sub-pass A: `local v1 = t1; local v2 = #t1 + 1; v1[v2] = rhs` -> `t1[#t1 + 1] = rhs`
  for (let i = 0; i + 2 < out.length; i++) {
    const m0 = out[i].match(/^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)$/);
    if (!m0) continue;
    const [, pad, v1, t1] = m0;
    const m1 = out[i + 1].match(/^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(#[A-Za-z_][A-Za-z0-9_]*\s*\+\s*1)$/);
    if (!m1 || m1[1] !== pad) continue;
    const [, , v2, lenPlus1] = m1;
    if (lenPlus1.replace(/\s+/g, '') !== `#${t1}+1` && lenPlus1.replace(/\s+/g, '') !== `#${v1}+1`) continue;
    const m2 = out[i + 2].match(/^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=\s*(.+)$/);
    if (!m2 || m2[1] !== pad || m2[2] !== v1 || m2[3] !== v2) continue;
    const rhs = m2[4];
    if (referencesIdent(rhs, v1) || referencesIdent(rhs, v2)) continue;
    if (!isDeadAfter(i + 3, v1) || !isDeadAfter(i + 3, v2)) continue;
    out.splice(i, 3, `${pad}${t1}[#${t1} + 1] = ${rhs}`);
  }

  // Sub-pass B: `local v1 = #t1 + 1; t1[v1] = rhs` -> `t1[#t1 + 1] = rhs`
  for (let i = 0; i + 1 < out.length; i++) {
    const m0 = out[i].match(/^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*#([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*1$/);
    if (!m0) continue;
    const [, pad, v1, t1] = m0;
    const m1 = out[i + 1].match(/^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=\s*(.+)$/);
    if (!m1 || m1[1] !== pad || m1[2] !== t1 || m1[3] !== v1) continue;
    const rhs = m1[4];
    if (referencesIdent(rhs, v1)) continue;
    if (!isDeadAfter(i + 2, v1)) continue;
    out.splice(i, 2, `${pad}${t1}[#${t1} + 1] = ${rhs}`);
  }

  return out;
}

/**
 * Run all modular post-structuring readability passes in sequence.
 */
export function runReadabilityPasses(lines: string[], _opts?: DecompileOptions): string[] {
  let cur = removeSelfAssignmentsPass(lines);
  cur = liftStateMachineLoopsPass(cur);
  cur = inlineSingleUseTempsPass(cur);
  cur = foldSwapMultiAssignmentsPass(cur);
  return cur;
}
