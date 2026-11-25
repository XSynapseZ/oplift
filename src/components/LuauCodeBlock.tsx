import React, { useMemo, useRef } from 'react';

export type CodeLanguage = 'luau' | 'disasm' | 'json' | 'plain';

interface Token {
  type:
    | 'comment'
    | 'string'
    | 'number'
    | 'keyword'
    | 'boolean'
    | 'builtin'
    | 'func'
    | 'prop'
    | 'operator'
    | 'punct'
    | 'opcode'
    | 'jsonKey'
    | 'plain';
  text: string;
}

const LUAU_KEYWORDS = new Set([
  'and',
  'break',
  'continue',
  'do',
  'else',
  'elseif',
  'end',
  'for',
  'function',
  'if',
  'in',
  'local',
  'not',
  'or',
  'repeat',
  'return',
  'then',
  'until',
  'while',
  'export',
  'type',
]);

const LUAU_BOOLEANS = new Set(['true', 'false', 'nil']);

const LUAU_BUILTINS = new Set([
  'self',
  'game',
  'workspace',
  'script',
  'shared',
  '_G',
  '_VERSION',
  'print',
  'warn',
  'error',
  'assert',
  'pcall',
  'xpcall',
  'pairs',
  'ipairs',
  'next',
  'select',
  'tonumber',
  'tostring',
  'typeof',
  'rawget',
  'rawset',
  'rawequal',
  'rawlen',
  'getmetatable',
  'setmetatable',
  'require',
  'unpack',
  'newproxy',
  'gcinfo',
  'tick',
  'time',
  'wait',
  'spawn',
  'delay',
  'task',
  'table',
  'string',
  'math',
  'bit32',
  'buffer',
  'coroutine',
  'utf8',
  'os',
  'debug',
  'vector',
  'Vector2',
  'Vector3',
  'CFrame',
  'Color3',
  'UDim',
  'UDim2',
  'Instance',
  'Enum',
  'BrickColor',
  'TweenInfo',
  'NumberRange',
  'NumberSequence',
  'ColorSequence',
  'Rect',
  'Ray',
  'Region3',
  'Random',
  'DateTime',
  'RaycastParams',
  'OverlapParams',
  'getgenv',
  'getscriptbytecode',
  'request',
  'http_request',
]);

const TOKEN_CLASSES: Record<Token['type'], string> = {
  comment: 'text-zinc-500 italic',
  string: 'text-amber-300',
  number: 'text-orange-300',
  keyword: 'text-violet-300 font-medium',
  boolean: 'text-sky-400 font-medium',
  builtin: 'text-teal-300',
  func: 'text-sky-300',
  prop: 'text-indigo-200',
  operator: 'text-rose-300/90',
  punct: 'text-zinc-500',
  opcode: 'text-emerald-400 font-medium',
  jsonKey: 'text-sky-300',
  plain: 'text-zinc-100',
};

function matchLongBracketOpen(src: string, idx: number): { eqCount: number; end: number } | null {
  if (src[idx] !== '[') return null;
  let j = idx + 1;
  while (j < src.length && src[j] === '=') j++;
  if (src[j] === '[') {
    return { eqCount: j - (idx + 1), end: j + 1 };
  }
  return null;
}

function findLongBracketClose(src: string, start: number, eqCount: number): number {
  const closing = `]${'='.repeat(eqCount)}]`;
  const pos = src.indexOf(closing, start);
  return pos === -1 ? src.length : pos + closing.length;
}

function isIdentStart(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
}

function isIdentPart(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95;
}

function isDigit(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return c >= 48 && c <= 57;
}

function tokenizeLuau(code: string): Token[] {
  const tokens: Token[] = [];
  const len = code.length;
  let i = 0;
  let prevNonWsType: Token['type'] | null = null;
  let prevNonWsText = '';

  const push = (type: Token['type'], text: string) => {
    if (!text) return;
    const last = tokens[tokens.length - 1];
    if (last && last.type === type) {
      last.text += text;
    } else {
      tokens.push({ type, text });
    }
    if (text.trim().length > 0) {
      prevNonWsType = type;
      prevNonWsText = text.trim();
    }
  };

  while (i < len) {
    const ch = code[i];

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      let j = i + 1;
      while (j < len && (code[j] === ' ' || code[j] === '\t' || code[j] === '\n' || code[j] === '\r')) j++;
      tokens.push({ type: 'plain', text: code.slice(i, j) });
      i = j;
      continue;
    }

    // Comments: -- or --[=[ ... ]=]
    if (ch === '-' && code[i + 1] === '-') {
      const lb = matchLongBracketOpen(code, i + 2);
      if (lb) {
        const end = findLongBracketClose(code, lb.end, lb.eqCount);
        push('comment', code.slice(i, end));
        i = end;
      } else {
        const nl = code.indexOf('\n', i + 2);
        const end = nl === -1 ? len : nl;
        push('comment', code.slice(i, end));
        i = end;
      }
      continue;
    }

    // Long bracket string: [[...]] or [=[...]=]
    if (ch === '[') {
      const lb = matchLongBracketOpen(code, i);
      if (lb) {
        const end = findLongBracketClose(code, lb.end, lb.eqCount);
        push('string', code.slice(i, end));
        i = end;
        continue;
      }
    }

    // Quoted strings ("..." or '...')
    if (ch === '"' || ch === "'") {
      const quote = ch;
      let j = i + 1;
      while (j < len && code[j] !== quote && code[j] !== '\n') {
        if (code[j] === '\\' && j + 1 < len) {
          j += 2;
        } else {
          j++;
        }
      }
      if (j < len && code[j] === quote) j++;
      push('string', code.slice(i, j));
      i = j;
      continue;
    }

    // Luau interpolated backtick strings: `hello {name}!`
    if (ch === '`') {
      let segStart = i;
      let j = i + 1;
      while (j < len && code[j] !== '`') {
        if (code[j] === '\\' && j + 1 < len) {
          j += 2;
          continue;
        }
        if (code[j] === '{') {
          push('string', code.slice(segStart, j));
          push('punct', '{');
          j++;
          let depth = 1;
          const exprStart = j;
          while (j < len && depth > 0) {
            if (code[j] === '"' || code[j] === "'") {
              const q = code[j++];
              while (j < len && code[j] !== q && code[j] !== '\n') {
                j += code[j] === '\\' ? 2 : 1;
              }
              if (j < len && code[j] === q) j++;
              continue;
            }
            if (code[j] === '{') depth++;
            else if (code[j] === '}') depth--;
            if (depth > 0) j++;
          }
          const innerTokens = tokenizeLuau(code.slice(exprStart, j));
          for (const t of innerTokens) tokens.push(t);
          if (j < len && code[j] === '}') {
            push('punct', '}');
            j++;
          }
          segStart = j;
          continue;
        }
        j++;
      }
      if (j < len && code[j] === '`') j++;
      push('string', code.slice(segStart, j));
      i = j;
      continue;
    }

    // Numbers: hex, binary, decimal, float, exponent, underscores
    if (isDigit(ch) || (ch === '.' && i + 1 < len && isDigit(code[i + 1]))) {
      let j = i;
      if (ch === '0' && (code[i + 1] === 'x' || code[i + 1] === 'X')) {
        j += 2;
        while (j < len && /[0-9a-fA-F_]/.test(code[j])) j++;
      } else if (ch === '0' && (code[i + 1] === 'b' || code[i + 1] === 'B')) {
        j += 2;
        while (j < len && /[01_]/.test(code[j])) j++;
      } else {
        while (j < len && /[0-9_]/.test(code[j])) j++;
        if (j < len && code[j] === '.' && code[j + 1] !== '.') {
          j++;
          while (j < len && /[0-9_]/.test(code[j])) j++;
        }
        if (j < len && (code[j] === 'e' || code[j] === 'E')) {
          j++;
          if (j < len && (code[j] === '+' || code[j] === '-')) j++;
          while (j < len && /[0-9_]/.test(code[j])) j++;
        }
      }
      push('number', code.slice(i, j));
      i = j;
      continue;
    }

    // Varargs `...`
    if (ch === '.' && code[i + 1] === '.' && code[i + 2] === '.') {
      push('boolean', '...');
      i += 3;
      continue;
    }

    // Identifiers, keywords, builtins, function calls, properties
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < len && isIdentPart(code[j])) j++;
      const word = code.slice(i, j);

      // Peek ahead past spaces to see if this identifier is called like `foo(` or `foo"` or `foo{`
      let k = j;
      while (k < len && (code[k] === ' ' || code[k] === '\t')) k++;
      const nextCh = code[k];
      const isCall = nextCh === '(' || (nextCh === '{' && !LUAU_KEYWORDS.has(word));
      const isAfterDotOrColon = prevNonWsType === 'punct' && (prevNonWsText === '.' || prevNonWsText === ':');

      if (LUAU_KEYWORDS.has(word) && !isAfterDotOrColon) {
        push('keyword', word);
      } else if (LUAU_BOOLEANS.has(word) && !isAfterDotOrColon) {
        push('boolean', word);
      } else if (isAfterDotOrColon) {
        push(isCall ? 'func' : 'prop', word);
      } else if (LUAU_BUILTINS.has(word)) {
        push('builtin', word);
      } else if (isCall) {
        push('func', word);
      } else {
        push('plain', word);
      }
      i = j;
      continue;
    }

    // Multi-char operators
    const three = code.slice(i, i + 3);
    if (three === '..=' || three === '//=') {
      push('operator', three);
      i += 3;
      continue;
    }
    const two = code.slice(i, i + 2);
    if (
      two === '==' ||
      two === '~=' ||
      two === '<=' ||
      two === '>=' ||
      two === '..' ||
      two === '//' ||
      two === '+=' ||
      two === '-=' ||
      two === '*=' ||
      two === '/=' ||
      two === '%=' ||
      two === '^=' ||
      two === '->' ||
      two === '::'
    ) {
      push('operator', two);
      i += 2;
      continue;
    }

    // Single-char operators & punctuation
    if ('+-*/%^#=<>~|&?'.includes(ch)) {
      push('operator', ch);
      i++;
      continue;
    }
    if ('(){}[],.;:'.includes(ch)) {
      push('punct', ch);
      i++;
      continue;
    }

    push('plain', ch);
    i++;
  }

  return tokens;
}

function tokenizeDisasm(code: string): Token[] {
  const tokens: Token[] = [];
  const lines = code.split('\n');
  lines.forEach((line, idx) => {
    if (idx > 0) tokens.push({ type: 'plain', text: '\n' });
    if (line.trimStart().startsWith('--')) {
      tokens.push({ type: 'comment', text: line });
      return;
    }
    const m = /^(\s*)(\d{3,4})(\s+)([A-Z0-9_]+)(.*)$/.exec(line);
    if (!m) {
      tokens.push({ type: 'plain', text: line });
      return;
    }
    const [, lead, pc, gap, op, rest] = m;
    if (lead) tokens.push({ type: 'plain', text: lead });
    tokens.push({ type: 'punct', text: pc });
    tokens.push({ type: 'plain', text: gap });
    tokens.push({ type: 'opcode', text: op });
    const commentIdx = rest.indexOf('  ;');
    if (commentIdx >= 0) {
      tokens.push({ type: 'plain', text: rest.slice(0, commentIdx) });
      tokens.push({ type: 'comment', text: rest.slice(commentIdx) });
    } else {
      tokens.push({ type: 'plain', text: rest });
    }
  });
  return tokens;
}

function tokenizeJson(code: string): Token[] {
  const tokens: Token[] = [];
  const regex = /("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g;
  let lastIdx = 0;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(code)) !== null) {
    if (match.index > lastIdx) {
      tokens.push({ type: 'punct', text: code.slice(lastIdx, match.index) });
    }
    const raw = match[0];
    if (raw.startsWith('"')) {
      if (match[2]) {
        const colonIdx = raw.lastIndexOf(':');
        tokens.push({ type: 'jsonKey', text: raw.slice(0, colonIdx) });
        tokens.push({ type: 'punct', text: raw.slice(colonIdx) });
      } else {
        tokens.push({ type: 'string', text: raw });
      }
    } else if (raw === 'true' || raw === 'false' || raw === 'null') {
      tokens.push({ type: 'boolean', text: raw });
    } else {
      tokens.push({ type: 'number', text: raw });
    }
    lastIdx = match.index + raw.length;
  }
  if (lastIdx < code.length) {
    tokens.push({ type: 'punct', text: code.slice(lastIdx) });
  }
  return tokens;
}

export function highlightCodeTokens(code: string, language: CodeLanguage): Token[] {
  if (!code) return [];
  if (language === 'luau') return tokenizeLuau(code);
  if (language === 'disasm') return tokenizeDisasm(code);
  if (language === 'json') return tokenizeJson(code);
  return [{ type: 'plain', text: code }];
}

interface LuauCodeBlockProps {
  code: string;
  language?: CodeLanguage;
  className?: string;
  showLineNumbers?: boolean;
}

export function LuauCodeBlock({
  code,
  language = 'luau',
  className = '',
  showLineNumbers = false,
}: LuauCodeBlockProps) {
  const lines = useMemo(() => {
    if (!showLineNumbers) return null;
    return code.split('\n');
  }, [code, showLineNumbers]);

  const tokens = useMemo(() => {
    if (showLineNumbers) return [];
    return highlightCodeTokens(code, language);
  }, [code, language, showLineNumbers]);

  const lineTokens = useMemo(() => {
    if (!showLineNumbers || !lines) return null;
    if (language === 'luau') {
      // Tokenize whole document once so multi-line comments/strings stay accurate across line splits
      const all = tokenizeLuau(code);
      const perLine: Token[][] = [[]];
      for (const tok of all) {
        if (!tok.text.includes('\n')) {
          perLine[perLine.length - 1].push(tok);
        } else {
          const parts = tok.text.split('\n');
          parts.forEach((part, idx) => {
            if (idx > 0) perLine.push([]);
            if (part) perLine[perLine.length - 1].push({ type: tok.type, text: part });
          });
        }
      }
      return perLine;
    }
    return lines.map((line) => highlightCodeTokens(line, language));
  }, [code, language, lines, showLineNumbers]);

  if (showLineNumbers && lineTokens) {
    const gutterWidth = Math.max(2, String(lineTokens.length).length);
    return (
      <pre className={`font-mono overflow-x-auto ${className}`}>
        <code className="block min-w-full">
          {lineTokens.map((toks, idx) => (
            <div key={idx} className="flex hover:bg-zinc-800/35 rounded-[2px] px-1 -mx-1 transition-colors">
              <span
                aria-hidden="true"
                className="select-none pr-3 mr-3.5 border-r border-[#202026] text-right text-zinc-600 shrink-0 tabular-nums"
                style={{ minWidth: `${gutterWidth + 1.4}ch` }}
              >
                {idx + 1}
              </span>
              <span className="flex-1 whitespace-pre">
                {toks.length > 0
                  ? toks.map((t, j) => (
                      <span key={j} className={TOKEN_CLASSES[t.type]}>
                        {t.text}
                      </span>
                    ))
                  : '\n'}
              </span>
            </div>
          ))}
        </code>
      </pre>
    );
  }

  return (
    <pre className={`font-mono overflow-x-auto ${className}`}>
      <code>
        {tokens.map((t, idx) => (
          <span key={idx} className={TOKEN_CLASSES[t.type]}>
            {t.text}
          </span>
        ))}
      </code>
    </pre>
  );
}

interface LuauCodeEditorProps {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  rows?: number;
}

export function LuauCodeEditor({
  value,
  onChange,
  placeholder = 'Write Luau source code here...',
  rows = 12,
}: LuauCodeEditorProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const tokens = useMemo(() => highlightCodeTokens(value, 'luau'), [value]);

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (preRef.current) {
      preRef.current.scrollTop = e.currentTarget.scrollTop;
      preRef.current.scrollLeft = e.currentTarget.scrollLeft;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const target = e.currentTarget;
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const updated = value.slice(0, start) + '    ' + value.slice(end);
      onChange(updated);
      requestAnimationFrame(() => {
        target.selectionStart = target.selectionEnd = start + 4;
      });
    }
  };

  const minHeightPx = Math.max(200, rows * 24 + 32);

  return (
    <div
      className="relative w-full bg-[#0C0C0E] border border-[#202026] focus-within:border-emerald-500/70 focus-within:ring-1 focus-within:ring-emerald-500/20 rounded-md overflow-hidden transition-colors"
      style={{ minHeight: `${minHeightPx}px` }}
    >
      <pre
        ref={preRef}
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 m-0 p-4 text-[13px] font-mono leading-[1.65] whitespace-pre overflow-hidden"
      >
        <code>
          {tokens.map((t, idx) => (
            <span key={idx} className={TOKEN_CLASSES[t.type]}>
              {t.text}
            </span>
          ))}
          {value.endsWith('\n') ? ' ' : ''}
        </code>
      </pre>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onScroll={handleScroll}
        onKeyDown={handleKeyDown}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        rows={rows}
        placeholder={placeholder}
        className="relative z-10 w-full h-full min-h-[inherit] bg-transparent p-4 text-[13px] font-mono leading-[1.65] text-transparent caret-emerald-400 placeholder:text-zinc-500 focus:outline-none resize-y whitespace-pre overflow-auto selection:bg-emerald-500/25"
      />
    </div>
  );
}
