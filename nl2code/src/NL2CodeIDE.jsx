import { useState, useCallback } from "react";

function tokenize(line) {
  return line
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

const BLOCKED = [
  { pattern: /system\s*\(/, label: "system() — OS command injection" },
  { pattern: /exec\s*\(/, label: "exec() — process execution" },
  { pattern: /rm\s+-rf/, label: "rm -rf — destructive command" },
  { pattern: /delete\s+\[/, label: "delete[] — memory corruption" },
  { pattern: /malloc\s*\(/, label: "malloc() — unmanaged heap" },
  { pattern: /free\s*\(/, label: "free() — unsafe memory release" },
  { pattern: /;/, label: "semicolon — code injection" },
  { pattern: /#include/, label: "#include — header injection" },
  { pattern: /\{/, label: "raw brace — injection risk" },
  { pattern: /\}/, label: "raw brace — injection risk" },
];

function securityScan(lines) {
  const issues = [];
  lines.forEach((line, i) => {
    BLOCKED.forEach(({ pattern, label }) => {
      if (pattern.test(line.toLowerCase()))
        issues.push({ line: i + 1, raw: line, label, severity: "critical" });
    });
    tokenize(line).forEach((t) => {
      if (t.length > 30)
        issues.push({
          line: i + 1,
          raw: line,
          label: `Identifier '${t}' exceeds 30 characters`,
          severity: "warning",
        });
    });
  });
  return issues;
}

function parseLine(t, lineNo) {
  const tokenStr = t.map((x) => `"${x}"`).join(" ");
  const err = (hint) => {
    throw { phase: "SYNTAX", lineNo, tokens: tokenStr, hint };
  };

  if (t.length === 2 && t[0] === "read")
    return { type: "READ_VAR", args: [t[1]], line: lineNo };
  if (t[0] === "read" && t.length !== 2)
    err("Expected: read <var> — takes exactly one variable name.");
  if (
    t.length === 6 &&
    t[0] === "create" &&
    t[1] === "array" &&
    t[3] === "of" &&
    t[4] === "size"
  )
    return { type: "CREATE_ARRAY", args: [t[2], t[5]], line: lineNo };
  if (t[0] === "create" && t.length > 1 && t[1] === "array") {
    const hasOf = t.includes("of"),
      hasSize = t.includes("size");
    if (!hasOf || !hasSize)
      err(
        `Expected: create array <arr> of size <n>\n  Missing keyword: ${!hasOf ? "'of'" : "'size'"}`,
      );
    err("Expected: create array <arr> of size <n> — wrong token count.");
  }
  if (t[0] === "create")  
    err("Expected: create array <arr> of size <n> — missing keyword 'array'.");
  if (t.length === 4 && t[0] === "set" && t[2] === "to")
    return { type: "SET_VAR", args: [t[1], t[3]], line: lineNo };
  if (t[0] === "set")
    err(
      t.includes("to")
        ? "Expected: set <var> to <value> — wrong token count."
        : "Expected: set <var> to <value> — missing keyword 'to'.",
    );
  if (
    t.length === 6 &&
    t[0] === "sum" &&
    t[1] === "of" &&
    t[2] === "array" &&
    t[4] === "into"
  )
    return { type: "SUM_ARRAY", args: [t[3], t[5]], line: lineNo };
  if (t[0] === "sum") {
    const missing = ["of", "array", "into"]
      .filter((k) => !t.includes(k))
      .map((k) => `'${k}'`)
      .join(", ");
    err(
      missing
        ? `Expected: sum of array <arr> into <var> — missing: ${missing}`
        : "Expected: sum of array <arr> into <var> — wrong token count.",
    );
  }
  if (t.length === 2 && t[0] === "print")
    return { type: "PRINT_VAR", args: [t[1]], line: lineNo };
  if (t[0] === "print")
    err("Expected: print <var> — takes exactly one variable name.");
  if (t.length === 4 && t[0] === "if" && t[2] === "greater")
    return { type: "IF_GREATER", args: [t[1], t[3]], line: lineNo };
  if (t[0] === "if")
    err(
      t.includes("greater")
        ? "Expected: if <var> greater <val> — wrong token count."
        : "Expected: if <var> greater <val> — missing keyword 'greater'.",
    );
  if (t.length === 1 && t[0] === "else")
    return { type: "ELSE_BLOCK", args: [], line: lineNo };
  if (t.length === 1 && t[0] === "endif")
    return { type: "END_IF", args: [], line: lineNo };
  err("No matching grammar rule. Check spelling and keyword order.");
}

function semanticCheck(program) {
  const vars = new Set(),
    arrays = new Set();
  let ifDepth = 0,
    elseCount = 0;
  const err = (stmtNo, msg, hint) => {
    throw { phase: "SEMANTIC", stmtNo, msg, hint };
  };
  for (let i = 0; i < program.length; i++) {
    const n = program[i];
    if (n.type === "READ_VAR") {
      vars.add(n.args[0]);
    } else if (n.type === "CREATE_ARRAY") {
      arrays.add(n.args[0]);
      vars.add(n.args[1]);
    } else if (n.type === "SET_VAR") {
      const val = n.args[1];
      if (!/^\d+$/.test(val) && !vars.has(val))
        err(
          i + 1,
          `Variable '${val}' used before declaration.`,
          `Declare first: read ${val}`,
        );
      vars.add(n.args[0]);
    } else if (n.type === "SUM_ARRAY") {
      if (!arrays.has(n.args[0]))
        err(
          i + 1,
          `Array '${n.args[0]}' used before declaration.`,
          `Declare first: create array ${n.args[0]} of size <n>`,
        );
      vars.add(n.args[1]);
    } else if (n.type === "PRINT_VAR") {
      if (!vars.has(n.args[0]))
        err(
          i + 1,
          `Variable '${n.args[0]}' printed before declaration.`,
          `Declare first: read ${n.args[0]}  OR  set ${n.args[0]} to <value>`,
        );
    } else if (n.type === "IF_GREATER") {
      if (!vars.has(n.args[0]))
        err(
          i + 1,
          `Variable '${n.args[0]}' used in IF before declaration.`,
          `Declare first: read ${n.args[0]}`,
        );
      if (!/^\d+$/.test(n.args[1]) && !vars.has(n.args[1]))
        err(
          i + 1,
          `Variable '${n.args[1]}' used in IF before declaration.`,
          `Declare first: read ${n.args[1]}`,
        );
      ifDepth++;
      elseCount = 0;
    } else if (n.type === "ELSE_BLOCK") {
      if (ifDepth === 0)
        err(
          i + 1,
          "'else' without matching 'if'.",
          "Every 'else' must follow an 'if' block.",
        );
      if (++elseCount > 1)
        err(
          i + 1,
          "Multiple 'else' blocks in one 'if'.",
          "Only one 'else' per 'if' allowed.",
        );
    } else if (n.type === "END_IF") {
      if (ifDepth === 0)
        err(
          i + 1,
          "'endif' without matching 'if'.",
          "Every 'endif' must close an 'if' block.",
        );
      ifDepth--;
      elseCount = 0;
    }
  }
  if (ifDepth > 0)
    err(
      -1,
      `${ifDepth} 'if' block(s) never closed.`,
      "Add 'endif' to close every 'if' block.",
    );
  const symVars = new Set(),
    symArrays = new Set();
  program.forEach((n) => {
    if (n.type === "READ_VAR") symVars.add(n.args[0]);
    if (n.type === "SET_VAR") symVars.add(n.args[0]);
    if (n.type === "SUM_ARRAY") symVars.add(n.args[1]);
    if (n.type === "CREATE_ARRAY") {
      symArrays.add(n.args[0]);
      symVars.add(n.args[1]);
    }
  });
  return { vars: [...symVars], arrays: [...symArrays] };
}

function generateCPP(program) {
  let code = "#include <iostream>\nusing namespace std;\n\nint main() {\n";
  const decl = new Set();
  let ind = 1;
  const pad = (n) => "    ".repeat(n);
  for (const node of program) {
    if (node.type === "READ_VAR") {
      const v = node.args[0];
      if (!decl.has(v)) {
        code += `${pad(ind)}int ${v};\n`;
        decl.add(v);
      }
      code += `${pad(ind)}cin >> ${v};\n`;
    } else if (node.type === "CREATE_ARRAY") {
      const [arr, n] = node.args;
      if (!decl.has(n)) {
        code += `${pad(ind)}int ${n};\n`;
        decl.add(n);
        code += `${pad(ind)}cin >> ${n};\n`;
      }
      code += `${pad(ind)}int ${arr}[${n}];\n`;
      code += `${pad(ind)}for (int i = 0; i < ${n}; i++) {\n${pad(ind + 1)}cin >> ${arr}[i];\n${pad(ind)}}\n`;
    } else if (node.type === "SET_VAR") {
      const [v, val] = node.args;
      if (!decl.has(v)) {
        code += `${pad(ind)}int ${v} = ${val};\n`;
        decl.add(v);
      } else code += `${pad(ind)}${v} = ${val};\n`;
    } else if (node.type === "SUM_ARRAY") {
      const [arr, s] = node.args;
      if (!decl.has(s)) {
        code += `${pad(ind)}int ${s} = 0;\n`;
        decl.add(s);
      } else code += `${pad(ind)}${s} = 0;\n`;
      code += `${pad(ind)}for (int x : ${arr}) {\n${pad(ind + 1)}${s} += x;\n${pad(ind)}}\n`;
    } else if (node.type === "PRINT_VAR") {
      code += `${pad(ind)}cout << ${node.args[0]} << "\\n";\n`;
    } else if (node.type === "IF_GREATER") {
      code += `${pad(ind)}if (${node.args[0]} > ${node.args[1]}) {\n`;
      ind++;
    } else if (node.type === "ELSE_BLOCK") {
      ind--;
      code += `${pad(ind)}} else {\n`;
      ind++;
    } else if (node.type === "END_IF") {
      ind--;
      code += `${pad(ind)}}\n`;
    }
  }
  code += `\n${pad(1)}return 0;\n}\n`;
  return code;
}

function runCompiler(input) {
  const lines = input.split("\n").filter((l) => l.trim() !== "");
  if (!lines.length)
    return {
      error: {
        phase: "INPUT",
        msg: "No input provided.",
        hint: "Type at least one statement.",
      },
    };
  const secIssues = securityScan(lines);
  if (secIssues.some((i) => i.severity === "critical"))
    return {
      error: {
        phase: "SECURITY",
        msg: "Input blocked — security violation detected.",
        issues: secIssues,
      },
      secIssues,
    };
  const allTokens = lines.map((l, i) => ({
    lineNo: i + 1,
    raw: l,
    tokens: tokenize(l),
  }));
  let program;
  try {
    program = allTokens.map(({ tokens, lineNo }) => parseLine(tokens, lineNo));
  } catch (e) {
    return { error: e, allTokens, secIssues };
  }
  let symbolTable;
  try {
    symbolTable = semanticCheck(program);
  } catch (e) {
    return { error: e, allTokens, program, secIssues };
  }
  return {
    allTokens,
    program,
    symbolTable,
    cppCode: generateCPP(program),
    secIssues,
  };
}

const GRAMMAR = [
  {
    syntax: "read <var>",
    example: "read n",
    node: "READ_VAR",
    cpp: "int n; cin >> n;",
  },
  {
    syntax: "create array <arr> of size <n>",
    example: "create array a of size n",
    node: "CREATE_ARRAY",
    cpp: "int a[n]; for(...) cin >> a[i];",
  },
  {
    syntax: "set <var> to <value>",
    example: "set x to 100",
    node: "SET_VAR",
    cpp: "int x = 100;",
  },
  {
    syntax: "sum of array <arr> into <var>",
    example: "sum of array a into s",
    node: "SUM_ARRAY",
    cpp: "int s=0; for(int x:a) s+=x;",
  },
  {
    syntax: "print <var>",
    example: "print x",
    node: "PRINT_VAR",
    cpp: 'cout << x << "\\n";',
  },
  {
    syntax: "if <var> greater <value>",
    example: "if s greater 10",
    node: "IF_GREATER",
    cpp: "if (s > 10) {",
  },
  { syntax: "else", example: "else", node: "ELSE_BLOCK", cpp: "} else {" },
  { syntax: "endif", example: "endif", node: "END_IF", cpp: "}" },
];

const NODE_DOT = {
  READ_VAR: "#60a5fa",
  CREATE_ARRAY: "#34d399",
  SET_VAR: "#a78bfa",
  SUM_ARRAY: "#fb923c",
  PRINT_VAR: "#f472b6",
  IF_GREATER: "#facc15",
  ELSE_BLOCK: "#94a3b8",
  END_IF: "#94a3b8",
};

const KW = new Set([
  "int",
  "for",
  "if",
  "else",
  "return",
  "using",
  "namespace",
  "std",
  "vector",
  "cout",
  "cin",
  "main",
  "include",
  "iostream",
]);

function CodeLine({ line }) {
  if (!line.trim()) return <div style={{ minHeight: "1.6em" }}>&nbsp;</div>;
  if (line.trim().startsWith("#"))
    return <div style={{ minHeight: "1.6em", color: "#c792ea" }}>{line}</div>;
  const regex =
    /("(?:[^"\\]|\\.)*")|([a-zA-Z_]\w*)|(\d+)|(>>|<<|[{}();,<>=\[\]+\-*/])|(\s+)/g;
  const parts = [];
  let m,
    k = 0;
  while ((m = regex.exec(line)) !== null) {
    const [full] = m;
    if (m[1])
      parts.push(
        <span key={k++} style={{ color: "#c3e88d" }}>
          {full}
        </span>,
      );
    else if (m[2] && KW.has(full))
      parts.push(
        <span key={k++} style={{ color: "#82aaff" }}>
          {full}
        </span>,
      );
    else if (m[2])
      parts.push(
        <span key={k++} style={{ color: "#eeffff" }}>
          {full}
        </span>,
      );
    else if (m[3])
      parts.push(
        <span key={k++} style={{ color: "#f78c6c" }}>
          {full}
        </span>,
      );
    else if (m[4])
      parts.push(
        <span key={k++} style={{ color: "#89ddff" }}>
          {full}
        </span>,
      );
    else
      parts.push(
        <span key={k++} style={{ color: "#a6accd" }}>
          {full}
        </span>,
      );
  }
  return <div style={{ minHeight: "1.6em" }}>{parts}</div>;
}

const NAV = [
  { id: "grammar", label: "Grammar Reference" },
  { id: "tokens", label: "Lexical Analysis", requires: "allTokens" },
  { id: "syntax", label: "Syntax Tree", requires: "allTokens" },
  { id: "ast", label: "AST", requires: "program" },
  { id: "symbols", label: "Symbol Table", requires: "symbolTable" },
  { id: "security", label: "Security Scan", requires: "_compiled" },
  { id: "output", label: "C++ Output", requires: "cppCode" },
  { id: "errors", label: "Errors", requires: "_error" },
];

const DEFAULT = `read n\ncreate array a of size n\nsum of array a into s\nif s greater 10\nprint s\nelse\nprint n\nendif`;


function useBreakpoint() {
  const [w, setW] = useState(
    typeof window !== "undefined" ? window.innerWidth : 1200,
  );
  useState(() => {
    const fn = () => setW(window.innerWidth);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  });
  return {
    isMobile: w < 640,
    isTablet: w >= 640 && w < 1024,
    isDesktop: w >= 1024,
    width: w,
  };
}

  //  MAIN APP

export default function NL2CodeIDE() {
  const [input, setInput] = useState(DEFAULT);
  const [result, setResult] = useState(null);
  const [tab, setTab] = useState("grammar");
  const [copied, setCopied] = useState(false);
  const [sideOpen, setSideOpen] = useState(false); 
  const [view, setView] = useState("editor"); 
  const { isMobile, isTablet, isDesktop } = useBreakpoint();

  const compile = useCallback(() => {
    const r = runCompiler(input);
    setResult(r);
    setTab(r.error ? "errors" : "output");
    if (isMobile) setView("output");
  }, [input, isMobile]);

  const clear = () => {
    setInput("");
    setResult(null);
    setTab("grammar");
  };

  const copyCode = () => {
    navigator.clipboard?.writeText(result?.cppCode || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const isEnabled = (item) => {
    if (!item.requires) return true;
    if (item.requires === "_compiled") return !!result;
    if (item.requires === "_error") return !!result?.error;
    return !!result?.[item.requires];
  };

  const success = result && !result.error;
  const stmts = input.split("\n").filter((l) => l.trim()).length;

  const BG = "#0d0f17";
  const SURFACE = "#141620";
  const SURFACE2 = "#1a1d2e";
  const BORDER = "#252840";
  const ACCENT = "#5b63f5";
  const TEXT = "#e2e4f0";
  const MUTED = "#6b7280";
  const DIM = "#363a52";

  const NavList = ({ onSelect }) => (
    <>
      <div
        style={{
          padding: "16px 16px 8px",
          fontSize: 10,
          color: MUTED,
          letterSpacing: "0.12em",
          fontWeight: 600,
          textTransform: "uppercase",
        }}
      >
        Pipeline
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        {NAV.map((item, idx) => {
          const enabled = isEnabled(item);
          const active = tab === item.id;
          const hasErr = item.id === "errors" && result?.error;
          const hasSec =
            item.id === "security" && result?.secIssues?.length > 0;
          return (
            <div
              key={item.id}
              onClick={() => {
                if (enabled) {
                  setTab(item.id);
                  onSelect?.();
                }
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 16px",
                cursor: enabled ? "pointer" : "default",
                background: active ? `${ACCENT}18` : "transparent",
                borderLeft: active
                  ? `2px solid ${ACCENT}`
                  : "2px solid transparent",
                color: !enabled ? DIM : active ? TEXT : MUTED,
                fontSize: 12,
                transition: "all 0.15s",
              }}
            >
              <span
                style={{
                  width: 18,
                  height: 18,
                  borderRadius: "50%",
                  flexShrink: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 10,
                  fontWeight: 700,
                  background: active
                    ? ACCENT
                    : enabled
                      ? SURFACE2
                      : "transparent",
                  color: active ? "#fff" : enabled ? MUTED : DIM,
                  border: `1px solid ${active ? ACCENT : enabled ? BORDER : "transparent"}`,
                }}
              >
                {idx + 1}
              </span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {hasErr && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: "#ef4444",
                    flexShrink: 0,
                  }}
                />
              )}
              {hasSec && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: "#f59e0b",
                    flexShrink: 0,
                  }}
                />
              )}
            </div>
          );
        })}
      </div>
      <div style={{ padding: "12px 16px", borderTop: `1px solid ${BORDER}` }}>
        <div
          style={{
            fontSize: 11,
            padding: "6px 10px",
            borderRadius: 6,
            background: !result
              ? `${ACCENT}15`
              : success
                ? "#10b98118"
                : "#ef444418",
            color: !result ? "#818cf8" : success ? "#10b981" : "#ef4444",
            border: `1px solid ${!result ? `${ACCENT}30` : success ? "#10b98130" : "#ef444430"}`,
          }}
        >
          {!result
            ? "Ready to compile"
            : success
              ? "Compiled successfully"
              : `Error — ${result.error.phase}`}
        </div>
      </div>
    </>
  );

  /* ── OUTPUT CONTENT ── */
  const OutputContent = () => (
    <div style={{ flex: 1, overflowY: "auto", padding: isMobile ? 14 : 20 }}>
      {/* GRAMMAR */}
      {tab === "grammar" && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 20,
              lineHeight: 1.6,
            }}
          >
            Supported statement patterns. Write one statement per line. The
            compiler validates each line against these rules before generating
            code.
          </p>
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: 12,
                minWidth: 500,
              }}
            >
              <thead>
                <tr style={{ borderBottom: `1px solid ${BORDER}` }}>
                  {["Pattern", "Example", "Node Type", "C++ Output"].map(
                    (h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: "left",
                          padding: "8px 12px",
                          color: MUTED,
                          fontSize: 10,
                          fontWeight: 600,
                          textTransform: "uppercase",
                          letterSpacing: "0.1em",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {GRAMMAR.map((r, i) => (
                  <tr
                    key={i}
                    style={{
                      borderBottom: `1px solid ${BORDER}30`,
                      background: i % 2 === 0 ? "transparent" : `${SURFACE}60`,
                    }}
                  >
                    <td
                      style={{
                        padding: "10px 12px",
                        color: "#82aaff",
                        fontWeight: 600,
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.syntax}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        color: "#c3e88d",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.example}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: "2px 8px",
                          borderRadius: 4,
                          color: NODE_DOT[r.node],
                          background: `${NODE_DOT[r.node]}18`,
                          border: `1px solid ${NODE_DOT[r.node]}30`,
                          whiteSpace: "nowrap",
                        }}
                      >
                        {r.node}
                      </span>
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        color: MUTED,
                        fontSize: 11,
                      }}
                    >
                      {r.cpp}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div
            style={{
              marginTop: 24,
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              padding: 16,
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: MUTED,
                fontWeight: 600,
                marginBottom: 10,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
              }}
            >
              Security Constraints
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr",
                gap: "6px 24px",
                fontSize: 11,
                color: DIM,
              }}
            >
              {BLOCKED.map((b, i) => (
                <div key={i} style={{ display: "flex", gap: 6 }}>
                  <span style={{ color: "#ef4444", flexShrink: 0 }}>x</span>
                  {b.label}
                </div>
              ))}
              <div style={{ display: "flex", gap: 6 }}>
                <span style={{ color: "#10b981", flexShrink: 0 }}>+</span>
                Whitelist grammar only — 8 patterns
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <span style={{ color: "#10b981", flexShrink: 0 }}>+</span>
                Deterministic output guaranteed
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "tokens" && result?.allTokens && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            Each input line normalized to lowercase and split into tokens.
            Special characters are stripped.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {result.allTokens.map(({ lineNo, raw, tokens }) => (
              <div
                key={lineNo}
                style={{
                  background: SURFACE,
                  border: `1px solid ${BORDER}`,
                  borderRadius: 8,
                  padding: "12px 14px",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    color: MUTED,
                    marginBottom: 8,
                    display: "flex",
                    gap: 8,
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: ACCENT }}>LINE {lineNo}</span>
                  <span style={{ color: DIM }}>/</span>
                  <span style={{ color: DIM, wordBreak: "break-all" }}>
                    {raw}
                  </span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {tokens.length === 0 ? (
                    <span style={{ color: "#ef4444", fontSize: 11 }}>
                      No tokens — line will fail parsing
                    </span>
                  ) : (
                    tokens.map((tok, i) => (
                      <span
                        key={i}
                        style={{
                          background: `${ACCENT}18`,
                          color: "#82aaff",
                          border: `1px solid ${ACCENT}30`,
                          borderRadius: 4,
                          padding: "2px 10px",
                          fontSize: 12,
                        }}
                      >
                        {tok}
                      </span>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "syntax" && result?.allTokens && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            Parse-tree view of token stream. Each input line is a branch; each
            token is a leaf node.
          </p>
          <div
            style={{
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              padding: 16,
              fontSize: 12,
              lineHeight: 1.9,
              overflowX: "auto",
            }}
          >
            <div style={{ color: "#34d399", fontWeight: 700, marginBottom: 6 }}>
              Program
            </div>
            {result.allTokens.map(({ lineNo, tokens }) => (
              <div key={lineNo} style={{ paddingLeft: 16 }}>
                <div style={{ color: "#fb923c" }}>+-- Line {lineNo}</div>
                {tokens.map((tk, i) => (
                  <div key={i} style={{ paddingLeft: 32, color: MUTED }}>
                    {i === tokens.length - 1 ? "\--" : "+--"}{" "}
                    <span style={{ color: TEXT }}>{tk}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "ast" && result?.program && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            Abstract Syntax Tree — each statement parsed into a typed node with
            its arguments.
          </p>
          <div
            style={{
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              padding: 16,
              fontSize: 12,
              lineHeight: 1.9,
              overflowX: "auto",
            }}
          >
            <div style={{ color: "#34d399", fontWeight: 800, marginBottom: 8 }}>
              PROGRAM
            </div>
            {result.program.map((node, i) => {
              const c = NODE_DOT[node.type] || "#888";
              return (
                <div
                  key={i}
                  style={{
                    paddingLeft: 20,
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginBottom: 4,
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: DIM }}>
                    {i === result.program.length - 1 ? "\--" : "+--"}
                  </span>
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      padding: "2px 9px",
                      borderRadius: 4,
                      color: c,
                      background: `${c}15`,
                      border: `1px solid ${c}35`,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {node.type}
                  </span>
                  {node.args.length > 0 && (
                    <span style={{ color: MUTED, fontSize: 11 }}>
                      (
                      {node.args.map((a, j) => (
                        <span key={j} style={{ color: "#c3e88d" }}>
                          {a}
                          {j < node.args.length - 1 ? ", " : ""}
                        </span>
                      ))}
                      )
                    </span>
                  )}
                  <span
                    style={{ marginLeft: "auto", color: DIM, fontSize: 10 }}
                  >
                    L{node.line}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SYMBOL TABLE */}
      {tab === "symbols" && result?.symbolTable && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            All declared identifiers tracked during semantic analysis.
          </p>
          <div
            style={{
              background: "#10b98110",
              border: "1px solid #10b98128",
              borderRadius: 8,
              padding: "10px 14px",
              fontSize: 12,
              color: "#10b981",
              marginBottom: 16,
            }}
          >
            All semantic rules passed — variables declared before use, if/endif
            balanced.
          </div>
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: 12,
                minWidth: 300,
              }}
            >
              <thead>
                <tr style={{ borderBottom: `1px solid ${BORDER}` }}>
                  {["Identifier", "C++ Type", "Category"].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "8px 12px",
                        color: MUTED,
                        fontSize: 10,
                        fontWeight: 600,
                        textTransform: "uppercase",
                        letterSpacing: "0.1em",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.symbolTable.vars.map((v, i) => (
                  <tr
                    key={v}
                    style={{
                      borderBottom: `1px solid ${BORDER}30`,
                      background: i % 2 === 0 ? "transparent" : `${SURFACE}60`,
                    }}
                  >
                    <td style={{ padding: "9px 12px", color: "#eeffff" }}>
                      {v}
                    </td>
                    <td style={{ padding: "9px 12px", color: "#82aaff" }}>
                      int
                    </td>
                    <td style={{ padding: "9px 12px", color: MUTED }}>
                      variable
                    </td>
                  </tr>
                ))}
                {result.symbolTable.arrays.map((a, i) => (
                  <tr
                    key={a}
                    style={{
                      borderBottom: `1px solid ${BORDER}30`,
                      background:
                        (result.symbolTable.vars.length + i) % 2 === 0
                          ? "transparent"
                          : `${SURFACE}60`,
                    }}
                  >
                    <td style={{ padding: "9px 12px", color: "#eeffff" }}>
                      {a}
                    </td>
                    <td style={{ padding: "9px 12px", color: "#82aaff" }}>
                      int[]
                    </td>
                    <td style={{ padding: "9px 12px", color: MUTED }}>array</td>
                  </tr>
                ))}
                {!result.symbolTable.vars.length &&
                  !result.symbolTable.arrays.length && (
                    <tr>
                      <td
                        colSpan={3}
                        style={{
                          padding: 16,
                          color: MUTED,
                          textAlign: "center",
                        }}
                      >
                        No symbols declared
                      </td>
                    </tr>
                  )}
              </tbody>
            </table>
          </div>
          <div
            style={{ marginTop: 12, fontSize: 11, color: DIM, lineHeight: 1.8 }}
          >
            Rules enforced: variable declared before print · array declared
            before sum · IF operands validated · if/endif balanced · one else
            per if
          </div>
        </div>
      )}

      {/* SECURITY */}
      {tab === "security" && result && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            Input is scanned for {BLOCKED.length} blocked patterns before any
            compilation begins.
          </p>
          {(!result.secIssues || result.secIssues.length === 0) && (
            <div
              style={{
                background: "#10b98110",
                border: "1px solid #10b98128",
                borderRadius: 8,
                padding: "10px 14px",
                fontSize: 12,
                color: "#10b981",
                marginBottom: 16,
              }}
            >
              No security issues detected. All {result.allTokens?.length || 0}{" "}
              statement(s) cleared.
            </div>
          )}
          {result.secIssues?.map((issue, i) => (
            <div
              key={i}
              style={{
                background:
                  issue.severity === "critical" ? "#ef444410" : "#f59e0b10",
                border: `1px solid ${issue.severity === "critical" ? "#ef444428" : "#f59e0b28"}`,
                borderRadius: 8,
                padding: "10px 14px",
                marginBottom: 8,
                fontSize: 12,
              }}
            >
              <div
                style={{
                  color: issue.severity === "critical" ? "#ef4444" : "#f59e0b",
                  fontWeight: 600,
                  marginBottom: 4,
                }}
              >
                {issue.severity.toUpperCase()} — Line {issue.line}
              </div>
              <div style={{ color: TEXT }}>{issue.label}</div>
              <div
                style={{
                  color: MUTED,
                  fontSize: 10,
                  marginTop: 4,
                  wordBreak: "break-all",
                }}
              >
                {issue.raw}
              </div>
            </div>
          ))}
          <div
            style={{
              marginTop: 16,
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              padding: 14,
              fontSize: 11,
              color: DIM,
              lineHeight: 1.9,
            }}
          >
            <div
              style={{
                color: MUTED,
                fontWeight: 600,
                marginBottom: 8,
                fontSize: 10,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
              }}
            >
              Security Architecture
            </div>
            {[
              `Input scanned against ${BLOCKED.length} blocked patterns before any processing`,
              "All characters normalized — special chars stripped at tokenization",
              "Whitelist-only grammar — only 8 approved patterns accepted",
              "Semantic validation prevents undeclared variable access",
              "Deterministic output — no probabilistic code generation",
            ].map((s, i) => (
              <div key={i}>
                {i + 1}. {s}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* C++ OUTPUT */}
      {tab === "output" && result?.cppCode && (
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              marginBottom: 16,
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <p style={{ color: MUTED, fontSize: 12, margin: 0 }}>
              Deterministic, safe, standards-compliant C++ output.
            </p>
            <button
              onClick={copyCode}
              style={{
                marginLeft: "auto",
                padding: "5px 14px",
                fontSize: 11,
                fontFamily: "inherit",
                background: copied ? "#10b98118" : SURFACE2,
                color: copied ? "#10b981" : MUTED,
                border: `1px solid ${copied ? "#10b98130" : BORDER}`,
                borderRadius: 6,
                cursor: "pointer",
                transition: "all 0.2s",
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <div
            style={{
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            <div style={{ display: "flex", fontSize: 12, lineHeight: 1.75 }}>
              <div
                style={{
                  flexShrink: 0,
                  textAlign: "right",
                  color: DIM,
                  padding: "14px 10px 14px 12px",
                  borderRight: `1px solid ${BORDER}`,
                  userSelect: "none",
                  minWidth: 36,
                  background: `${SURFACE2}80`,
                }}
              >
                {result.cppCode.split("\n").map((_, i) => (
                  <div key={i} style={{ minHeight: "1.6em" }}>
                    {i + 1}
                  </div>
                ))}
              </div>
              <div style={{ flex: 1, padding: "14px 16px", overflowX: "auto" }}>
                {result.cppCode.split("\n").map((line, i) => (
                  <CodeLine key={i} line={line} />
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ERRORS */}
      {tab === "errors" && result?.error && (
        <div>
          <p
            style={{
              color: MUTED,
              fontSize: 12,
              marginBottom: 16,
              lineHeight: 1.6,
            }}
          >
            Compilation stopped. See the error details and fix hint below.
          </p>
          <div
            style={{
              background: "#ef444410",
              border: "1px solid #ef444430",
              borderRadius: 8,
              padding: 16,
              marginBottom: 16,
            }}
          >
            <div
              style={{
                color: "#ef4444",
                fontWeight: 700,
                marginBottom: 10,
                fontSize: 13,
              }}
            >
              [{result.error.phase} ERROR]
              {result.error.lineNo ? `  —  Line ${result.error.lineNo}` : ""}
              {result.error.stmtNo > 0
                ? `  —  Statement ${result.error.stmtNo}`
                : ""}
            </div>
            {result.error.msg && (
              <div style={{ color: TEXT, marginBottom: 10, fontSize: 12 }}>
                {result.error.msg}
              </div>
            )}
            {result.error.tokens && (
              <div style={{ fontSize: 11, marginBottom: 10 }}>
                <span style={{ color: MUTED }}>Tokens found: </span>
                <span style={{ color: "#c3e88d", wordBreak: "break-all" }}>
                  {result.error.tokens}
                </span>
              </div>
            )}
            {result.error.hint && (
              <div
                style={{
                  background: "#10b98110",
                  border: "1px solid #10b98128",
                  borderRadius: 6,
                  padding: "10px 12px",
                  fontSize: 11,
                  color: "#10b981",
                  whiteSpace: "pre-wrap",
                }}
              >
                Fix: {result.error.hint}
              </div>
            )}
            {result.error.issues && (
              <div
                style={{
                  marginTop: 12,
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                }}
              >
                {result.error.issues.map((iss, i) => (
                  <div
                    key={i}
                    style={{
                      background: "#ef444408",
                      border: "1px solid #ef444420",
                      borderRadius: 6,
                      padding: "7px 12px",
                      fontSize: 11,
                    }}
                  >
                    <span style={{ color: "#ef4444" }}>Line {iss.line}: </span>
                    <span style={{ color: TEXT }}>{iss.label}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div
            style={{
              background: SURFACE,
              border: `1px solid ${BORDER}`,
              borderRadius: 8,
              padding: 14,
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: MUTED,
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                marginBottom: 10,
              }}
            >
              Pipeline Trace
            </div>
            {[
              { label: "Security Scan", ok: result.error.phase !== "SECURITY" },
              { label: "Lexical Analysis", ok: !!result.allTokens },
              { label: "Syntax Parsing", ok: !!result.program },
              { label: "Semantic Analysis", ok: !!result.symbolTable },
              { label: "Code Generation", ok: !!result.cppCode },
            ].map((s) => (
              <div
                key={s.label}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 6,
                  fontSize: 12,
                }}
              >
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: s.ok ? "#10b981" : "#ef4444",
                    flexShrink: 0,
                  }}
                />
                <span style={{ color: s.ok ? MUTED : TEXT }}>{s.label}</span>
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: 10,
                    color: s.ok ? "#10b981" : "#ef4444",
                  }}
                >
                  {s.ok ? "pass" : "fail"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  /* ────────────────────────────────────────────
     RENDER — 3 responsive layouts
  ──────────────────────────────────────────── */

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        background: BG,
        color: TEXT,
        fontFamily: "'JetBrains Mono','Fira Code',monospace",
        fontSize: 13,
        overflow: "hidden",
      }}
    >
      {/* ── TOP BAR ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          height: 48,
          padding: "0 16px",
          background: SURFACE,
          borderBottom: `1px solid ${BORDER}`,
          flexShrink: 0,
          gap: 10,
        }}
      >
        {/* mobile: hamburger */}
        {!isDesktop && (
          <button
            onClick={() => setSideOpen((s) => !s)}
            style={{
              background: "transparent",
              border: "none",
              color: MUTED,
              cursor: "pointer",
              padding: "4px 6px",
              fontSize: 18,
              lineHeight: 1,
              flexShrink: 0,
            }}
            aria-label="Toggle menu"
          >
            ☰
          </button>
        )}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: ACCENT,
              boxShadow: `0 0 8px ${ACCENT}88`,
            }}
          />  
          <span
            style={{
              color: TEXT,
              fontWeight: 700,
              fontSize: 13,
              letterSpacing: "0.08em",
            }}
          >
            NL2CODE
          </span>
          {!isMobile && (
            <span style={{ color: DIM, fontSize: 11 }}>
              / Natural Language Compiler
            </span>
          )}
        </div>

        {/* mobile: editor / output toggle */}
        {isMobile && (
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              background: SURFACE2,
              border: `1px solid ${BORDER}`,
              borderRadius: 6,
              overflow: "hidden",
            }}
          >
            {["editor", "output"].map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                style={{
                  padding: "4px 12px",
                  fontSize: 11,
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "inherit",
                  background: view === v ? ACCENT : "transparent",
                  color: view === v ? "#fff" : MUTED,
                  transition: "all 0.15s",
                }}
              >
                {v === "editor" ? "Editor" : "Output"}
              </button>
            ))}
          </div>
        )}

        {!isMobile && (
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              gap: 16,
              fontSize: 11,
              color: MUTED,
            }}
          >
            <span>Rishikesh R. Mahato</span>
            {!isTablet && (
              <>
                <span style={{ color: DIM }}>24CSB0A88</span>
                <span style={{ color: DIM }}>NIT Warangal</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* ── BODY ── */}
      <div
        style={{
          display: "flex",
          flex: 1,
          minHeight: 0,
          overflow: "hidden",
          position: "relative",
        }}
      >
        {/* MOBILE DRAWER OVERLAY */}
        {!isDesktop && sideOpen && (
          <div
            onClick={() => setSideOpen(false)}
            style={{
              position: "absolute",
              inset: 0,
              background: "rgba(0,0,0,0.6)",
              zIndex: 10,
            }}
          />
        )}

        {/* SIDEBAR — desktop: permanent | tablet/mobile: drawer */}
        <div
          style={{
            width: 220,
            background: SURFACE,
            borderRight: `1px solid ${BORDER}`,
            display: "flex",
            flexDirection: "column",
            flexShrink: 0,
            ...(isDesktop
              ? {}
              : {
                  position: "absolute",
                  top: 0,
                  left: 0,
                  bottom: 0,
                  zIndex: 20,
                  transform: sideOpen ? "translateX(0)" : "translateX(-100%)",
                  transition: "transform 0.22s ease",
                  boxShadow: sideOpen ? "4px 0 24px rgba(0,0,0,0.5)" : "none",
                }),
          }}
        >
          <NavList
            onSelect={() => {
              if (!isDesktop) setSideOpen(false);
              if (isMobile) setView("output");
            }}
          />
        </div>

        {/* EDITOR + OUTPUT — desktop: side-by-side | tablet: stacked | mobile: toggle */}
        <div
          style={{
            display: "flex",
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            flexDirection: isDesktop ? "row" : isMobile ? "column" : "column",
          }}
        >
          {/* EDITOR */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              borderRight: isDesktop ? `1px solid ${BORDER}` : "none",
              borderBottom: !isDesktop ? `1px solid ${BORDER}` : "none",
              ...(isDesktop
                ? { width: "40%", minWidth: 260 }
                : isMobile
                  ? { display: view === "editor" ? "flex" : "none", flex: 1 }
                  : { flex: "0 0 45%", minHeight: 200, maxHeight: "45%" }),
            }}
          >
            {/* editor header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                height: 36,
                padding: "0 14px",
                background: SURFACE2,
                borderBottom: `1px solid ${BORDER}`,
                flexShrink: 0,
              }}
            >
              <span style={{ fontSize: 11, color: MUTED }}>input.nl</span>
              <span style={{ marginLeft: "auto", fontSize: 11, color: DIM }}>
                {stmts} line{stmts !== 1 ? "s" : ""}
              </span>
            </div>

            {/* editor body */}
            <div
              style={{
                flex: 1,
                display: "flex",
                overflow: "hidden",
                background: BG,
              }}
            >
              <div
                style={{
                  flexShrink: 0,
                  textAlign: "right",
                  fontSize: 12,
                  lineHeight: "1.75",
                  color: DIM,
                  padding: "12px 10px 12px 8px",
                  borderRight: `1px solid ${BORDER}`,
                  userSelect: "none",
                  minWidth: 34,
                }}
              >
                {(input || " ").split("\n").map((_, i) => (
                  <div key={i}>{i + 1}</div>
                ))}
              </div>
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                spellCheck={false}
                placeholder={
                  "Type structured English...\n\nExample:\n  read n\n  create array a of size n\n  sum of array a into s\n  if s greater 10\n  print s\n  else\n  print n\n  endif"
                }
                style={{
                  flex: 1,
                  resize: "none",
                  background: BG,
                  color: TEXT,
                  border: "none",
                  outline: "none",
                  padding: "12px 14px",
                  fontFamily: "inherit",
                  fontSize: 13,
                  lineHeight: 1.75,
                  caretColor: "#818cf8",
                }}
              />
            </div>

            {/* buttons */}
            <div
              style={{
                display: "flex",
                gap: 8,
                padding: "8px 14px",
                background: SURFACE2,
                borderTop: `1px solid ${BORDER}`,
                flexShrink: 0,
                alignItems: "center",
              }}
            >
              <button
                onClick={compile}
                style={{
                  padding: "7px 18px",
                  background: ACCENT,
                  color: "#fff",
                  border: "none",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  fontSize: 12,
                  fontWeight: 600,
                  letterSpacing: "0.04em",
                  boxShadow: `0 2px 12px ${ACCENT}44`,
                }}
              >
                Compile
              </button>
              <button
                onClick={clear}
                style={{
                  padding: "7px 12px",
                  background: "transparent",
                  color: MUTED,
                  border: `1px solid ${BORDER}`,
                  borderRadius: 6,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  fontSize: 12,
                }}
              >
                Clear
              </button>
              {isMobile && result && (
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: 10,
                    padding: "3px 8px",
                    borderRadius: 10,
                    background: success ? "#10b98118" : "#ef444418",
                    color: success ? "#10b981" : "#ef4444",
                    border: `1px solid ${success ? "#10b98130" : "#ef444430"}`,
                  }}
                >
                  {success ? "OK" : "Error"}
                </span>
              )}
            </div>
          </div>

          {/* OUTPUT */}
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              overflow: "hidden",
              background: BG,
              ...(isMobile
                ? { display: view === "output" ? "flex" : "none" }
                : {}),
            }}
          >
            <div
              style={{
                height: 36,
                display: "flex",
                alignItems: "center",
                padding: "0 16px",
                background: SURFACE2,
                borderBottom: `1px solid ${BORDER}`,
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  fontSize: 11,
                  color: MUTED,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  fontWeight: 600,
                }}
              >
                {NAV.find((n) => n.id === tab)?.label || "Output"}
              </span>
            </div>
            <OutputContent />
          </div>
        </div>
      </div>
    </div>
  );
}
