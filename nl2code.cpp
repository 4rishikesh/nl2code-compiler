#include <iostream>
#include <sstream>
#include <vector>
#include <set>
#include <fstream>
#include <cctype>
using namespace std;

void lexError(int lineNo, const string &msg) {
    cout << "\n[LEXICAL ERROR] Line " << lineNo << ": " << msg << "\n";
    cout << "  Hint: Input must contain only letters, digits, and underscores.\n";
    exit(1);
}

void parseError(int lineNo, const string &tokens, const string &hint) {
    cout << "\n[SYNTAX ERROR] Line " << lineNo << ": Unrecognised statement.\n";
    cout << "  Tokens found : " << tokens << "\n";
    cout << "  Hint         : " << hint   << "\n";
    cout << "\n  Supported statement formats:\n";
    cout << "    read <var>\n";
    cout << "    read array <arr> of size <n>\n";
    cout << "    set <var> to <value>\n";
    cout << "    sum of array <arr> into <var>\n";
    cout << "    print <var>\n";
    cout << "    if <var> greater <value_or_var>\n";
    cout << "    else\n";
    cout << "    endif\n";
    exit(1);
}

void semanticError(int context, const string &msg, const string &hint) {
    cout << "\n[SEMANTIC ERROR]";
    if(context >= 0) cout << " Near statement " << context + 1;
    cout << ": " << msg << "\n";
    cout << "  Hint: " << hint << "\n";
    exit(1);
}



//Tokenizer (LA)

vector<string> tokenize(const string &line) {
    string normalised = line;
    for(char &c : normalised) {
        if(c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if(!((c >= 'a' && c <= 'z') ||
             (c >= '0' && c <= '9') ||
              c == '_'))
            c = ' ';
    }
    vector<string> tokens;
    string word;
    stringstream ss(normalised);
    while(ss >> word) tokens.push_back(word);
    return tokens;
}

void printTokens(const vector<vector<string>> &allTokens) {
    cout << "\n";
    cout << "  PHASE 1 — LEXICAL ANALYSIS (TOKENIZATION)\n";
    for(int i = 0; i < (int)allTokens.size(); i++) {
        cout << "  Line " << i + 1 << " : ";
        if(allTokens[i].empty()) {
            cout << "[EMPTY LINE — no tokens produced]";
        } else {
            for(const string &w : allTokens[i]) cout << "[" << w << "] ";
        }
        cout << "\n";
    }
}


//Syntax tree

void printSyntaxTree(const vector<vector<string>> &allTokens) {
    cout << "\n";
    cout << "  PHASE 2 — SYNTAX TREE (PARSE-TREE STYLE)\n";
    cout << "  Program\n";
    for(int i = 0; i < (int)allTokens.size(); i++) {
        cout << "  |-- Line " << i + 1 << "\n";
        for(const string &tk : allTokens[i]) {
            cout << "  |    |-- " << tk << "\n";
        }
    }
}


//AST node

struct ASTNode {
    string         type;
    vector<string> args;
    int            line = -1;
};

 

//Parser

ASTNode parseLine(const vector<string> &t, int lineNo) {
    ASTNode node;
    node.line = lineNo;

    string tokenStr;
    for(const string &s : t) tokenStr += "\"" + s + "\" ";

    if(t.size() == 2 && t[0] == "read") {
        node.type = "READ_VAR";
        node.args = {t[1]};
        return node;
    }

    if(t.size() == 6 && t[0] == "read" && t[1] == "array"
       && t[3] == "of" && t[4] == "size") {
        node.type = "READ_ARRAY";
        node.args = {t[2], t[5]};
        return node;
    }

    if(t.size() >= 2 && t[0] == "read" && t.size() != 2) {
        bool hasArray = false, hasOf = false, hasSize = false;
        for(const string &s : t) {
            if(s == "array") hasArray = true;
            if(s == "of")    hasOf    = true;
            if(s == "size")  hasSize  = true;
        }
        if(hasArray && (!hasOf || !hasSize)) {
            parseError(lineNo, tokenStr,
                "Did you mean: read array <arr> of size <n> ?\n"
                "           Missing keyword: " +
                string(!hasOf ? "'of'" : "'size'"));
        }
    }

    if(t.size() == 4 && t[0] == "set" && t[2] == "to") {
        node.type = "SET_VAR";
        node.args = {t[1], t[3]};
        return node;
    }

    if(t.size() >= 2 && t[0] == "set") {
        bool hasTo = false;
        for(const string &s : t) if(s == "to") hasTo = true;
        if(!hasTo)
            parseError(lineNo, tokenStr,
                "Did you mean: set <var> to <value> ?\n"
                "           Missing keyword 'to'.");
        else
            parseError(lineNo, tokenStr,
                "Did you mean: set <var> to <value> ?\n"
                "           Expected exactly 4 tokens.");
    }

    if(t.size() == 6 && t[0] == "sum" && t[1] == "of"
       && t[2] == "array" && t[4] == "into") {
        node.type = "SUM_ARRAY";
        node.args = {t[3], t[5]};
        return node;
    }

    if(t.size() >= 2 && t[0] == "sum") {
        bool hasOf = false, hasArray = false, hasInto = false;
        for(const string &s : t) {
            if(s == "of")    hasOf    = true;
            if(s == "array") hasArray = true;
            if(s == "into")  hasInto  = true;
        }
        string missing;
        if(!hasOf)    missing += "'of' ";
        if(!hasArray) missing += "'array' ";
        if(!hasInto)  missing += "'into' ";
        if(!missing.empty())
            parseError(lineNo, tokenStr,
                "Did you mean: sum of array <arr> into <var> ?\n"
                "           Missing keyword(s): " + missing);
        else
            parseError(lineNo, tokenStr,
                "Did you mean: sum of array <arr> into <var> ?\n"
                "           Check token count (expected 6).");
    }

    if(t.size() == 2 && t[0] == "print") {
        node.type = "PRINT_VAR";
        node.args = {t[1]};
        return node;
    }

    if(!t.empty() && t[0] == "print" && t.size() != 2) {
        parseError(lineNo, tokenStr,
            "Did you mean: print <var> ?\n"
            "           'print' expects exactly one variable name.");
    }

    if(t.size() == 4 && t[0] == "if" && t[2] == "greater") {
        node.type = "IF_GREATER";
        node.args = {t[1], t[3]};
        return node;
    }

    if(t.size() >= 2 && t[0] == "if") {
        bool hasGreater = false;
        for(const string &s : t) if(s == "greater") hasGreater = true;
        if(!hasGreater)
            parseError(lineNo, tokenStr,
                "Did you mean: if <var> greater <value_or_var> ?\n"
                "           Missing keyword 'greater'.");
        else
            parseError(lineNo, tokenStr,
                "Did you mean: if <var> greater <value_or_var> ?\n"
                "           Expected exactly 4 tokens.");
    }

    if(t.size() == 1 && t[0] == "else") {
        node.type = "ELSE_BLOCK";
        return node;
    }

    if(t.size() == 1 && t[0] == "endif") {
        node.type = "END_IF";
        return node;
    }

    parseError(lineNo, tokenStr,
        "Statement does not match any supported grammar rule.\n"
        "           Check spelling, keyword order, and token count.");

    return node;
}

void printAST(const vector<ASTNode> &program) {
    cout << "\n";
    cout << "  PHASE 4 — AST GENERATION OUTPUT\n";
    cout << "  PROGRAM\n";
    for(const auto &node : program) {
        cout << "  |-- [" << node.type << "]";
        if(!node.args.empty()) {
            cout << "  args: (";
            for(int i = 0; i < (int)node.args.size(); i++) {
                cout << node.args[i];
                if(i != (int)node.args.size() - 1) cout << ", ";
            }
            cout << ")";
        }
        cout << "\n";
    }
}


//Semantic analysis

void semanticCheck(const vector<ASTNode> &program) {
    set<string> vars;
    set<string> arrays;
    int ifDepth   = 0;
    int elseCount = 0;

    for(int i = 0; i < (int)program.size(); i++) {
        const ASTNode &node = program[i];

        if(node.type == "READ_VAR") {
            vars.insert(node.args[0]);
        }
        else if(node.type == "READ_ARRAY") {
            arrays.insert(node.args[0]);
            vars.insert(node.args[1]);
        }
        else if(node.type == "SET_VAR") {
            const string &val = node.args[1];
            if(!isdigit(val[0]) && vars.find(val) == vars.end()) {
                semanticError(i,
                    "Variable '" + val + "' used in assignment before declaration.",
                    "Declare '" + val + "' with 'read " + val + "' before using it.");
            }
            vars.insert(node.args[0]);
        }
        else if(node.type == "SUM_ARRAY") {
            const string &arr = node.args[0];
            if(arrays.find(arr) == arrays.end()) {
                semanticError(i,
                    "Array '" + arr + "' used in sum before declaration.",
                    "Declare it first with: read array " + arr + " of size <n>");
            }
            vars.insert(node.args[1]);
        }
        else if(node.type == "PRINT_VAR") {
            const string &v = node.args[0];
            if(vars.find(v) == vars.end()) {
                semanticError(i,
                    "Variable '" + v + "' printed before declaration.",
                    "Declare it first with: read " + v + "  OR  set " + v + " to <value>");
            }
        }
        else if(node.type == "IF_GREATER") {
            const string &v1 = node.args[0];
            if(vars.find(v1) == vars.end()) {
                semanticError(i,
                    "Variable '" + v1 + "' used in IF condition before declaration.",
                    "Declare it first with: read " + v1 + "  OR  set " + v1 + " to <value>");
            }
            const string &v2 = node.args[1];
            if(!isdigit(v2[0]) && vars.find(v2) == vars.end()) {
                semanticError(i,
                    "Variable '" + v2 + "' used in IF condition before declaration.",
                    "Declare it first with: read " + v2 + "  OR  set " + v2 + " to <value>");
            }
            ifDepth++;
            elseCount = 0;
        }
        else if(node.type == "ELSE_BLOCK") {
            if(ifDepth == 0) {
                semanticError(i,
                    "'else' found without a matching 'if' block.",
                    "Every 'else' must be preceded by an 'if <var> greater <val>' statement.");
            }
            elseCount++;
            if(elseCount > 1) {
                semanticError(i,
                    "Multiple 'else' blocks inside a single 'if'.",
                    "Only one 'else' is allowed per 'if' block.");
            }
        }
        else if(node.type == "END_IF") {
            if(ifDepth == 0) {
                semanticError(i,
                    "'endif' found without a matching 'if' block.",
                    "Every 'endif' must close an 'if <var> greater <val>' statement.");
            }
            ifDepth--;
            elseCount = 0;
        }
    }

    if(ifDepth > 0) {
        semanticError(-1,
            to_string(ifDepth) + " 'if' block(s) were never closed.",
            "Add 'endif' at the end of every 'if' block.");
    }
}

void printSymbolTable(const vector<ASTNode> &program) {
    set<string> vars;
    set<string> arrays;
    for(const auto &node : program) {
        if(node.type == "READ_VAR")   vars.insert(node.args[0]);
        if(node.type == "SET_VAR")    vars.insert(node.args[0]);
        if(node.type == "SUM_ARRAY")  vars.insert(node.args[1]);
        if(node.type == "READ_ARRAY") {
            arrays.insert(node.args[0]);
            vars.insert(node.args[1]);
        }
    }
    cout << "\n  Symbol Table:\n";
    cout << "  +-----------------+----------+\n";
    cout << "  | Identifier      | Type     |\n";
    cout << "  +-----------------+----------+\n";
    for(const string &v : vars)
        cout << "  | " << v << string(16 - (int)v.size(), ' ') << "| int      |\n";
    for(const string &a : arrays)
        cout << "  | " << a << string(16 - (int)a.size(), ' ') << "| int[]    |\n";
    cout << "  +-----------------+----------+\n";
}


string generateCPP(const vector<ASTNode> &program) {
    string code;
    code += "#include <iostream>\n";
    code += "#include <vector>\n";
    code += "using namespace std;\n\n";
    code += "int main() {\n";

    set<string> declaredVars;
    int indent = 1;

    auto pad = [](int level) -> string { return string(level * 4, ' '); };

    for(const auto &node : program) {

        if(node.type == "READ_VAR") {
            const string &v = node.args[0];
            if(declaredVars.find(v) == declaredVars.end()) {
                code += pad(indent) + "int " + v + ";\n";
                declaredVars.insert(v);
            }
            code += pad(indent) + "cin >> " + v + ";\n";
        }

        else if(node.type == "READ_ARRAY") {
            const string &arr = node.args[0];
            const string &n   = node.args[1];
            if(declaredVars.find(n) == declaredVars.end()) {
                code += pad(indent) + "int " + n + ";\n";
                declaredVars.insert(n);
                code += pad(indent) + "cin >> " + n + ";\n";
            }
            code += pad(indent) + "vector<int> " + arr + "(" + n + ");\n";
            code += pad(indent) + "for (int i = 0; i < " + n + "; i++) {\n";
            code += pad(indent + 1) + "cin >> " + arr + "[i];\n";
            code += pad(indent) + "}\n";
        }

        else if(node.type == "SET_VAR") {
            const string &v   = node.args[0];
            const string &val = node.args[1];
            if(declaredVars.find(v) == declaredVars.end()) {
                code += pad(indent) + "int " + v + " = " + val + ";\n";
                declaredVars.insert(v);
            } else {
                code += pad(indent) + v + " = " + val + ";\n";
            }
        }

        else if(node.type == "SUM_ARRAY") {
            const string &arr = node.args[0];
            const string &s   = node.args[1];
            if(declaredVars.find(s) == declaredVars.end()) {
                code += pad(indent) + "int " + s + " = 0;\n";
                declaredVars.insert(s);
            } else {
                code += pad(indent) + s + " = 0;\n";
            }
            code += pad(indent) + "for (int x : " + arr + ") {\n";
            code += pad(indent + 1) + s + " += x;\n";
            code += pad(indent) + "}\n";
        }

        else if(node.type == "PRINT_VAR") {
            code += pad(indent) + "cout << " + node.args[0] + " << \"\\n\";\n";
        }

        else if(node.type == "IF_GREATER") {
            code += pad(indent) + "if (" + node.args[0] + " > " + node.args[1] + ") {\n";
            indent++;
        }

        else if(node.type == "ELSE_BLOCK") {
            indent--;
            code += pad(indent) + "} else {\n";
            indent++;
        }

        else if(node.type == "END_IF") {
            indent--;
            code += pad(indent) + "}\n";
        }
    }

    code += "\n" + pad(1) + "return 0;\n";
    code += "}\n";
    return code;
}



int main() {

    cout << "\n";
    cout << "#       NATURAL LANGUAGE TO CODE COMPILER                   #\n";
    cout << "\n  Type your structured English program below.\n";
    cout << "  Press ENTER on a blank line when done.\n";
    cout << "\n  Supported statements:\n";
    cout << "    read <var>\n";
    cout << "    read array <arr> of size <n>\n";
    cout << "    set <var> to <value>\n";
    cout << "    sum of array <arr> into <var>\n";
    cout << "    print <var>\n";
    cout << "    if <var> greater <value_or_var>\n";
    cout << "    else\n";
    cout << "    endif\n\n";

    vector<string> lines;
    int lineNo = 1;
    while(true) {
        cout << "  > ";
        string line;
        getline(cin, line);
        if(line.find_first_not_of(" \t") == string::npos) break;
        lines.push_back(line);
        lineNo++;
    }

    if(lines.empty()) {
        cout << "\n[INPUT ERROR] No statements entered. Please type at least one line.\n";
        return 1;
    }

    int L = (int)lines.size();

    vector<vector<string>> allTokens;
    for(int i = 0; i < L; i++)
        allTokens.push_back(tokenize(lines[i]));
    printTokens(allTokens);

    printSyntaxTree(allTokens);

    cout << "\n";
    cout << "  PHASE 3 — PARSING (Pattern Matching → AST Nodes)\n";

    vector<ASTNode> program;
    for(int i = 0; i < L; i++) {
        if(allTokens[i].empty()) {
            parseError(i + 1, "[empty]",
                "Line is empty. Every line must contain a valid statement.");
        }
        program.push_back(parseLine(allTokens[i], i + 1));
        cout << "  Line " << i + 1 << " -> [" << program.back().type << "] parsed OK\n";
    }
    cout << "\n  Parse SUCCESS — all " << L << " line(s) matched grammar rules.\n";

    printAST(program);

    cout << "\n";
    cout << "  PHASE 5 — SEMANTIC ANALYSIS\n";
    semanticCheck(program);
    cout << "  All semantic rules passed.\n";
    printSymbolTable(program);

    cout << "\n";
    cout << "  PHASE 6 — GENERATED C++ CODE\n";
    string cppCode = generateCPP(program);
    cout << cppCode;

    ofstream fout("generated.cpp");
    if(!fout.is_open()) {
        cout << "\n[FILE ERROR] Could not open 'generated.cpp' for writing.\n";
        return 1;
    }
    fout << cppCode;
    fout.close();

    cout << "\n  Generated code saved to: generated.cpp\n";
    cout << "#  Compilation complete. No errors detected.                 #\n";

    return 0;
}



//  Valid test (7 lines):
//    read n
//    read array a of size n
//    sum of array a into s
//    if s greater 10
//    print s
//    else
//    print n
//    endif
//
//  Error test — undeclared variable:
//    print x
//
//  Error test — missing keyword:
//    read array a size n
//
//  Error test — missing endif:
//    read x
//    if x greater 5
//    print x
//
//  Error test — else without if:
//    else

// 8
// read n
// read array a of size n
// sum of array a into s
// if s greater 10
// print s
// else
// print n
// endif        

// User types:
// "take a number from user and check if it is greater than 10 and print it"

// AI outputs:
// read x
// if x greater 10
// print x
// endif

//architecture after AI integration

// main()
//   ↓
// Read free English from user
//   ↓
// Send to Gemini API  
//   ↓
// Get structured grammar back  
//   ↓
// Validate it matches grammar  
//   ↓
// Feed into existing pipeline (tokenize → parse → AST → semantic → codegen)
//   ↓
// Generated C++