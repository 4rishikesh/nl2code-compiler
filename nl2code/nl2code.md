# NL2CODE: Natural Language to Code Compiler

## Overview

NL2CODE is a rule-based compiler that translates structured English statements into valid C++ code.
The system is designed to demonstrate core concepts of compiler design using a deterministic pipeline consisting of lexical analysis, parsing, abstract syntax tree construction, semantic validation, and code generation.

The project focuses on correctness, clarity, and strict grammar enforcement rather than probabilistic or AI-based interpretation.

---

## Objectives

* To design a simple compiler for structured English input
* To implement standard compiler phases in a clear and modular way
* To provide detailed error reporting for both syntax and semantic issues
* To generate readable and correct C++ code

---

## Features

* Deterministic compilation process
* Strict grammar validation
* Lexical, syntactic, and semantic error handling
* Support for variables, arrays, and conditional statements
* Automatic generation of C++ source code
* Output saved to `generated.cpp`

---

## Supported Grammar

| Operation     | Syntax                          |
| ------------- | ------------------------------- |
| Read variable | `read <var>`                    |
| Read array    | `read array <arr> of size <n>`  |
| Assignment    | `set <var> to <value>`          |
| Array sum     | `sum of array <arr> into <var>` |
| Print         | `print <var>`                   |
| Condition     | `if <var> greater <value>`      |
| Else          | `else`                          |
| End block     | `endif`                         |

---

## Compiler Pipeline

1. Lexical Analysis
   Input is normalized and tokenized

2. Syntax Analysis
   Tokens are validated against predefined grammar rules

3. AST Generation
   Statements are converted into structured nodes

4. Semantic Analysis
   Variable declarations, array usage, and control flow are verified

5. Code Generation
   Equivalent C++ code is produced

---

## Project Structure

```id="h1s8yt"
main()
 ├── tokenize()
 ├── printTokens()
 ├── printSyntaxTree()
 ├── parseLine()
 ├── printAST()
 ├── semanticCheck()
 ├── printSymbolTable()
 └── generateCPP()
```

---

## How to Run

### Compile

```bash id="2k2j6t"
g++ compiler.cpp -o nl2code
```

### Execute

```bash id="rhb7pl"
./nl2code
```

### Example Input

```id="0v2ksc"
read n
read array a of size n
sum of array a into s
if s greater 10
print s
else
print n
endif
```

### Output

* Displays all compilation phases
* Generates `generated.cpp`

---

## Error Handling

The compiler detects and reports:

* Invalid grammar or syntax errors
* Use of undeclared variables
* Incorrect array usage
* Improper conditional structures such as unmatched `if` and `endif`

Each error includes a message, location, and suggestion for correction.

---

## Design Approach

The system follows a deterministic, rule-based approach:

* No ambiguity in parsing
* No probabilistic interpretation
* Clear separation of compiler phases
* Emphasis on correctness and traceability

---

## Future Work

* Integration of an AI preprocessing layer to convert free-form English into structured grammar
* Extension to support additional programming constructs
* Web-based interface for interactive use
* Support for multiple target languages

---

## Author

Rishikesh Raj Mahato
B.Tech Computer Science and Engineering
NIT Warangal

---

## License

This project is intended for academic and educational use.
