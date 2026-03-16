**Code Style and Housekeeping Rules:**

1. **Maximum Line Width:** Strictly adhere to a maximum line width of 79 characters. This applies to everything: logic, string literals, and comments. Wrap long expressions or string literals as needed.
2. **Obvious Comments:** Absolutely no comments stating the obvious or explaining what the code is doing if the code is self-explanatory. Only add comments if there is a non-obvious "why" or complex design decision.
3. **Empty Lines:** NO empty lines are allowed inside function bodies (between statements). You must use exactly one single empty line between function definitions to separate them.
4. **Control Flow:** No early returns. Every function must follow the single-entry, single-exit principle. Declare a result variable at the top, mutate it, and return it at the very bottom. Never use `continue`. If possible, use smarter `for` loop conditions or extra state variables instead of `break`.
5. **Naming Conventions:** Use clear, unambiguous, and pronounceable words. Avoid cryptic abbreviations. A variable should describe its purpose (e.g., `elapsed`, `percentage`, `data`). Single-letter variables are only acceptable for standard loop counters (`i`, `j`, `k`) or when the context makes them universally understood domain symbols (e.g., `b` for a buffer pointer in a short scope).
6. **Braces:** Always use curly braces `{}` for control flow boundaries (`if`, `else if`, `else`, `while`, `for`). 
    *   **Allowed Single-Line:** `if (cond) { stmt; }` is ONLY allowed if there is no `else` or `else if` branch and it contains exactly one statement.
    *   **Prohibited Single-Line:** Any structure with an `else` or `else if` branch MUST use multi-line blocks for all branches. Any block with more than one statement MUST be multi-line.
7. **Pointers & Types:** ALWAYS place spaces around the asterisk. In both declarations and parameters, it should be `type * variable` (e.g. `char * data` or `struct sb * b`).
8. **Unary Operators:** NEVER put a space between unary operators (`&`, `*` for dereference, `!`, `++`, `--`) and their operands (e.g. `&variable`, `*pointer`, `!condition`, `i++`).
9. **Helper Functions:** Break out short helper functions instead of deep nested monolithic long bodies.
10. **Nested Conditions:** Avoid nested `if` if you can structure it into a more readable `if else if else`.
11. **Semantic Naming:** Strive for single, highly descriptive words for functions rather than generic "ActionObject" verb-noun pairs. Think about the *meaning* rather than the *action* (e.g., `successful()` instead of `handle_a()`, `otherwise()` instead of `handle_other()`).
12. **Helper Functions & Visibility:** Public interfaces (`.h`) should adhere strictly to `{concept}_{action}` (e.g. `notion_operation`). Small internal logic components should be marked `static` and optionally reverse their verb-noun order (e.g. `static void extended_action_something()`).
13. **Measurements & Counts:** Do not use `size` or `length`. If tracking raw memory capacity, use `bytes`. If tracking the number of elements in an array, use `count`.
14. **Declarations:** NEVER put multiple variable declarations on a single line. Each declaration must reside on its own line.
15. **Aesthetics:** Prefer `data` over `buffer`. Use `16 * 1024` instead of `16384`. Space after commas in function calls and definitions.

---

### Examples: DO and DON'T

#### 1. Naming & Function Signatures
**DO:**
```c
void * copy_buffer(void * data, size_t bytes);
void sort_items(struct item * array, size_t count);

// Spaces around asterisk
char * string_copy_pointer(char * destination, const char * source) { 
... 
}

void foo() {
    double elapsed = calculate(); // use clear names
}
```

**DON'T:**
```c
char* data; // Missing spaces
char *data; // Missing space before
```

#### 2. Types & Parameters
**DO:**
```c
void * data, size_t bytes
```

**DON'T:**
```c
void* ptr, size_t size
```

#### 3. Control Flow & Braces
**DO:**
```c
if (only_one) {
    do_a();
    do_b();
}

if (simple) { single(); }

if (branch) {
    first();
} else {
    second();
}
```

**DON'T:**
```c
if (multi) { stmt1; stmt2; } // Multi-statement must be multi-line

if (cond) { a(); } else { b(); } // If else exists, all must be multi-line
```

#### 4. Declarations
**DO:**
```c
int a;
int b;
mbedtls_ssl_context ssl;
mbedtls_ssl_config config;
```

**DON'T:**
```c
int a, b;
mbedtls_ssl_context ssl; mbedtls_ssl_config config;
```
