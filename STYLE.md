**Code Style and Housekeeping Rules:**

1. **Maximum Line Width:** Strictly adhere to a maximum line width of 79 characters. 
2. **Obvious Comments:** Absolutely no comments stating the obvious.
3. **Empty Lines:** NO empty lines inside function bodies. Exactly one empty line between function definitions.
4. **Control Flow:** Single-entry, single-exit. Declare a result variable at the top, return it at the bottom. No early returns, no `continue`.
5. **Naming Conventions:** Use clear, unambiguous words. Avoid cryptic abbreviations. Prefer `data` over `buffer`.
6. **Braces:** Always use curly braces `{}`. 
    *   **Mandatory Single-Line:** `if (cond) { stmt; }` MUST be on a single line if there is no `else/else if` branch, it contains exactly one statement, and the result fits in 79 chars.
    *   **Prohibited Single-Line:** Any structure with an `else` branch MUST use multi-line blocks for all branches. Multi-statement blocks MUST be multi-line.
7. **Pointers & Types:** ALWAYS place spaces around the asterisk in declarations and parameters: `type * variable` (e.g. `char * data`).
8. **Unary Operators:** NEVER put a space between unary operators (`&`, `*` for dereference, `!`, `++`, `--`) and their operands (e.g. `&variable`, `*pointer`, `!condition`).
9. **Helper Functions:** Break out short helpers. Internal logic should be `static`.
10. **Measurements & Counts:** Use `bytes` for memory, `count` for elements.
11. **Declarations:** One variable per line.
12. **Aesthetics:** Use `16 * 1024` instead of `16384`. Space after commas in function arguments.

---

### Examples: DO and DON'T

#### 1. Condensing Simple Ifs
**DO:**
```c
if (failed) { ok = 0; }

if (mbedtls_ssl_handshake(&ssl) != 0) { ok = 0; }
```

**DON'T:**
```c
if (failed) {
    ok = 0;
}

if (cond) { a(); } else { b(); } // Prohibited: has else
```

#### 2. Pointers & Unary
**DO:**
```c
char * data = fetch(&state);
*pointer = '\0';
if (!condition) { ... }
```

**DON'T:**
```c
char *data; // Missing space before data
char * data = fetch(& state); // Extra space after &
```
