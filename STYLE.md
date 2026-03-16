**Code Style and Housekeeping Rules:**

1. **Maximum Line Width:** Strictly adhere to a maximum line width of 79 characters. This applies to everything: logic, string literals, and comments. Wrap long expressions or string literals as needed.
2. **Obvious Comments:** Absolutely no comments stating the obvious or explaining what the code is doing if the code is self-explanatory. Only add comments if there is a non-obvious "why" or complex design decision.
3. **Empty Lines:** NO empty lines are allowed inside function bodies (between statements). You must use exactly one single empty line between function definitions to separate them.
4. **Control Flow:** No early returns. Every function must follow the single-entry, single-exit principle. Declare a result variable at the top, mutate it, and return it at the very bottom. Never use `continue`. If possible, use smarter `for` loop conditions or extra state variables instead of `break`.
5. **Naming Conventions:** Use extremely compact and short variable names, especially in local scopes. Prefer abbreviations and single letters where context is clear (e.g., `sb`, `m`, `f`, `ptr`, `res`). Avoid multi-word identifiers if a shorter abbreviation works.
6. **Braces:** Always use curly braces `{}` for control flow boundaries (`if`, `else if`, `else`, `while`, `for`). A single-line block `if (cond) { stmt; }` is ONLY allowed for simple `if` statements that have no `else` or `else if` branch and contain exactly one statement. If any branch of a control structure exists beyond a single `if`, or if a block contains multiple statements, all branches and blocks must be multi-line.
7. **Pointers & Types:** Place the asterisk attached to the variable name with a space after the type, rather than attached to the type. (e.g. `char * d` or `const char * s`).
8. **Helper Functions:** Break out short helper functions instead of deep nested monolithic long bodies.
9. **Nested Conditions:** Avoid nested `if` if you can structure it into a more readable `if else if else`.
10. **Semantic Naming:** Strive for single, highly descriptive words for functions rather than generic "ActionObject" verb-noun pairs. Think about the *meaning* rather than the *action* (e.g., `successful()` instead of `handle_a()`, `otherwise()` instead of `handle_other()`).
11. **Helper Functions & Visibility:** Public interfaces (`.h`) should adhere strictly to `{concept}_{action}` (e.g. `notion_operation`). Small internal logic components should be marked `static` and optionally reverse their verb-noun order (e.g. `static void extended_action_something()`).
12. **Measurements & Counts:** Do not use `size` or `length`. If tracking raw memory capacity, use `bytes`. If tracking the number of elements in an array, use `count`.
13. **Abbreviation Tolerances & Pronounceability:** A short name is fine locally, but public APIs should use full, unambiguous words. Only severely abbreviate standard acronyms if they pass the "Pronounceability Test" (you can say them out loud without spelling them) or are universally understood domain terminology (e.g., `sse` for `server_side_events`).

---

### Examples: DO and DON'T

#### 1. Naming & Function Signatures
**DO:**
```c
// Use count / bytes to distinguish capacity measurements natively
void * copy_buffer(void * data, size_t bytes);
void sort_items(struct item * arr, size_t count);

// Public APIs employ fully spelled-out explicit vocabulary
char * string_copy_pointer(char * destination, const char * source) { 
... 
}

// Local internals can aggressively rely on acronyms / domain abbreviations
struct state {
    struct connection sse; // "server_side_events" is a mouthful, sse works
};

void foo() {
    int r = bar(); // local scope -> one letter abbreviations are great
}
```

**DON'T:**
```c
// Avoid ambiguous generic identifiers
void * process(void * data, size_t size); 
void * process(void * data, size_t len); 

// Short abbreviated names leaking into public boundary APIs
char * strcpy(char*dest, const char*src) {
}

// Obfuscated identifiers failing the pronounceability test
struct state {
    struct connection cnssv; // "cnssv" cannot be easily pronounced or guessed
};
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
if (b1) {
    do_something();
} else if (b2) {
    do_other_thing();
} else {
    fallback();
}
```

**DON'T:**
```c
if (b1) do_something();
else if (b2) do_other_thing();
else fallback();

// Or placing elses on the same line as closing braces:
if (b1) { } 
else if (b2) { } 
else { }
```

#### 4. Continuations, Breaks, and Smart Conditions
**DO:**
```c
int found = 0;
for (int i = 0; i < len && !found; i++) {
    if (match(i)) {
        found = 1;
    }
}
```

**DON'T:**
```c
for (int i = 0; i < len; i++) {
    if (skip(i)) {
        continue;
    }
    if (match(i)) {
        break;
    }
}
```

#### 5. Avoiding Deep Nesting & Semantic Naming
**DO:**
```c
if (a) {
    successful();
} else if (b) {
    instead();
} else {
    otherwise();
}
```

**DON'T:**
```c
if (a) {
    handle_a();
} else {
    if (b) {
        handle_b();
    } else {
        handle_other();
    }
}
```

#### 6. Commenting Logic
**DO:**
```c
if (special_case) { // this condition needs explaining
    process();
} else { // the explanation of else branch is necessary here
    fallback();
}
```

**DON'T:**
```c
// the following inline condition needs to be explained in length
if (special_case) {
    process();
// the explanation of else branch is necessary here
} else {
    fallback();
}
```

#### 7. Function Returns (Single Entry / Single Exit)
**DO:**
```c
int process_data(int * data) {
    int res = 0;
    if (data) {
        if (*data > 0) {
            res = 1;
        } else {
            res = -1;
        }
    }
    return res;
}
```

**DON'T:**
```c
int process_data(int * data) {
    if (!data) {
        return 0; // Don't use early returns
    }
    if (*data > 0) {
        return 1;
    }
    return -1;
}
```

#### 8. Internal Helpers (Reverse Verb-Noun)
**DO:**
```c
// notion.h
void notion_operation();

// notion.c
#include "notion.h"
#include "something.h"

// Note the reversed verbose-noun action vs concept declaration
static void extended_action_something() {
   something_action();
}

void notion_operation() {
   extended_action_something();
}
```

**DON'T:**
```c
// notion.h
void notion_operation();

// notion.c
#include "notion.h"
#include "something.h"

// Avoid leaking standard namespace formats internally if unnecessary 
void something_extended_action() {
   something_action();
}

void notion_operation() {
   something_extended_action();
}
```

#### 9. Empty Lines & Function Spacing
**DO:**
```c
void foo1() {
   bar1();
   bar2();
}

void foo2() {
   bar1();
   bar2();
}
```

**DON'T:**
```c
void foo1() {
   bar1(); // don't insert empty lines anywhere inside function bodies

   bar2();
}

void foo2() { // but do separate functions with exactly ONE empty line
   bar1();

   // next line calls function bar2() - DO NOT comment the obvious
   bar2();
}
```
