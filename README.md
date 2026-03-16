# curly

curly is a minimalist, dependency-free HTTPS client built with Cosmopolitan Libc and MbedTLS. It compiles into a single fat binary that runs natively on Linux, macOS, Windows, FreeBSD, OpenBSD, and NetBSD.

## Test

### Windows (cmd/powershell)
```bash
curly.exe https://example.com
```

### macOS / Linux
```bash
./curly https://example.com
```

### Download cosmo.zip to /tmp
```bash
./curly https://cosmo.zip/pub/cosmocc/cosmocc.zip -o /tmp/cosmocc.zip
```

### List GitHub Models

```bash
curl -X GET "https://models.github.ai/catalog/models"
```

### Complex POST (Gemini API)
```bash
./curly -X POST https://generativelanguage.googleapis.com/v1beta/openai/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GEMINI_API_KEY" \
  -d '{"model":"models/gemma-3-1b-it","stream":false,"messages":[{"role":"user","content":"Hello"}]}'
```

**Expected Output:**

```json
{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"Hello there! How's your day going so far? 😊 \n\nIs there anything you’d like to chat about, or anything I can help you with?","role":"assistant"}}],"created":1773624851,"id":"E163acnyMfre_uMP26nN4AE","model":"models/gemma-3-1b-it","object":"chat.completion","usage":{"completion_tokens":34,"prompt_tokens":2,"total_tokens":36}}
```

## Actually Portable Executable

curly uses the Cosmopolitan toolchain to achieve its cross-platform "Actually Portable Executable" (APE) format.

1.  Toolchain: Downloads cosmocc and the Cosmopolitan SDK.
2.  TLS Support: Statically links mbedtls source files directly from the Cosmopolitan tree.
3.  Universal Binary: The resulting .exe is an APE binary. On Unix-like systems, it runs as a native ELF/Mach-O; on Windows, it runs as a native PE.

### Build

```bash
# Clone and build
git clone https://github.com/leok7v/curly.git
cd curly
make

# Clean up build artifacts but keep toolchain
make clean

# Full cleanup (removes toolchain and downloads)
make distclean
```

## CI/CD

The GitHub Actions workflow is optimized for efficiency:
- Manual Trigger: Build is only invoked manually via workflow_dispatch or on version tags (e.g., v1.0.0).
- Persistent Caching: The Cosmopolitan toolchain (approx. 0.5 GB) is cached by GitHub to ensure fast subsequent builds without re-downloading.
- Auto-Release: Tagged commits automatically generate a GitHub Release with pre-built binaries for all platforms.
