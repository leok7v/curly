# curly

curly is a minimalist, dependency-free HTTPS client built with Cosmopolitan Libc and MbedTLS. It compiles into a single fat binary that runs natively on Linux, macOS, Windows, FreeBSD, OpenBSD, and NetBSD.

## One-Line Test

Test the GitHub Models API directly from your terminal:

### Windows (cmd/powershell)
```bash
curly.exe https://example.com
```

### macOS / Linux
```bash
./curly https://example.com
```

## How it's Built

curly uses the Cosmopolitan toolchain to achieve its cross-platform "Actually Portable Executable" (APE) format.

1.  Toolchain: Downloads cosmocc and the Cosmopolitan SDK.
2.  TLS Support: Statically links mbedtls source files directly from the Cosmopolitan tree.
3.  Universal Binary: The resulting .exe is an APE binary. On Unix-like systems, it runs as a native ELF/Mach-O; on Windows, it runs as a native PE.

### Local Build Instructions

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
