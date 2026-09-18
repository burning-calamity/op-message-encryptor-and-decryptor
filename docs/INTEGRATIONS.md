# Integrated companion projects

The cipher engine incorporates focused, dependency-free ideas and test data
from two companion repositories maintained by the same project owner:

## rotor-cracker

Source: <https://github.com/burning-calamity/rotor-cracker>

Integrated pieces:

- Enigma I–VIII and Beta/Gamma rotor wiring and turnover data.
- Wide and thin reflector wiring.
- Three- and four-rotor double-stepping behavior.
- A bounded starting-position search with optional crib filtering.

The complete rotor-cracker GUI, multiprocessing cracker, and its many machine
families remain in the companion project. This repository exposes a compact
M3/M4 implementation suitable for the shared registry, CLI, browser, and APK.

## unhasher

Source: <https://github.com/burning-calamity/unhasher>

Integrated pieces:

- FNV-1a 32-bit, MurmurHash3 x86-32, and CRC32C implementations.
- Digest-shape identification for the built-in hash catalogue.
- A deliberately bounded finite-candidate preimage search.

The search feature does not mathematically reverse cryptographic hashes. It
only compares candidates from the caller-provided finite character and length
space, and enforces a maximum attempt count.

## Keeping cipher frontends synchronized

`encripter.py` is the canonical Python cipher engine. The package core, Kivy
APK engine, and browser's base64-embedded Pyodide engine must contain those
same implementations and registry entries.

After changing a cipher, run:

```bash
python scripts/sync_cipher_engines.py
```

Windows Command Prompt users can run `sync_cipher_engines.bat` instead.

CI runs the command with `--check` and fails if any frontend is stale. The
OpenBoard Java keyboard and AutoHotkey keyboard remain independent native
frontends because they use different languages and platform-specific APIs;
their supported subsets are validated by their own build checks.
