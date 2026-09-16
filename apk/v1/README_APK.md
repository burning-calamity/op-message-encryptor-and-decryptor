# APK v1 Build Notes

This folder is now an Android-oriented Kivy project wrapper around the cipher
engine in `encripter.py`.

## Files

- `main.py` — Kivy entrypoint used by Buildozer. It imports `encripter.py` and
  exposes the registry through a simple mobile UI.
- `encripter.py` — copied cipher engine/source module.
- `buildozer.spec` — Buildozer configuration for producing an Android APK.
- `requirements.txt` — Python dependency hint for local tooling.

## Build from Linux

```bash
cd apk/v1
python3 -m pip install --user buildozer
buildozer android debug
```

The debug APK should be produced under `apk/v1/bin/` if the Android SDK/NDK and
Buildozer prerequisites are installed correctly.

## Notes

The original desktop Tkinter GUI in `encripter.py` is not used by the APK. The
APK starts from `main.py`, which uses Kivy widgets instead.

## Mobile UI features

- Registry-driven cipher picker synchronized with the top-level `encripter.py`
  engine, including the latest classical/transposition additions such as route,
  columnar, Lorenz Toy, Quagmire V/VI, and Cistercian numeral helpers.
- Search box for quickly filtering the large cipher list by cipher name,
  parameter name, label, or default value.
- Category/group picker for narrowing the registry to common families such as
  Classical, Vigenere, Transposition, Morse/Symbol, Encoding, Checksums/Hash,
  Modern, and Fun transforms.
- Dynamic parameter fields generated from each `CipherEntry`.
- Encode/decode run mode plus Swap, Paste, Copy, Clear, Info, and Self-test
  actions.
- SmartGuess button that displays the top ranked candidates for unknown text.
- Analyze button with quick character, word, index-of-coincidence, and top-letter
  statistics for ciphertext inspection on mobile.
