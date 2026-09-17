# OpenBoard encryption keyboard

The [`openboard-encrypting`](../openboard-encrypting) directory is a Git
submodule pinned to the
[`burning-calamity/openboard-encrypting`](https://github.com/burning-calamity/openboard-encrypting)
repository. Keeping it as a submodule preserves its independent GPL-3.0 license
and history rather than copying the Android project's generated assets and
dictionaries into this Python package.

Clone this repository and initialize the keyboard in one command:

```bash
git clone --recurse-submodules https://github.com/burning-calamity/op-message-encryptor-and-decryptor.git
```

For an existing clone, initialize or refresh it with:

```bash
git submodule update --init --recursive
git submodule update --remote openboard-encrypting
```

Run the portable Python, shell-syntax, and Java cipher compilation checks:

```bash
./scripts/check_all.sh
```

On a machine with Android SDK components installed, include the full APK build
and Android lint pass:

```bash
./scripts/check_all.sh --android
```

The Android build uses the JDK version expected by the pinned OpenBoard Gradle
toolchain. CI provisions JDK 11 explicitly before running it.
