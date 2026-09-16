"""All The Ciphers Python library.

Import this package to encode, decode, guess, and brute-force many classical
ciphers and encodings.
"""
from __future__ import annotations

from .core import (
    CipherEntry,
    Param,
    BruteForce,
    SmartGuess,
    call_decode,
    call_encode,
    get_registry,
)

__version__ = "2.1.0"


def list_ciphers() -> list[str]:
    """Return all available cipher names."""
    return [entry.name for entry in get_registry()]


def get_cipher(name: str) -> CipherEntry:
    """Return a cipher registry entry by name, case-insensitive."""
    wanted = name.casefold()
    for entry in get_registry():
        if entry.name.casefold() == wanted:
            return entry
    raise ValueError(f"Unknown cipher: {name}")


def encode(cipher: str, text: str, **params: object) -> str:
    """Encode text with a named cipher.

    Example:
        encode("Caesar", "HELLO", shift=3)
    """
    return call_encode(cipher, text, {k: str(v) for k, v in params.items()})


def decode(cipher: str, text: str, **params: object) -> str:
    """Decode text with a named cipher.

    Example:
        decode("Caesar", "KHOOR", shift=3)
    """
    return call_decode(cipher, text, {k: str(v) for k, v in params.items()})


def smart_guess(text: str):
    """Return ranked SmartGuess candidates."""
    return SmartGuess(text)


def brute_force(text: str, families: list[str] | None = None):
    """Return ranked brute-force candidates."""
    return BruteForce(text, families)

