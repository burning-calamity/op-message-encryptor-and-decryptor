#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
All-The-Ciphers — COMPLETE + SmartGuess + BruteForce (Part 1)
This is a single-file toolkit with:
- Classical & polygraphic ciphers
- Encodings & novelty systems
- Tagged formats for reliable round-trips
- Smart English scoring
- SmartGuess dispatcher (detect + decode)
- BruteForce (ranked) for common key spaces

Part 1 includes all cipher/codec implementations and the new
SmartGuess/BruteForce cores. Part 2 will include GUI wiring, CLI,
and extended tests (keep this file name the same).
"""

from __future__ import annotations

import base64
import binascii
import html
import hashlib
import gzip
import hmac
import importlib
import importlib.util
import json
import math
import quopri
import random
import re
import string
import textwrap
import unicodedata
import urllib.parse
import zlib
from typing import List, Tuple, Dict, Iterable, Optional, Iterator

# GUI & CLI come in Part 2
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception:
    class _MissingTkWidget:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("Tkinter is not available in this Python environment")

    class _MissingTkModule:
        END = "end"
        WORD = "word"
        BOTH = "both"
        LEFT = "left"
        RIGHT = "right"
        X = "x"
        Y = "y"
        VERTICAL = "vertical"
        HORIZONTAL = "horizontal"

        def __getattr__(self, _name):
            return _MissingTkWidget

    tk = _MissingTkModule()
    ttk = _MissingTkModule()
    messagebox = _MissingTkModule()

# =============================================================================
# Core utilities
# =============================================================================

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_SET = set(ALPHA)
ALNUM = string.ascii_uppercase + string.digits

def to_upper(s: str) -> str:
    return s.upper()

def only_alpha(s: str, keep_spaces: bool = False) -> str:
    s = to_upper(s)
    out = []
    for ch in s:
        if ch in ALPHA_SET:
            out.append(ch)
        elif keep_spaces and ch.isspace():
            out.append(ch)
    return "".join(out)

def alpha_num(s: str, keep_spaces: bool = False) -> str:
    s = to_upper(s)
    out = []
    for ch in s:
        if ch in ALPHA or ch.isdigit():
            out.append(ch)
        elif keep_spaces and ch.isspace():
            out.append(ch)
    return "".join(out)

def chunk(s: str, n: int) -> List[str]:
    return [s[i:i+n] for i in range(0, len(s), n)]

def mod_inv(a: int, m: int) -> int:
    a = a % m
    if a == 0:
        raise ValueError("No inverse for 0")
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q*new_t
        r, new_r = new_r, r - q*new_r
    if r != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return t % m

def key_to_shifts(key: str, alphabet: str = ALPHA) -> List[int]:
    key = only_alpha(key)
    return [alphabet.index(k) for k in key]

def repeat_key_shifts(text_len: int, shifts: List[int]) -> List[int]:
    if not shifts:
        return [0] * text_len
    reps = (text_len + len(shifts) - 1) // len(shifts)
    return (shifts * reps)[:text_len]

def rotate_alpha_from_keyword(keyword: str, alphabet: str = ALPHA) -> str:
    seen = set()
    out = []
    for ch in only_alpha(keyword):
        if ch not in seen:
            out.append(ch); seen.add(ch)
    for ch in alphabet:
        if ch not in seen:
            out.append(ch)
    return "".join(out)

def numeric_order_from_keyword(keyword: str) -> List[int]:
    kw = to_upper(keyword)
    pairs = [(ch, i) for i, ch in enumerate(kw)]
    pairs_sorted = sorted(pairs, key=lambda x: (x[0], x[1]))
    rank = [0] * len(kw)
    for r, (_, i) in enumerate(pairs_sorted):
        rank[i] = r
    return rank

def apply_monoalpha(text: str, src_alpha: str, dst_alpha: str, keep_others: bool = False) -> str:
    table = {s: d for s, d in zip(src_alpha, dst_alpha)}
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in table:
            mapped = table[cu]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

# =============================================================================
# Classical shifts / substitutions
# =============================================================================

def Caesar_encode(text: str, shift: int | str = 3, keep_others: bool = True) -> str:
    if isinstance(shift, str): shift = int(shift.strip())
    out = []
    for ch in text:
        if ch.upper() in ALPHA_SET:
            idx = ALPHA.index(ch.upper())
            new = ALPHA[(idx + shift) % 26]
            out.append(new if ch.isupper() else new.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Caesar_decode(text: str, shift: int | str = 3, keep_others: bool = True) -> str:
    if isinstance(shift, str): shift = int(shift.strip())
    return Caesar_encode(text, -shift, keep_others=keep_others)

def ROT13_encode(text: str) -> str:
    return Caesar_encode(text, 13, keep_others=True)

def ROT13_decode(text: str) -> str:
    return Caesar_encode(text, -13, keep_others=True)

def ROT47_encode(text: str) -> str:
    out = []
    for ch in text:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)

def ROT47_decode(text: str) -> str:
    out = []
    for ch in text:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 - 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)

def Atbash_encode(text: str, keep_others: bool = True) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            new = ALPHA[25 - ALPHA.index(cu)]
            out.append(new if ch.isupper() else new.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Atbash_decode(text: str, keep_others: bool = True) -> str:
    return Atbash_encode(text, keep_others=keep_others)

def Affine_encode(text: str, a: int | str = 5, b: int | str = 8, m: int | str = 26, keep_others: bool = True) -> str:
    a = int(a); b = int(b); m = int(m)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            x = ALPHA.index(cu)
            y = (a * x + b) % m
            new = ALPHA[y]
            out.append(new if ch.isupper() else new.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Affine_decode(text: str, a: int | str = 5, b: int | str = 8, m: int | str = 26, keep_others: bool = True) -> str:
    a = int(a); b = int(b); m = int(m)
    a_inv = mod_inv(a, m)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            y = ALPHA.index(cu)
            x = (a_inv * (y - b)) % m
            new = ALPHA[x]
            out.append(new if ch.isupper() else new.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def KeywordShift_encode(text: str, keyword: str = "CIPHER", keep_others: bool = True) -> str:
    dst = rotate_alpha_from_keyword(keyword)
    return apply_monoalpha(text, ALPHA, dst, keep_others=keep_others)

def KeywordShift_decode(text: str, keyword: str = "CIPHER", keep_others: bool = True) -> str:
    dst = rotate_alpha_from_keyword(keyword)
    return apply_monoalpha(text, dst, ALPHA, keep_others=keep_others)

def KeywordSubstitute_encode(text: str, keyword: str = "CIPHER", keep_others: bool = True) -> str:
    return KeywordShift_encode(text, keyword, keep_others)

def KeywordSubstitute_decode(text: str, keyword: str = "CIPHER", keep_others: bool = True) -> str:
    return KeywordShift_decode(text, keyword, keep_others)


def _normalized_alphabet(alphabet: str) -> str:
    seen = []
    for ch in alphabet:
        if ch not in seen:
            seen.append(ch)
    if len(seen) < 2:
        raise ValueError("alphabet must contain at least two unique characters")
    return "".join(seen)

def CaesarCustom_encode(text: str, shift: int | str = 3, alphabet: str = ALPHA, keep_others: bool = True) -> str:
    alpha = _normalized_alphabet(alphabet or ALPHA)
    shift = int(shift)
    out = []
    for ch in text:
        target = ch if ch in alpha else ch.upper() if ch.upper() in alpha else None
        if target is not None:
            mapped = alpha[(alpha.index(target) + shift) % len(alpha)]
            out.append(mapped if ch == target or not ch.islower() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def CaesarCustom_decode(text: str, shift: int | str = 3, alphabet: str = ALPHA, keep_others: bool = True) -> str:
    return CaesarCustom_encode(text, -int(shift), alphabet, keep_others)

def CaesarProgressive_encode(text: str, start: int | str = 0, step: int | str = 1, keep_others: bool = True) -> str:
    start = int(start)
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = start + pos * step
            mapped = ALPHA[(ALPHA.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def CaesarProgressive_decode(text: str, start: int | str = 0, step: int | str = 1, keep_others: bool = True) -> str:
    start = int(start)
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = start + pos * step
            mapped = ALPHA[(ALPHA.index(cu) - shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def KeyedCaesar_encode(text: str, keyword: str = "CIPHER", shift: int | str = 3, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    return CaesarCustom_encode(text, shift, alpha, keep_others)

def KeyedCaesar_decode(text: str, keyword: str = "CIPHER", shift: int | str = 3, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    return CaesarCustom_decode(text, shift, alpha, keep_others)

_QWERTY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_DVORAK_UPPER = "AXJEUIDCHTNMBRLPOYGKQFVSZW"
_DVORAK = _DVORAK_UPPER + _DVORAK_UPPER.lower()
_DVORAK_ENC = str.maketrans(_QWERTY, _DVORAK)
_DVORAK_DEC = str.maketrans(_DVORAK, _QWERTY)

def DvorakKeyboard_encode(text: str) -> str:
    return text.translate(_DVORAK_ENC)

def DvorakKeyboard_decode(text: str) -> str:
    return text.translate(_DVORAK_DEC)

def Kamasutra_encode(text: str, key: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> str:
    letters = only_alpha(key) or ALPHA
    letters = "".join(dict.fromkeys(letters + ALPHA))[:26]
    half = len(letters) // 2
    trans = {}
    for a, b in zip(letters[:half], letters[half:half*2]):
        trans[a] = b
        trans[b] = a
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in trans:
            mapped = trans[cu]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)

def Kamasutra_decode(text: str, key: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> str:
    return Kamasutra_encode(text, key)

def Trithemius_encode(text: str, start: int | str = 0, keep_others: bool = True) -> str:
    return CaesarProgressive_encode(text, int(start), 1, keep_others)

def Trithemius_decode(text: str, start: int | str = 0, keep_others: bool = True) -> str:
    return CaesarProgressive_decode(text, int(start), 1, keep_others)

def VariantBeaufort_encode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    shifts = key_to_shifts(key)
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = shifts[ki % len(shifts)] if shifts else 0
            c = (ALPHA.index(cu) + k) % 26
            out.append(ALPHA[c] if ch.isupper() else ALPHA[c].lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VariantBeaufort_decode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    shifts = key_to_shifts(key)
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = shifts[ki % len(shifts)] if shifts else 0
            p = (ALPHA.index(cu) - k) % 26
            out.append(ALPHA[p] if ch.isupper() else ALPHA[p].lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def WordCaesar_encode(text: str, shift: int | str = 1) -> str:
    shift = int(shift)
    words = text.split()
    if not words:
        return ""
    return " ".join(words[(i - shift) % len(words)] for i in range(len(words)))

def WordCaesar_decode(text: str, shift: int | str = 1) -> str:
    return WordCaesar_encode(text, -int(shift))


def LatinReverseCustom_encode(text: str, alphabet: str = ALPHA, keep_others: bool = True) -> str:
    alpha = _normalized_alphabet(alphabet or ALPHA)
    rev = alpha[::-1]
    return CaesarCustom_encode(apply_monoalpha(text, alpha, rev, keep_others=True), 0, alpha, keep_others)

def LatinReverseCustom_decode(text: str, alphabet: str = ALPHA, keep_others: bool = True) -> str:
    return LatinReverseCustom_encode(text, alphabet, keep_others)

def KeyedAlphabetArbitrary_encode(text: str, source: str = ALPHA, target: str = "QWERTYUIOPASDFGHJKLZXCVBNM", keep_others: bool = True) -> str:
    src = _normalized_alphabet(source or ALPHA)
    dst = _normalized_alphabet(target or ALPHA)
    if len(src) != len(dst):
        return "Err:source and target alphabets must have the same unique length"
    return apply_monoalpha(text, src, dst, keep_others)

def KeyedAlphabetArbitrary_decode(text: str, source: str = ALPHA, target: str = "QWERTYUIOPASDFGHJKLZXCVBNM", keep_others: bool = True) -> str:
    src = _normalized_alphabet(source or ALPHA)
    dst = _normalized_alphabet(target or ALPHA)
    if len(src) != len(dst):
        return "Err:source and target alphabets must have the same unique length"
    return apply_monoalpha(text, dst, src, keep_others)

def KeyedCaesarProgressive_encode(text: str, keyword: str = "CIPHER", start: int | str = 0, step: int | str = 1, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    start = int(start)
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            mapped = alpha[(alpha.index(cu) + start + pos * step) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def KeyedCaesarProgressive_decode(text: str, keyword: str = "CIPHER", start: int | str = 0, step: int | str = 1, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    start = int(start)
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            mapped = alpha[(alpha.index(cu) - start - pos * step) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VigenereCustom_encode(text: str, key: str = "LEMON", alphabet: str = ALPHA, keep_others: bool = True) -> str:
    alpha = _normalized_alphabet(alphabet or ALPHA)
    key_vals = [alpha.index(ch) for ch in key if ch in alpha]
    if not key_vals:
        return "Err:key must contain at least one alphabet character"
    out = []
    ki = 0
    for ch in text:
        target = ch if ch in alpha else ch.upper() if ch.upper() in alpha else None
        if target is not None:
            mapped = alpha[(alpha.index(target) + key_vals[ki % len(key_vals)]) % len(alpha)]
            out.append(mapped if ch == target or not ch.islower() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VigenereCustom_decode(text: str, key: str = "LEMON", alphabet: str = ALPHA, keep_others: bool = True) -> str:
    alpha = _normalized_alphabet(alphabet or ALPHA)
    key_vals = [alpha.index(ch) for ch in key if ch in alpha]
    if not key_vals:
        return "Err:key must contain at least one alphabet character"
    out = []
    ki = 0
    for ch in text:
        target = ch if ch in alpha else ch.upper() if ch.upper() in alpha else None
        if target is not None:
            mapped = alpha[(alpha.index(target) - key_vals[ki % len(key_vals)]) % len(alpha)]
            out.append(mapped if ch == target or not ch.islower() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VigenereProgressive_encode(text: str, key: str = "LEMON", step: int | str = 1, keep_others: bool = True) -> str:
    step = int(step)
    shifts = key_to_shifts(key)
    if not shifts:
        return "Err:key must contain letters"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = shifts[ki % len(shifts)] + ki * step
            mapped = ALPHA[(ALPHA.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VigenereProgressive_decode(text: str, key: str = "LEMON", step: int | str = 1, keep_others: bool = True) -> str:
    step = int(step)
    shifts = key_to_shifts(key)
    if not shifts:
        return "Err:key must contain letters"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = shifts[ki % len(shifts)] + ki * step
            mapped = ALPHA[(ALPHA.index(cu) - shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def _parse_word_map(mapping: str) -> Dict[str, str]:
    out = {}
    for part in mapping.replace(";", ",").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out

def WordSubstitution_encode(text: str, mapping: str = "hello=hola,world=mundo") -> str:
    table = _parse_word_map(mapping)
    return " ".join(table.get(word.lower(), word) for word in text.split())

def WordSubstitution_decode(text: str, mapping: str = "hello=hola,world=mundo") -> str:
    table = {v.lower(): k for k, v in _parse_word_map(mapping).items()}
    return " ".join(table.get(word.lower(), word) for word in text.split())

def CodebookSubstitution_encode(text: str, codebook: str = "attack=17,dawn=42") -> str:
    table = _parse_word_map(codebook)
    return " ".join(table.get(word.lower(), word) for word in text.split())

def CodebookSubstitution_decode(text: str, codebook: str = "attack=17,dawn=42") -> str:
    table = {v.lower(): k for k, v in _parse_word_map(codebook).items()}
    return " ".join(table.get(word.lower(), word) for word in text.split())


_BOOK_DEFAULT = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima "
    "mike november oscar papa quebec romeo sierra tango uniform victor whiskey "
    "xray yankee zulu"
)

def _book_words(book: str) -> List[str]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9'-]*", book or _BOOK_DEFAULT)
    return words or re.findall(r"[A-Za-z][A-Za-z0-9'-]*", _BOOK_DEFAULT)

def BookCipher_encode(text: str, book: str = _BOOK_DEFAULT, sep: str = "-") -> str:
    words = _book_words(book)
    by_initial: Dict[str, List[int]] = {}
    for i, word in enumerate(words, 1):
        by_initial.setdefault(word[0].upper(), []).append(i)
    counters = {ch: 0 for ch in ALPHA}
    out = []
    for ch in only_alpha(text):
        choices = by_initial.get(ch)
        if not choices:
            out.append("0" + sep + ch)
            continue
        idx = counters[ch] % len(choices)
        counters[ch] += 1
        out.append(str(choices[idx]))
    return " ".join(out)

def BookCipher_decode(text: str, book: str = _BOOK_DEFAULT, sep: str = "-") -> str:
    words = _book_words(book)
    out = []
    for token in re.findall(r"0\W*[A-Za-z]|\d+", text):
        if token.startswith("0") and re.search(r"[A-Za-z]", token):
            out.append(re.search(r"[A-Za-z]", token).group(0).upper())
            continue
        n = int(re.search(r"\d+", token).group(0))
        if 1 <= n <= len(words):
            out.append(words[n-1][0].upper())
    return "".join(out)

def DictionaryCode_encode(text: str, dictionary: str = _BOOK_DEFAULT, sep: str = ".") -> str:
    words = _book_words(dictionary)
    by_letter: Dict[str, List[Tuple[int, int]]] = {}
    for wi, word in enumerate(words, 1):
        for ci, ch in enumerate(word.upper(), 1):
            if ch in ALPHA_SET:
                by_letter.setdefault(ch, []).append((wi, ci))
    counters = {ch: 0 for ch in ALPHA}
    out = []
    for ch in only_alpha(text):
        choices = by_letter.get(ch)
        if not choices:
            out.append("0" + sep + ch)
            continue
        wi, ci = choices[counters[ch] % len(choices)]
        counters[ch] += 1
        out.append(f"{wi}{sep}{ci}")
    return " ".join(out)

def DictionaryCode_decode(text: str, dictionary: str = _BOOK_DEFAULT, sep: str = ".") -> str:
    words = _book_words(dictionary)
    out = []
    for token in text.split():
        nums = re.findall(r"\d+", token)
        if len(nums) >= 2:
            wi, ci = int(nums[0]), int(nums[1])
            if 1 <= wi <= len(words) and 1 <= ci <= len(words[wi-1]):
                ch = words[wi-1][ci-1].upper()
                if ch in ALPHA_SET:
                    out.append(ch)
        elif token.startswith("0") and re.search(r"[A-Za-z]", token):
            out.append(re.search(r"[A-Za-z]", token).group(0).upper())
    return "".join(out)

def _book_pages(book: str) -> List[List[List[str]]]:
    source = book or _BOOK_DEFAULT
    pages = []
    for page in source.split("\f"):
        lines = []
        for line in page.splitlines() or [page]:
            words = re.findall(r"[A-Za-z0-9'-]+", line)
            if words:
                lines.append(words)
        if lines:
            pages.append(lines)
    if not pages:
        pages = [[_book_words(_BOOK_DEFAULT)]]
    return pages

def PageLineWordLetter_encode(text: str, book: str = _BOOK_DEFAULT, sep: str = ".") -> str:
    pages = _book_pages(book)
    index: Dict[str, List[Tuple[int, int, int, int]]] = {}
    for pi, page in enumerate(pages, 1):
        for li, line in enumerate(page, 1):
            for wi, word in enumerate(line, 1):
                for ci, ch in enumerate(word.upper(), 1):
                    if ch in ALPHA_SET:
                        index.setdefault(ch, []).append((pi, li, wi, ci))
    counters = {ch: 0 for ch in ALPHA}
    out = []
    for ch in only_alpha(text):
        choices = index.get(ch)
        if not choices:
            out.append("0" + sep + ch)
            continue
        coord = choices[counters[ch] % len(choices)]
        counters[ch] += 1
        out.append(sep.join(str(n) for n in coord))
    return " ".join(out)

def PageLineWordLetter_decode(text: str, book: str = _BOOK_DEFAULT, sep: str = ".") -> str:
    pages = _book_pages(book)
    out = []
    for token in text.split():
        nums = re.findall(r"\d+", token)
        if len(nums) >= 4:
            pi, li, wi, ci = (int(n) for n in nums[:4])
            try:
                ch = pages[pi-1][li-1][wi-1][ci-1].upper()
                if ch in ALPHA_SET:
                    out.append(ch)
            except Exception:
                continue
        elif token.startswith("0") and re.search(r"[A-Za-z]", token):
            out.append(re.search(r"[A-Za-z]", token).group(0).upper())
    return "".join(out)


def DellaPortaDisk_encode(text: str, keyword: str = "CIPHER", shift: int | str = 0, keep_others: bool = True) -> str:
    disk = rotate_alpha_from_keyword(keyword)
    shift = int(shift)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            mapped = disk[(ALPHA.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def DellaPortaDisk_decode(text: str, keyword: str = "CIPHER", shift: int | str = 0, keep_others: bool = True) -> str:
    disk = rotate_alpha_from_keyword(keyword)
    shift = int(shift)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in disk:
            mapped = ALPHA[(disk.index(cu) - shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def WolseleyDisk_encode(text: str, keyword: str = "WOLSELEY", shift: int | str = 0, keep_others: bool = True) -> str:
    disk = rotate_alpha_from_keyword(keyword)
    shift = int(shift)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            mapped = disk[(25 - ALPHA.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def WolseleyDisk_decode(text: str, keyword: str = "WOLSELEY", shift: int | str = 0, keep_others: bool = True) -> str:
    disk = rotate_alpha_from_keyword(keyword)
    shift = int(shift)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in disk:
            mapped = ALPHA[(25 - ((disk.index(cu) - shift) % 26)) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

_DORABELLA_ALPHA = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
_DORABELLA_SYMBOLS = [
    "◜", "◠", "◝", "◞", "◡", "◟", "△", "▷",
    "▽", "◁", "◇", "○", "□", "●", "■", "▲",
    "▶", "▼", "◀", "◆", "◎", "◉", "◌", "◍", "◐",
]
_DORABELLA_ENC = dict(zip(_DORABELLA_ALPHA, _DORABELLA_SYMBOLS))
_DORABELLA_DEC = {v: k for k, v in _DORABELLA_ENC.items()}

def Dorabella_encode(text: str, sep: str = " ") -> str:
    tokens = []
    for ch in text:
        cu = ch.upper().replace("J", "I")
        if cu in _DORABELLA_ENC:
            tokens.append(_DORABELLA_ENC[cu])
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return sep.join(tokens) if sep else "".join(tokens)

def Dorabella_decode(text: str, sep: str = " ") -> str:
    out = []
    if sep:
        tokens = text.split(sep)
        for tok in tokens:
            if tok == "/":
                out.append(" ")
            else:
                out.append(_DORABELLA_DEC.get(tok, tok))
        return "".join(out)
    for ch in text:
        if ch == "/":
            out.append(" ")
        else:
            out.append(_DORABELLA_DEC.get(ch, ch))
    return "".join(out)

_GOLDBUG_SYMBOLS = [
    "5", "†", "8", "1", "0", "3", "4", "6", "*", "9", "(", ")", ";",
    "?", "¶", "]", "[", "$", "7", ":", "2", "#", "-", ".", "!",
]
_GOLDBUG_ENC = dict(zip(ALPHA, _GOLDBUG_SYMBOLS))
_GOLDBUG_DEC = {v: k for k, v in _GOLDBUG_ENC.items()}

def GoldBug_encode(text: str, sep: str = " ") -> str:
    """Edgar Allan Poe Gold-Bug style monoalphabetic symbol substitution."""
    tokens = []
    for ch in text:
        cu = ch.upper()
        if cu in _GOLDBUG_ENC:
            tokens.append(_GOLDBUG_ENC[cu])
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return sep.join(tokens) if sep else "".join(tokens)

def GoldBug_decode(text: str, sep: str = " ") -> str:
    out = []
    tokens = text.split(sep) if sep else list(text)
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        else:
            out.append(_GOLDBUG_DEC.get(tok, tok))
    return "".join(out)

_LITERARY_DANCING_MEN_SYMBOLS = [
    "𐂀", "𐂁", "𐂂", "𐂃", "𐂄", "𐂅", "𐂆", "𐂇", "𐂈", "𐂉", "𐂊", "𐂋", "𐂌",
    "𐂍", "𐂎", "𐂏", "𐂐", "𐂑", "𐂒", "𐂓", "𐂔", "𐂕", "𐂖", "𐂗", "𐂘", "𐂙",
]
_LITERARY_DANCING_MEN_ENC = dict(zip(ALPHA, _LITERARY_DANCING_MEN_SYMBOLS))
_LITERARY_DANCING_MEN_DEC = {v: k for k, v in _LITERARY_DANCING_MEN_ENC.items()}

def DancingMenTokenized_encode(text: str, sep: str = " ") -> str:
    """Sherlock Holmes Dancing Men style glyph substitution."""
    tokens = []
    for ch in text:
        cu = ch.upper()
        if cu in _LITERARY_DANCING_MEN_ENC:
            tokens.append(_LITERARY_DANCING_MEN_ENC[cu])
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return sep.join(tokens) if sep else "".join(tokens)

def DancingMenTokenized_decode(text: str, sep: str = " ") -> str:
    out = []
    tokens = text.split(sep) if sep else list(text)
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        else:
            out.append(_LITERARY_DANCING_MEN_DEC.get(tok, tok))
    return "".join(out)

_MARY_WORD_CODES = {
    "QUEEN": "900", "KING": "901", "SCOTLAND": "902", "ENGLAND": "903",
    "FRANCE": "904", "LETTER": "905", "MESSENGER": "906", "PLOT": "907",
    "PRISON": "908", "HELP": "909",
}
_MARY_WORD_DEC = {v: k for k, v in _MARY_WORD_CODES.items()}

def MaryQueenScots_encode(text: str, sep: str = " ") -> str:
    """Toy nomenclator inspired by Mary Queen of Scots ciphers.

    Common words become three-digit code groups; remaining letters use
    two-digit alphabet numbers.
    """
    tokens = []
    for word in re.findall(r"[A-Za-z]+|[^A-Za-z]+", text):
        up = word.upper()
        if up in _MARY_WORD_CODES:
            tokens.append(_MARY_WORD_CODES[up])
        elif word.isalpha():
            tokens.extend(f"{ALPHA.index(ch) + 1:02d}" for ch in up)
        else:
            for ch in word:
                if ch.isspace():
                    tokens.append("/")
                elif ch.strip():
                    tokens.append(ch)
    return sep.join(tokens) if sep else "".join(tokens)

def MaryQueenScots_decode(text: str, sep: str = " ") -> str:
    tokens = text.split(sep) if sep else re.findall(r"9\d\d|\d\d|.", text)
    out = []
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        elif tok in _MARY_WORD_DEC:
            out.append(_MARY_WORD_DEC[tok])
        elif tok.isdigit() and len(tok) == 2 and 1 <= int(tok) <= 26:
            out.append(ALPHA[int(tok) - 1])
        else:
            out.append(tok)
    return "".join(out)

def SLIDEX_encode(text: str, key: str = "SLIDEX", row_labels: str = "12345", col_labels: str = "12345", sep: str = " ") -> str:
    _, pos, _rev = _key_square_5(key)
    rows = ((row_labels or "") + "12345")[:5]
    cols = ((col_labels or "") + "12345")[:5]
    out = []
    for ch in only_alpha(text).replace("J", "I"):
        r, c = pos[ch]
        out.append(rows[r] + cols[c])
    return sep.join(out) if sep else "".join(out)

def SLIDEX_decode(text: str, key: str = "SLIDEX", row_labels: str = "12345", col_labels: str = "12345", sep: str = " ") -> str:
    _sq, _pos, rev = _key_square_5(key)
    rows = ((row_labels or "") + "12345")[:5]
    cols = ((col_labels or "") + "12345")[:5]
    tokens = text.split(sep) if sep else re.findall(r"..", re.sub(r"\s+", "", text))
    out = []
    for tok in tokens:
        if len(tok) < 2:
            continue
        try:
            out.append(rev[(rows.index(tok[0]), cols.index(tok[1]))])
        except ValueError:
            continue
    return "".join(out).lower()

def AlbertiDisk_encode(text: str, outer: str = ALPHA, inner_key: str = "CIPHER", period: int | str = 5, step: int | str = 1, keep_others: bool = True) -> str:
    outer_alpha = _normalized_alphabet(outer or ALPHA)
    inner_alpha = rotate_alpha_from_keyword(inner_key)
    period = max(1, int(period))
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in outer_alpha:
            shift = (pos // period) * step
            shifted_inner = inner_alpha[shift % 26:] + inner_alpha[:shift % 26]
            mapped = shifted_inner[outer_alpha.index(cu)]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def AlbertiDisk_decode(text: str, outer: str = ALPHA, inner_key: str = "CIPHER", period: int | str = 5, step: int | str = 1, keep_others: bool = True) -> str:
    outer_alpha = _normalized_alphabet(outer or ALPHA)
    inner_alpha = rotate_alpha_from_keyword(inner_key)
    period = max(1, int(period))
    step = int(step)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        shift = (pos // period) * step
        shifted_inner = inner_alpha[shift % 26:] + inner_alpha[:shift % 26]
        if cu in shifted_inner:
            mapped = outer_alpha[shifted_inner.index(cu)]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def WheatstoneCryptograph_encode(text: str, keyword: str = "WHEATSTONE", indicator: str = "A", keep_others: bool = True) -> str:
    plain = ALPHA
    cipher = _rotate_alpha_to_indicator(rotate_alpha_from_keyword(keyword), indicator)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in plain:
            shifted = cipher[pos % 26:] + cipher[:pos % 26]
            mapped = shifted[plain.index(cu)]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def WheatstoneCryptograph_decode(text: str, keyword: str = "WHEATSTONE", indicator: str = "A", keep_others: bool = True) -> str:
    plain = ALPHA
    cipher = _rotate_alpha_to_indicator(rotate_alpha_from_keyword(keyword), indicator)
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        shifted = cipher[pos % 26:] + cipher[:pos % 26]
        if cu in shifted:
            mapped = plain[shifted.index(cu)]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Condi_encode(text: str, keyword: str = "CIPHER", start: int | str = 0, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    shift = int(start) % 26
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            pidx = alpha.index(cu)
            mapped = alpha[(pidx + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            shift = (pidx + 1) % 26
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Condi_decode(text: str, keyword: str = "CIPHER", start: int | str = 0, keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    shift = int(start) % 26
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            pidx = (alpha.index(cu) - shift) % 26
            mapped = alpha[pidx]
            out.append(mapped if ch.isupper() else mapped.lower())
            shift = (pidx + 1) % 26
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Ragbaby_encode(text: str, keyword: str = "RAGBABY", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    out = []
    word_no = 1
    char_no = 0
    in_word = False
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            if not in_word:
                in_word = True
                char_no = 0
            char_no += 1
            shift = word_no + char_no
            mapped = alpha[(alpha.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
            if ch.isspace() and in_word:
                word_no += 1
                in_word = False
    return "".join(out)

def Ragbaby_decode(text: str, keyword: str = "RAGBABY", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(keyword)
    out = []
    word_no = 1
    char_no = 0
    in_word = False
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            if not in_word:
                in_word = True
                char_no = 0
            char_no += 1
            shift = word_no + char_no
            mapped = alpha[(alpha.index(cu) - shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
            if ch.isspace() and in_word:
                word_no += 1
                in_word = False
    return "".join(out)

def StraddlingCheckerboard_encode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: str = "3,7") -> str:
    return SCB_encode(text, keyword, _parse_rowdigits(rowdigits))

def StraddlingCheckerboard_decode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: str = "3,7") -> str:
    return SCB_decode(text, keyword, _parse_rowdigits(rowdigits))

def MonomeDinome_encode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: str = "2,6") -> str:
    return SCB_encode(text, keyword, _parse_rowdigits(rowdigits))

def MonomeDinome_decode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: str = "2,6") -> str:
    return SCB_decode(text, keyword, _parse_rowdigits(rowdigits))


def _chaocipher_step(left: str, right: str, plain_ch: str | None = None, cipher_ch: str | None = None) -> Tuple[str, str]:
    if plain_ch is None and cipher_ch is None:
        return left, right
    cidx = left.index(cipher_ch) if cipher_ch is not None else right.index(plain_ch)
    pidx = right.index(plain_ch) if plain_ch is not None else left.index(cipher_ch)
    left = left[cidx:] + left[:cidx]
    right = right[pidx:] + right[:pidx]
    left = left[0] + left[2:14] + left[1] + left[14:]
    right = right[0:2] + right[3:14] + right[2] + right[14:]
    return left, right


def _chaocipher_alphabets(left: str, right: str) -> Tuple[str, str]:
    lalpha = _normalized_alphabet(left or "HXUCZVAMDSLKPEFJRIGTWOBNYQ")
    ralpha = _normalized_alphabet(right or "PTLNBQDEOYSFAVZKGJRIHWXUMC")
    if len(lalpha) != 26 or len(ralpha) != 26:
        raise ValueError("Chaocipher alphabets must contain 26 unique letters")
    return lalpha, ralpha


def Chaocipher_encode(text: str, left: str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ", right: str = "PTLNBQDEOYSFAVZKGJRIHWXUMC", keep_others: bool = True) -> str:
    try:
        lalpha, ralpha = _chaocipher_alphabets(left, right)
    except ValueError as e:
        return f"Err:{e}"
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            idx = ralpha.index(cu)
            mapped = lalpha[idx]
            out.append(mapped if ch.isupper() else mapped.lower())
            lalpha, ralpha = _chaocipher_step(lalpha, ralpha, plain_ch=cu, cipher_ch=mapped)
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def Chaocipher_decode(text: str, left: str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ", right: str = "PTLNBQDEOYSFAVZKGJRIHWXUMC", keep_others: bool = True) -> str:
    try:
        lalpha, ralpha = _chaocipher_alphabets(left, right)
    except ValueError as e:
        return f"Err:{e}"
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            idx = lalpha.index(cu)
            mapped = ralpha[idx]
            out.append(mapped if ch.isupper() else mapped.lower())
            lalpha, ralpha = _chaocipher_step(lalpha, ralpha, plain_ch=mapped, cipher_ch=cu)
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def _stable_column_order(key: str) -> List[int]:
    clean = [ch for ch in to_upper(key) if ch in ALPHA_SET]
    if not clean:
        clean = list("KEY")
    return [idx for idx, _ in sorted(enumerate(clean), key=lambda item: (item[1], item[0]))]


def Nicodemus_encode(text: str, key: str = "NICODEMUS", vigenere_key: str = "KEY") -> str:
    mixed = Vigenere_encode("".join(ch for ch in text if not ch.isspace()), vigenere_key)
    cols = len([ch for ch in to_upper(key) if ch in ALPHA_SET]) or 3
    rows = math.ceil(len(mixed) / cols)
    grid = [[""] * cols for _ in range(rows)]
    i = 0
    for r in range(rows):
        for c in range(cols):
            if i < len(mixed):
                grid[r][c] = mixed[i]
                i += 1
    out = []
    for c in _stable_column_order(key):
        for r in range(rows):
            if grid[r][c]:
                out.append(grid[r][c])
    return "".join(out)


def Nicodemus_decode(text: str, key: str = "NICODEMUS", vigenere_key: str = "KEY") -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len([ch for ch in to_upper(key) if ch in ALPHA_SET]) or 3
    rows = math.ceil(len(s) / cols)
    short = rows * cols - len(s)
    counts = {c: rows - (1 if c >= cols - short and short else 0) for c in range(cols)}
    columns: Dict[int, List[str]] = {}
    idx = 0
    for c in _stable_column_order(key):
        n = counts[c]
        columns[c] = list(s[idx:idx+n])
        idx += n
    mixed = []
    for r in range(rows):
        for c in range(cols):
            if columns.get(c):
                mixed.append(columns[c].pop(0))
    return Vigenere_decode("".join(mixed), vigenere_key)


def _phillips_square_for_group(key: str, group: int) -> Tuple[Dict[str, Tuple[int, int]], Dict[Tuple[int, int], str]]:
    square, _, _ = _key_square_5(key)
    rows = [list(square[i:i+5]) for i in range(0, 25, 5)]
    shift = group % 5
    rows = rows[shift:] + rows[:shift]
    mixed = "".join("".join(row) for row in rows)
    pos = {ch: divmod(i, 5) for i, ch in enumerate(mixed)}
    rev = {divmod(i, 5): ch for i, ch in enumerate(mixed)}
    return pos, rev


def Phillips_encode(text: str, key: str = "PHILLIPS", period: int | str = 5, keep_others: bool = True) -> str:
    period = max(1, int(period))
    out = []
    n = 0
    for ch in text:
        cu = 'I' if ch.upper() == 'J' else ch.upper()
        if cu in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            pos, rev = _phillips_square_for_group(key, n // period)
            r, c = pos[cu]
            mapped = rev[((r + 1) % 5, c)]
            out.append(mapped if ch.isupper() else mapped.lower())
            n += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def Phillips_decode(text: str, key: str = "PHILLIPS", period: int | str = 5, keep_others: bool = True) -> str:
    period = max(1, int(period))
    out = []
    n = 0
    for ch in text:
        cu = 'I' if ch.upper() == 'J' else ch.upper()
        if cu in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            pos, rev = _phillips_square_for_group(key, n // period)
            r, c = pos[cu]
            mapped = rev[((r - 1) % 5, c)]
            out.append(mapped if ch.isupper() else mapped.lower())
            n += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def Slidefair_encode(text: str, key: str = "SLIDE", keep_others: bool = True) -> str:
    shifts = key_to_shifts(key)
    if not shifts:
        return "Err:key must contain letters"
    letters = [(i, ch) for i, ch in enumerate(text) if ch.upper() in ALPHA_SET]
    repl: Dict[int, str] = {}
    for pair_no in range(0, len(letters), 2):
        i1, a = letters[pair_no]
        if pair_no + 1 >= len(letters):
            k = shifts[(pair_no // 2) % len(shifts)]
            repl[i1] = _shift_alpha_char(a, k)
            break
        i2, b = letters[pair_no + 1]
        k = shifts[(pair_no // 2) % len(shifts)]
        ai, bi = ALPHA.index(a.upper()), ALPHA.index(b.upper())
        c1 = ALPHA[(ai + k) % 26]
        c2 = ALPHA[(bi + ai + k) % 26]
        repl[i1] = c1 if a.isupper() else c1.lower()
        repl[i2] = c2 if b.isupper() else c2.lower()
    return "".join(repl.get(i, ch if keep_others or ch.upper() in ALPHA_SET else "") for i, ch in enumerate(text))


def Slidefair_decode(text: str, key: str = "SLIDE", keep_others: bool = True) -> str:
    shifts = key_to_shifts(key)
    if not shifts:
        return "Err:key must contain letters"
    letters = [(i, ch) for i, ch in enumerate(text) if ch.upper() in ALPHA_SET]
    repl: Dict[int, str] = {}
    for pair_no in range(0, len(letters), 2):
        i1, a = letters[pair_no]
        if pair_no + 1 >= len(letters):
            k = shifts[(pair_no // 2) % len(shifts)]
            repl[i1] = _shift_alpha_char(a, -k)
            break
        i2, b = letters[pair_no + 1]
        k = shifts[(pair_no // 2) % len(shifts)]
        ai = (ALPHA.index(a.upper()) - k) % 26
        bi = (ALPHA.index(b.upper()) - ai - k) % 26
        p1 = ALPHA[ai]
        p2 = ALPHA[bi]
        repl[i1] = p1 if a.isupper() else p1.lower()
        repl[i2] = p2 if b.isupper() else p2.lower()
    return "".join(repl.get(i, ch if keep_others or ch.upper() in ALPHA_SET else "") for i, ch in enumerate(text))


def Redefence_encode(text: str, rails: int | str = 3, offset: int | str = 1) -> str:
    return RailFenceOffset_encode(text, rails, offset)


def Redefence_decode(text: str, rails: int | str = 3, offset: int | str = 1) -> str:
    return RailFenceOffset_decode(text, rails, offset)



def _shift_alpha_char(ch: str, shift: int) -> str:
    cu = ch.upper()
    if cu not in ALPHA_SET:
        return ch
    mapped = ALPHA[(ALPHA.index(cu) + shift) % 26]
    return mapped if ch.isupper() else mapped.lower()


def _checkerboard_positions(rows: int, cols: int) -> List[Tuple[int, int]]:
    return [(r, c) for parity in (0, 1) for r in range(rows) for c in range(cols) if (r + c) % 2 == parity]


def CheckerboardTransposition_encode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    if rows <= 0 or cols <= 0:
        return "Err:rows and cols must be positive"
    block = rows * cols
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    positions = _checkerboard_positions(rows, cols)
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(rows)]
        out.extend(grid[r][c] for r, c in positions)
    return "".join(out)


def CheckerboardTransposition_decode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    if rows <= 0 or cols <= 0:
        return "Err:rows and cols must be positive"
    block = rows * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of rows*cols"
    positions = _checkerboard_positions(rows, cols)
    out = []
    for off in range(0, len(text), block):
        grid = [[""] * cols for _ in range(rows)]
        chunk = text[off:off + block]
        for ch, (r, c) in zip(chunk, positions):
            grid[r][c] = ch
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])


def _jefferson_disks(disks: str = "") -> List[str]:
    spec = (disks or "").strip()
    if not spec:
        return [ALPHA[i:] + ALPHA[:i] for i in range(26)]
    parts = [p.strip() for p in spec.replace("\n", ";").split(";") if p.strip()]
    if len(parts) == 1 and "," in parts[0]:
        shifts = [int(x.strip()) for x in parts[0].split(",") if x.strip()]
        return [ALPHA[n % 26:] + ALPHA[:n % 26] for n in shifts]
    parsed = [_normalized_alphabet(part) for part in parts]
    disks_out = [part for part in parsed if len(part) == 26]
    return disks_out or [ALPHA[i:] + ALPHA[:i] for i in range(26)]


def JeffersonDisk_encode(text: str, offset: int | str = 6, disks: str = "") -> str:
    offset = int(offset) % 26
    wheels = _jefferson_disks(disks)
    out = []
    n = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            disk = wheels[n % len(wheels)]
            mapped = disk[(disk.index(cu) + offset) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def JeffersonDisk_decode(text: str, offset: int | str = 6, disks: str = "") -> str:
    return JeffersonDisk_encode(text, -int(offset), disks)


def SeriatedPlayfair_encode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    period = max(2, int(period))
    s = only_alpha(text)
    out = []
    for i in range(0, len(s), period):
        out.append(Playfair_encode(s[i:i+period], key))
    return "".join(out)


def SeriatedPlayfair_decode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    period = max(2, int(period))
    s = only_alpha(text)
    out = []
    step = period if period % 2 == 0 else period + 1
    for i in range(0, len(s), step):
        out.append(Playfair_decode(s[i:i+step], key))
    return "".join(out)


def TriSquare_encode(text: str, key1: str = "ALPHA", key2: str = "BRAVO", key3: str = "CHARLIE") -> str:
    normal = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    posN = {ch: divmod(i, 5) for i, ch in enumerate(normal)}
    _, _, rev1 = _key_square_5(key1)
    _, _, rev2 = _key_square_5(key2)
    _, _, rev3 = _key_square_5(key3)
    out = []
    for a, b in _playfair_prepare(text):
        ra, ca = posN[a]
        rb, cb = posN[b]
        out.extend([rev1[(ra, cb)], rev2[(rb, ca)], rev3[(ra, ca)]])
    return "".join(out).lower()


def TriSquare_decode(text: str, key1: str = "ALPHA", key2: str = "BRAVO", key3: str = "CHARLIE") -> str:
    normal = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    revN = {divmod(i, 5): ch for i, ch in enumerate(normal)}
    _, pos1, _ = _key_square_5(key1)
    _, pos2, _ = _key_square_5(key2)
    s = only_alpha(text)
    out = []
    for i in range(0, len(s) - 2, 3):
        c1, c2 = s[i], s[i+1]
        ra, cb = pos1[c1]
        rb, ca = pos2[c2]
        out.append(revN[(ra, ca)])
        out.append(revN[(rb, cb)])
    return "".join(out).lower()


def Cadenus_encode(text: str, key: str = "CADENUS", height: int | str = 25, pad: str = "X") -> str:
    height = max(1, int(height))
    cols = len([ch for ch in to_upper(key) if ch in ALPHA_SET]) or 1
    block = height * cols
    padch = (pad or "X")[0]
    s = "".join(ch for ch in text if not ch.isspace())
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    order = _stable_column_order(key)
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(height)]
        for c in order:
            for r in range(height):
                out.append(grid[r][c])
    return "".join(out)


def Cadenus_decode(text: str, key: str = "CADENUS", height: int | str = 25, pad: str = "X") -> str:
    height = max(1, int(height))
    cols = len([ch for ch in to_upper(key) if ch in ALPHA_SET]) or 1
    block = height * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of height*key length"
    order = _stable_column_order(key)
    out = []
    for off in range(0, len(text), block):
        grid = [[""] * cols for _ in range(height)]
        idx = off
        for c in order:
            for r in range(height):
                grid[r][c] = text[idx]
                idx += 1
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])



def Clave_encode(text: str, key: str = "CLAVE", alphabet_key: str = "CIPHER", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(alphabet_key)
    key_vals = [alpha.index(ch) for ch in to_upper(key) if ch in alpha]
    if not key_vals:
        return "Err:key must contain letters"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            p = alpha.index(cu)
            mapped = alpha[(p + key_vals[ki % len(key_vals)]) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def Clave_decode(text: str, key: str = "CLAVE", alphabet_key: str = "CIPHER", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(alphabet_key)
    key_vals = [alpha.index(ch) for ch in to_upper(key) if ch in alpha]
    if not key_vals:
        return "Err:key must contain letters"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            c = alpha.index(cu)
            mapped = alpha[(c - key_vals[ki % len(key_vals)]) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def PhillipsRC_encode(text: str, key: str = "PHILLIPS", period: int | str = 5, keep_others: bool = True) -> str:
    period = max(1, int(period))
    out = []
    n = 0
    for ch in text:
        cu = 'I' if ch.upper() == 'J' else ch.upper()
        if cu in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            pos, rev = _phillips_square_for_group(key, n // period)
            r, c = pos[cu]
            mapped = rev[((r + 1) % 5, (c + 1) % 5)]
            out.append(mapped if ch.isupper() else mapped.lower())
            n += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def PhillipsRC_decode(text: str, key: str = "PHILLIPS", period: int | str = 5, keep_others: bool = True) -> str:
    period = max(1, int(period))
    out = []
    n = 0
    for ch in text:
        cu = 'I' if ch.upper() == 'J' else ch.upper()
        if cu in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            pos, rev = _phillips_square_for_group(key, n // period)
            r, c = pos[cu]
            mapped = rev[((r - 1) % 5, (c - 1) % 5)]
            out.append(mapped if ch.isupper() else mapped.lower())
            n += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def _key_permutation(key: str) -> List[int]:
    clean = [ch for ch in str(key) if ch.strip()]
    if not clean:
        clean = list("123")
    if all(ch.isdigit() for ch in clean) and len(set(clean)) == len(clean):
        return [idx for idx, _ in sorted(enumerate([int(ch) for ch in clean]), key=lambda item: (item[1], item[0]))]
    return [idx for idx, _ in sorted(enumerate(clean), key=lambda item: (item[1], item[0]))]


def Swagman_encode(text: str, key: str = "3142", pad: str = "X") -> str:
    order = _key_permutation(key)
    width = len(order)
    padch = (pad or "X")[0]
    s = "".join(ch for ch in text if not ch.isspace())
    if len(s) % width:
        s += padch * (width - len(s) % width)
    out = []
    for off in range(0, len(s), width):
        block = s[off:off + width]
        out.extend(block[i] for i in order)
    return "".join(out)


def Swagman_decode(text: str, key: str = "3142", pad: str = "X") -> str:
    order = _key_permutation(key)
    width = len(order)
    if len(text) % width:
        return "Err:ciphertext length must be a multiple of key length"
    out = []
    for off in range(0, len(text), width):
        block = text[off:off + width]
        plain = [""] * width
        for cipher_pos, plain_pos in enumerate(order):
            plain[plain_pos] = block[cipher_pos]
        out.extend(plain)
    return "".join(out).rstrip((pad or "X")[0])


def AlternatingColumnar_encode(text: str, key: str = "CIPHER") -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len(key) or 1
    rows = math.ceil(len(s) / cols)
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(s):
                grid[r][c] = s[idx]
                idx += 1
    out = []
    for n, c in enumerate(_stable_column_order(key)):
        rng = range(rows) if n % 2 == 0 else range(rows - 1, -1, -1)
        for r in rng:
            if grid[r][c]:
                out.append(grid[r][c])
    return "".join(out)


def AlternatingColumnar_decode(text: str, key: str = "CIPHER") -> str:
    s = text
    cols = len(key) or 1
    rows = math.ceil(len(s) / cols)
    short = rows * cols - len(s)
    counts = {c: rows - (1 if c >= cols - short and short else 0) for c in range(cols)}
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for n, c in enumerate(_stable_column_order(key)):
        rng = list(range(rows) if n % 2 == 0 else range(rows - 1, -1, -1))
        present = [r for r in rng if r < counts[c]]
        for r in present:
            grid[r][c] = s[idx]
            idx += 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols) if grid[r][c])


def BoustrophedonRoute_encode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    if rows <= 0 or cols <= 0:
        return "Err:rows and cols must be positive"
    block = rows * cols
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(rows)]
        for r, row in enumerate(grid):
            out.extend(row if r % 2 == 0 else reversed(row))
    return "".join(out)


def BoustrophedonRoute_decode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    if rows <= 0 or cols <= 0:
        return "Err:rows and cols must be positive"
    block = rows * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of rows*cols"
    out = []
    for off in range(0, len(text), block):
        chunk = text[off:off + block]
        grid = [[""] * cols for _ in range(rows)]
        idx = 0
        for r in range(rows):
            col_range = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            for c in col_range:
                grid[r][c] = chunk[idx]
                idx += 1
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])



def CistercianNumerals_encode(text: str) -> str:
    return " ".join(f"[C{ord(ch):04d}]" if ord(ch) <= 9999 else f"[U{ord(ch):06X}]" for ch in text)


def CistercianNumerals_decode(text: str) -> str:
    out = []
    for token in text.replace("][", "] [").split():
        if token.startswith("[C") and token.endswith("]"):
            out.append(chr(int(token[2:-1])))
        elif token.startswith("[U") and token.endswith("]"):
            out.append(chr(int(token[2:-1], 16)))
        else:
            out.append(token)
    return "".join(out)


def _lorenz_stream(seed: str, wheels: str = "41,31,29,26,23"):
    periods = [max(2, int(x.strip())) for x in str(wheels).split(",") if x.strip()]
    if not periods:
        periods = [41, 31, 29, 26, 23]
    state = sum((i + 1) * ord(ch) for i, ch in enumerate(seed or "LORENZ")) or 1
    positions = [state % p for p in periods]
    while True:
        bitmix = 0
        for i, p in enumerate(periods):
            positions[i] = (positions[i] + 1 + (state % (i + 3))) % p
            bitmix ^= ((positions[i] * (i + 5) + state) % 26)
        state = (state * 1103515245 + 12345 + bitmix) & 0x7FFFFFFF
        yield bitmix % 26


def LorenzToy_encode(text: str, seed: str = "LORENZ", wheels: str = "41,31,29,26,23", keep_others: bool = True) -> str:
    stream = _lorenz_stream(seed, wheels)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(cu) + k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def LorenzToy_decode(text: str, seed: str = "LORENZ", wheels: str = "41,31,29,26,23", keep_others: bool = True) -> str:
    stream = _lorenz_stream(seed, wheels)
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(cu) - k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)


def CompleteColumnar_encode(text: str, key: str = "CIPHER", pad: str = "X") -> str:
    cols = len(key) or 1
    padch = (pad or "X")[0]
    s = "".join(ch for ch in text if not ch.isspace())
    if len(s) % cols:
        s += padch * (cols - len(s) % cols)
    return Columnar_encode(s, key)


def CompleteColumnar_decode(text: str, key: str = "CIPHER", pad: str = "X") -> str:
    return Columnar_decode(text, key).rstrip((pad or "X")[0])


def ColumnarPadded_encode(text: str, key: str = "CIPHER", pad: str = "X", policy: str = "minimal") -> str:
    cols = len(key) or 1
    padch = (pad or "X")[0]
    s = "".join(ch for ch in text if not ch.isspace())
    policy = str(policy or "minimal").lower()
    need = (-len(s)) % cols
    if policy == "full" and need == 0:
        need = cols
    if policy != "none":
        s += padch * need
    return Columnar_encode(s, key)


def ColumnarPadded_decode(text: str, key: str = "CIPHER", pad: str = "X", policy: str = "minimal") -> str:
    plain = Columnar_decode(text, key)
    return plain if str(policy or "minimal").lower() == "none" else plain.rstrip((pad or "X")[0])


def _spiral_positions(rows: int, cols: int) -> List[Tuple[int, int]]:
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    pos: List[Tuple[int, int]] = []
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            pos.append((top, c))
        top += 1
        for r in range(top, bottom + 1):
            pos.append((r, right))
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                pos.append((bottom, c))
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                pos.append((r, left))
            left += 1
    return pos


def SpiralInwardRoute_encode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    positions = _spiral_positions(rows, cols)
    out = []
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(rows)]
        out.extend(grid[r][c] for r, c in positions)
    return "".join(out)


def SpiralInwardRoute_decode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of rows*cols"
    positions = _spiral_positions(rows, cols)
    out = []
    for off in range(0, len(text), block):
        grid = [[""] * cols for _ in range(rows)]
        for ch, (r, c) in zip(text[off:off + block], positions):
            grid[r][c] = ch
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])


def SpiralOutwardRoute_encode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    positions = list(reversed(_spiral_positions(rows, cols)))
    out = []
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(rows)]
        out.extend(grid[r][c] for r, c in positions)
    return "".join(out)


def SpiralOutwardRoute_decode(text: str, rows: int | str = 5, cols: int | str = 5, pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of rows*cols"
    positions = list(reversed(_spiral_positions(rows, cols)))
    out = []
    for off in range(0, len(text), block):
        grid = [[""] * cols for _ in range(rows)]
        for ch, (r, c) in zip(text[off:off + block], positions):
            grid[r][c] = ch
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])



def _amsco_cell_lengths(length: int, cols: int, start_len: int) -> List[List[int]]:
    rows = []
    used = 0
    toggle = 0 if int(start_len) == 1 else 1
    while used < length:
        row = []
        for _ in range(cols):
            want = 1 if toggle % 2 == 0 else 2
            take = min(want, max(0, length - used))
            row.append(take)
            used += take
            toggle += 1
            if used >= length:
                row.extend([0] * (cols - len(row)))
                break
        rows.append(row)
    return rows or [[0] * cols]


def AMSCO_encode(text: str, key: str = "CIPHER", start_len: int | str = 1) -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len(key) or 1
    lengths = _amsco_cell_lengths(len(s), cols, int(start_len))
    cells = [[""] * cols for _ in lengths]
    idx = 0
    for r, row in enumerate(lengths):
        for c, n in enumerate(row):
            cells[r][c] = s[idx:idx+n]
            idx += n
    out = []
    for c in _stable_column_order(key):
        for r in range(len(cells)):
            out.append(cells[r][c])
    return "".join(out)


def AMSCO_decode(text: str, key: str = "CIPHER", start_len: int | str = 1) -> str:
    s = text
    cols = len(key) or 1
    lengths = _amsco_cell_lengths(len(s), cols, int(start_len))
    cells = [[""] * cols for _ in lengths]
    idx = 0
    for c in _stable_column_order(key):
        for r, row in enumerate(lengths):
            n = row[c]
            cells[r][c] = s[idx:idx+n]
            idx += n
    out = []
    for r in range(len(cells)):
        for c in range(cols):
            out.append(cells[r][c])
    return "".join(out)


def _reverse_blocks_by_digits(text: str, digits: str) -> str:
    sizes = [max(1, int(ch)) for ch in str(digits) if ch.isdigit() and ch != "0"] or [5]
    out = []
    idx = 0
    block_no = 0
    while idx < len(text):
        size = sizes[block_no % len(sizes)]
        out.append(text[idx:idx+size][::-1])
        idx += size
        block_no += 1
    return "".join(out)


def Bazeries_encode(text: str, number: str = "31415", key: str = "BAZERIES", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(key)
    subbed = apply_monoalpha(text, ALPHA, alpha, keep_others)
    return _reverse_blocks_by_digits(subbed, number)


def Bazeries_decode(text: str, number: str = "31415", key: str = "BAZERIES", keep_others: bool = True) -> str:
    alpha = rotate_alpha_from_keyword(key)
    unblocked = _reverse_blocks_by_digits(text, number)
    return apply_monoalpha(unblocked, alpha, ALPHA, keep_others)


def DisruptedTransposition_encode(text: str, key: str = "DISRUPT", pad: str = "X") -> str:
    cols = len(key) or 1
    padch = (pad or "X")[0]
    s = "".join(ch for ch in text if not ch.isspace())
    if len(s) % cols:
        s += padch * (cols - len(s) % cols)
    rows = len(s) // cols
    grid = []
    idx = 0
    for r in range(rows):
        row = list(s[idx:idx+cols])
        idx += cols
        shift = r % cols
        grid.append(row[shift:] + row[:shift])
    out = []
    for c in _stable_column_order(key):
        for r in range(rows):
            out.append(grid[r][c])
    return "".join(out)


def DisruptedTransposition_decode(text: str, key: str = "DISRUPT", pad: str = "X") -> str:
    cols = len(key) or 1
    if len(text) % cols:
        return "Err:ciphertext length must be a multiple of key length"
    rows = len(text) // cols
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in _stable_column_order(key):
        for r in range(rows):
            grid[r][c] = text[idx]
            idx += 1
    out = []
    for r, row in enumerate(grid):
        shift = r % cols
        plain_row = row[-shift:] + row[:-shift] if shift else row
        out.extend(plain_row)
    return "".join(out).rstrip((pad or "X")[0])


def IncompleteColumnar_encode(text: str, key: str = "CIPHER", keep_spaces: str = "false") -> str:
    keep = str(keep_spaces).lower() in {"1", "true", "yes", "on"}
    s = text if keep else "".join(ch for ch in text if not ch.isspace())
    cols = len(key) or 1
    rows = math.ceil(len(s) / cols)
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(s):
                grid[r][c] = s[idx]
                idx += 1
    out = []
    for c in _stable_column_order(key):
        for r in range(rows):
            if grid[r][c]:
                out.append(grid[r][c])
    return "".join(out)


def IncompleteColumnar_decode(text: str, key: str = "CIPHER", keep_spaces: str = "false") -> str:
    s = text
    cols = len(key) or 1
    rows = math.ceil(len(s) / cols)
    extra = len(s) % cols
    counts = {c: rows for c in range(cols)}
    if extra:
        for c in range(extra, cols):
            counts[c] = rows - 1
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in _stable_column_order(key):
        for r in range(counts[c]):
            grid[r][c] = s[idx]
            idx += 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols) if grid[r][c])


def ScytalePadded_encode(text: str, diameter: int | str = 5, pad: str = "X") -> str:
    diameter = max(1, int(diameter))
    padch = (pad or "X")[0]
    s = text
    if len(s) % diameter:
        s += padch * (diameter - len(s) % diameter)
    return Scytale_encode(s, diameter)


def ScytalePadded_decode(text: str, diameter: int | str = 5, pad: str = "X") -> str:
    return Scytale_decode(text, diameter).rstrip((pad or "X")[0])


# Additional polygraphic/classical roadmap ciphers

def _playfair_prepare_6(text: str) -> List[Tuple[str, str]]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    s = "".join(ch for ch in to_upper(text) if ch in alphabet)
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        if i + 1 < len(s):
            b = s[i + 1]
            if a == b:
                pairs.append((a, "X" if a != "X" else "Q"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, "X" if a != "X" else "Q"))
            i += 1
    return pairs


def Playfair6x6_encode(text: str, key: str = "KEYWORD") -> str:
    _, pos, rev = _key_square_6(key)
    out = []
    for a, b in _playfair_prepare_6(text):
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(rev[(ra, (ca + 1) % 6)])
            out.append(rev[(rb, (cb + 1) % 6)])
        elif ca == cb:
            out.append(rev[((ra + 1) % 6, ca)])
            out.append(rev[((rb + 1) % 6, cb)])
        else:
            out.append(rev[(ra, cb)])
            out.append(rev[(rb, ca)])
    return "".join(out).lower()


def Playfair6x6_decode(text: str, key: str = "KEYWORD") -> str:
    _, pos, rev = _key_square_6(key)
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    if len(s) % 2:
        s += "X"
    out = []
    for i in range(0, len(s), 2):
        a, b = s[i], s[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(rev[(ra, (ca - 1) % 6)])
            out.append(rev[(rb, (cb - 1) % 6)])
        elif ca == cb:
            out.append(rev[((ra - 1) % 6, ca)])
            out.append(rev[((rb - 1) % 6, cb)])
        else:
            out.append(rev[(ra, cb)])
            out.append(rev[(rb, ca)])
    return "".join(out).lower()


def FourSquare6x6_encode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    _, _, rev1 = _key_square_6(key1)
    _, _, rev2 = _key_square_6(key2)
    posN = {ch: divmod(i, 6) for i, ch in enumerate(normal)}
    out = []
    for a, b in _playfair_prepare_6(text):
        ra, ca = posN[a]
        rb, cb = posN[b]
        out.append(rev1[(ra, cb)])
        out.append(rev2[(rb, ca)])
    return "".join(out).lower()


def FourSquare6x6_decode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    _, pos1, _ = _key_square_6(key1)
    _, pos2, _ = _key_square_6(key2)
    revN = {divmod(i, 6): ch for i, ch in enumerate(normal)}
    valid = set(pos1) & set(pos2)
    s = "".join(ch for ch in to_upper(text) if ch in valid)
    if len(s) % 2:
        s += "X"
    out = []
    for i in range(0, len(s), 2):
        a, b = s[i], s[i + 1]
        ra, cb = pos1[a]
        rb, ca = pos2[b]
        out.append(revN[(ra, ca)])
        out.append(revN[(rb, cb)])
    return "".join(out).lower()


def TwoSquare6x6_encode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    _, posL, revL = _key_square_6(key1)
    _, posR, revR = _key_square_6(key2)
    out = []
    for a, b in _playfair_prepare_6(text):
        ra, ca = posL[a]
        rb, cb = posR[b]
        out.append(revR[(ra, cb)])
        out.append(revL[(rb, ca)])
    return "".join(out).lower()


def TwoSquare6x6_decode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    _, posL, revL = _key_square_6(key1)
    _, posR, revR = _key_square_6(key2)
    valid = set(posL) & set(posR)
    s = "".join(ch for ch in to_upper(text) if ch in valid)
    if len(s) % 2:
        s += "X"
    out = []
    for i in range(0, len(s), 2):
        a, b = s[i], s[i + 1]
        ra, cb = posR[a]
        rb, ca = posL[b]
        out.append(revL[(ra, ca)])
        out.append(revR[(rb, cb)])
    return "".join(out).lower()


def Bifid6x6_encode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    period = max(1, int(period))
    _, pos, rev = _key_square_6(key)
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    out = []
    for block in chunk(s, period):
        rows = []
        cols = []
        for ch in block:
            r, c = pos[ch]
            rows.append(r)
            cols.append(c)
        merged = rows + cols
        for i in range(0, len(merged), 2):
            out.append(rev[(merged[i], merged[i + 1])])
    return "".join(out).lower()


def Bifid6x6_decode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    period = max(1, int(period))
    _, pos, rev = _key_square_6(key)
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    out = []
    for block in chunk(s, period):
        flat = []
        for ch in block:
            flat.extend(pos[ch])
        n = len(block)
        rows = flat[:n]
        cols = flat[n:]
        for r, c in zip(rows, cols):
            out.append(rev[(r, c)])
    return "".join(out).lower()


def _gromark_digits(primer: str, length: int) -> List[int]:
    digits = [int(ch) for ch in str(primer) if ch.isdigit()] or [1, 2, 3, 4, 5]
    i = 0
    while len(digits) < length:
        digits.append((digits[i] + digits[i + 1]) % 10)
        i += 1
    return digits[:length]


def Gromark_encode(text: str, primer: str = "12345", key: str = "GROMARK") -> str:
    cipher_alpha = rotate_alpha_from_keyword(key)
    shifts = _gromark_digits(primer, len(only_alpha(text)))
    out = []
    idx = 0
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            val = (ALPHA.index(up) + shifts[idx]) % 26
            out.append(cipher_alpha[val] if ch.isupper() else cipher_alpha[val].lower())
            idx += 1
        else:
            out.append(ch)
    return "".join(out)


def Gromark_decode(text: str, primer: str = "12345", key: str = "GROMARK") -> str:
    cipher_alpha = rotate_alpha_from_keyword(key)
    shifts = _gromark_digits(primer, len(only_alpha(text)))
    out = []
    idx = 0
    for ch in text:
        up = ch.upper()
        if up in cipher_alpha:
            val = (cipher_alpha.index(up) - shifts[idx]) % 26
            out.append(ALPHA[val] if ch.isupper() else ALPHA[val].lower())
            idx += 1
        else:
            out.append(ch)
    return "".join(out)


def NihilistSubstitution_encode(text: str, square_key: str = "NIHILIST", key: str = "KEY") -> str:
    _, pos, _ = _key_square_5(square_key)
    key_nums = []
    for ch in only_alpha(key):
        ch = "I" if ch == "J" else ch
        if ch in pos:
            r, c = pos[ch]
            key_nums.append((r + 1) * 10 + c + 1)
    key_nums = key_nums or [11]
    out = []
    idx = 0
    for ch in to_upper(text):
        ch = "I" if ch == "J" else ch
        if ch in pos:
            r, c = pos[ch]
            out.append(str((r + 1) * 10 + c + 1 + key_nums[idx % len(key_nums)]))
            idx += 1
    return " ".join(out)


def NihilistSubstitution_decode(text: str, square_key: str = "NIHILIST", key: str = "KEY") -> str:
    _, pos, rev = _key_square_5(square_key)
    key_nums = []
    for ch in only_alpha(key):
        ch = "I" if ch == "J" else ch
        if ch in pos:
            r, c = pos[ch]
            key_nums.append((r + 1) * 10 + c + 1)
    key_nums = key_nums or [11]
    nums = [int(x) for x in re.findall(r"\d+", text)]
    out = []
    for i, n in enumerate(nums):
        val = n - key_nums[i % len(key_nums)]
        r, c = divmod(val, 10)
        out.append(rev.get((r - 1, c - 1), ""))
    return "".join(out).lower()


def _parse_hill3_key(key: str) -> List[List[int]]:
    parts = [p.strip() for p in str(key).replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    if len(parts) == 9:
        nums = [int(p) % 26 for p in parts]
    else:
        letters = only_alpha(str(key))
        if len(letters) < 9:
            raise ValueError("Hill 3x3 key must be nine numbers or at least nine letters")
        nums = [ALPHA.index(ch) for ch in letters[:9]]
    mat = [nums[0:3], nums[3:6], nums[6:9]]
    det = _det3(mat) % 26
    mod_inv(det, 26)
    return mat


def _det3(m: List[List[int]]) -> int:
    return (
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
        - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
        + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    )


def _inv3_mod26(m: List[List[int]]) -> List[List[int]]:
    det = _det3(m) % 26
    inv_det = mod_inv(det, 26)
    cof = [
        [m[1][1]*m[2][2] - m[1][2]*m[2][1], -(m[1][0]*m[2][2] - m[1][2]*m[2][0]), m[1][0]*m[2][1] - m[1][1]*m[2][0]],
        [-(m[0][1]*m[2][2] - m[0][2]*m[2][1]), m[0][0]*m[2][2] - m[0][2]*m[2][0], -(m[0][0]*m[2][1] - m[0][1]*m[2][0])],
        [m[0][1]*m[1][2] - m[0][2]*m[1][1], -(m[0][0]*m[1][2] - m[0][2]*m[1][0]), m[0][0]*m[1][1] - m[0][1]*m[1][0]],
    ]
    adj = [[cof[c][r] for c in range(3)] for r in range(3)]
    return [[(adj[r][c] * inv_det) % 26 for c in range(3)] for r in range(3)]


def _hill3_apply(text: str, mat: List[List[int]]) -> str:
    s = only_alpha(text)
    while len(s) % 3:
        s += "X"
    out = []
    for block in chunk(s, 3):
        vec = [ALPHA.index(ch) for ch in block]
        for row in mat:
            out.append(ALPHA[sum(row[i] * vec[i] for i in range(3)) % 26])
    return "".join(out).lower()


def Hill3x3_encode(text: str, key: str = "6,24,1,13,16,10,20,17,15") -> str:
    return _hill3_apply(text, _parse_hill3_key(key))


def Hill3x3_decode(text: str, key: str = "6,24,1,13,16,10,20,17,15") -> str:
    return _hill3_apply(text, _inv3_mod26(_parse_hill3_key(key)))


def _labels_unique(labels: str, size: int) -> str:
    lab = "".join(ch for ch in str(labels) if not ch.isspace())
    if len(lab) != size or len(set(lab)) != size:
        raise ValueError(f"labels must contain {size} unique non-space characters")
    return lab


def PolybiusCustom_encode(text: str, key: str = "KEYWORD", row_labels: str = "12345", col_labels: str = "12345", sep: str = " ") -> str:
    rows = _labels_unique(row_labels, 5)
    cols = _labels_unique(col_labels, 5)
    _, pos, _ = _key_square_5(key)
    out = []
    for ch in to_upper(text):
        if ch == "J":
            ch = "I"
        if ch in pos:
            r, c = pos[ch]
            out.append(rows[r] + cols[c])
        elif ch.isspace():
            out.append("/")
    return sep.join(out)


def PolybiusCustom_decode(text: str, key: str = "KEYWORD", row_labels: str = "12345", col_labels: str = "12345", sep: str = " ") -> str:
    rows = _labels_unique(row_labels, 5)
    cols = _labels_unique(col_labels, 5)
    _, _, rev = _key_square_5(key)
    raw = text.strip()
    tokens = raw.split(sep) if sep else [raw[i:i+2] for i in range(0, len(raw), 2)]
    out = []
    for tok in tokens:
        tok = tok.strip()
        if tok == "/":
            out.append(" ")
        elif len(tok) == 2 and tok[0] in rows and tok[1] in cols:
            out.append(rev.get((rows.index(tok[0]), cols.index(tok[1])), ""))
    return "".join(out).lower()


def ADFGXCustom_encode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER", labels: str = "ADFGX") -> str:
    lab = _labels_unique(labels, 5)
    _, pos, _ = _key_square_5(square_key)
    frac = []
    for ch in to_upper(text):
        if ch == "J":
            ch = "I"
        if ch in pos:
            r, c = pos[ch]
            frac.append(lab[r] + lab[c])
    return _columnar_route("".join(frac), route_key)


def ADFGXCustom_decode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER", labels: str = "ADFGX") -> str:
    lab = _labels_unique(labels, 5)
    _, _, rev = _key_square_5(square_key)
    frac = _columnar_unroute(text, route_key)
    out = []
    for a, b in _pairwise(frac):
        if a in lab and b in lab:
            out.append(rev.get((lab.index(a), lab.index(b)), ""))
    return "".join(out).lower()


def _matrix_minor(mat: List[List[int]], skip_r: int, skip_c: int) -> List[List[int]]:
    return [[v for c, v in enumerate(row) if c != skip_c] for r, row in enumerate(mat) if r != skip_r]


def _det_matrix(mat: List[List[int]]) -> int:
    if len(mat) == 1:
        return mat[0][0]
    if len(mat) == 2:
        return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]
    return sum(((-1) ** c) * mat[0][c] * _det_matrix(_matrix_minor(mat, 0, c)) for c in range(len(mat)))


def _parse_hilln_key(key: str, size: int, modulus: int) -> List[List[int]]:
    size = max(2, int(size))
    modulus = max(2, int(modulus))
    need = size * size
    parts = [p.strip() for p in str(key).replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    if len(parts) == need:
        nums = [int(p) % modulus for p in parts]
    else:
        letters = only_alpha(str(key))
        if len(letters) < need:
            raise ValueError(f"Hill {size}x{size} key must be {need} numbers or at least {need} letters")
        nums = [ALPHA.index(ch) % modulus for ch in letters[:need]]
    mat = [nums[i:i+size] for i in range(0, need, size)]
    mod_inv(_det_matrix(mat) % modulus, modulus)
    return mat


def _invert_matrix_mod(mat: List[List[int]], modulus: int) -> List[List[int]]:
    n = len(mat)
    det = _det_matrix(mat) % modulus
    inv_det = mod_inv(det, modulus)
    cof = []
    for r in range(n):
        row = []
        for c in range(n):
            row.append(((-1) ** (r + c)) * _det_matrix(_matrix_minor(mat, r, c)))
        cof.append(row)
    adj = [[cof[c][r] for c in range(n)] for r in range(n)]
    return [[(adj[r][c] * inv_det) % modulus for c in range(n)] for r in range(n)]


def _hilln_apply(text: str, mat: List[List[int]], alphabet: str) -> str:
    n = len(mat)
    pos = {ch: i for i, ch in enumerate(alphabet)}
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    pad = alphabet[23 % len(alphabet)] if alphabet else "X"
    while len(s) % n:
        s += pad
    out = []
    for block in chunk(s, n):
        vec = [pos[ch] for ch in block]
        for row in mat:
            out.append(alphabet[sum(row[i] * vec[i] for i in range(n)) % len(alphabet)])
    return "".join(out).lower()


def HillNxN_encode(text: str, key: str = "6,24,1,13,16,10,20,17,15", size: int | str = 3, alphabet: str = ALPHA) -> str:
    alpha = "".join(dict.fromkeys(to_upper(alphabet))) or ALPHA
    mat = _parse_hilln_key(key, int(size), len(alpha))
    return _hilln_apply(text, mat, alpha)


def HillNxN_decode(text: str, key: str = "6,24,1,13,16,10,20,17,15", size: int | str = 3, alphabet: str = ALPHA) -> str:
    alpha = "".join(dict.fromkeys(to_upper(alphabet))) or ALPHA
    mat = _parse_hilln_key(key, int(size), len(alpha))
    return _hilln_apply(text, _invert_matrix_mod(mat, len(alpha)), alpha)


def _trifid_custom_tables(alphabet: str) -> Tuple[Dict[str, Tuple[int, int, int]], Dict[Tuple[int, int, int], str]]:
    alpha = "".join(dict.fromkeys(to_upper(alphabet)))
    if len(alpha) != 27:
        raise ValueError("alphabet must contain exactly 27 unique symbols")
    pos = {}
    rev = {}
    for i, ch in enumerate(alpha):
        layer = i // 9
        row, col = divmod(i % 9, 3)
        pos[ch] = (layer, row, col)
        rev[(layer, row, col)] = ch
    return pos, rev


def TrifidCustom_encode(text: str, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.", period: int | str = 5) -> str:
    period = max(1, int(period))
    pos, rev = _trifid_custom_tables(alphabet)
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    out = []
    for block in chunk(s, period):
        coords = [[], [], []]
        for ch in block:
            a, b, c = pos[ch]
            coords[0].append(a); coords[1].append(b); coords[2].append(c)
        merged = coords[0] + coords[1] + coords[2]
        for i in range(0, len(merged), 3):
            out.append(rev[(merged[i], merged[i + 1], merged[i + 2])])
    return "".join(out).lower()


def TrifidCustom_decode(text: str, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.", period: int | str = 5) -> str:
    period = max(1, int(period))
    pos, rev = _trifid_custom_tables(alphabet)
    s = "".join(ch for ch in to_upper(text) if ch in pos)
    out = []
    for block in chunk(s, period):
        flat = []
        for ch in block:
            flat.extend(pos[ch])
        n = len(block)
        for coords in zip(flat[:n], flat[n:2*n], flat[2*n:]):
            out.append(rev[coords])
    return "".join(out).lower()


def _complete_route_with_len(frac: str, key: str, pad: str) -> Tuple[str, int]:
    cols = max(1, len(key))
    rows = math.ceil(len(frac) / cols)
    original_len = len(frac)
    padded = frac + pad * (rows * cols - len(frac))
    grid = [list(padded[i:i+cols]) for i in range(0, len(padded), cols)]
    out = []
    for c in _stable_column_order(key):
        for r in range(rows):
            out.append(grid[r][c])
    return "".join(out), original_len


def _complete_unroute_with_len(cipher: str, key: str, original_len: int) -> str:
    cols = max(1, len(key))
    rows = math.ceil(len(cipher) / cols)
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in _stable_column_order(key):
        for r in range(rows):
            if idx < len(cipher):
                grid[r][c] = cipher[idx]
                idx += 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols))[:original_len]


def ADFGVXEscaped_encode(text: str, square_key: str = "KEYW0RD", route_key: str = "CIPHER") -> str:
    labels = "ADFGVX"
    _, pos, _ = _key_square_6(square_key)
    hex_text = text.encode("utf-8").hex().upper()
    frac = []
    for ch in hex_text:
        r, c = pos[ch]
        frac.append(labels[r] + labels[c])
    routed, original_len = _complete_route_with_len("".join(frac), route_key, labels[0])
    return f"[ADFGVXESC]{original_len}|{routed}"


def ADFGVXEscaped_decode(text: str, square_key: str = "KEYW0RD", route_key: str = "CIPHER") -> str:
    labels = "ADFGVX"
    _, _, rev = _key_square_6(square_key)
    body = text
    original_len = len(body)
    if text.startswith("[ADFGVXESC]") and "|" in text:
        meta, body = text.split("|", 1)
        original_len = int(meta[len("[ADFGVXESC]"):])
    frac = _complete_unroute_with_len(body, route_key, original_len)
    hex_chars = []
    for a, b in _pairwise(frac):
        if a in labels and b in labels:
            hex_chars.append(rev.get((labels.index(a), labels.index(b)), ""))
    hex_text = "".join(hex_chars)
    if len(hex_text) % 2:
        hex_text = hex_text[:-1]
    try:
        return bytes.fromhex(hex_text).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def _key_square_5_q(keyword: str) -> Tuple[str, Dict[str, Tuple[int, int]], Dict[Tuple[int, int], str]]:
    alpha = "ABCDEFGHIJKLMNOPRSTUVWXYZ"  # Q omitted, I/J kept separate
    mixed = ""; seen = set()
    for ch in only_alpha(keyword):
        if ch == "Q":
            continue
        if ch not in seen and ch in alpha:
            mixed += ch; seen.add(ch)
    for ch in alpha:
        if ch not in seen:
            mixed += ch
    idx = {}; rev = {}
    for i, ch in enumerate(mixed):
        r, c = divmod(i, 5)
        idx[ch] = (r, c); rev[(r, c)] = ch
    return mixed, idx, rev


def _playfair_prepare_variant(text: str, omit: str = "J", filler: str = "X") -> List[Tuple[str, str]]:
    omit = (omit or "J").upper()[0]
    filler = (filler or "X").upper()[0]
    s = only_alpha(text)
    if omit == "J":
        s = s.replace("J", "I")
    elif omit == "Q":
        s = s.replace("Q", "K")
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        if i + 1 < len(s):
            b = s[i + 1]
            if a == b:
                pairs.append((a, filler if a != filler else "Z"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, filler if a != filler else "Z"))
            i += 1
    return pairs


def _playfair_core_from_square(text: str, key: str, encode: bool, omit: str = "J", filler: str = "X") -> str:
    _, pos, rev = _key_square_5_q(key) if omit.upper().startswith("Q") else _key_square_5(key)
    pairs = _playfair_prepare_variant(text, omit, filler) if encode else chunk(only_alpha(text), 2)
    out = []
    for pair in pairs:
        if len(pair) != 2:
            continue
        a, b = pair
        if a not in pos or b not in pos:
            continue
        ra, ca = pos[a]; rb, cb = pos[b]
        step = 1 if encode else -1
        if ra == rb:
            out.append(rev[(ra, (ca + step) % 5)])
            out.append(rev[(rb, (cb + step) % 5)])
        elif ca == cb:
            out.append(rev[((ra + step) % 5, ca)])
            out.append(rev[((rb + step) % 5, cb)])
        else:
            out.append(rev[(ra, cb)])
            out.append(rev[(rb, ca)])
    return "".join(out).lower()


def PlayfairQOmitted_encode(text: str, key: str = "KEYWORD", filler: str = "X") -> str:
    return _playfair_core_from_square(text, key, True, "Q", filler)


def PlayfairQOmitted_decode(text: str, key: str = "KEYWORD", filler: str = "X") -> str:
    return _playfair_core_from_square(text, key, False, "Q", filler)




def _playfair_unpad_text(s: str, filler: str = "X") -> str:
    filler = (filler or "X").upper()[0]
    chars = list(s)
    out = []
    i = 0
    while i < len(chars):
        if i + 2 < len(chars) and chars[i] == chars[i + 2] and chars[i + 1] == filler:
            out.append(chars[i])
            i += 2
        else:
            out.append(chars[i])
            i += 1
    if out and out[-1] == filler:
        out.pop()
    return "".join(out)

def PlayfairPreserve_encode(text: str, key: str = "KEYWORD", filler: str = "X") -> str:
    letters = Playfair_encode(text, key).upper()
    it = iter(letters)
    out = []
    for ch in text:
        if ch.upper() in ALPHA_SET:
            try:
                mapped = next(it)
            except StopIteration:
                break
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    out.extend(it)
    return "".join(out)


def PlayfairPreserve_decode(text: str, key: str = "KEYWORD", filler: str = "X") -> str:
    letters = _playfair_unpad_text(Playfair_decode(text, key).upper(), filler)
    it = iter(letters)
    out = []
    for ch in text:
        if ch.upper() in ALPHA_SET:
            try:
                mapped = next(it)
            except StopIteration:
                break
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    out.extend(it)
    return "".join(out)


def PlayfairPadding_encode(text: str, key: str = "KEYWORD", filler: str = "X", omit: str = "J") -> str:
    return _playfair_core_from_square(text, key, True, omit, filler)


def PlayfairPadding_decode(text: str, key: str = "KEYWORD", filler: str = "X", omit: str = "J") -> str:
    return _playfair_core_from_square(text, key, False, omit, filler)


def DoublePlayfair_encode(text: str, key1: str = "ALPHA", key2: str = "OMEGA") -> str:
    return Playfair_encode(Playfair_encode(text, key1), key2)


def DoublePlayfair_decode(text: str, key1: str = "ALPHA", key2: str = "OMEGA") -> str:
    return Playfair_decode(Playfair_decode(text, key2), key1)


def PolybiusColumnar_encode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER", row_labels: str = "12345", col_labels: str = "12345") -> str:
    frac = PolybiusCustom_encode(text, square_key, row_labels, col_labels, sep="")
    routed, original_len = _complete_route_with_len(frac, route_key, row_labels[0] if row_labels else "1")
    return f"[POLYCOL]{original_len}|{routed}"


def PolybiusColumnar_decode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER", row_labels: str = "12345", col_labels: str = "12345") -> str:
    body = text
    original_len = len(body)
    if text.startswith("[POLYCOL]") and "|" in text:
        meta, body = text.split("|", 1)
        original_len = int(meta[len("[POLYCOL]"):])
    frac = _complete_unroute_with_len(body, route_key, original_len)
    return PolybiusCustom_decode(frac, square_key, row_labels, col_labels, sep="")


def DoubleColumnarIrregular_encode(text: str, key1: str = "ALPHA", key2: str = "OMEGA") -> str:
    first = IncompleteColumnar_encode(text, key1, "false")
    return IncompleteColumnar_encode(first, key2, "false")


def DoubleColumnarIrregular_decode(text: str, key1: str = "ALPHA", key2: str = "OMEGA") -> str:
    first = IncompleteColumnar_decode(text, key2, "false")
    return IncompleteColumnar_decode(first, key1, "false")


def TwinBifid_encode(text: str, key1: str = "ALPHA", key2: str = "OMEGA", period: int | str = 5) -> str:
    s = only_alpha(text).replace("J", "I")
    left = Bifid_encode(s[::2], key1, period).upper()
    right = Bifid_encode(s[1::2], key2, period).upper()
    return f"[TWINBIFID]{len(left)}|{left}{right}"


def TwinBifid_decode(text: str, key1: str = "ALPHA", key2: str = "OMEGA", period: int | str = 5) -> str:
    body = text
    left_len = (len(body) + 1) // 2
    if text.startswith("[TWINBIFID]") and "|" in text:
        meta, body = text.split("|", 1)
        left_len = int(meta[len("[TWINBIFID]"):])
    left = Bifid_decode(body[:left_len], key1, period).upper()
    right = Bifid_decode(body[left_len:], key2, period).upper()
    out = []
    for i in range(max(len(left), len(right))):
        if i < len(left):
            out.append(left[i])
        if i < len(right):
            out.append(right[i])
    return "".join(out).lower()


def TwoSquareVertical_encode(text: str, key_top: str = "EXAMPLE", key_bottom: str = "KEYWORD") -> str:
    _, posT, revT = _key_square_5(key_top)
    _, posB, revB = _key_square_5(key_bottom)
    out = []
    for a, b in _playfair_prepare(text):
        rt, ct = posT[a]
        rb, cb = posB[b]
        if ct == cb:
            out.append(revT[((rt + 1) % 5, ct)])
            out.append(revB[((rb + 1) % 5, cb)])
        else:
            out.append(revT[(rt, cb)])
            out.append(revB[(rb, ct)])
    return "".join(out).lower()


def TwoSquareVertical_decode(text: str, key_top: str = "EXAMPLE", key_bottom: str = "KEYWORD") -> str:
    _, posT, revT = _key_square_5(key_top)
    _, posB, revB = _key_square_5(key_bottom)
    s = only_alpha(text)
    if len(s) % 2:
        s += "X"
    out = []
    for a, b in chunk(s, 2):
        rt, ct = posT[a]
        rb, cb = posB[b]
        if ct == cb:
            out.append(revT[((rt - 1) % 5, ct)])
            out.append(revB[((rb - 1) % 5, cb)])
        else:
            out.append(revT[(rt, cb)])
            out.append(revB[(rb, ct)])
    return "".join(out).lower()


def _route_positions(rows: int, cols: int, preset: str) -> List[Tuple[int, int]]:
    preset = str(preset or "row").lower().replace("_", "-")
    if preset in {"column", "col", "down-columns"}:
        return [(r, c) for c in range(cols) for r in range(rows)]
    if preset in {"reverse-row", "reverse", "rtl"}:
        return [(r, c) for r in range(rows) for c in range(cols - 1, -1, -1)]
    if preset in {"boustrophedon", "snake"}:
        out = []
        for r in range(rows):
            rng = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            out.extend((r, c) for c in rng)
        return out
    return [(r, c) for r in range(rows) for c in range(cols)]


def ReadingOrderRoute_encode(text: str, rows: int | str = 5, cols: int | str = 5, preset: str = "column", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    positions = _route_positions(rows, cols, preset)
    out = []
    for off in range(0, len(s), block):
        grid = [list(s[off + r * cols:off + (r + 1) * cols]) for r in range(rows)]
        out.extend(grid[r][c] for r, c in positions)
    return "".join(out)


def ReadingOrderRoute_decode(text: str, rows: int | str = 5, cols: int | str = 5, preset: str = "column", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    block = rows * cols
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of rows*cols"
    positions = _route_positions(rows, cols, preset)
    out = []
    for off in range(0, len(text), block):
        grid = [[""] * cols for _ in range(rows)]
        for ch, (r, c) in zip(text[off:off + block], positions):
            grid[r][c] = ch
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])


def _rotate_grid_clockwise(grid: List[List[str]]) -> List[List[str]]:
    return [list(row) for row in zip(*grid[::-1])]


def _rotate_grid_counterclockwise(grid: List[List[str]]) -> List[List[str]]:
    return [list(row) for row in zip(*grid)][::-1]


def RotatingSquareRoute_encode(text: str, size: int | str = 5, turns: int | str = 1, pad: str = "X") -> str:
    size = int(size)
    turns = int(turns) % 4
    block = size * size
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    for off in range(0, len(s), block):
        grid = [list(s[off + r * size:off + (r + 1) * size]) for r in range(size)]
        for _ in range(turns):
            grid = _rotate_grid_clockwise(grid)
        out.extend("".join(row) for row in grid)
    return "".join(out)


def RotatingSquareRoute_decode(text: str, size: int | str = 5, turns: int | str = 1, pad: str = "X") -> str:
    size = int(size)
    turns = int(turns) % 4
    block = size * size
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of size*size"
    out = []
    for off in range(0, len(text), block):
        grid = [list(text[off + r * size:off + (r + 1) * size]) for r in range(size)]
        for _ in range(turns):
            grid = _rotate_grid_counterclockwise(grid)
        out.extend("".join(row) for row in grid)
    return "".join(out).rstrip((pad or "X")[0])


def _parse_grille_mask(mask: str, rows: int, cols: int) -> List[Tuple[int, int]]:
    compact = "".join(ch for ch in str(mask) if ch in "01Xx#.")
    if len(compact) != rows * cols:
        raise ValueError("mask must contain rows*cols mask characters")
    holes = []
    for i, ch in enumerate(compact):
        if ch in "1Xx#":
            holes.append(divmod(i, cols))
    if not holes:
        raise ValueError("mask must contain at least one hole")
    return holes


def GrilleMask_encode(text: str, rows: int | str = 5, cols: int | str = 5, mask: str = "1000001000001000001000001", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    holes = _parse_grille_mask(mask, rows, cols)
    block = len(holes)
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    for off in range(0, len(s), block):
        grid = [[padch] * cols for _ in range(rows)]
        for ch, (r, c) in zip(s[off:off + block], holes):
            grid[r][c] = ch
        out.extend("".join(row) for row in grid)
    return "".join(out)


def GrilleMask_decode(text: str, rows: int | str = 5, cols: int | str = 5, mask: str = "1000001000001000001000001", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    holes = _parse_grille_mask(mask, rows, cols)
    cell_count = rows * cols
    if len(text) % cell_count:
        return "Err:ciphertext length must be a multiple of rows*cols"
    out = []
    for off in range(0, len(text), cell_count):
        block = text[off:off + cell_count]
        for r, c in holes:
            out.append(block[r * cols + c])
    return "".join(out).rstrip((pad or "X")[0])


def CardanGrille_encode(text: str, rows: int | str = 5, cols: int | str = 5, mask: str = "1000001000001000001000001", cover: str = "", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    holes = _parse_grille_mask(mask, rows, cols)
    cell_count = rows * cols
    block = len(holes)
    padch = (pad or "X")[0]
    cover_stream = cover or (padch * cell_count)
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    cover_i = 0
    for off in range(0, len(s), block):
        grid = []
        for _ in range(cell_count):
            grid.append(cover_stream[cover_i % len(cover_stream)])
            cover_i += 1
        for ch, (r, c) in zip(s[off:off + block], holes):
            grid[r * cols + c] = ch
        out.append("".join(grid))
    return "".join(out)


def CardanGrille_decode(text: str, rows: int | str = 5, cols: int | str = 5, mask: str = "1000001000001000001000001", cover: str = "", pad: str = "X") -> str:
    rows, cols = int(rows), int(cols)
    holes = _parse_grille_mask(mask, rows, cols)
    cell_count = rows * cols
    if len(text) % cell_count:
        return "Err:ciphertext length must be a multiple of rows*cols"
    out = []
    for off in range(0, len(text), cell_count):
        block = text[off:off + cell_count]
        for r, c in holes:
            out.append(block[r * cols + c])
    return "".join(out).rstrip((pad or "X")[0])


def _rotate_pos_cw(r: int, c: int, n: int) -> Tuple[int, int]:
    return c, n - 1 - r


def _fleissner_holes(mask: str, size: int) -> List[Tuple[int, int]]:
    compact = "".join(ch for ch in str(mask) if ch in "01Xx#.")
    if len(compact) != size * size:
        raise ValueError("mask must contain size*size mask characters")
    holes = [divmod(i, size) for i, ch in enumerate(compact) if ch in "1Xx#"]
    if len(holes) != (size * size) // 4:
        raise ValueError("turning grille mask must contain exactly size*size/4 holes")
    seen = set()
    for r, c in holes:
        rr, cc = r, c
        for _ in range(4):
            if (rr, cc) in seen:
                raise ValueError("turning grille mask overlaps during rotation")
            seen.add((rr, cc))
            rr, cc = _rotate_pos_cw(rr, cc, size)
    if len(seen) != size * size:
        raise ValueError("turning grille mask does not cover the full square")
    return holes


def FleissnerGrille_encode(text: str, size: int | str = 4, mask: str = "1100110000000000", pad: str = "X") -> str:
    size = int(size)
    holes = _fleissner_holes(mask, size)
    block = size * size
    padch = (pad or "X")[0]
    s = text
    if len(s) % block:
        s += padch * (block - len(s) % block)
    out = []
    for off in range(0, len(s), block):
        grid = [[padch] * size for _ in range(size)]
        idx = off
        current = holes[:]
        for _ in range(4):
            for r, c in current:
                grid[r][c] = s[idx]
                idx += 1
            current = [_rotate_pos_cw(r, c, size) for r, c in current]
        out.extend("".join(row) for row in grid)
    return "".join(out)


def FleissnerGrille_decode(text: str, size: int | str = 4, mask: str = "1100110000000000", pad: str = "X") -> str:
    size = int(size)
    holes = _fleissner_holes(mask, size)
    block = size * size
    if len(text) % block:
        return "Err:ciphertext length must be a multiple of size*size"
    out = []
    for off in range(0, len(text), block):
        grid = [list(text[off + r * size:off + (r + 1) * size]) for r in range(size)]
        current = holes[:]
        for _ in range(4):
            for r, c in current:
                out.append(grid[r][c])
            current = [_rotate_pos_cw(r, c, size) for r, c in current]
    return "".join(out).rstrip((pad or "X")[0])


def TurningCardanGrille_encode(text: str, size: int | str = 4, mask: str = "1100110000000000", pad: str = "X") -> str:
    return FleissnerGrille_encode(text, size, mask, pad)


def TurningCardanGrille_decode(text: str, size: int | str = 4, mask: str = "1100110000000000", pad: str = "X") -> str:
    return FleissnerGrille_decode(text, size, mask, pad)


def RasterBits_encode(text: str, width: int | str = 8, on: str = "#", off: str = ".") -> str:
    width = max(1, int(width))
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    rows = [bits[i:i+width] for i in range(0, len(bits), width)]
    on = (on or "#")[0]
    off = (off or ".")[0]
    return "\n".join("".join(on if bit == "1" else off for bit in row) for row in rows)


def RasterBits_decode(text: str, width: int | str = 8, on: str = "#", off: str = ".") -> str:
    on = (on or "#")[0]
    bits = "".join("1" if ch == on else "0" for ch in text if ch == on or ch == (off or ".")[0])
    bits = bits[:len(bits) - (len(bits) % 8)]
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def _hagelin_stream(seed: str, wheels: str = "17,19,21,23,25,26"):
    periods = [max(2, int(x.strip())) for x in str(wheels).split(",") if x.strip()] or [17, 19, 21, 23, 25, 26]
    state = sum((i + 1) * ord(ch) for i, ch in enumerate(seed or "HAGELIN")) or 1
    positions = [state % p for p in periods]
    while True:
        total = 0
        for i, p in enumerate(periods):
            positions[i] = (positions[i] + 1 + (state % (i + 2))) % p
            total += (positions[i] * (i + 3) + state) % 26
        state = (state * 1664525 + 1013904223 + total) & 0xFFFFFFFF
        yield total % 26


def HagelinToy_encode(text: str, seed: str = "HAGELIN", wheels: str = "17,19,21,23,25,26") -> str:
    stream = _hagelin_stream(seed, wheels)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) + k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


def HagelinToy_decode(text: str, seed: str = "HAGELIN", wheels: str = "17,19,21,23,25,26") -> str:
    stream = _hagelin_stream(seed, wheels)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) - k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)

_ENIGMA_ROTORS = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
_ENIGMA_REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}

def _enigma_parse_rotors(rotors: str) -> List[str]:
    parts = [p.strip().upper() for p in re.split(r"[,\s-]+", str(rotors)) if p.strip()]
    if not parts:
        parts = ["I", "II", "III"]
    out = []
    for part in parts[:3]:
        if part not in _ENIGMA_ROTORS:
            raise ValueError(f"unknown rotor {part!r}")
        out.append(part)
    while len(out) < 3:
        out.append(["I", "II", "III"][len(out)])
    return out

def _enigma_positions(setting: str) -> List[int]:
    letters = [ch for ch in str(setting).upper() if ch in ALPHA]
    letters = (letters + list("AAA"))[:3]
    return [ALPHA.index(ch) for ch in letters]

def _enigma_plugboard_pairs(plugboard: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for token in re.split(r"[\s,;]+", str(plugboard).upper()):
        token = "".join(ch for ch in token if ch in ALPHA)
        if len(token) != 2 or token[0] == token[1]:
            continue
        a, b = token
        if a in pairs or b in pairs:
            continue
        pairs[a] = b
        pairs[b] = a
    return pairs

def _enigma_step(rotor_names: List[str], pos: List[int]) -> None:
    notches = [_ENIGMA_ROTORS[name][1] for name in rotor_names]
    if ALPHA[pos[1]] in notches[1]:
        pos[0] = (pos[0] + 1) % 26
        pos[1] = (pos[1] + 1) % 26
    if ALPHA[pos[2]] in notches[2]:
        pos[1] = (pos[1] + 1) % 26
    pos[2] = (pos[2] + 1) % 26

def _enigma_forward(idx: int, wiring: str, pos: int, ring: int) -> int:
    shifted = (idx + pos - ring) % 26
    wired = ALPHA.index(wiring[shifted])
    return (wired - pos + ring) % 26

def _enigma_backward(idx: int, wiring: str, pos: int, ring: int) -> int:
    shifted = (idx + pos - ring) % 26
    wired = wiring.index(ALPHA[shifted])
    return (wired - pos + ring) % 26

def EnigmaI_encode(text: str, rotors: str = "I II III", reflector: str = "B", ring: str = "AAA", setting: str = "AAA", plugboard: str = "") -> str:
    """Enigma I style rotor machine simulation with three rotors and plugboard."""
    rotor_names = _enigma_parse_rotors(rotors)
    reflector_wiring = _ENIGMA_REFLECTORS.get(str(reflector).upper(), _ENIGMA_REFLECTORS["B"])
    rings = _enigma_positions(ring)
    pos = _enigma_positions(setting)
    plugs = _enigma_plugboard_pairs(plugboard)
    wirings = [_ENIGMA_ROTORS[name][0] for name in rotor_names]
    out = []
    for ch in text:
        up = ch.upper()
        if up not in ALPHA_SET:
            out.append(ch)
            continue
        _enigma_step(rotor_names, pos)
        up = plugs.get(up, up)
        idx = ALPHA.index(up)
        for i in (2, 1, 0):
            idx = _enigma_forward(idx, wirings[i], pos[i], rings[i])
        idx = ALPHA.index(reflector_wiring[idx])
        for i in (0, 1, 2):
            idx = _enigma_backward(idx, wirings[i], pos[i], rings[i])
        mapped = plugs.get(ALPHA[idx], ALPHA[idx])
        out.append(mapped if ch.isupper() else mapped.lower())
    return "".join(out)

def EnigmaI_decode(text: str, rotors: str = "I II III", reflector: str = "B", ring: str = "AAA", setting: str = "AAA", plugboard: str = "") -> str:
    return EnigmaI_encode(text, rotors, reflector, ring, setting, plugboard)

def _m209_stream(key: str, wheels: str = "26,25,23,21,19,17") -> Iterator[int]:
    periods = [max(2, int(x.strip())) for x in str(wheels).split(",") if x.strip()] or [26, 25, 23, 21, 19, 17]
    seed = sum((i + 1) * ord(ch) for i, ch in enumerate(key or "M209")) or 1
    positions = [(seed + i * 7) % p for i, p in enumerate(periods)]
    while True:
        active = 0
        for i, p in enumerate(periods):
            pin = ((positions[i] * 1103515245 + seed + i * 12345) >> (i + 3)) & 1
            if pin:
                active += i + 1
            positions[i] = (positions[i] + 1) % p
        seed = (seed * 1664525 + 1013904223 + active) & 0xFFFFFFFF
        yield (active * 3 + seed) % 26

def M209_encode(text: str, key: str = "M209", wheels: str = "26,25,23,21,19,17") -> str:
    """M-209/Hagelin inspired pin-wheel stream cipher."""
    stream = _m209_stream(key, wheels)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) + k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)

def M209_decode(text: str, key: str = "M209", wheels: str = "26,25,23,21,19,17") -> str:
    stream = _m209_stream(key, wheels)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) - k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)

def Typex_encode(text: str, rotors: str = "IV V II", reflector: str = "C", ring: str = "AAA", setting: str = "AAA", plugboard: str = "") -> str:
    """British Typex-inspired rotor machine profile using the Enigma engine."""
    return EnigmaI_encode(text, rotors, reflector, ring, setting, plugboard)

def Typex_decode(text: str, rotors: str = "IV V II", reflector: str = "C", ring: str = "AAA", setting: str = "AAA", plugboard: str = "") -> str:
    return Typex_encode(text, rotors, reflector, ring, setting, plugboard)

def _sigaba_stream(key: str = "SIGABA", control: str = "CONTROL") -> Iterator[int]:
    seed = sum((i + 1) * ord(ch) for i, ch in enumerate((key or "SIGABA") + (control or "CONTROL"))) or 1
    cipher_rotors = [(seed + 11 * i) % 26 for i in range(5)]
    control_rotors = [(seed // (i + 2) + 7 * i) % 26 for i in range(5)]
    index_rotors = [(seed // (i + 5) + 3 * i) % 10 for i in range(5)]
    while True:
        control_sum = sum((control_rotors[i] * (i + 3) + index_rotors[i]) for i in range(5))
        moving = {control_sum % 5, (control_sum // 5) % 5}
        shift = 0
        for i in range(5):
            if i in moving:
                cipher_rotors[i] = (cipher_rotors[i] + 1 + index_rotors[i]) % 26
            control_rotors[i] = (control_rotors[i] + 1 + (seed >> i)) % 26
            index_rotors[i] = (index_rotors[i] + control_rotors[i] + i) % 10
            shift += cipher_rotors[i] * (i + 1)
        seed = (seed * 1103515245 + 12345 + shift) & 0x7FFFFFFF
        yield shift % 26

def SIGABAToy_encode(text: str, key: str = "SIGABA", control: str = "CONTROL") -> str:
    """SIGABA-inspired rotor-controlled stream cipher."""
    stream = _sigaba_stream(key, control)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) + k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)

def SIGABAToy_decode(text: str, key: str = "SIGABA", control: str = "CONTROL") -> str:
    stream = _sigaba_stream(key, control)
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA_SET:
            k = next(stream)
            mapped = ALPHA[(ALPHA.index(up) - k) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


_HOMOPHONIC_POOLS = {
    "E": ["00", "01", "02", "03"], "T": ["04", "05", "06"], "A": ["07", "08", "09"],
    "O": ["10", "11", "12"], "I": ["13", "14"], "N": ["15", "16"], "S": ["17", "18"],
    "H": ["19", "20"], "R": ["21", "22"], "D": ["23", "24"], "L": ["25", "26"],
    "C": ["27", "28"], "U": ["29", "30"], "M": ["31", "32"], "W": ["33", "34"],
    "F": ["35"], "G": ["36"], "Y": ["37"], "P": ["38"], "B": ["39"], "V": ["40"],
    "K": ["41"], "J": ["42"], "X": ["43"], "Q": ["44"], "Z": ["45"],
}
_HOMOPHONIC_REVERSE = {code: ch for ch, codes in _HOMOPHONIC_POOLS.items() for code in codes}


def HomophonicSubstitution_encode(text: str) -> str:
    counts = {ch: 0 for ch in _HOMOPHONIC_POOLS}
    out = []
    for ch in to_upper(text):
        if ch in _HOMOPHONIC_POOLS:
            pool = _HOMOPHONIC_POOLS[ch]
            out.append(pool[counts[ch] % len(pool)])
            counts[ch] += 1
        elif ch.isspace():
            out.append("/")
    return " ".join(out)


def HomophonicSubstitution_decode(text: str) -> str:
    out = []
    for token in text.replace("/", " / ").split():
        if token == "/":
            out.append(" ")
        else:
            out.append(_HOMOPHONIC_REVERSE.get(token.zfill(2), ""))
    return "".join(out).lower()


def HeadlinePuzzle_encode(text: str, filler_word: str = "headline") -> str:
    filler = filler_word or "headline"
    words = []
    for ch in text:
        if ch.isalpha():
            head = ch.upper()
            words.append(head + filler[1:])
        elif ch.isspace():
            words.append("/")
    return " ".join(words)


def HeadlinePuzzle_decode(text: str, filler_word: str = "headline") -> str:
    out = []
    for token in text.split():
        if token == "/":
            out.append(" ")
        elif token:
            out.append(token[0])
    return "".join(out).lower()


def MurrayCode_encode(text: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    if len(bits) % 5:
        bits += "0" * (5 - len(bits) % 5)
    return " ".join(bits[i:i+5] for i in range(0, len(bits), 5))


def MurrayCode_decode(text: str) -> str:
    bits = "".join(ch for ch in text if ch in "01")
    bits = bits[:len(bits) - (len(bits) % 8)]
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


_MARITIME_FLAGS = {ch: f"[{ch}-flag]" for ch in ALPHA}
_ICS_PHRASES = {
    "A": "I have a diver down; keep well clear at slow speed",
    "B": "I am taking in, discharging, or carrying dangerous goods",
    "C": "Yes",
    "D": "Keep clear of me; I am maneuvering with difficulty",
    "E": "I am altering my course to starboard",
    "F": "I am disabled; communicate with me",
    "G": "I require a pilot",
    "H": "I have a pilot on board",
    "I": "I am altering my course to port",
    "J": "I am on fire and have dangerous cargo; keep clear",
    "K": "I wish to communicate with you",
    "L": "You should stop your vessel instantly",
    "M": "My vessel is stopped and making no way",
    "N": "No",
    "O": "Man overboard",
    "P": "All persons should report on board; vessel is about to proceed",
    "Q": "My vessel is healthy and I request free pratique",
    "R": "Received",
    "S": "I am operating astern propulsion",
    "T": "Keep clear of me; I am engaged in pair trawling",
    "U": "You are running into danger",
    "V": "I require assistance",
    "W": "I require medical assistance",
    "X": "Stop carrying out your intentions and watch for my signals",
    "Y": "I am dragging my anchor",
    "Z": "I require a tug",
}
_CIRTH_RUNES = dict(zip(ALPHA, "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᛁᛃᛇᛈᛉᛊᛏᛒᛖᛗᛚᛜᛟᛞᚪᚫᚣ"))
_TENGWAR_TOKENS = {
    "A":"[tinco]", "B":"[parma]", "C":"[calma]", "D":"[quesse]", "E":"[ando]", "F":"[umbar]",
    "G":"[anga]", "H":"[ungwe]", "I":"[thule]", "J":"[formen]", "K":"[harma]", "L":"[hwesta]",
    "M":"[anto]", "N":"[ampa]", "O":"[anca]", "P":"[unque]", "Q":"[numen]", "R":"[malta]",
    "S":"[noldo]", "T":"[nwalme]", "U":"[ore]", "V":"[vala]", "W":"[anna]", "X":"[vilya]",
    "Y":"[romen]", "Z":"[arda]",
}
_ZODIAC_SYMBOLS = dict(zip(ALPHA, "♈♉♊♋♌♍♎♏♐♑♒♓☉☽☿♀♂♃♄⛢♆♇⚷⚸⚹⚺"))
_WINGDINGS_TOKENS = {ch: f"[wd-{i:02d}]" for i, ch in enumerate(ALPHA, 1)}


def _simple_symbol_encode(text: str, mapping: Dict[str, str]) -> str:
    out = []
    for ch in text:
        up = ch.upper()
        if up in mapping:
            out.append(mapping[up])
        elif ch.isspace():
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _simple_symbol_decode(text: str, mapping: Dict[str, str]) -> str:
    rev = {v: k for k, v in mapping.items()}
    if any(token.startswith("[") for token in mapping.values()):
        out = text
        for token, ch in sorted(rev.items(), key=lambda item: -len(item[0])):
            out = out.replace(token, ch.lower())
        return out
    return "".join(rev.get(ch, " " if ch.isspace() else ch) for ch in text).lower()


def MaritimeFlags_encode(text: str) -> str:
    return _simple_symbol_encode(text, _MARITIME_FLAGS)


def MaritimeFlags_decode(text: str) -> str:
    return _simple_symbol_decode(text, _MARITIME_FLAGS)


def InternationalSignals_encode(text: str) -> str:
    out = []
    for ch in only_alpha(text, keep_spaces=True):
        if ch == " ":
            out.append("/")
        elif ch in _ICS_PHRASES:
            out.append(f"{ch}: {_ICS_PHRASES[ch]}")
    return " | ".join(out)


def InternationalSignals_decode(text: str) -> str:
    rev = {re.sub(r"[^A-Z0-9]+", "", v.upper()): k for k, v in _ICS_PHRASES.items()}
    out = []
    for part in re.split(r"\s*\|\s*|\n+", text):
        part = part.strip()
        if not part:
            continue
        if part == "/":
            out.append(" ")
            continue
        m = re.match(r"([A-Za-z])\s*:", part)
        if m:
            out.append(m.group(1).upper())
            continue
        norm = re.sub(r"[^A-Z0-9]+", "", part.upper())
        out.append(rev.get(norm, part[:1].upper()))
    return "".join(out).lower()


def Cirth_encode(text: str) -> str:
    return _simple_symbol_encode(text, _CIRTH_RUNES)


def Cirth_decode(text: str) -> str:
    return _simple_symbol_decode(text, _CIRTH_RUNES)


def TengwarTokens_encode(text: str) -> str:
    return _simple_symbol_encode(text, _TENGWAR_TOKENS)


def TengwarTokens_decode(text: str) -> str:
    return _simple_symbol_decode(text, _TENGWAR_TOKENS)


def ZodiacSymbols_encode(text: str) -> str:
    return _simple_symbol_encode(text, _ZODIAC_SYMBOLS)


def ZodiacSymbols_decode(text: str) -> str:
    return _simple_symbol_decode(text, _ZODIAC_SYMBOLS)


def WingdingsTokens_encode(text: str) -> str:
    return _simple_symbol_encode(text, _WINGDINGS_TOKENS)


def WingdingsTokens_decode(text: str) -> str:
    return _simple_symbol_decode(text, _WINGDINGS_TOKENS)


_SEMAPHORE_ARM_PAIRS = [f"{a}-{b}" for a in range(1, 9) for b in range(a + 1, 9)]
_SEMAPHORE_ARMS = {ch: _SEMAPHORE_ARM_PAIRS[i] for i, ch in enumerate(ALPHA)}
_SEMAPHORE_ARMS_REV = {v: k for k, v in _SEMAPHORE_ARMS.items()}
_PIGPEN_UNICODE = dict(zip(ALPHA, "△◇□▽○◁▷⬠⬡⬢⬣⬤◐◑◒◓◔◕◖◗◜◝◞◟◆◇"))
_PIGPEN_UNICODE_REV = {v: k for k, v in _PIGPEN_UNICODE.items()}
_BRAILLE_GRADE1_DIGITS = dict(zip("1234567890", "ABCDEFGHIJ"))


def SemaphoreArms_encode(text: str) -> str:
    out = []
    for ch in to_upper(text):
        if ch in _SEMAPHORE_ARMS:
            out.append(_SEMAPHORE_ARMS[ch])
        elif ch.isspace():
            out.append("/")
    return "[SEMARMS]|" + " ".join(out)


def SemaphoreArms_decode(text: str) -> str:
    s = text[len("[SEMARMS]|"):] if text.startswith("[SEMARMS]|") else text
    out = []
    for token in s.replace("/", " / ").split():
        if token == "/":
            out.append(" ")
        else:
            out.append(_SEMAPHORE_ARMS_REV.get(token, ""))
    return "".join(out).lower()


def PigpenUnicode_encode(text: str) -> str:
    return _simple_symbol_encode(text, _PIGPEN_UNICODE)


def PigpenUnicode_decode(text: str) -> str:
    return _simple_symbol_decode(text, _PIGPEN_UNICODE)


def BrailleGrade1_encode(text: str) -> str:
    out = []
    for ch in text:
        up = ch.upper()
        if ch.isdigit():
            out.append("⠼" + chr(0x2800 + BRAILLE_PATTERNS[_BRAILLE_GRADE1_DIGITS[ch]]))
        elif up in BRAILLE_PATTERNS:
            out.append(chr(0x2800 + BRAILLE_PATTERNS[up]))
        elif ch.isspace():
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def BrailleGrade1_decode(text: str) -> str:
    digit_rev = {chr(0x2800 + BRAILLE_PATTERNS[v]): k for k, v in _BRAILLE_GRADE1_DIGITS.items()}
    out = []
    i = 0
    while i < len(text):
        if text[i] == "⠼" and i + 1 < len(text):
            out.append(digit_rev.get(text[i + 1], ""))
            i += 2
            continue
        out.append(BRAILLE_REV.get(text[i], " " if text[i].isspace() else text[i]))
        i += 1
    return "".join(out).lower()


def BaconBiliteral_encode(text: str, a_char: str = "A", b_char: str = "B") -> str:
    a_char = (a_char or "A")[0]
    b_char = (b_char or "B")[0]
    out = []
    for ch in only_alpha(text):
        bits = f"{ALPHA.index(ch):05b}"
        out.append("".join(b_char if bit == "1" else a_char for bit in bits))
    return " ".join(out)


def BaconBiliteral_decode(text: str, a_char: str = "A", b_char: str = "B") -> str:
    a_char = (a_char or "A")[0]
    b_char = (b_char or "B")[0]
    compact = "".join(ch for ch in text if ch in {a_char, b_char})
    out = []
    for group in chunk(compact[:len(compact) - (len(compact) % 5)], 5):
        val = int("".join("1" if ch == b_char else "0" for ch in group), 2)
        if 0 <= val < 26:
            out.append(ALPHA[val])
    return "".join(out).lower()


def WhitespaceBinary_encode(text: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    return "".join("\t" if bit == "1" else " " for bit in bits)


def WhitespaceBinary_decode(text: str) -> str:
    bits = "".join("1" if ch == "\t" else "0" for ch in text if ch in {" ", "\t"})
    bits = bits[:len(bits) - (len(bits) % 8)]
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def SnowSteg_encode(text: str, cover: str = "snow") -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    lines = (cover or "snow").splitlines() or [cover or "snow"]
    out = []
    for i, bit in enumerate(bits):
        base = lines[i % len(lines)].rstrip(" ")
        out.append(base + ("  " if bit == "1" else " "))
    return "[SNOW]" + str(len(bits)) + "|\n" + "\n".join(out)


def SnowSteg_decode(text: str, cover: str = "snow") -> str:
    body = text
    bit_len = None
    if text.startswith("[SNOW]") and "|\n" in text:
        meta, body = text.split("|\n", 1)
        bit_len = int(meta[len("[SNOW]"):])
    bits = []
    for line in body.splitlines():
        spaces = len(line) - len(line.rstrip(" "))
        if spaces:
            bits.append("1" if spaces >= 2 else "0")
    bitstr = "".join(bits)
    if bit_len is not None:
        bitstr = bitstr[:bit_len]
    bitstr = bitstr[:len(bitstr) - (len(bitstr) % 8)]
    try:
        return bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


_RFC1924_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"


def _base_n_encode_bytes(data: bytes, alphabet: str) -> str:
    if not data:
        return ""
    base = len(alphabet)
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, rem = divmod(n, base)
        out.append(alphabet[rem])
    leading = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * leading + "".join(reversed(out or [alphabet[0]]))


def _base_n_decode_bytes(text: str, alphabet: str) -> bytes:
    if not text:
        return b""
    base = len(alphabet)
    lookup = {ch: i for i, ch in enumerate(alphabet)}
    n = 0
    for ch in text:
        if ch not in lookup:
            continue
        n = n * base + lookup[ch]
    leading = len(text) - len(text.lstrip(alphabet[0]))
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big") if n else b""
    return b"\x00" * leading + body


def RFC1924Base85_encode(text: str) -> str:
    data = text.encode("utf-8")
    return f"[RFC1924-85]{len(data)}|" + _base_n_encode_bytes(data, _RFC1924_ALPHABET)


def RFC1924Base85_decode(text: str) -> str:
    body = text
    expected = None
    if text.startswith("[RFC1924-85]") and "|" in text:
        meta, body = text.split("|", 1)
        expected = int(meta[len("[RFC1924-85]"):])
    try:
        data = _base_n_decode_bytes(body, _RFC1924_ALPHABET)
        if expected is not None:
            data = data[-expected:] if expected else b""
        return data.decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def PEMArmor_encode(text: str, label: str = "MESSAGE") -> str:
    label = (label or "MESSAGE").upper()
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    lines = "\n".join(chunk(b64, 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----"


def PEMArmor_decode(text: str, label: str = "MESSAGE") -> str:
    lines = [line.strip() for line in text.strip().splitlines() if line.strip() and not line.startswith("-----")]
    try:
        return base64.b64decode("".join(lines)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def MessagePackHex_encode(text: str) -> str:
    data = text.encode("utf-8")
    if len(data) <= 31:
        packed = bytes([0xA0 | len(data)]) + data
    elif len(data) <= 255:
        packed = b"\xD9" + bytes([len(data)]) + data
    elif len(data) <= 65535:
        packed = b"\xDA" + len(data).to_bytes(2, "big") + data
    else:
        packed = b"\xDB" + len(data).to_bytes(4, "big") + data
    return packed.hex().upper()


def MessagePackHex_decode(text: str) -> str:
    try:
        data = bytes.fromhex("".join(ch for ch in text if ch in string.hexdigits))
        if not data:
            return ""
        first = data[0]
        if 0xA0 <= first <= 0xBF:
            length = first & 0x1F; start = 1
        elif first == 0xD9:
            length = data[1]; start = 2
        elif first == 0xDA:
            length = int.from_bytes(data[1:3], "big"); start = 3
        elif first == 0xDB:
            length = int.from_bytes(data[1:5], "big"); start = 5
        else:
            return "Err:unsupported MessagePack type"
        return data[start:start+length].decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def OpenPGPArmor_encode(text: str, label: str = "MESSAGE") -> str:
    label = (label or "MESSAGE").upper()
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    lines = "\n".join(chunk(b64, 64))
    return f"-----BEGIN PGP {label}-----\n\n{lines}\n-----END PGP {label}-----"


def OpenPGPArmor_decode(text: str, label: str = "MESSAGE") -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("-----")]
    try:
        return base64.b64decode("".join(lines)).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def _intel_hex_record(addr: int, rectype: int, data: bytes) -> str:
    length = len(data)
    fields = bytes([length, (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + data
    checksum = (-sum(fields)) & 0xFF
    return ":" + fields.hex().upper() + f"{checksum:02X}"


def IntelHex_encode(text: str, bytes_per_record: int | str = 16) -> str:
    data = text.encode("utf-8")
    n = max(1, int(bytes_per_record))
    lines = []
    for addr in range(0, len(data), n):
        lines.append(_intel_hex_record(addr & 0xFFFF, 0, data[addr:addr+n]))
    lines.append(_intel_hex_record(0, 1, b""))
    return "\n".join(lines)


def IntelHex_decode(text: str, bytes_per_record: int | str = 16) -> str:
    out = bytearray()
    try:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                return "Err:invalid Intel HEX record"
            raw = bytes.fromhex(line[1:])
            length, rectype = raw[0], raw[3]
            data = raw[4:4+length]
            if ((sum(raw[:-1]) + raw[-1]) & 0xFF) != 0:
                return "Err:Intel HEX checksum mismatch"
            if rectype == 0:
                out.extend(data)
            elif rectype == 1:
                break
        return bytes(out).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"


def _srecord_line(addr: int, data: bytes) -> str:
    addr_bytes = addr.to_bytes(2, "big")
    count = len(addr_bytes) + len(data) + 1
    body = bytes([count]) + addr_bytes + data
    checksum = (~sum(body)) & 0xFF
    return "S1" + body.hex().upper() + f"{checksum:02X}"


def MotorolaSRecord_encode(text: str, bytes_per_record: int | str = 16) -> str:
    data = text.encode("utf-8")
    n = max(1, int(bytes_per_record))
    lines = []
    for addr in range(0, len(data), n):
        lines.append(_srecord_line(addr & 0xFFFF, data[addr:addr+n]))
    lines.append("S9030000FC")
    return "\n".join(lines)


def MotorolaSRecord_decode(text: str, bytes_per_record: int | str = 16) -> str:
    out = bytearray()
    try:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("S9"):
                break
            if not line.startswith("S1"):
                return "Err:unsupported S-record type"
            raw = bytes.fromhex(line[2:])
            count = raw[0]
            if count != len(raw) - 1:
                return "Err:S-record byte count mismatch"
            if ((sum(raw[:-1]) + raw[-1]) & 0xFF) != 0xFF:
                return "Err:S-record checksum mismatch"
            out.extend(raw[3:-1])
        return bytes(out).decode("utf-8")
    except Exception as exc:
        return f"Err:{exc}"

# =============================================================================
# Vigenère family
# =============================================================================

def _vig_core(text: str, key: str, enc: bool, keep_others: bool = True) -> str:
    key_shifts = key_to_shifts(key)
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = key_shifts[ki % len(key_shifts)] if key_shifts else 0
            a = ALPHA.index(cu)
            b = (a + s) % 26 if enc else (a - s) % 26
            out.append(ALPHA[b] if ch.isupper() else ALPHA[b].lower())
            ki += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Vigenere_encode(text: str, key: str = "LEMON", keep_others: bool = True) -> str:
    return _vig_core(text, key, True, keep_others)

def Vigenere_decode(text: str, key: str = "LEMON", keep_others: bool = True) -> str:
    return _vig_core(text, key, False, keep_others)

def ChiffreIndechiffrable_encode(text: str, key: str = "VIGENERE", keep_others: bool = True) -> str:
    return Vigenere_encode(text, key, keep_others)

def ChiffreIndechiffrable_decode(text: str, key: str = "VIGENERE", keep_others: bool = True) -> str:
    return Vigenere_decode(text, key, keep_others)

def Autokey_encode(text: str, key: str = "QUEENLY", keep_others: bool = True) -> str:
    stream = list(only_alpha(key))
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = ALPHA.index(stream[0]) if stream else 0
            stream = stream[1:] + [cu]
            a = ALPHA.index(cu)
            b = ALPHA[(a + s) % 26]
            out.append(b if ch.isupper() else b.lower())
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Autokey_decode(text: str, key: str = "QUEENLY", keep_others: bool = True) -> str:
    stream = list(only_alpha(key))
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = ALPHA.index(stream[0]) if stream else 0
            a = ALPHA.index(cu)
            p = ALPHA[(a - s) % 26]
            out.append(p if ch.isupper() else p.lower())
            stream = stream[1:] + [p]
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Beaufort_encode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    ks = key_to_shifts(key)
    out = []
    i = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = ks[i % len(ks)] if ks else 0
            p = ALPHA.index(cu)
            c = (s - p) % 26
            new = ALPHA[c]
            out.append(new if ch.isupper() else new.lower())
            i += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Beaufort_decode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    return Beaufort_encode(text, key, keep_others)

def Gronsfeld_encode(text: str, key: str = "314159", keep_others: bool = True) -> str:
    digits = [int(d) for d in key if d.isdigit()]
    out = []
    i = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = digits[i % len(digits)] if digits else 0
            a = ALPHA.index(cu)
            b = ALPHA[(a + s) % 26]
            out.append(b if ch.isupper() else b.lower())
            i += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def Gronsfeld_decode(text: str, key: str = "314159", keep_others: bool = True) -> str:
    digits = [int(d) for d in key if d.isdigit()]
    out = []
    i = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            s = digits[i % len(digits)] if digits else 0
            a = ALPHA.index(cu)
            p = ALPHA[(a - s) % 26]
            out.append(p if ch.isupper() else p.lower())
            i += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

# Porta (historic/table are equivalent for this build)
def _porta_shift(ch: str, k: str) -> str:
    k = k.upper()
    if k not in ALPHA_SET or ch.upper() not in ALPHA_SET:
        return ch
    idx = (ALPHA.index(k)) // 2
    left = "ABCDEFGHIJKLM"
    right = "NOPQRSTUVWXYZ"
    lch = ch.upper()
    if lch in left:
        pos = left.index(lch)
        res = right[(pos + idx) % 13]
    else:
        pos = right.index(lch)
        res = left[(pos + idx) % 13]
    return res if ch.isupper() else res.lower()

def PortaHistoric_encode(text: str, key: str = "PORTA", keep_others: bool = True) -> str:
    out = []
    k = only_alpha(key) or "A"
    i = 0
    for ch in text:
        if ch.upper() in ALPHA_SET:
            out.append(_porta_shift(ch, k[i % len(k)]))
            i += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def PortaHistoric_decode(text: str, key: str = "PORTA", keep_others: bool = True) -> str:
    return PortaHistoric_encode(text, key, keep_others)

PortaTable_encode = PortaHistoric_encode
PortaTable_decode = PortaHistoric_decode

def RunningKey_encode(text: str, key: str = "THENEVERENDINGSTORY", keep_others: bool = True) -> str:
    return Vigenere_encode(text, key, keep_others)

def RunningKey_decode(text: str, key: str = "THENEVERENDINGSTORY", keep_others: bool = True) -> str:
    return Vigenere_decode(text, key, keep_others)


def RunningKeyBook_encode(text: str, book: str = "THENEVERENDINGSTORY", keep_others: bool = True) -> str:
    key = only_alpha(book) or "A"
    return Vigenere_encode(text, key, keep_others)

def RunningKeyBook_decode(text: str, book: str = "THENEVERENDINGSTORY", keep_others: bool = True) -> str:
    key = only_alpha(book) or "A"
    return Vigenere_decode(text, key, keep_others)

def InterruptedKey_encode(text: str, key: str = "CIPHER", period: int | str = 5, keep_others: bool = True) -> str:
    key = only_alpha(key) or "A"
    period = max(1, int(period))
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            kch = key[(pos % period) % len(key)]
            mapped = ALPHA[(ALPHA.index(cu) + ALPHA.index(kch)) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def InterruptedKey_decode(text: str, key: str = "CIPHER", period: int | str = 5, keep_others: bool = True) -> str:
    key = only_alpha(key) or "A"
    period = max(1, int(period))
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            kch = key[(pos % period) % len(key)]
            mapped = ALPHA[(ALPHA.index(cu) - ALPHA.index(kch)) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def ProgressiveKey_encode(text: str, key: str = "LEMON", increment: int | str = 1, group: int | str = 5, keep_others: bool = True) -> str:
    key_shifts = key_to_shifts(key)
    if not key_shifts:
        return "Err:key must contain letters"
    increment = int(increment)
    group = max(1, int(group))
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = key_shifts[pos % len(key_shifts)] + (pos // group) * increment
            mapped = ALPHA[(ALPHA.index(cu) + shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def ProgressiveKey_decode(text: str, key: str = "LEMON", increment: int | str = 1, group: int | str = 5, keep_others: bool = True) -> str:
    key_shifts = key_to_shifts(key)
    if not key_shifts:
        return "Err:key must contain letters"
    increment = int(increment)
    group = max(1, int(group))
    out = []
    pos = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = key_shifts[pos % len(key_shifts)] + (pos // group) * increment
            mapped = ALPHA[(ALPHA.index(cu) - shift) % 26]
            out.append(mapped if ch.isupper() else mapped.lower())
            pos += 1
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def BeaufortAutokey_encode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    stream = list(only_alpha(key) or "A")
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = ALPHA.index(stream[0])
            c = (k - ALPHA.index(cu)) % 26
            mapped = ALPHA[c]
            out.append(mapped if ch.isupper() else mapped.lower())
            stream = stream[1:] + [cu]
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def BeaufortAutokey_decode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    stream = list(only_alpha(key) or "A")
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            k = ALPHA.index(stream[0])
            p = (k - ALPHA.index(cu)) % 26
            mapped = ALPHA[p]
            out.append(mapped if ch.isupper() else mapped.lower())
            stream = stream[1:] + [mapped]
        else:
            out.append(ch if keep_others else "")
    return "".join(out)

def VariantBeaufortAutokey_encode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    return Autokey_encode(text, key, keep_others)

def VariantBeaufortAutokey_decode(text: str, key: str = "FORT", keep_others: bool = True) -> str:
    return Autokey_decode(text, key, keep_others)

def OTPLetters_encode(text: str, key: str = "XMCKL", keep_others: bool = True) -> str:
    return Vigenere_encode(text, key, keep_others)

def OTPLetters_decode(text: str, key: str = "XMCKL", keep_others: bool = True) -> str:
    return Vigenere_decode(text, key, keep_others)

# =============================================================================
# Fun / novelty
# =============================================================================

def Backslang_encode(text: str) -> str: return text[::-1]
def Backslang_decode(text: str) -> str: return text[::-1]

def Rovarspraket_encode(text: str) -> str:
    vowels = set("AEIOUYaeiouy")
    out = []
    for ch in text:
        if ch.isalpha() and ch not in vowels:
            o = ch + ("o" if ch.islower() else "O") + ch
            out.append(o)
        else:
            out.append(ch)
    return "".join(out)

def Rovarspraket_decode(text: str) -> str:
    vowels = set("AEIOUYaeiouy")
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isalpha() and ch not in vowels:
            if i+2 < len(text) and (text[i+1] in "oO") and (text[i+2] == ch):
                out.append(ch); i += 3; continue
        out.append(ch); i += 1
    return "".join(out)

def Tutnese_encode(text: str) -> str:
    rules = {
        'b':'bub', 'c':'cash', 'd':'dud', 'f':'fuf', 'g':'gug', 'h':'hash',
        'j':'jug', 'k':'kuck', 'l':'lul', 'm':'mum', 'n':'nun', 'p':'pup',
        'q':'quack', 'r':'rur', 's':'sus', 't':'tut', 'v':'vuv', 'w':'wack',
        'x':'ex', 'y':'yub', 'z':'zub',
        ' ': ' ', '\t':'\t', '\n':'\n'
    }
    out = []
    for ch in text:
        lower = ch.lower()
        if lower in rules:
            w = rules[lower]
            out.append(w if ch.islower() else w.capitalize())
        elif lower in "aeiou":
            w = f"{lower}yay"
            out.append(w if ch.islower() else w.capitalize())
        else:
            out.append(ch)
    return "[TUT]|" + "".join(out)

def Tutnese_decode(text: str) -> str:
    s = text
    if s.startswith("[TUT]|"):
        s = s[len("[TUT]|"):]
    pairs = {
        'bub':'b','cash':'c','dud':'d','fuf':'f','gug':'g','hash':'h',
        'jug':'j','kuck':'k','lul':'l','mum':'m','nun':'n','pup':'p',
        'quack':'q','rur':'r','sus':'s','tut':'t','vuv':'v','wack':'w',
        'ex':'x','yub':'y','zub':'z'
    }
    i = 0; out = []
    while i < len(s):
        if s[i].isspace():
            out.append(s[i]); i += 1; continue
        matched = False
        for L in (5,4,3,2):
            if i+L <= len(s):
                seg = s[i:i+L]; seg_l = seg.lower()
                if seg_l in pairs:
                    ch = pairs[seg_l]
                    out.append(ch if seg.islower() else ch.upper())
                    i += L; matched = True; break
                if seg_l.endswith("yay") and len(seg_l) == 4 and seg_l[0] in "aeiou":
                    ch = seg_l[0]
                    out.append(ch if seg.islower() else ch.upper())
                    i += L; matched = True; break
        if not matched:
            out.append(s[i]); i += 1
    return "".join(out)

LEET_MAP = {
    'A':'4', 'B':'8', 'C':'<', 'D':'|)', 'E':'3', 'F':'ph', 'G':'6', 'H':'#',
    'I':'1', 'J':']', 'K':'|<', 'L':'1_', 'M':'^^', 'N':'^/', 'O':'0', 'P':'|*',
    'Q':'(,)', 'R':'|2', 'S':'5', 'T':'7', 'U':'(_)', 'V':'\\/', 'W':'\\/\\/',
    'X':'}{', 'Y':'`/', 'Z':'2'
}
REV_LEET = {v:k for k,v in sorted(LEET_MAP.items(), key=lambda kv: -len(kv[1]))}

def LEET_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in LEET_MAP:
            out.append(LEET_MAP[cu])
        else:
            out.append(ch)
    return "[LEET]|" + "".join(out)

def LEET_decode(text: str) -> str:
    s = text
    if s.startswith("[LEET]|"):
        s = s[len("[LEET]|"):]
    out = []
    i = 0
    tokens = sorted(REV_LEET.keys(), key=len, reverse=True)
    while i < len(s):
        matched = False
        for tok in tokens:
            if s.startswith(tok, i):
                out.append(REV_LEET[tok])
                i += len(tok)
                matched = True
                break
        if not matched:
            out.append(s[i].upper() if s[i].isalpha() else s[i])
            i += 1
    return "".join(out).lower()

def KeyboardSub_encode(text: str) -> str:
    line1 = "QWERTYUIOP"
    line2 = "ASDFGHJKL"
    line3 = "ZXCVBNM"
    subs = {}
    for row in (line1, line2, line3):
        for i, ch in enumerate(row):
            subs[ch] = row[(i+1) % len(row)]
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in subs:
            rep = subs[cu]
            out.append(rep if ch.isupper() else rep.lower())
        else:
            out.append(ch)
    return "".join(out)

def KeyboardSub_decode(text: str) -> str:
    line1 = "QWERTYUIOP"
    line2 = "ASDFGHJKL"
    line3 = "ZXCVBNM"
    subs = {}
    for row in (line1, line2, line3):
        for i, ch in enumerate(row):
            subs[row[(i+1) % len(row)]] = ch
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in subs:
            rep = subs[cu]
            out.append(rep if ch.isupper() else rep.lower())
        else:
            out.append(ch)
    return "".join(out)

def KeyboardReversed_encode(text: str) -> str:
    qwerty = "QWERTYUIOPASDFGHJKLZXCVBNM"
    rev = qwerty[::-1]
    return apply_monoalpha(text, qwerty, rev, keep_others=True)

def KeyboardReversed_decode(text: str) -> str:
    qwerty = "QWERTYUIOPASDFGHJKLZXCVBNM"
    rev = qwerty[::-1]
    return apply_monoalpha(text, rev, qwerty, keep_others=True)


_KEYBOARD_ROWS = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"]
_KEYBOARD_POS = {ch: (r + 1, c + 1) for r, row in enumerate(_KEYBOARD_ROWS) for c, ch in enumerate(row)}
_KEYBOARD_REV = {pos: ch for ch, pos in _KEYBOARD_POS.items()}

def KeyboardCoordinate_encode(text: str, sep: str = ".") -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _KEYBOARD_POS:
            r, c = _KEYBOARD_POS[cu]
            out.append(f"{r}{sep}{c}")
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def KeyboardCoordinate_decode(text: str, sep: str = ".") -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
            continue
        nums = re.findall(r"\d+", tok)
        if len(nums) >= 2:
            out.append(_KEYBOARD_REV.get((int(nums[0]), int(nums[1])), ""))
        else:
            out.append(tok)
    return "".join(out).lower()

def QWERTYAdjacent_encode(text: str, direction: str = "right") -> str:
    direction = (direction or "right").lower()
    dr, dc = {
        "left": (0, -1), "right": (0, 1), "up": (-1, 0), "down": (1, 0),
    }.get(direction, (0, 1))
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _KEYBOARD_POS:
            r, c = _KEYBOARD_POS[cu]
            row = _KEYBOARD_ROWS[r - 1]
            if dr == 0:
                nc = ((c - 1 + dc) % len(row)) + 1
                rep = _KEYBOARD_REV[(r, nc)]
            else:
                nr = ((r - 1 + dr) % len(_KEYBOARD_ROWS)) + 1
                nrow = _KEYBOARD_ROWS[nr - 1]
                nc = min(c, len(nrow))
                rep = _KEYBOARD_REV[(nr, nc)]
            out.append(rep if ch.isupper() else rep.lower())
        else:
            out.append(ch)
    return "".join(out)

def QWERTYAdjacent_decode(text: str, direction: str = "right") -> str:
    inverse = {"left": "right", "right": "left", "up": "down", "down": "up"}
    return QWERTYAdjacent_encode(text, inverse.get((direction or "right").lower(), "left"))


_CHESSBOARD_ALPH = ALPHA + string.digits
_CHESSBOARD_SQUARES = [f"{file}{rank}" for rank in range(1, 9) for file in "ABCDEFGH"]
_CHESSBOARD_MAP = {ch: _CHESSBOARD_SQUARES[i] for i, ch in enumerate(_CHESSBOARD_ALPH)}
_CHESSBOARD_REV = {v: k for k, v in _CHESSBOARD_MAP.items()}

def ChessboardCoordinate_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _CHESSBOARD_MAP:
            out.append(_CHESSBOARD_MAP[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def ChessboardCoordinate_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        up = tok.upper()
        if up == "/":
            out.append(" ")
        elif up in _CHESSBOARD_REV:
            out.append(_CHESSBOARD_REV[up])
        else:
            out.append(tok)
    return "".join(out).lower()


A1Z26_SEP = "-"

def A1Z26_encode(text: str) -> str:
    tokens = []
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            tokens.append(str(ALPHA.index(cu) + 1))
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return A1Z26_SEP.join(tokens)

def A1Z26_decode(text: str) -> str:
    normalized = text.replace(",", " ").replace(";", " ").strip()
    if A1Z26_SEP in normalized or "/" in normalized:
        parts = normalized.replace("/", f"{A1Z26_SEP}/{A1Z26_SEP}").split(A1Z26_SEP)
    else:
        parts = normalized.split()
    out = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if part == "/":
            out.append(" ")
            continue
        try:
            n = int(part)
            out.append(ALPHA[n - 1] if 1 <= n <= 26 else "")
        except Exception:
            out.append(part)
    return "".join(out).lower()

NATO_WORDS = {
    "A":"Alfa", "B":"Bravo", "C":"Charlie", "D":"Delta", "E":"Echo", "F":"Foxtrot",
    "G":"Golf", "H":"Hotel", "I":"India", "J":"Juliett", "K":"Kilo", "L":"Lima",
    "M":"Mike", "N":"November", "O":"Oscar", "P":"Papa", "Q":"Quebec", "R":"Romeo",
    "S":"Sierra", "T":"Tango", "U":"Uniform", "V":"Victor", "W":"Whiskey", "X":"X-ray",
    "Y":"Yankee", "Z":"Zulu", "0":"Zero", "1":"One", "2":"Two", "3":"Three",
    "4":"Four", "5":"Five", "6":"Six", "7":"Seven", "8":"Eight", "9":"Nine"
}
NATO_REV = {v.upper().replace("-", ""): k for k, v in NATO_WORDS.items()}

def NATO_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in NATO_WORDS:
            out.append(NATO_WORDS[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def NATO_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
        else:
            out.append(NATO_REV.get(tok.upper().replace("-", ""), tok))
    return "".join(out).lower()


MULTITAP_MAP = {
    "A":"2", "B":"22", "C":"222", "D":"3", "E":"33", "F":"333",
    "G":"4", "H":"44", "I":"444", "J":"5", "K":"55", "L":"555",
    "M":"6", "N":"66", "O":"666", "P":"7", "Q":"77", "R":"777", "S":"7777",
    "T":"8", "U":"88", "V":"888", "W":"9", "X":"99", "Y":"999", "Z":"9999",
    "0":"0", "1":"1", "2":"22222", "3":"3333", "4":"4444", "5":"5555",
    "6":"6666", "7":"77777", "8":"8888", "9":"99999"
}
MULTITAP_REV = {v: k for k, v in MULTITAP_MAP.items()}

def MultiTap_encode(text: str) -> str:
    tokens = []
    for ch in text:
        cu = ch.upper()
        if cu in MULTITAP_MAP:
            tokens.append(MULTITAP_MAP[cu])
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return " ".join(tokens)

def MultiTap_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
        else:
            out.append(MULTITAP_REV.get(tok, tok))
    return "".join(out).lower()


T9_GROUPS = {
    "2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL",
    "6": "MNO", "7": "PQRS", "8": "TUV", "9": "WXYZ",
}
T9_MAP = {ch: digit for digit, letters in T9_GROUPS.items() for ch in letters}

def T9_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in T9_MAP:
            out.append(T9_MAP[cu])
        elif ch.isdigit():
            out.append(ch)
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return "".join(out)

def T9_decode(text: str) -> str:
    out = []
    for ch in text:
        if ch in T9_GROUPS:
            out.append("[" + T9_GROUPS[ch] + "]")
        elif ch == "/":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out).lower()

def VanityPhone_encode(text: str, keep_punctuation: bool = True) -> str:
    keep = str(keep_punctuation).lower() not in {"0", "false", "no", "off"}
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in T9_MAP:
            out.append(T9_MAP[cu])
        elif ch.isdigit():
            out.append(ch)
        elif ch.isspace():
            out.append("-")
        elif keep:
            out.append(ch)
    return "".join(out)

def VanityPhone_decode(text: str, keep_punctuation: bool = True) -> str:
    groups = []
    for ch in text:
        if ch in T9_GROUPS:
            groups.append(T9_GROUPS[ch])
        elif ch in "- .()/":
            groups.append(" ")
        else:
            groups.append(ch)
    return " ".join(g if len(g) > 1 else g for g in groups).lower()


TAP_ALPH = "ABCDEFGHIJLMNOPQRSTUVWXYZ"  # C/K share a cell in the classic tap code.
TAP_POS = {ch: divmod(i, 5) for i, ch in enumerate(TAP_ALPH)}
TAP_REV = {divmod(i, 5): ch for i, ch in enumerate(TAP_ALPH)}

def TapCode_encode(text: str) -> str:
    tokens = []
    for ch in to_upper(text):
        if ch == "K":
            ch = "C"
        if ch in TAP_POS:
            r, c = TAP_POS[ch]
            tokens.append(f"{r + 1}.{c + 1}")
        elif ch.isspace():
            tokens.append("/")
        else:
            tokens.append(ch)
    return " ".join(tokens)

def TapCode_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").replace(",", " ").split():
        if tok == "/":
            out.append(" ")
            continue
        sep = "." if "." in tok else "-" if "-" in tok else None
        if sep:
            try:
                r, c = tok.split(sep, 1)
                out.append(TAP_REV.get((int(r) - 1, int(c) - 1), ""))
                continue
            except Exception:
                pass
        out.append(tok)
    return "".join(out).lower()

BRAILLE_PATTERNS = {"A": 0x01, "B": 0x03, "C": 0x09, "D": 0x19, "E": 0x11, "F": 0x0B, "G": 0x1B, "H": 0x13, "I": 0x0A, "J": 0x1A, "K": 0x05, "L": 0x07, "M": 0x0D, "N": 0x1D, "O": 0x15, "P": 0x0F, "Q": 0x1F, "R": 0x17, "S": 0x0E, "T": 0x1E, "U": 0x25, "V": 0x27, "W": 0x3A, "X": 0x2D, "Y": 0x3D, "Z": 0x35}
BRAILLE_REV = {chr(0x2800 + v): k for k, v in BRAILLE_PATTERNS.items()}

def BrailleUnicode_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in BRAILLE_PATTERNS:
            out.append(chr(0x2800 + BRAILLE_PATTERNS[cu]))
        elif ch.isspace():
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)

def BrailleUnicode_decode(text: str) -> str:
    out = []
    for ch in text:
        out.append(BRAILLE_REV.get(ch, " " if ch.isspace() else ch))
    return "".join(out).lower()


APCO_WORDS = {
    "A":"Adam", "B":"Boy", "C":"Charles", "D":"David", "E":"Edward", "F":"Frank",
    "G":"George", "H":"Henry", "I":"Ida", "J":"John", "K":"King", "L":"Lincoln",
    "M":"Mary", "N":"Nora", "O":"Ocean", "P":"Paul", "Q":"Queen", "R":"Robert",
    "S":"Sam", "T":"Tom", "U":"Union", "V":"Victor", "W":"William", "X":"X-ray",
    "Y":"Young", "Z":"Zebra", "0":"Zero", "1":"One", "2":"Two", "3":"Three",
    "4":"Four", "5":"Five", "6":"Six", "7":"Seven", "8":"Eight", "9":"Nine"
}
APCO_REV = {v.upper().replace("-", ""): k for k, v in APCO_WORDS.items()}

def APCO_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in APCO_WORDS:
            out.append(APCO_WORDS[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def APCO_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
        else:
            out.append(APCO_REV.get(tok.upper().replace("-", ""), tok))
    return "".join(out).lower()

_BAUDOT_LTRS = {
    "E":"00001", "\n":"00010", "A":"00011", " ":"00100", "S":"00101", "I":"00110", "U":"00111",
    "\r":"01000", "D":"01001", "R":"01010", "J":"01011", "N":"01100", "F":"01101", "C":"01110", "K":"01111",
    "T":"10000", "Z":"10001", "L":"10010", "W":"10011", "H":"10100", "Y":"10101", "P":"10110", "Q":"10111",
    "O":"11000", "B":"11001", "G":"11010", "M":"11100", "X":"11101", "V":"11110"
}
_BAUDOT_FIGS = {
    "3":"00001", "\n":"00010", "-":"00011", " ":"00100", "'":"00101", "8":"00110", "7":"00111",
    "\r":"01000", "$":"01001", "4":"01010", ",":"01100", "!":"01101", ":":"01110", "(":"01111",
    "5":"10000", '"':"10001", ")":"10010", "2":"10011", "#":"10100", "6":"10101", "0":"10110", "1":"10111",
    "9":"11000", "?":"11001", "&":"11010", ".":"11100", "/":"11101", ";":"11110"
}
_BAUDOT_LTRS_REV = {v: k for k, v in _BAUDOT_LTRS.items()}
_BAUDOT_FIGS_REV = {v: k for k, v in _BAUDOT_FIGS.items()}
_BAUDOT_FIGS_SHIFT = "11011"
_BAUDOT_LTRS_SHIFT = "11111"

def BaudotITA2_encode(text: str) -> str:
    mode = "letters"
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _BAUDOT_LTRS:
            if mode != "letters":
                out.append(_BAUDOT_LTRS_SHIFT)
                mode = "letters"
            out.append(_BAUDOT_LTRS[cu])
        elif ch in _BAUDOT_FIGS:
            if mode != "figures":
                out.append(_BAUDOT_FIGS_SHIFT)
                mode = "figures"
            out.append(_BAUDOT_FIGS[ch])
        else:
            out.append(_BAUDOT_LTRS[" "])
    return " ".join(out)

def BaudotITA2_decode(text: str) -> str:
    try:
        raw = "".join(ch for ch in text if ch in "01")
        if len(raw) % 5:
            return "Err:Baudot bitstream length must be a multiple of 5"
        mode = "letters"
        out = []
        for code in chunk(raw, 5):
            if code == _BAUDOT_FIGS_SHIFT:
                mode = "figures"
                continue
            if code == _BAUDOT_LTRS_SHIFT:
                mode = "letters"
                continue
            table = _BAUDOT_FIGS_REV if mode == "figures" else _BAUDOT_LTRS_REV
            out.append(table.get(code, ""))
        return "".join(out).lower()
    except Exception as e:
        return f"Err:{e}"

_UPSIDE_MAP = str.maketrans({
    "a":"ɐ", "b":"q", "c":"ɔ", "d":"p", "e":"ǝ", "f":"ɟ", "g":"ƃ", "h":"ɥ", "i":"ᴉ", "j":"ɾ", "k":"ʞ", "l":"l", "m":"ɯ", "n":"u", "o":"o", "p":"d", "q":"b", "r":"ɹ", "s":"s", "t":"ʇ", "u":"n", "v":"ʌ", "w":"ʍ", "x":"x", "y":"ʎ", "z":"z", ".":"˙", ",":"'", "'":",", "?":"¿", "!":"¡", "(":")", ")":"(", "[":"]", "]":"[", "{":"}", "}":"{", "<":">", ">":"<", "_":"‾"
})
_UPSIDE_REV = str.maketrans({v: k for k, v in _UPSIDE_MAP.items()})

def UpsideDown_encode(text: str) -> str:
    return text.lower().translate(_UPSIDE_MAP)[::-1]

def UpsideDown_decode(text: str) -> str:
    return text[::-1].translate(_UPSIDE_REV)

_MIRROR_MAP = str.maketrans({
    "b":"d", "d":"b", "p":"q", "q":"p", "<":">", ">":"<", "(":")", ")":"(", "[":"]", "]":"[", "{":"}", "}":"{", "/":"\\", "\\":"/"
})

def MirrorText_encode(text: str) -> str:
    return text.translate(_MIRROR_MAP)[::-1]

def MirrorText_decode(text: str) -> str:
    return text[::-1].translate(_MIRROR_MAP)

_ZW_ZERO = "\u200b"
_ZW_ONE = "\u200c"

def ZeroWidthBinary_encode(text: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    return "[ZW]" + "".join(_ZW_ONE if bit == "1" else _ZW_ZERO for bit in bits)

def ZeroWidthBinary_decode(text: str) -> str:
    try:
        payload = text[4:] if text.startswith("[ZW]") else text
        bits = "".join("1" if ch == _ZW_ONE else "0" for ch in payload if ch in {_ZW_ZERO, _ZW_ONE})
        if len(bits) % 8:
            return "Err:zero-width bit length must be a multiple of 8"
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"


_ELDER_FUTHARK = {
    "TH":"ᚦ", "NG":"ᛜ", "A":"ᚨ", "B":"ᛒ", "C":"ᚲ", "D":"ᛞ", "E":"ᛖ", "F":"ᚠ", "G":"ᚷ", "H":"ᚺ",
    "I":"ᛁ", "J":"ᛃ", "K":"ᚲ", "L":"ᛚ", "M":"ᛗ", "N":"ᚾ", "O":"ᛟ", "P":"ᛈ", "Q":"ᚲ", "R":"ᚱ",
    "S":"ᛊ", "T":"ᛏ", "U":"ᚢ", "V":"ᚹ", "W":"ᚹ", "X":"ᛉ", "Y":"ᛇ", "Z":"ᛉ"
}
_ELDER_REV = {v: k.lower() for k, v in _ELDER_FUTHARK.items() if len(k) == 1}
_ELDER_REV.update({"ᚦ":"th", "ᛜ":"ng"})

def ElderFuthark_encode(text: str) -> str:
    out = []
    i = 0
    upper = text.upper()
    while i < len(text):
        pair = upper[i:i+2]
        if pair in _ELDER_FUTHARK:
            out.append(_ELDER_FUTHARK[pair])
            i += 2
            continue
        ch = upper[i]
        out.append(_ELDER_FUTHARK.get(ch, text[i]))
        i += 1
    return "".join(out)

def ElderFuthark_decode(text: str) -> str:
    return "".join(_ELDER_REV.get(ch, ch) for ch in text)

_YOUNGER_FUTHARK = {
    "A":"ᛅ", "B":"ᛒ", "C":"ᚴ", "D":"ᛏ", "E":"ᛁ", "F":"ᚠ", "G":"ᚴ", "H":"ᚼ", "I":"ᛁ", "J":"ᛁ", "K":"ᚴ",
    "L":"ᛚ", "M":"ᛘ", "N":"ᚾ", "O":"ᚢ", "P":"ᛒ", "Q":"ᚴ", "R":"ᚱ", "S":"ᛋ", "T":"ᛏ", "U":"ᚢ", "V":"ᚠ",
    "W":"ᚢ", "X":"ᚴᛋ", "Y":"ᛦ", "Z":"ᛋ"
}
_YOUNGER_REV = {v: k.lower() for k, v in _YOUNGER_FUTHARK.items() if len(v) == 1}

def YoungerFuthark_encode(text: str) -> str:
    return "".join(_YOUNGER_FUTHARK.get(ch.upper(), ch) for ch in text)

def YoungerFuthark_decode(text: str) -> str:
    return "".join(_YOUNGER_REV.get(ch, ch) for ch in text)

_OGHAM = {
    "A":"ᚐ", "B":"ᚁ", "C":"ᚉ", "D":"ᚇ", "E":"ᚓ", "F":"ᚃ", "G":"ᚌ", "H":"ᚆ", "I":"ᚔ", "J":"ᚔ", "K":"ᚉ",
    "L":"ᚂ", "M":"ᚋ", "N":"ᚅ", "O":"ᚑ", "P":"ᚚ", "Q":"ᚊ", "R":"ᚏ", "S":"ᚄ", "T":"ᚈ", "U":"ᚒ", "V":"ᚃ",
    "W":"ᚃ", "X":"ᚎ", "Y":"ᚔ", "Z":"ᚎ"
}
_OGHAM_REV = {v: k.lower() for k, v in _OGHAM.items()}

def Ogham_encode(text: str) -> str:
    body = "".join(_OGHAM.get(ch.upper(), ch) for ch in text)
    return "᚛" + body + "᚜"

def Ogham_decode(text: str) -> str:
    stripped = text.replace("᚛", "").replace("᚜", "")
    return "".join(_OGHAM_REV.get(ch, ch) for ch in stripped)

def _pua_map(start: int) -> Dict[str, str]:
    return {ch: chr(start + i) for i, ch in enumerate(ALPHA)}

def _sub_symbol_encode(text: str, table: Dict[str, str]) -> str:
    return "".join(table.get(ch.upper(), ch) for ch in text)

def _sub_symbol_decode(text: str, table: Dict[str, str]) -> str:
    rev = {v: k.lower() for k, v in table.items()}
    return "".join(rev.get(ch, ch) for ch in text)

_AUREBESH = _pua_map(0xE000)
_THEBAN = _pua_map(0xE100)
_GALACTIC = _pua_map(0xE200)
_DANCING_MEN = _pua_map(0xE300)
_MOON_TYPE = _pua_map(0xE400)

def Aurebesh_encode(text: str) -> str:
    return _sub_symbol_encode(text, _AUREBESH)

def Aurebesh_decode(text: str) -> str:
    return _sub_symbol_decode(text, _AUREBESH)

def Theban_encode(text: str) -> str:
    return _sub_symbol_encode(text, _THEBAN)

def Theban_decode(text: str) -> str:
    return _sub_symbol_decode(text, _THEBAN)

def StandardGalactic_encode(text: str) -> str:
    return _sub_symbol_encode(text, _GALACTIC)

def StandardGalactic_decode(text: str) -> str:
    return _sub_symbol_decode(text, _GALACTIC)

def DancingMen_encode(text: str) -> str:
    return _sub_symbol_encode(text, _DANCING_MEN)

def DancingMen_decode(text: str) -> str:
    return _sub_symbol_decode(text, _DANCING_MEN)

def MoonType_encode(text: str) -> str:
    return _sub_symbol_encode(text, _MOON_TYPE)

def MoonType_decode(text: str) -> str:
    return _sub_symbol_decode(text, _MOON_TYPE)

_CALC_ENC = str.maketrans({"O":"0", "I":"1", "Z":"2", "E":"3", "H":"4", "S":"5", "G":"6", "L":"7", "B":"8", "Q":"9"})
_CALC_DEC = str.maketrans({"0":"o", "1":"i", "2":"z", "3":"e", "4":"h", "5":"s", "6":"g", "7":"l", "8":"b", "9":"q"})

def CalculatorSpelling_encode(text: str) -> str:
    return text.upper().translate(_CALC_ENC)[::-1]

def CalculatorSpelling_decode(text: str) -> str:
    return text[::-1].translate(_CALC_DEC).lower()


_ZALGO_MARKS = ["\u0301", "\u0300", "\u0302", "\u0303", "\u0304", "\u0336"]

def Zalgo_encode(text: str, intensity: int | str = 2) -> str:
    intensity = max(0, min(6, int(intensity)))
    marks = "".join(_ZALGO_MARKS[:intensity])
    return "".join(ch + (marks if ch.isalpha() else "") for ch in text)

def Zalgo_decode(text: str, intensity: int | str = 2) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFD", text) if not unicodedata.combining(ch))

_INV_CHARS = ["\u2060", "\u2061", "\u2062", "\u2063"]

def InvisibleUnicode_encode(text: str, cover: str = "") -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    if len(bits) % 2:
        bits += "0"
    hidden = "".join(_INV_CHARS[int(bits[i:i+2], 2)] for i in range(0, len(bits), 2))
    return (cover or "[INV]") + hidden

def InvisibleUnicode_decode(text: str, cover: str = "") -> str:
    try:
        bits = "".join(f"{_INV_CHARS.index(ch):02b}" for ch in text if ch in _INV_CHARS)
        if len(bits) % 8:
            bits = bits[:len(bits) - (len(bits) % 8)]
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

_NULL_WORDS = {
    "A":"able", "B":"baker", "C":"charlie", "D":"delta", "E":"eager", "F":"foxtrot", "G":"golf", "H":"hotel", "I":"item", "J":"jolly", "K":"kilo", "L":"lima", "M":"mike", "N":"november", "O":"orange", "P":"papa", "Q":"queen", "R":"romeo", "S":"sierra", "T":"tango", "U":"union", "V":"victor", "W":"whiskey", "X":"xray", "Y":"yankee", "Z":"zebra"
}

def NullAcrostic_encode(text: str) -> str:
    words = []
    for ch in text.upper():
        if ch in _NULL_WORDS:
            words.append(_NULL_WORDS[ch])
        elif ch.isspace():
            words.append("/")
    return " ".join(words)

def NullAcrostic_decode(text: str) -> str:
    out = []
    for tok in text.split():
        if tok == "/":
            out.append(" ")
        elif tok:
            out.append(tok[0])
    return "".join(out).lower()

def AcrosticGenerator_encode(text: str, filler_word: str = "cover") -> str:
    tail = re.sub(r"^[A-Za-z]+", "", filler_word or "") or (filler_word[1:] if len(filler_word) > 1 else "word")
    words = []
    for ch in text:
        if ch.isspace():
            words.append("/")
        elif ch.isalpha():
            words.append(ch.upper() + tail)
        else:
            words.append(ch)
    return " ".join(words)

def AcrosticGenerator_decode(text: str, filler_word: str = "cover") -> str:
    out = []
    for tok in text.split():
        if tok == "/":
            out.append(" ")
        elif tok:
            out.append(tok[0])
    return "".join(out).lower()

def EveryNthHider_encode(text: str, n: int | str = 3, filler: str = "x") -> str:
    n = max(1, int(n))
    filler = (filler or "x")[0]
    out = []
    for ch in text:
        out.append(filler * (n - 1) + ch)
    return "".join(out)

def EveryNthHider_decode(text: str, n: int | str = 3, filler: str = "x") -> str:
    n = max(1, int(n))
    return text[n-1::n]

_SOLRESOL = ["do", "re", "mi", "fa", "sol", "la", "si"]
_SOLRESOL_MAP = {ch: _SOLRESOL[i // 7] + "-" + _SOLRESOL[i % 7] for i, ch in enumerate(ALPHA)}
_SOLRESOL_REV = {v: k.lower() for k, v in _SOLRESOL_MAP.items()}

def Solresol_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _SOLRESOL_MAP:
            out.append(_SOLRESOL_MAP[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def Solresol_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
        else:
            out.append(_SOLRESOL_REV.get(tok.lower(), tok))
    return "".join(out)

_NOTES = ["C", "D", "E", "F", "G", "A", "B"]
_MUSIC_MAP = {ch: f"{_NOTES[i % 7]}{4 + (i // 7)}" for i, ch in enumerate(ALPHA)}
_MUSIC_REV = {v: k.lower() for k, v in _MUSIC_MAP.items()}

def MusicNotes_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _MUSIC_MAP:
            out.append(_MUSIC_MAP[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def MusicNotes_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        if tok == "/":
            out.append(" ")
        else:
            out.append(_MUSIC_REV.get(tok.upper(), tok))
    return "".join(out)

# =============================================================================
# Encodings
# =============================================================================

def Binary_encode(text: str) -> str:
    data = text.encode("utf-8")
    return " ".join(format(b, "08b") for b in data)

def Binary_decode(text: str) -> str:
    bits = text.replace("\n", " ").split()
    try:
        data = bytes(int(b, 2) for b in bits)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Octal_encode(text: str) -> str:
    data = text.encode("utf-8")
    return " ".join(format(b, "03o") for b in data)

def Octal_decode(text: str) -> str:
    parts = text.replace("\n", " ").split()
    try:
        data = bytes(int(p, 8) for p in parts)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Hex_encode(text: str) -> str: return text.encode("utf-8").hex()

def Hex_decode(text: str) -> str:
    try:
        return bytes.fromhex(text.strip()).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def Base64_decode(text: str) -> str:
    try:
        return base64.b64decode(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def A85_encode(text: str) -> str:
    return base64.a85encode(text.encode("utf-8")).decode("ascii")

def A85_decode(text: str) -> str:
    try:
        return base64.a85decode(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def B85_encode(text: str) -> str:
    return base64.b85encode(text.encode("utf-8")).decode("ascii")

def B85_decode(text: str) -> str:
    try:
        return base64.b85decode(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Base32_encode(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("ascii")

def Base32_decode(text: str) -> str:
    try:
        return base64.b32decode(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"



def Base16Sep_encode(text: str, sep: str = " ") -> str:
    pairs = chunk(text.encode("utf-8").hex().upper(), 2)
    return sep.join(pairs)

def Base16Sep_decode(text: str, sep: str = " ") -> str:
    try:
        cleaned = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
        if len(cleaned) % 2:
            return "Err:Base16 needs an even number of hex digits"
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Base32Hex_encode(text: str) -> str:
    return base64.b32hexencode(text.encode("utf-8")).decode("ascii")

def Base32Hex_decode(text: str) -> str:
    try:
        return base64.b32hexdecode(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Base64URL_encode(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")

def Base64URL_decode(text: str) -> str:
    try:
        s = text.strip()
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"


BASE92_ALPH = "".join(chr(i) for i in range(33, 127) if chr(i) not in {'"', '\\'})
BASE92_REV = {ch: i for i, ch in enumerate(BASE92_ALPH)}

def Base92_encode(text: str) -> str:
    data = text.encode("utf-8")
    if not data:
        return ""
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 92)
        out.append(BASE92_ALPH[r])
    leading = len(data) - len(data.lstrip(b"\x00"))
    return BASE92_ALPH[0] * leading + ("".join(reversed(out)) or BASE92_ALPH[0])

def Base92_decode(text: str) -> str:
    try:
        s = text.strip()
        if not s:
            return ""
        n = 0
        for ch in s:
            n = n * 92 + BASE92_REV[ch]
        blen = (n.bit_length() + 7) // 8
        data = n.to_bytes(blen, "big") if blen else b""
        leading = len(s) - len(s.lstrip(BASE92_ALPH[0]))
        return (b"\x00" * leading + data).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def yEnc_encode(text: str) -> str:
    out = []
    for byte in text.encode("utf-8"):
        val = (byte + 42) % 256
        if val in (0, 10, 13, 61):
            out.append("=" + chr((val + 64) % 256))
        else:
            out.append(chr(val))
    return "[YENC]" + "".join(out)

def yEnc_decode(text: str) -> str:
    try:
        s = text[6:] if text.startswith("[YENC]") else text
        data = bytearray()
        i = 0
        while i < len(s):
            val = ord(s[i])
            if s[i] == "=":
                i += 1
                if i >= len(s):
                    return "Err:truncated yEnc escape"
                val = (ord(s[i]) - 64) % 256
            data.append((val - 42) % 256)
            i += 1
        return bytes(data).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"
CROCKFORD32_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CROCKFORD32_REV = {ch: i for i, ch in enumerate(CROCKFORD32_ALPH)}
CROCKFORD32_REV.update({"O": 0, "I": 1, "L": 1})
BASE45_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE45_REV = {ch: i for i, ch in enumerate(BASE45_ALPH)}

def Base32Crockford_encode(text: str) -> str:
    data = text.encode("utf-8")
    if not data:
        return ""
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 32)
        out.append(CROCKFORD32_ALPH[r])
    leading = len(data) - len(data.lstrip(bytes([0])))
    return "0" * leading + ("".join(reversed(out)) or "0")

def Base32Crockford_decode(text: str) -> str:
    s = "".join(ch for ch in text.upper() if ch not in "- \t\r\n")
    if not s:
        return ""
    n = 0
    try:
        for ch in s:
            n = n * 32 + CROCKFORD32_REV[ch]
    except KeyError as e:
        return f"Err:invalid Crockford Base32 character {e.args[0]!r}"
    blen = (n.bit_length() + 7) // 8
    data = n.to_bytes(blen, "big") if blen else b""
    leading = len(s) - len(s.lstrip("0"))
    return (bytes([0]) * leading + data).decode("utf-8", errors="replace")

def Base45_encode(text: str) -> str:
    data = text.encode("utf-8")
    out = []
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            x = data[i] * 256 + data[i + 1]
            e = x // (45 * 45)
            x %= 45 * 45
            d = x // 45
            c = x % 45
            out.extend([BASE45_ALPH[c], BASE45_ALPH[d], BASE45_ALPH[e]])
            i += 2
        else:
            x = data[i]
            out.extend([BASE45_ALPH[x % 45], BASE45_ALPH[x // 45]])
            i += 1
    return "".join(out)

def Base45_decode(text: str) -> str:
    s = "".join(ch for ch in text.strip() if ch not in "\r\n\t")
    out = bytearray()
    i = 0
    try:
        while i < len(s):
            if i + 2 < len(s):
                x = BASE45_REV[s[i]] + BASE45_REV[s[i+1]] * 45 + BASE45_REV[s[i+2]] * 45 * 45
                if x > 0xffff:
                    return "Err:invalid Base45 triplet"
                out.extend([(x // 256) & 0xff, x & 0xff])
                i += 3
            elif i + 1 < len(s):
                x = BASE45_REV[s[i]] + BASE45_REV[s[i+1]] * 45
                if x > 0xff:
                    return "Err:invalid Base45 pair"
                out.append(x)
                i += 2
            else:
                return "Err:invalid Base45 length"
    except KeyError as e:
        return f"Err:invalid Base45 character {e.args[0]!r}"
    return bytes(out).decode("utf-8", errors="replace")

def QuotedPrintable_encode(text: str) -> str:
    return quopri.encodestring(text.encode("utf-8"), quotetabs=True).decode("ascii")

def QuotedPrintable_decode(text: str) -> str:
    try:
        return quopri.decodestring(text.encode("ascii")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

BASE36_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def Base36_encode(text: str) -> str:
    data = text.encode("utf-8")
    n = int.from_bytes(data, "big")
    if n == 0: return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 36)
        out.append(BASE36_ALPH[r])
    return "".join(reversed(out))

def Base36_decode(text: str) -> str:
    s = text.strip().upper()
    n = 0
    for ch in s:
        n = n*36 + BASE36_ALPH.index(ch)
    blen = (n.bit_length() + 7)//8
    return n.to_bytes(blen, "big").decode("utf-8", errors="replace")

BASE58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def Base58_encode(text: str) -> str:
    data = text.encode("utf-8")
    n = int.from_bytes(data, "big")
    out = []
    if n == 0:
        out.append(BASE58_ALPH[0])
    else:
        while n > 0:
            n, r = divmod(n, 58)
            out.append(BASE58_ALPH[r])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1"*leading_zeros + "".join(reversed(out))

def Base58_decode(text: str) -> str:
    s = text.strip()
    n = 0
    for ch in s:
        n = n*58 + BASE58_ALPH.index(ch)
    out = []
    while n > 0:
        n, r = divmod(n, 256)
        out.append(r)
    out_bytes = bytes(reversed(out))
    leading_ones = len(s) - len(s.lstrip("1"))
    out_bytes = b"\x00"*leading_ones + out_bytes
    return out_bytes.decode("utf-8", errors="replace")


BASE62_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def Base62_encode(text: str) -> str:
    data = text.encode("utf-8")
    if not data:
        return ""
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(BASE62_ALPH[r])
    leading_zeros = len(data) - len(data.lstrip(bytes([0])))
    return BASE62_ALPH[0] * leading_zeros + ("".join(reversed(out)) or BASE62_ALPH[0])

def Base62_decode(text: str) -> str:
    s = text.strip()
    if not s:
        return ""
    n = 0
    try:
        for ch in s:
            n = n * 62 + BASE62_ALPH.index(ch)
    except ValueError as e:
        return f"Err:{e}"
    blen = (n.bit_length() + 7) // 8
    out = n.to_bytes(blen, "big") if blen else b""
    leading = len(s) - len(s.lstrip(BASE62_ALPH[0]))
    return (bytes([0]) * leading + out).decode("utf-8", errors="replace")

Z85_ALPH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
Z85_REV = {ch: i for i, ch in enumerate(Z85_ALPH)}

def Z85_encode(text: str) -> str:
    data = text.encode("utf-8")
    pad = (-len(data)) % 4
    padded = data + bytes(pad)
    out = []
    for i in range(0, len(padded), 4):
        value = int.from_bytes(padded[i:i+4], "big")
        chars = []
        for _ in range(5):
            value, rem = divmod(value, 85)
            chars.append(Z85_ALPH[rem])
        out.extend(reversed(chars))
    meta = {"n": len(data)}
    return "[Z85]" + json.dumps(meta) + "|" + "".join(out)

def Z85_decode(text: str) -> str:
    body = text.strip()
    original_len = None
    if body.startswith("[Z85]"):
        try:
            meta_end = body.index("|", len("[Z85]"))
            meta = json.loads(body[len("[Z85]"):meta_end])
            original_len = int(meta.get("n"))
            body = body[meta_end+1:]
        except Exception as e:
            return f"Err:{e}"
    if len(body) % 5:
        return "Err:Z85 length must be a multiple of 5"
    out = bytearray()
    try:
        for i in range(0, len(body), 5):
            value = 0
            for ch in body[i:i+5]:
                value = value * 85 + Z85_REV[ch]
            out.extend(value.to_bytes(4, "big"))
    except KeyError as e:
        return f"Err:invalid Z85 character {e.args[0]!r}"
    data = bytes(out[:original_len]) if original_len is not None else bytes(out)
    return data.decode("utf-8", errors="replace")

def Punycode_encode(text: str) -> str:
    try:
        return text.encode("punycode").decode("ascii")
    except Exception as e:
        return f"Err:{e}"

def Punycode_decode(text: str) -> str:
    try:
        return text.encode("ascii").decode("punycode")
    except Exception as e:
        return f"Err:{e}"


BASE91_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
BASE91_DEC = {ch: i for i, ch in enumerate(BASE91_ALPH)}

def Base91_encode(text: str) -> str:
    data = text.encode("utf-8")
    b = 0
    n = 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(BASE91_ALPH[v % 91])
            out.append(BASE91_ALPH[v // 91])
    if n:
        out.append(BASE91_ALPH[b % 91])
        if n > 7 or b > 90:
            out.append(BASE91_ALPH[b // 91])
    return "".join(out)

def Base91_decode(text: str) -> str:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    try:
        for ch in text.strip():
            if ch.isspace():
                continue
            c = BASE91_DEC[ch]
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v >= 0:
            out.append((b | v << n) & 255)
    except KeyError as e:
        return f"Err:invalid Base91 character {e.args[0]!r}"
    return bytes(out).decode("utf-8", errors="replace")

def GrayCode_encode(text: str) -> str:
    return " ".join(format(byte ^ (byte >> 1), "08b") for byte in text.encode("utf-8"))

def _gray_to_binary(gray: int) -> int:
    value = gray
    while gray:
        gray >>= 1
        value ^= gray
    return value

def GrayCode_decode(text: str) -> str:
    try:
        data = bytes(_gray_to_binary(int(tok, 2)) for tok in text.replace("\n", " ").split())
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def UUEncode_encode(text: str) -> str:
    data = text.encode("utf-8")
    lines = ["begin 644 data"]
    for i in range(0, len(data), 45):
        lines.append(binascii.b2a_uu(data[i:i+45]).decode("ascii").rstrip("\n"))
    lines.extend(["`", "end"])
    return "\n".join(lines)

def UUEncode_decode(text: str) -> str:
    out = bytearray()
    for line in text.splitlines():
        if not line or line.startswith("begin") or line == "end":
            continue
        try:
            out.extend(binascii.a2b_uu(line.encode("ascii")))
        except Exception as e:
            return f"Err:{e}"
    return bytes(out).decode("utf-8", errors="replace")

XX_ALPH = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
XX_REV = {ch: i for i, ch in enumerate(XX_ALPH)}

def XXEncode_encode(text: str) -> str:
    data = text.encode("utf-8")
    lines = ["begin 644 data"]
    for i in range(0, len(data), 45):
        chunk_bytes = data[i:i+45]
        chars = [XX_ALPH[len(chunk_bytes)]]
        for j in range(0, len(chunk_bytes), 3):
            block = chunk_bytes[j:j+3]
            padded = block + bytes(3 - len(block))
            value = int.from_bytes(padded, "big")
            chars.extend([
                XX_ALPH[(value >> 18) & 0x3f],
                XX_ALPH[(value >> 12) & 0x3f],
                XX_ALPH[(value >> 6) & 0x3f],
                XX_ALPH[value & 0x3f],
            ])
        lines.append("".join(chars))
    lines.extend(["+", "end"])
    return "\n".join(lines)

def XXEncode_decode(text: str) -> str:
    out = bytearray()
    try:
        for line in text.splitlines():
            if not line or line.startswith("begin") or line == "end":
                continue
            length = XX_REV[line[0]]
            if length == 0:
                continue
            buf = bytearray()
            body = line[1:]
            for i in range(0, len(body), 4):
                quad = body[i:i+4]
                if len(quad) < 4:
                    break
                value = 0
                for ch in quad:
                    value = (value << 6) | XX_REV[ch]
                buf.extend(value.to_bytes(3, "big"))
            out.extend(buf[:length])
    except KeyError as e:
        return f"Err:invalid xxencode character {e.args[0]!r}"
    except Exception as e:
        return f"Err:{e}"
    return bytes(out).decode("utf-8", errors="replace")


def _take_utf8_prefix(s: str, byte_len: int) -> Tuple[str, str]:
    data = s.encode("utf-8")
    head = data[:byte_len]
    tail = data[byte_len:]
    return head.decode("utf-8", errors="replace"), tail.decode("utf-8", errors="replace")

def Netstring_encode(text: str) -> str:
    data = text.encode("utf-8")
    return f"{len(data)}:{text},"

def Netstring_decode(text: str) -> str:
    try:
        colon = text.index(":")
        byte_len = int(text[:colon])
        body, rest = _take_utf8_prefix(text[colon+1:], byte_len)
        if not rest.startswith(","):
            return "Err:missing netstring comma terminator"
        return body
    except Exception as e:
        return f"Err:{e}"

def BencodeString_encode(text: str) -> str:
    data = text.encode("utf-8")
    return f"{len(data)}:{text}"

def BencodeString_decode(text: str) -> str:
    try:
        colon = text.index(":")
        byte_len = int(text[:colon])
        body, _ = _take_utf8_prefix(text[colon+1:], byte_len)
        return body
    except Exception as e:
        return f"Err:{e}"

def Base100Emoji_encode(text: str) -> str:
    return "".join(chr(0x1F300 + b) for b in text.encode("utf-8"))

def Base100Emoji_decode(text: str) -> str:
    out = bytearray()
    for ch in text:
        value = ord(ch) - 0x1F300
        if 0 <= value <= 255:
            out.append(value)
        elif ch.isspace():
            continue
        else:
            return f"Err:invalid Base100 character {ch!r}"
    return bytes(out).decode("utf-8", errors="replace")

def ParityBits_encode(text: str) -> str:
    tokens = []
    for b in text.encode("utf-8"):
        bits = format(b, "08b")
        parity = str(bits.count("1") % 2)  # even parity bit appended after data bits
        tokens.append(bits + parity)
    return " ".join(tokens)

def ParityBits_decode(text: str) -> str:
    out = bytearray()
    for tok in text.replace("\n", " ").split():
        if len(tok) != 9 or any(ch not in "01" for ch in tok):
            return f"Err:invalid parity token {tok!r}"
        bits, parity = tok[:8], tok[8]
        if str(bits.count("1") % 2) != parity:
            return f"Err:parity check failed for {tok!r}"
        out.append(int(bits, 2))
    return bytes(out).decode("utf-8", errors="replace")

def HexColor_encode(text: str) -> str:
    data = text.encode("utf-8")
    pad = (-len(data)) % 3
    padded = data + bytes(pad)
    colors = ["#" + padded[i:i+3].hex().upper() for i in range(0, len(padded), 3)]
    return "[HEXCOLOR]" + json.dumps({"n": len(data)}) + "|" + " ".join(colors)

def HexColor_decode(text: str) -> str:
    body = text.strip()
    original_len = None
    if body.startswith("[HEXCOLOR]"):
        try:
            meta_end = body.index("|", len("[HEXCOLOR]"))
            original_len = int(json.loads(body[len("[HEXCOLOR]"):meta_end]).get("n"))
            body = body[meta_end+1:]
        except Exception as e:
            return f"Err:{e}"
    out = bytearray()
    for tok in body.replace(",", " ").split():
        tok = tok.strip().lstrip("#")
        if len(tok) != 6:
            return f"Err:invalid hex color {tok!r}"
        try:
            out.extend(bytes.fromhex(tok))
        except Exception as e:
            return f"Err:{e}"
    data = bytes(out[:original_len]) if original_len is not None else bytes(out)
    return data.decode("utf-8", errors="replace")


def RLE_encode(text: str) -> str:
    if not text:
        return "[RLE][]"
    runs = []
    current = text[0]
    count = 1
    for ch in text[1:]:
        if ch == current:
            count += 1
        else:
            runs.append([current, count])
            current = ch
            count = 1
    runs.append([current, count])
    return "[RLE]" + json.dumps(runs, ensure_ascii=False)

def RLE_decode(text: str) -> str:
    body = text.strip()
    if body.startswith("[RLE]"):
        body = body[len("[RLE]"):]
    try:
        runs = json.loads(body)
        return "".join(str(ch) * int(count) for ch, count in runs)
    except Exception as e:
        return f"Err:{e}"


def BWT_encode(text: str) -> str:
    if text == "":
        return "[BWT]{\"idx\":0}|"
    rotations = [(text[i:] + text[:i], i) for i in range(len(text))]
    rotations.sort(key=lambda item: item[0])
    idx = next(pos for pos, (_, original) in enumerate(rotations) if original == 0)
    last_col = "".join(rotation[-1] for rotation, _ in rotations)
    return "[BWT]" + json.dumps({"idx": idx}, separators=(",", ":")) + "|" + last_col

def BWT_decode(text: str) -> str:
    try:
        if not text.startswith("[BWT]"):
            return "Err:bad BWT format"
        sep = text.index("|", len("[BWT]"))
        meta = json.loads(text[len("[BWT]"):sep])
        idx = int(meta.get("idx", 0))
        last_col = text[sep+1:]
        table = [""] * len(last_col)
        for _ in last_col:
            table = sorted(ch + row for ch, row in zip(last_col, table))
        return table[idx] if table else ""
    except Exception as e:
        return f"Err:{e}"

def MoveToFront_encode(text: str) -> str:
    alphabet = list(range(256))
    out = []
    for byte in text.encode("utf-8"):
        idx = alphabet.index(byte)
        out.append(idx)
        alphabet.insert(0, alphabet.pop(idx))
    return "[MTF]" + " ".join(f"{value:02X}" for value in out)

def MoveToFront_decode(text: str) -> str:
    try:
        body = text[len("[MTF]"):] if text.startswith("[MTF]") else text
        alphabet = list(range(256))
        out = bytearray()
        for token in body.replace(",", " ").split():
            idx = int(token, 16)
            if not 0 <= idx < len(alphabet):
                return "Err:MTF index out of range"
            byte = alphabet[idx]
            out.append(byte)
            alphabet.insert(0, alphabet.pop(idx))
        return bytes(out).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def ZlibBase64_encode(text: str, level: int | str = 9) -> str:
    level = int(level)
    payload = zlib.compress(text.encode("utf-8"), level)
    return "[ZLIB64]" + base64.b64encode(payload).decode("ascii")

def ZlibBase64_decode(text: str, level: int | str = 9) -> str:
    try:
        body = text[len("[ZLIB64]"):] if text.startswith("[ZLIB64]") else text
        return zlib.decompress(base64.b64decode(body.encode("ascii"))).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def GzipBase64_encode(text: str, level: int | str = 9) -> str:
    payload = gzip.compress(text.encode("utf-8"), compresslevel=int(level))
    return "[GZIP64]" + base64.b64encode(payload).decode("ascii")

def GzipBase64_decode(text: str, level: int | str = 9) -> str:
    try:
        body = text[len("[GZIP64]"):] if text.startswith("[GZIP64]") else text
        return gzip.decompress(base64.b64decode(body.encode("ascii"))).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def BinaryEndianWords_encode(text: str, word_bytes: int | str = 2, endian: str = "big") -> str:
    word_bytes = int(word_bytes)
    if word_bytes not in (1, 2, 4, 8):
        return "Err:word_bytes must be 1, 2, 4, or 8"
    endian = endian.lower()
    if endian not in ("big", "little"):
        return "Err:endian must be big or little"
    data = text.encode("utf-8")
    pad = (-len(data)) % word_bytes
    padded = data + b"\x00" * pad
    words = []
    for i in range(0, len(padded), word_bytes):
        words.append(str(int.from_bytes(padded[i:i+word_bytes], endian)))
    meta = json.dumps({"n": len(data), "w": word_bytes, "endian": endian}, separators=(",", ":"))
    return "[BINWORDS]" + meta + "|" + " ".join(words)

def BinaryEndianWords_decode(text: str, word_bytes: int | str = 2, endian: str = "big") -> str:
    try:
        body = text
        n = None
        if text.startswith("[BINWORDS]"):
            sep = text.index("|", len("[BINWORDS]"))
            meta = json.loads(text[len("[BINWORDS]"):sep])
            n = int(meta.get("n", 0))
            word_bytes = int(meta.get("w", word_bytes))
            endian = meta.get("endian", endian)
            body = text[sep+1:]
        word_bytes = int(word_bytes)
        endian = endian.lower()
        out = bytearray()
        for token in body.replace(",", " ").split():
            out.extend(int(token).to_bytes(word_bytes, endian))
        data = bytes(out[:n]) if n is not None else bytes(out).rstrip(b"\x00")
        return data.decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def CStringEscapes_encode(text: str) -> str:
    return text.encode("unicode_escape").decode("ascii")

def CStringEscapes_decode(text: str) -> str:
    try:
        return bytes(text, "utf-8").decode("unicode_escape")
    except Exception as e:
        return f"Err:{e}"

def _hamming74_encode_nibble(n: int) -> str:
    d1 = (n >> 3) & 1
    d2 = (n >> 2) & 1
    d3 = (n >> 1) & 1
    d4 = n & 1
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p4 = d2 ^ d3 ^ d4
    return "".join(str(bit) for bit in (p1, p2, d1, p4, d2, d3, d4))

def Hamming74_encode(text: str) -> str:
    tokens = []
    for byte in text.encode("utf-8"):
        tokens.append(_hamming74_encode_nibble(byte >> 4))
        tokens.append(_hamming74_encode_nibble(byte & 0x0F))
    return " ".join(tokens)

def _hamming74_decode_word(word: str) -> Tuple[int, bool]:
    bits = [int(ch) for ch in word]
    p1, p2, d1, p4, d2, d3, d4 = bits
    s1 = p1 ^ d1 ^ d2 ^ d4
    s2 = p2 ^ d1 ^ d3 ^ d4
    s4 = p4 ^ d2 ^ d3 ^ d4
    syndrome = s1 + (s2 << 1) + (s4 << 2)
    corrected = False
    if syndrome:
        if 1 <= syndrome <= 7:
            bits[syndrome - 1] ^= 1
            corrected = True
        else:
            raise ValueError("invalid Hamming syndrome")
    _, _, d1, _, d2, d3, d4 = bits
    return (d1 << 3) | (d2 << 2) | (d3 << 1) | d4, corrected

def Hamming74_decode(text: str) -> str:
    words = text.replace("\n", " ").split()
    if len(words) % 2:
        return "Err:Hamming(7,4) data must contain an even number of codewords"
    out = bytearray()
    try:
        for i in range(0, len(words), 2):
            if len(words[i]) != 7 or len(words[i+1]) != 7:
                return "Err:Hamming(7,4) codewords must be 7 bits"
            hi, _ = _hamming74_decode_word(words[i])
            lo, _ = _hamming74_decode_word(words[i+1])
            out.append((hi << 4) | lo)
    except Exception as e:
        return f"Err:{e}"
    return bytes(out).decode("utf-8", errors="replace")

def _luhn_check_digit(digits: str) -> str:
    total = 0
    parity = (len(digits) + 1) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - total % 10) % 10)

def Luhn_encode(text: str) -> str:
    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        return "Err:Luhn requires at least one digit"
    return digits + _luhn_check_digit(digits)

def Luhn_decode(text: str) -> str:
    digits = "".join(ch for ch in text if ch.isdigit())
    if len(digits) < 2:
        return "Err:Luhn value must include data and check digit"
    body, check = digits[:-1], digits[-1]
    expected = _luhn_check_digit(body)
    if check != expected:
        return f"Err:Luhn check failed expected {expected} got {check}"
    return body


def JSONStringEscapes_encode(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)

def JSONStringEscapes_decode(text: str) -> str:
    try:
        return json.loads(text)
    except Exception as e:
        return f"Err:{e}"

def OctalEscapes_encode(text: str) -> str:
    return "".join(f"\\{b:03o}" for b in text.encode("utf-8"))

def OctalEscapes_decode(text: str) -> str:
    out = bytearray()
    i = 0
    try:
        while i < len(text):
            if text[i] == "\\" and i + 3 < len(text) and all(ch in "01234567" for ch in text[i+1:i+4]):
                out.append(int(text[i+1:i+4], 8))
                i += 4
            else:
                out.extend(text[i].encode("utf-8"))
                i += 1
        return bytes(out).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def Hexdump_encode(text: str) -> str:
    data = text.encode("utf-8")
    lines = []
    for offset in range(0, len(data), 16):
        block = data[offset:offset+16]
        hex_part = " ".join(f"{b:02x}" for b in block)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in block)
        lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)

def Hexdump_decode(text: str) -> str:
    hex_bytes = []
    try:
        for line in text.splitlines():
            left = line.split("|", 1)[0]
            parts = left.split()
            if parts and all(ch in "0123456789abcdefABCDEF" for ch in parts[0]) and len(parts[0]) >= 4:
                parts = parts[1:]
            for part in parts:
                if len(part) == 2 and all(ch in "0123456789abcdefABCDEF" for ch in part):
                    hex_bytes.append(part)
        return bytes.fromhex("".join(hex_bytes)).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def DataURI_encode(text: str, mime: str = "text/plain;charset=utf-8") -> str:
    payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"data:{mime};base64,{payload}"

def DataURI_decode(text: str, mime: str = "text/plain;charset=utf-8") -> str:
    try:
        header, payload = text.split(",", 1)
        if not header.startswith("data:"):
            return "Err:not a data URI"
        if ";base64" in header:
            return base64.b64decode(payload.encode("ascii")).decode("utf-8", errors="replace")
        return urllib.parse.unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Err:{e}"

def URLForm_encode(text: str) -> str:
    return urllib.parse.quote_plus(text)

def URLForm_decode(text: str) -> str:
    try:
        return urllib.parse.unquote_plus(text)
    except Exception as e:
        return f"Err:{e}"

def CRC32_encode(text: str) -> str:
    crc = zlib.crc32(text.encode("utf-8")) & 0xffffffff
    return f"[CRC32]{crc:08X}|{text}"

def CRC32_decode(text: str) -> str:
    try:
        if not text.startswith("[CRC32]"):
            return "Err:bad CRC32 format"
        sep = text.index("|", len("[CRC32]"))
        expected = int(text[len("[CRC32]"):sep], 16)
        body = text[sep+1:]
        actual = zlib.crc32(body.encode("utf-8")) & 0xffffffff
        if actual != expected:
            return f"Err:CRC32 mismatch expected {expected:08X} got {actual:08X}"
        return body
    except Exception as e:
        return f"Err:{e}"

def Adler32_encode(text: str) -> str:
    checksum = zlib.adler32(text.encode("utf-8")) & 0xffffffff
    return f"[ADLER32]{checksum:08X}|{text}"

def Adler32_decode(text: str) -> str:
    try:
        if not text.startswith("[ADLER32]"):
            return "Err:bad Adler32 format"
        sep = text.index("|", len("[ADLER32]"))
        expected = int(text[len("[ADLER32]"):sep], 16)
        body = text[sep+1:]
        actual = zlib.adler32(body.encode("utf-8")) & 0xffffffff
        if actual != expected:
            return f"Err:Adler32 mismatch expected {expected:08X} got {actual:08X}"
        return body
    except Exception as e:
        return f"Err:{e}"


def _crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    crc = init & 0xffff
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
    return crc & 0xffff

def CRC16CCITT_encode(text: str) -> str:
    checksum = _crc16_ccitt(text.encode("utf-8"))
    return f"[CRC16-CCITT]{checksum:04X}|{text}"

def CRC16CCITT_decode(text: str) -> str:
    try:
        if not text.startswith("[CRC16-CCITT]"):
            return "Err:bad CRC16-CCITT format"
        sep = text.index("|", len("[CRC16-CCITT]"))
        expected = int(text[len("[CRC16-CCITT]"):sep], 16)
        body = text[sep+1:]
        actual = _crc16_ccitt(body.encode("utf-8"))
        if actual != expected:
            return f"Err:CRC16-CCITT mismatch expected {expected:04X} got {actual:04X}"
        return body
    except Exception as e:
        return f"Err:{e}"

def _fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for byte in data:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1

def Fletcher16_encode(text: str) -> str:
    checksum = _fletcher16(text.encode("utf-8"))
    return f"[FLETCHER16]{checksum:04X}|{text}"

def Fletcher16_decode(text: str) -> str:
    try:
        if not text.startswith("[FLETCHER16]"):
            return "Err:bad Fletcher16 format"
        sep = text.index("|", len("[FLETCHER16]"))
        expected = int(text[len("[FLETCHER16]"):sep], 16)
        body = text[sep+1:]
        actual = _fletcher16(body.encode("utf-8"))
        if actual != expected:
            return f"Err:Fletcher16 mismatch expected {expected:04X} got {actual:04X}"
        return body
    except Exception as e:
        return f"Err:{e}"

def _fletcher32(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    sum1 = 0xffff
    sum2 = 0xffff
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i+1]
        sum1 = (sum1 + word) % 0xffff
        sum2 = (sum2 + sum1) % 0xffff
    return ((sum2 & 0xffff) << 16) | (sum1 & 0xffff)

def Fletcher32_encode(text: str) -> str:
    checksum = _fletcher32(text.encode("utf-8"))
    return f"[FLETCHER32]{checksum:08X}|{text}"

def Fletcher32_decode(text: str) -> str:
    try:
        if not text.startswith("[FLETCHER32]"):
            return "Err:bad Fletcher32 format"
        sep = text.index("|", len("[FLETCHER32]"))
        expected = int(text[len("[FLETCHER32]"):sep], 16)
        body = text[sep+1:]
        actual = _fletcher32(body.encode("utf-8"))
        if actual != expected:
            return f"Err:Fletcher32 mismatch expected {expected:08X} got {actual:08X}"
        return body
    except Exception as e:
        return f"Err:{e}"

_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8],
]
_VERHOEFF_INV = [0,4,3,2,1,5,6,7,8,9]

def _digits_only_or_err(text: str) -> str:
    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        raise ValueError("numeric text required")
    return digits

def _verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])

def Verhoeff_encode(text: str) -> str:
    try:
        digits = _digits_only_or_err(text)
        return digits + _verhoeff_check_digit(digits)
    except Exception as e:
        return f"Err:{e}"

def Verhoeff_decode(text: str) -> str:
    try:
        digits = _digits_only_or_err(text)
        c = 0
        for i, ch in enumerate(reversed(digits)):
            c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
        if c != 0:
            return "Err:Verhoeff check digit mismatch"
        return digits[:-1]
    except Exception as e:
        return f"Err:{e}"

_DAMM_TABLE = [
    [0,3,1,7,5,9,8,6,4,2],
    [7,0,9,2,1,5,4,8,6,3],
    [4,2,0,6,8,7,1,3,5,9],
    [1,7,5,0,9,8,3,4,2,6],
    [6,1,2,3,0,4,5,9,7,8],
    [3,6,7,4,2,0,9,5,8,1],
    [5,8,6,9,7,2,0,1,3,4],
    [8,9,4,5,3,6,2,0,1,7],
    [9,4,3,8,6,1,7,2,0,5],
    [2,5,8,1,4,3,6,7,9,0],
]

def _damm_checksum(digits: str) -> int:
    interim = 0
    for ch in digits:
        interim = _DAMM_TABLE[interim][int(ch)]
    return interim

def Damm_encode(text: str) -> str:
    try:
        digits = _digits_only_or_err(text)
        return digits + str(_damm_checksum(digits))
    except Exception as e:
        return f"Err:{e}"

def Damm_decode(text: str) -> str:
    try:
        digits = _digits_only_or_err(text)
        if _damm_checksum(digits) != 0:
            return "Err:Damm check digit mismatch"
        return digits[:-1]
    except Exception as e:
        return f"Err:{e}"

def _int_to_elias_gamma(n: int) -> str:
    if n <= 0:
        raise ValueError("Elias gamma only encodes positive integers")
    bits = bin(n)[2:]
    return "0" * (len(bits) - 1) + bits

def _elias_gamma_to_int(bits: str) -> int:
    if not bits or set(bits) - {"0", "1"}:
        raise ValueError("binary Elias gamma token required")
    zeros = len(bits) - len(bits.lstrip("0"))
    need = zeros + 1
    if len(bits) != zeros + need or bits[zeros] != "1":
        raise ValueError("invalid Elias gamma token length")
    return int(bits[zeros:], 2)

def EliasGamma_encode(text: str) -> str:
    return " ".join(_int_to_elias_gamma(byte + 1) for byte in text.encode("utf-8"))

def EliasGamma_decode(text: str) -> str:
    try:
        if not text.strip():
            return ""
        data = bytearray()
        for token in text.split():
            value = _elias_gamma_to_int(token) - 1
            if not 0 <= value <= 255:
                return "Err:Elias gamma byte out of range"
            data.append(value)
        return data.decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def _fibonacci_numbers_upto(n: int) -> List[int]:
    fibs = [1, 2]
    while fibs[-1] <= n:
        fibs.append(fibs[-1] + fibs[-2])
    return fibs[:-1]

def _int_to_fibonacci_code(n: int) -> str:
    if n <= 0:
        raise ValueError("Fibonacci coding only encodes positive integers")
    fibs = _fibonacci_numbers_upto(n)
    bits = ["0"] * len(fibs)
    remaining = n
    for idx in range(len(fibs) - 1, -1, -1):
        if fibs[idx] <= remaining:
            bits[idx] = "1"
            remaining -= fibs[idx]
    return "".join(bits) + "1"

def _fibonacci_code_to_int(bits: str) -> int:
    if not bits or set(bits) - {"0", "1"}:
        raise ValueError("binary Fibonacci token required")
    if len(bits) < 2 or not bits.endswith("11"):
        raise ValueError("Fibonacci token must end with 11")
    payload = bits[:-1]
    fibs = [1, 2]
    while len(fibs) < len(payload):
        fibs.append(fibs[-1] + fibs[-2])
    return sum(fib for bit, fib in zip(payload, fibs) if bit == "1")

def FibonacciCode_encode(text: str) -> str:
    return " ".join(_int_to_fibonacci_code(byte + 1) for byte in text.encode("utf-8"))

def FibonacciCode_decode(text: str) -> str:
    try:
        if not text.strip():
            return ""
        data = bytearray()
        for token in text.split():
            value = _fibonacci_code_to_int(token) - 1
            if not 0 <= value <= 255:
                return "Err:Fibonacci byte out of range"
            data.append(value)
        return data.decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

_HAMMING1511_DATA_POS = [3,5,6,7,9,10,11,12,13,14,15]
_HAMMING1511_PARITY_POS = [1,2,4,8]

def _hamming1511_encode_block(bits11: str) -> str:
    code = [0] * 16
    for bit, pos in zip(bits11, _HAMMING1511_DATA_POS):
        code[pos] = int(bit)
    for parity in _HAMMING1511_PARITY_POS:
        value = 0
        for pos in range(1, 16):
            if pos & parity and pos != parity:
                value ^= code[pos]
        code[parity] = value
    return "".join(str(code[pos]) for pos in range(1, 16))

def _hamming1511_decode_block(word: str) -> Tuple[str, int]:
    if len(word) != 15 or set(word) - {"0", "1"}:
        raise ValueError("Hamming(15,11) blocks must be 15 binary digits")
    code = [0] + [int(ch) for ch in word]
    syndrome = 0
    for parity in _HAMMING1511_PARITY_POS:
        value = 0
        for pos in range(1, 16):
            if pos & parity:
                value ^= code[pos]
        if value:
            syndrome |= parity
    corrected = 0
    if 1 <= syndrome <= 15:
        code[syndrome] ^= 1
        corrected = syndrome
    return "".join(str(code[pos]) for pos in _HAMMING1511_DATA_POS), corrected

def Hamming1511_encode(text: str) -> str:
    data = text.encode("utf-8")
    bits = "".join(f"{byte:08b}" for byte in data)
    if len(bits) % 11:
        bits += "0" * (11 - (len(bits) % 11))
    blocks = [_hamming1511_encode_block(bits[i:i+11]) for i in range(0, len(bits), 11)]
    return f"[HAM1511]{json.dumps({'bytes': len(data)}, separators=(',', ':'))}|" + " ".join(blocks)

def Hamming1511_decode(text: str) -> str:
    try:
        byte_len = None
        payload = text.strip()
        if payload.startswith("[HAM1511]"):
            sep = payload.index("|", len("[HAM1511]"))
            meta = json.loads(payload[len("[HAM1511]"):sep])
            byte_len = int(meta.get("bytes", 0))
            payload = payload[sep+1:].strip()
        if not payload:
            return "" if byte_len in (None, 0) else "Err:missing Hamming(15,11) blocks"
        bits = ""
        for token in payload.split():
            decoded, _corrected = _hamming1511_decode_block(token)
            bits += decoded
        if byte_len is None:
            byte_len = len(bits) // 8
        bits = bits[:byte_len * 8]
        data = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8)
        return data.decode("utf-8")
    except Exception as e:
        return f"Err:{e}"


def _uleb128_encode_int(n: int) -> List[int]:
    if n < 0:
        raise ValueError("LEB128 only encodes non-negative integers")
    out = []
    while True:
        byte = n & 0x7f
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return out

def _uleb128_decode_bytes(data: List[int]) -> List[int]:
    values = []
    value = 0
    shift = 0
    for byte in data:
        value |= (byte & 0x7f) << shift
        if byte & 0x80:
            shift += 7
            if shift > 35:
                raise ValueError("LEB128 value too large for byte codec")
            continue
        values.append(value)
        value = 0
        shift = 0
    if shift:
        raise ValueError("unterminated LEB128 value")
    return values

def LEB128_encode(text: str) -> str:
    encoded = []
    for byte in text.encode("utf-8"):
        encoded.extend(_uleb128_encode_int(byte))
    return " ".join(f"{byte:02X}" for byte in encoded)

def LEB128_decode(text: str) -> str:
    try:
        compact = text.replace("0x", "").replace(",", " ")
        data = [int(part, 16) for part in compact.split()] if compact.strip() else []
        values = _uleb128_decode_bytes(data)
        if any(not 0 <= value <= 255 for value in values):
            return "Err:LEB128 decoded value outside byte range"
        return bytes(values).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def _int_to_elias_delta(n: int) -> str:
    if n <= 0:
        raise ValueError("Elias delta only encodes positive integers")
    bits = bin(n)[2:]
    return _int_to_elias_gamma(len(bits)) + bits[1:]

def _elias_delta_to_int(bits: str) -> int:
    if not bits or set(bits) - {"0", "1"}:
        raise ValueError("binary Elias delta token required")
    zeros = len(bits) - len(bits.lstrip("0"))
    gamma_len = zeros * 2 + 1
    if len(bits) < gamma_len:
        raise ValueError("truncated Elias delta length prefix")
    width = _elias_gamma_to_int(bits[:gamma_len])
    payload = bits[gamma_len:]
    if len(payload) != width - 1:
        raise ValueError("invalid Elias delta payload length")
    return int("1" + payload, 2)

def EliasDelta_encode(text: str) -> str:
    return " ".join(_int_to_elias_delta(byte + 1) for byte in text.encode("utf-8"))

def EliasDelta_decode(text: str) -> str:
    try:
        if not text.strip():
            return ""
        data = bytearray()
        for token in text.split():
            value = _elias_delta_to_int(token) - 1
            if not 0 <= value <= 255:
                return "Err:Elias delta byte out of range"
            data.append(value)
        return data.decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def _int_to_golomb(n: int, m: int) -> str:
    if n < 0 or m <= 0:
        raise ValueError("Golomb coding requires n >= 0 and m > 0")
    q, r = divmod(n, m)
    b = math.ceil(math.log2(m)) if m > 1 else 1
    cutoff = (1 << b) - m
    prefix = "1" * q + "0"
    if m == 1:
        return prefix
    if r < cutoff:
        return prefix + format(r, f"0{b-1}b")
    return prefix + format(r + cutoff, f"0{b}b")

def _golomb_to_int(bits: str, m: int) -> int:
    if not bits or set(bits) - {"0", "1"} or m <= 0:
        raise ValueError("invalid Golomb token")
    q = 0
    while q < len(bits) and bits[q] == "1":
        q += 1
    if q >= len(bits) or bits[q] != "0":
        raise ValueError("Golomb token missing unary terminator")
    rest = bits[q+1:]
    if m == 1:
        if rest:
            raise ValueError("Golomb m=1 token has extra bits")
        return q
    b = math.ceil(math.log2(m))
    cutoff = (1 << b) - m
    short_len = b - 1
    if len(rest) == short_len:
        r = int(rest or "0", 2)
        if r >= cutoff:
            raise ValueError("invalid short Golomb remainder")
    elif len(rest) == b:
        r = int(rest, 2) - cutoff
        if r < cutoff or r >= m:
            raise ValueError("invalid long Golomb remainder")
    else:
        raise ValueError("invalid Golomb remainder length")
    return q * m + r

def Golomb_encode(text: str, m: int | str = 10) -> str:
    m = int(m)
    return " ".join(_int_to_golomb(byte, m) for byte in text.encode("utf-8"))

def Golomb_decode(text: str, m: int | str = 10) -> str:
    try:
        m = int(m)
        if not text.strip():
            return ""
        values = [_golomb_to_int(token, m) for token in text.split()]
        if any(not 0 <= value <= 255 for value in values):
            return "Err:Golomb decoded value outside byte range"
        return bytes(values).decode("utf-8")
    except Exception as e:
        return f"Err:{e}"

def CRC8_encode(text: str) -> str:
    crc = 0
    for byte in text.encode("utf-8"):
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xff if crc & 0x80 else (crc << 1) & 0xff
    return f"[CRC8]{crc:02X}|{text}"

def CRC8_decode(text: str) -> str:
    try:
        if not text.startswith("[CRC8]"):
            return "Err:bad CRC8 format"
        sep = text.index("|", len("[CRC8]"))
        expected = int(text[len("[CRC8]"):sep], 16)
        body = text[sep+1:]
        actual = int(CRC8_encode(body)[len("[CRC8]"):len("[CRC8]")+2], 16)
        if actual != expected:
            return f"Err:CRC8 mismatch expected {expected:02X} got {actual:02X}"
        return body
    except Exception as e:
        return f"Err:{e}"

def _crc64_ecma(data: bytes) -> int:
    crc = 0
    poly = 0x42F0E1EBA9EA3693
    for byte in data:
        crc ^= byte << 56
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xffffffffffffffff if crc & (1 << 63) else (crc << 1) & 0xffffffffffffffff
    return crc

def CRC64ECMA_encode(text: str) -> str:
    crc = _crc64_ecma(text.encode("utf-8"))
    return f"[CRC64-ECMA]{crc:016X}|{text}"

def CRC64ECMA_decode(text: str) -> str:
    try:
        if not text.startswith("[CRC64-ECMA]"):
            return "Err:bad CRC64-ECMA format"
        sep = text.index("|", len("[CRC64-ECMA]"))
        expected = int(text[len("[CRC64-ECMA]"):sep], 16)
        body = text[sep+1:]
        actual = _crc64_ecma(body.encode("utf-8"))
        if actual != expected:
            return f"Err:CRC64-ECMA mismatch expected {expected:016X} got {actual:016X}"
        return body
    except Exception as e:
        return f"Err:{e}"

def _hash_wrapper_encode(text: str, algorithm: str) -> str:
    digest = hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    return f"[{algorithm.upper()}]{digest}|{text}"

def _hash_wrapper_decode(text: str, algorithm: str) -> str:
    try:
        tag = f"[{algorithm.upper()}]"
        if not text.startswith(tag):
            return f"Err:bad {algorithm.upper()} format"
        sep = text.index("|", len(tag))
        expected = text[len(tag):sep].lower()
        body = text[sep+1:]
        actual = hashlib.new(algorithm, body.encode("utf-8")).hexdigest()
        if actual != expected:
            return f"Err:{algorithm.upper()} mismatch"
        return body
    except Exception as e:
        return f"Err:{e}"

def MD5_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "md5")

def MD5_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "md5")

def SHA1_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "sha1")

def SHA1_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "sha1")

def SHA256_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "sha256")

def SHA256_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "sha256")

def SHA3_256_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "sha3_256")

def SHA3_256_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "sha3_256")

def HMAC_encode(text: str, key: str = "secret", algorithm: str = "sha256") -> str:
    try:
        digest = hmac.new(key.encode("utf-8"), text.encode("utf-8"), algorithm).hexdigest()
        return f"[HMAC:{algorithm.lower()}]{digest}|{text}"
    except Exception as e:
        return f"Err:{e}"

def HMAC_decode(text: str, key: str = "secret", algorithm: str = "sha256") -> str:
    try:
        tag = f"[HMAC:{algorithm.lower()}]"
        if not text.startswith(tag):
            return "Err:bad HMAC format"
        sep = text.index("|", len(tag))
        expected = text[len(tag):sep].lower()
        body = text[sep+1:]
        actual = hmac.new(key.encode("utf-8"), body.encode("utf-8"), algorithm).hexdigest()
        if not hmac.compare_digest(actual, expected):
            return "Err:HMAC mismatch"
        return body
    except Exception as e:
        return f"Err:{e}"

def PBKDF2_encode(text: str, salt: str = "salt", iterations: int | str = 100000, algorithm: str = "sha256", dklen: int | str = 32) -> str:
    try:
        iterations = int(iterations)
        dklen = int(dklen)
        digest = hashlib.pbkdf2_hmac(algorithm, text.encode("utf-8"), salt.encode("utf-8"), iterations, dklen).hex()
        meta = json.dumps({"alg": algorithm.lower(), "salt": salt, "iter": iterations, "dklen": dklen}, separators=(",", ":"))
        return f"[PBKDF2]{meta}|{digest}"
    except Exception as e:
        return f"Err:{e}"

def PBKDF2_decode(text: str, salt: str = "salt", iterations: int | str = 100000, algorithm: str = "sha256", dklen: int | str = 32) -> str:
    try:
        if not text.startswith("[PBKDF2]"):
            return "Err:PBKDF2 is one-way; expected [PBKDF2] metadata format"
        sep = text.index("|", len("[PBKDF2]"))
        meta = json.loads(text[len("[PBKDF2]"):sep])
        digest = text[sep+1:]
        return f"PBKDF2 {meta.get('alg', algorithm)} iter={meta.get('iter', iterations)} salt={meta.get('salt', salt)!r} dklen={meta.get('dklen', dklen)} digest={digest}"
    except Exception as e:
        return f"Err:{e}"


def BLAKE2b_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "blake2b")

def BLAKE2b_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "blake2b")

def BLAKE2s_encode(text: str) -> str:
    return _hash_wrapper_encode(text, "blake2s")

def BLAKE2s_decode(text: str) -> str:
    return _hash_wrapper_decode(text, "blake2s")

def Scrypt_encode(text: str, salt: str = "salt", n: int | str = 16384, r: int | str = 8, p: int | str = 1, dklen: int | str = 32) -> str:
    try:
        n = int(n); r = int(r); p = int(p); dklen = int(dklen)
        digest = hashlib.scrypt(text.encode("utf-8"), salt=salt.encode("utf-8"), n=n, r=r, p=p, dklen=dklen).hex()
        meta = json.dumps({"salt": salt, "n": n, "r": r, "p": p, "dklen": dklen}, separators=(",", ":"))
        return f"[SCRYPT]{meta}|{digest}"
    except Exception as e:
        return f"Err:{e}"

def Scrypt_decode(text: str, salt: str = "salt", n: int | str = 16384, r: int | str = 8, p: int | str = 1, dklen: int | str = 32) -> str:
    try:
        if not text.startswith("[SCRYPT]"):
            return "Err:scrypt is one-way; expected [SCRYPT] metadata format"
        sep = text.index("|", len("[SCRYPT]"))
        meta = json.loads(text[len("[SCRYPT]"):sep])
        digest = text[sep+1:]
        return f"scrypt n={meta.get('n', n)} r={meta.get('r', r)} p={meta.get('p', p)} salt={meta.get('salt', salt)!r} dklen={meta.get('dklen', dklen)} digest={digest}"
    except Exception as e:
        return f"Err:{e}"

def _hkdf_extract(salt: bytes, ikm: bytes, algorithm: str) -> bytes:
    if not salt:
        salt = bytes(hashlib.new(algorithm).digest_size)
    return hmac.new(salt, ikm, algorithm).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int, algorithm: str) -> bytes:
    digest_size = hashlib.new(algorithm).digest_size
    if length > 255 * digest_size:
        raise ValueError("HKDF output too long")
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), algorithm).digest()
        okm += previous
        counter += 1
    return okm[:length]

def HKDF_encode(text: str, salt: str = "salt", info: str = "", algorithm: str = "sha256", length: int | str = 32) -> str:
    try:
        length = int(length)
        prk = _hkdf_extract(salt.encode("utf-8"), text.encode("utf-8"), algorithm)
        okm = _hkdf_expand(prk, info.encode("utf-8"), length, algorithm)
        meta = json.dumps({"alg": algorithm.lower(), "salt": salt, "info": info, "len": length}, separators=(",", ":"))
        return f"[HKDF]{meta}|{okm.hex()}"
    except Exception as e:
        return f"Err:{e}"

def HKDF_decode(text: str, salt: str = "salt", info: str = "", algorithm: str = "sha256", length: int | str = 32) -> str:
    try:
        if not text.startswith("[HKDF]"):
            return "Err:HKDF is one-way; expected [HKDF] metadata format"
        sep = text.index("|", len("[HKDF]"))
        meta = json.loads(text[len("[HKDF]"):sep])
        digest = text[sep+1:]
        return f"HKDF {meta.get('alg', algorithm)} salt={meta.get('salt', salt)!r} info={meta.get('info', info)!r} len={meta.get('len', length)} okm={digest}"
    except Exception as e:
        return f"Err:{e}"

def _hotp(secret: bytes, counter: int, digits: int, algorithm: str) -> str:
    msg = int(counter).to_bytes(8, "big")
    digest = hmac.new(secret, msg, algorithm).digest()
    offset = digest[-1] & 0x0f
    code_int = int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff
    return str(code_int % (10 ** int(digits))).zfill(int(digits))

def _otp_secret_bytes(secret: str, base32_secret: str = "false") -> bytes:
    if str(base32_secret).lower() in {"1", "true", "yes", "y"}:
        padded = secret.strip().replace(" ", "").upper()
        padded += "=" * ((8 - len(padded) % 8) % 8)
        return base64.b32decode(padded.encode("ascii"))
    return secret.encode("utf-8")

def HOTP_encode(text: str, secret: str = "secret", counter: int | str = 0, digits: int | str = 6, algorithm: str = "sha1", base32_secret: str = "false") -> str:
    try:
        code = _hotp(_otp_secret_bytes(secret, base32_secret), int(counter), int(digits), algorithm)
        meta = json.dumps({"counter": int(counter), "digits": int(digits), "alg": algorithm.lower()}, separators=(",", ":"))
        return f"[HOTP]{meta}|{code}"
    except Exception as e:
        return f"Err:{e}"

def HOTP_decode(text: str, secret: str = "secret", counter: int | str = 0, digits: int | str = 6, algorithm: str = "sha1", base32_secret: str = "false") -> str:
    try:
        if text.startswith("[HOTP]"):
            sep = text.index("|", len("[HOTP]"))
            meta = json.loads(text[len("[HOTP]"):sep])
            supplied = text[sep+1:].strip()
            counter = int(meta.get("counter", counter))
            digits = int(meta.get("digits", digits))
            algorithm = meta.get("alg", algorithm)
        else:
            supplied = text.strip()
        expected = _hotp(_otp_secret_bytes(secret, base32_secret), int(counter), int(digits), algorithm)
        return "OK" if hmac.compare_digest(supplied, expected) else f"Err:HOTP mismatch expected {expected}"
    except Exception as e:
        return f"Err:{e}"

def TOTP_encode(text: str, secret: str = "secret", time_step: int | str = 30, digits: int | str = 6, algorithm: str = "sha1", for_time: int | str = 0, base32_secret: str = "false") -> str:
    try:
        timestamp = int(for_time) if str(for_time) not in {"", "0"} else int(time.time())
        counter = timestamp // int(time_step)
        code = _hotp(_otp_secret_bytes(secret, base32_secret), counter, int(digits), algorithm)
        meta = json.dumps({"time": timestamp, "step": int(time_step), "counter": counter, "digits": int(digits), "alg": algorithm.lower()}, separators=(",", ":"))
        return f"[TOTP]{meta}|{code}"
    except Exception as e:
        return f"Err:{e}"

def TOTP_decode(text: str, secret: str = "secret", time_step: int | str = 30, digits: int | str = 6, algorithm: str = "sha1", for_time: int | str = 0, base32_secret: str = "false") -> str:
    try:
        if text.startswith("[TOTP]"):
            sep = text.index("|", len("[TOTP]"))
            meta = json.loads(text[len("[TOTP]"):sep])
            supplied = text[sep+1:].strip()
            counter = int(meta.get("counter"))
            digits = int(meta.get("digits", digits))
            algorithm = meta.get("alg", algorithm)
        else:
            timestamp = int(for_time) if str(for_time) not in {"", "0"} else int(time.time())
            counter = timestamp // int(time_step)
            supplied = text.strip()
        expected = _hotp(_otp_secret_bytes(secret, base32_secret), counter, int(digits), algorithm)
        return "OK" if hmac.compare_digest(supplied, expected) else f"Err:TOTP mismatch expected {expected}"
    except Exception as e:
        return f"Err:{e}"

def URL_encode(text: str) -> str: return urllib.parse.quote(text, safe="")
def URL_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text)
    except Exception as e:
        return f"Err:{e}"

def HTMLEntities_encode(text: str) -> str: return html.escape(text, quote=True)
def HTMLEntities_decode(text: str) -> str: return html.unescape(text)

def UEscapes_encode(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if 32 <= code <= 126 and ch not in {'\\'}:
            out.append(ch)
        else:
            if code <= 0xFFFF:
                out.append("\\u%04x" % code)
            else:
                out.append("\\U%08x" % code)
    return "".join(out)

def UEscapes_decode(text: str) -> str:
    try:
        return bytes(text, "utf-8").decode("unicode_escape")
    except Exception as e:
        return f"Err:{e}"

def AsciiShiftHex_encode(text: str, shift: int | str = 1) -> str:
    if isinstance(shift, str): shift = int(shift.strip())
    data = text.encode("utf-8")
    shifted = bytes(((b + shift) % 256) for b in data)
    return shifted.hex()

def AsciiShiftHex_decode(text: str, shift: int | str = 1) -> str:
    if isinstance(shift, str): shift = int(shift.strip())
    try:
        data = bytes.fromhex(text)
    except Exception as e:
        return f"Err:{e}"
    unshifted = bytes(((b - shift) % 256) for b in data)
    return unshifted.decode("utf-8", errors="replace")

DNA_MAP = {0:'A', 1:'C', 2:'G', 3:'T'}
DNA_REV = {'A':0,'C':1,'G':2,'T':3,'a':0,'c':1,'g':2,'t':3}

def DNA_encode(text: str) -> str:
    data = text.encode("utf-8")
    bits = "".join(format(b, "08b") for b in data)
    out = []
    for i in range(0, len(bits), 2):
        pair = bits[i:i+2]
        if len(pair) < 2: pair = pair + "0"
        val = int(pair, 2); out.append(DNA_MAP[val])
    return "".join(out)

def DNA_decode(text: str) -> str:
    vals = []
    for ch in text:
        if ch in DNA_REV:
            vals.append(DNA_REV[ch])
        elif ch.isspace():
            continue
        else:
            return f"Err:invalid base '{ch}'"
    bits = "".join(format(v, "02b") for v in vals)
    if len(bits) % 8 != 0:
        bits = bits[:len(bits) - (len(bits) % 8)]
    data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    return data.decode("utf-8", errors="replace")

_CODON_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?;:-_/@#$%&*+=()[]{}"
_DNA_BASES = "ACGT"
_RNA_BASES = "ACGU"

def _codon_table(bases: str) -> Dict[str, str]:
    return {ch: bases[(i >> 4) & 3] + bases[(i >> 2) & 3] + bases[i & 3] for i, ch in enumerate(_CODON_ALPHABET)}

def _codon_rev(bases: str) -> Dict[str, str]:
    table = _codon_table(bases)
    return {v: k for k, v in table.items()}

def DNACodon_encode(text: str) -> str:
    table = _codon_table(_DNA_BASES)
    return " ".join(table.get(ch.upper(), ch) for ch in text)

def DNACodon_decode(text: str) -> str:
    rev = _codon_rev(_DNA_BASES)
    out = []
    for tok in re.findall(r"[ACGTacgt]{3}|.", text):
        up = tok.upper()
        if up in rev:
            out.append(rev[up])
        elif tok.isspace():
            continue
        else:
            out.append(tok)
    return "".join(out).lower()

def RNACodon_encode(text: str) -> str:
    table = _codon_table(_RNA_BASES)
    return " ".join(table.get(ch.upper(), ch) for ch in text)

def RNACodon_decode(text: str) -> str:
    rev = _codon_rev(_RNA_BASES)
    out = []
    for tok in re.findall(r"[ACGUacgu]{3}|.", text):
        up = tok.upper()
        if up in rev:
            out.append(rev[up])
        elif tok.isspace():
            continue
        else:
            out.append(tok)
    return "".join(out).lower()

_AA_1_TO_3 = {
    "A": "Ala", "R": "Arg", "N": "Asn", "D": "Asp", "C": "Cys",
    "Q": "Gln", "E": "Glu", "G": "Gly", "H": "His", "I": "Ile",
    "L": "Leu", "K": "Lys", "M": "Met", "F": "Phe", "P": "Pro",
    "S": "Ser", "T": "Thr", "W": "Trp", "Y": "Tyr", "V": "Val",
    "B": "Asx", "Z": "Glx", "X": "Xaa", "*": "Stop",
}
_AA_3_TO_1 = {v.upper(): k for k, v in _AA_1_TO_3.items()}

def AminoAcid_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _AA_1_TO_3:
            out.append(_AA_1_TO_3[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return " ".join(out)

def AminoAcid_decode(text: str) -> str:
    out = []
    for tok in text.replace("/", " / ").split():
        up = tok.upper()
        if tok == "/":
            out.append(" ")
        elif up in _AA_3_TO_1:
            out.append(_AA_3_TO_1[up])
        else:
            out.append(tok)
    return "".join(out).lower()

def IChingHexagram_encode(text: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    if len(bits) % 6:
        bits += "0" * (6 - len(bits) % 6)
    return "".join(chr(0x4DC0 + int(bits[i:i+6], 2)) for i in range(0, len(bits), 6))

def IChingHexagram_decode(text: str) -> str:
    vals = []
    for ch in text:
        code = ord(ch)
        if 0x4DC0 <= code <= 0x4DFF:
            vals.append(f"{code - 0x4DC0:06b}")
        elif ch.isspace():
            continue
        else:
            return f"Err:invalid hexagram '{ch}'"
    bits = "".join(vals)
    bits = bits[:len(bits) - (len(bits) % 8)]
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8").rstrip("\x00")
    except Exception as exc:
        return f"Err:{exc}"

_TAROT_CARDS = [
    "Fool", "Magician", "HighPriestess", "Empress", "Emperor", "Hierophant", "Lovers", "Chariot",
    "Strength", "Hermit", "WheelOfFortune", "Justice", "HangedMan", "Death", "Temperance", "Devil",
    "Tower", "Star", "Moon", "Sun", "Judgement", "World",
    "AceWands", "TwoWands", "ThreeWands", "FourWands", "FiveWands", "SixWands", "SevenWands",
    "EightWands", "NineWands", "TenWands", "PageWands", "KnightWands", "QueenWands", "KingWands",
    "AceCups", "TwoCups", "ThreeCups", "FourCups", "FiveCups", "SixCups", "SevenCups", "EightCups",
    "NineCups", "TenCups", "PageCups", "KnightCups", "QueenCups", "KingCups",
    "AceSwords", "TwoSwords", "ThreeSwords", "FourSwords", "FiveSwords", "SixSwords",
    "SevenSwords", "EightSwords", "NineSwords", "TenSwords", "PageSwords", "KnightSwords",
    "QueenSwords", "KingSwords",
    "AcePentacles", "TwoPentacles", "ThreePentacles", "FourPentacles", "FivePentacles",
    "SixPentacles", "SevenPentacles", "EightPentacles", "NinePentacles", "TenPentacles",
    "PagePentacles", "KnightPentacles", "QueenPentacles", "KingPentacles",
]
_TAROT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?;:-_/@#$%&*+=()[]{}<>"
_TAROT_MAP = {ch: _TAROT_CARDS[i] for i, ch in enumerate(_TAROT_ALPHABET)}
_TAROT_REV = {v.upper(): ch for ch, v in _TAROT_MAP.items()}

def TarotCard_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in _TAROT_MAP:
            out.append(_TAROT_MAP[cu])
        else:
            out.append(ch)
    return " ".join(out)

def TarotCard_decode(text: str) -> str:
    out = []
    for tok in text.split():
        key = re.sub(r"[^A-Z0-9]+", "", tok.upper())
        out.append(_TAROT_REV.get(key, tok))
    return "".join(out).lower()

# =============================================================================
# Polybius/Playfair family & transpositions & routes
# =============================================================================

def _key_square_5(keyword: str) -> Tuple[str, Dict[str, Tuple[int,int]], Dict[Tuple[int,int], str]]:
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I/J merged
    mixed = ""; seen = set()
    for ch in only_alpha(keyword):
        ch = 'I' if ch == 'J' else ch
        if ch not in seen and ch in alpha:
            mixed += ch; seen.add(ch)
    for ch in alpha:
        if ch not in seen:
            mixed += ch
    idx = {}; rev = {}
    for i, ch in enumerate(mixed):
        r, c = divmod(i, 5)
        idx[ch] = (r, c); rev[(r, c)] = ch
    return mixed, idx, rev

def _key_square_6(keyword: str) -> Tuple[str, Dict[str, Tuple[int,int]], Dict[Tuple[int,int], str]]:
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    mixed = ""; seen = set()
    for ch in to_upper(keyword):
        if ch in alpha and ch not in seen:
            mixed += ch; seen.add(ch)
    for ch in alpha:
        if ch not in seen:
            mixed += ch
    idx = {}; rev = {}
    for i, ch in enumerate(mixed):
        r, c = divmod(i, 6)
        idx[ch] = (r, c); rev[(r, c)] = ch
    return mixed, idx, rev

def Polybius_encode(text: str, key: str = "KEYWORD") -> str:
    _, pos, _ = _key_square_5(key)
    out = []
    for ch in to_upper(text):
        if ch == 'J': ch = 'I'
        if ch in pos:
            r, c = pos[ch]; out.append(f"{r+1}{c+1}")
        elif ch.isspace():
            out.append("/")
        else:
            out.append("")
    return " ".join(out).replace(" / ", " / ")

def Polybius_decode(text: str, key: str = "KEYWORD") -> str:
    _, _, rev = _key_square_5(key)
    tokens = text.replace("/", " / ").split()
    out = []
    for t in tokens:
        if t == "/":
            out.append(" ")
        elif len(t) == 2 and t[0].isdigit() and t[1].isdigit():
            r = int(t[0])-1; c = int(t[1])-1
            ch = rev.get((r, c), '')
            out.append(ch)
    return "".join(out).lower()

def _playfair_prepare(text: str) -> List[Tuple[str,str]]:
    s = "".join(('I' if ch=='J' else ch) for ch in only_alpha(text))
    pairs = []; i = 0
    while i < len(s):
        a = s[i]
        if i+1 < len(s):
            b = s[i+1]
            if a == b:
                pairs.append((a, 'X')); i += 1
            else:
                pairs.append((a, b)); i += 2
        else:
            pairs.append((a, 'X')); i += 1
    return pairs

def Playfair_encode(text: str, key: str = "KEYWORD") -> str:
    _, pos, rev = _key_square_5(key)
    pairs = _playfair_prepare(text)
    out = []
    for a, b in pairs:
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            out.append(rev[(ra, (ca+1)%5)])
            out.append(rev[(rb, (cb+1)%5)])
        elif ca == cb:
            out.append(rev[((ra+1)%5, ca)])
            out.append(rev[((rb+1)%5, cb)])
        else:
            out.append(rev[(ra, cb)])
            out.append(rev[(rb, ca)])
    return "".join(out).lower()

def Playfair_decode(text: str, key: str = "KEYWORD") -> str:
    _, pos, rev = _key_square_5(key)
    s = only_alpha(text)
    out = []
    for i in range(0, len(s), 2):
        a = s[i]; b = s[i+1]
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            out.append(rev[(ra, (ca-1)%5)])
            out.append(rev[(rb, (cb-1)%5)])
        elif ca == cb:
            out.append(rev[((ra-1)%5, ca)])
            out.append(rev[((rb-1)%5, cb)])
        else:
            out.append(rev[(ra, cb)])
            out.append(rev[(rb, ca)])
    return "".join(out).lower()

def FourSquare_encode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    normal = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    sq1, pos1, rev1 = _key_square_5(key1)
    sq2, pos2, rev2 = _key_square_5(key2)
    posN = {ch: divmod(i,5) for i, ch in enumerate(normal)}
    revN = {divmod(i,5): ch for i, ch in enumerate(normal)}
    pairs = _playfair_prepare(text)
    out = []
    for a,b in pairs:
        ra, ca = posN[a]; rb, cb = posN[b]
        out.append(rev1[(ra, cb)])
        out.append(rev2[(rb, ca)])
    return "".join(out).lower()

def FourSquare_decode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    normal = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    sq1, pos1, rev1 = _key_square_5(key1)
    sq2, pos2, rev2 = _key_square_5(key2)
    posN = {ch: divmod(i,5) for i, ch in enumerate(normal)}
    revN = {divmod(i,5): ch for i, ch in enumerate(normal)}
    s = only_alpha(text)
    out = []
    for i in range(0, len(s), 2):
        a = s[i]; b = s[i+1]
        ra, cb = pos1[a]; rb, ca = pos2[b]
        out.append(revN[(ra, ca)])
        out.append(revN[(rb, cb)])
    return "".join(out).lower()

def TwoSquare_encode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    sqL, posL, revL = _key_square_5(key1)
    sqR, posR, revR = _key_square_5(key2)
    normal = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    posN = {ch: divmod(i,5) for i, ch in enumerate(normal)}
    pairs = _playfair_prepare(text)
    out = []
    for a,b in pairs:
        ra, ca = posL.get(a, posN[a]); rb, cb = posR.get(b, posN[b])
        out.append(revR[(ra, cb)])
        out.append(revL[(rb, ca)])
    return "".join(out).lower()

def TwoSquare_decode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    sqL, posL, revL = _key_square_5(key1)
    sqR, posR, revR = _key_square_5(key2)
    s = only_alpha(text)
    out = []
    for i in range(0, len(s), 2):
        a = s[i]; b = s[i+1]
        ra, cb = posR[a]; rb, ca = posL[b]
        out.append(revL[(ra, ca)])
        out.append(revR[(rb, cb)])
    return "".join(out).lower()

def _col_order(key: str) -> List[int]:
    return numeric_order_from_keyword(key)

def Columnar_encode(text: str, key: str = "CIPHER") -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len(key); order = _col_order(key)
    rows = math.ceil(len(s)/cols)
    grid = [[""]*cols for _ in range(rows)]
    i = 0
    for r in range(rows):
        for c in range(cols):
            if i < len(s):
                grid[r][c] = s[i]; i += 1
    out = []
    for ord_val in sorted(set(order)):
        for c, o in sorted([(c, o) for c, o in enumerate(order) if o == ord_val], key=lambda x: x[0]):
            for r in range(rows):
                if grid[r][c] != "":
                    out.append(grid[r][c])
    return "".join(out)

def Columnar_decode(text: str, key: str = "CIPHER") -> str:
    s = text
    cols = len(key); order = _col_order(key)
    rows = math.ceil(len(s)/cols)
    base = len(s) // cols; extra = len(s) % cols
    columns_sorted = []
    for ord_val in sorted(set(order)):
        columns_sorted += [c for c, o in enumerate(order) if o == ord_val]
    counts = {c: base for c in range(cols)}
    for i in range(extra):
        counts[i] += 1
    grid_cols = {}; idx = 0
    for c in columns_sorted:
        L = counts[c]; grid_cols[c] = list(s[idx:idx+L]); idx += L
    out = []
    for r in range(rows):
        for c in range(cols):
            if grid_cols[c]:
                out.append(grid_cols[c].pop(0))
    return "".join(out)

def KeyphraseTransposition_encode(text: str, keyphrase: str = "THE QUICK BROWN FOX") -> str:
    key = rotate_alpha_from_keyword(keyphrase or "KEYPHRASE")
    order = _col_order(key)
    out = []
    for i in range(0, len(text), len(key)):
        block = text[i:i+len(key)]
        cols = sorted(range(len(block)), key=lambda c: (order[c], c))
        out.extend(block[c] for c in cols)
    return "".join(out)

def KeyphraseTransposition_decode(text: str, keyphrase: str = "THE QUICK BROWN FOX") -> str:
    key = rotate_alpha_from_keyword(keyphrase or "KEYPHRASE")
    order = _col_order(key)
    out = []
    for i in range(0, len(text), len(key)):
        block = text[i:i+len(key)]
        cols = sorted(range(len(block)), key=lambda c: (order[c], c))
        plain = [""] * len(block)
        for src, col in enumerate(cols):
            plain[col] = block[src]
        out.extend(plain)
    return "".join(out)

def Myszkowski_encode(text: str, key: str = "TOMATO") -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len(key)
    rows = math.ceil(len(s)/cols)
    grid = [[""]*cols for _ in range(rows)]
    i = 0
    for r in range(rows):
        for c in range(cols):
            if i < len(s):
                grid[r][c] = s[i]; i += 1
    kw = to_upper(key)
    groups: Dict[str, List[int]] = {}
    for i, ch in enumerate(kw):
        groups.setdefault(ch, []).append(i)
    out = []
    for ch in sorted(groups.keys()):
        for c in groups[ch]:
            for r in range(rows):
                if grid[r][c]:
                    out.append(grid[r][c])
    return "".join(out)

def Myszkowski_decode(text: str, key: str = "TOMATO") -> str:
    s = text; cols = len(key); rows = math.ceil(len(s)/cols)
    kw = to_upper(key)
    groups: Dict[str, List[int]] = {}
    for i, ch in enumerate(kw):
        groups.setdefault(ch, []).append(i)
    order_cols = []
    for ch in sorted(groups.keys()):
        order_cols += groups[ch]
    base = len(s)//cols; extra = len(s)%cols
    counts = {c: base for c in range(cols)}
    for i in range(extra):
        counts[i] += 1
    grid_cols = {}; idx = 0
    for c in order_cols:
        L = counts[c]; grid_cols[c] = list(s[idx:idx+L]); idx += L
    out = []
    for r in range(rows):
        for c in range(cols):
            if grid_cols[c]:
                out.append(grid_cols[c].pop(0))
    return "".join(out)

def CaesarBox_encode(text: str, cols: int | str = 4) -> str:
    if isinstance(cols, str): cols = int(cols)
    s = "".join(ch for ch in text if not ch.isspace())
    rows = math.ceil(len(s)/cols)
    grid = [[""]*cols for _ in range(rows)]
    i = 0
    for r in range(rows):
        for c in range(cols):
            if i < len(s):
                grid[r][c] = s[i]; i += 1
    return "".join(grid[r][c] for c in range(cols) for r in range(rows) if grid[r][c] != "")

def CaesarBox_decode(text: str, cols: int | str = 4) -> str:
    if isinstance(cols, str): cols = int(cols)
    s = text; rows = math.ceil(len(s)/cols)
    base = len(s)//cols; extra = len(s)%cols
    col_lengths = [base + (1 if c < extra else 0) for c in range(cols)]
    grid = [[""]*cols for _ in range(rows)]
    idx = 0; cols_data = []
    for c in range(cols):
        L = col_lengths[c]; cols_data.append(list(s[idx:idx+L])); idx += L
    for c in range(cols):
        for r in range(rows):
            if cols_data[c]:
                grid[r][c] = cols_data[c].pop(0)
    return "".join(grid[r][c] for r in range(rows) for c in range(cols) if grid[r][c] != "")

def Scytale_encode(text: str, diameter: int | str = 5) -> str:
    if isinstance(diameter, str): diameter = int(diameter)
    s = "".join(ch for ch in text if not ch.isspace())
    rows = diameter
    cols = math.ceil(len(s)/rows)
    grid = [[""]*cols for _ in range(rows)]
    i = 0
    for c in range(cols):
        for r in range(rows):
            if i < len(s):
                grid[r][c] = s[i]; i += 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols) if grid[r][c])

def Scytale_decode(text: str, diameter: int | str = 5) -> str:
    if isinstance(diameter, str): diameter = int(diameter)
    s = text; rows = diameter; cols = math.ceil(len(s)/rows)
    base = len(s)//rows; extra = len(s)%rows
    row_lengths = [base + (1 if r < extra else 0) for r in range(rows)]
    rows_data = []; idx = 0
    for r in range(rows):
        L = row_lengths[r]; rows_data.append(list(s[idx:idx+L])); idx += L
    out = []
    for c in range(cols):
        for r in range(rows):
            if rows_data[r]:
                out.append(rows_data[r].pop(0))
    return "".join(out)

def DoubleTransposition_encode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    return Columnar_encode(Columnar_encode(text, key1), key2)

def DoubleTransposition_decode(text: str, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> str:
    return Columnar_decode(Columnar_decode(text, key2), key1)

def Route_encode(text: str, rows: int | str = 5, cols: int | str = 5, route: str = "URDL") -> str:
    if isinstance(rows, str): rows = int(rows)
    if isinstance(cols, str): cols = int(cols)
    s = "".join(ch for ch in text if not ch.isspace())
    L = rows*cols
    s = s.ljust(L, 'X')
    grid = [list(s[r*cols:(r+1)*cols]) for r in range(rows)]
    top, left, bottom, right = 0, 0, rows-1, cols-1
    out = []
    def ring():
        nonlocal top,left,bottom,right
        for c in range(left, right+1): out.append(grid[top][c])
        for r in range(top+1, bottom+1): out.append(grid[r][right])
        if bottom>top:
            for c in range(right-1, left-1, -1): out.append(grid[bottom][c])
        if right>left:
            for r in range(bottom-1, top, -1): out.append(grid[r][left])
        top += 1; left += 1; bottom -= 1; right -= 1
    while top <= bottom and left <= right:
        ring()
    return "".join(out).rstrip('X')

def Route_decode(text: str, rows: int | str = 5, cols: int | str = 5, route: str = "URDL") -> str:
    if isinstance(rows, str): rows = int(rows)
    if isinstance(cols, str): cols = int(cols)
    s = text; L = rows*cols
    s = s.ljust(L, 'X')
    grid = [[""]*cols for _ in range(rows)]
    top, left, bottom, right = 0, 0, rows-1, cols-1
    idx = 0
    while top <= bottom and left <= right:
        for c in range(left, right+1):
            grid[top][c] = s[idx]; idx += 1
        for r in range(top+1, bottom+1):
            grid[r][right] = s[idx]; idx += 1
        if bottom>top:
            for c in range(right-1, left-1, -1):
                grid[bottom][c] = s[idx]; idx += 1
        if right>left:
            for r in range(bottom-1, top, -1):
                grid[r][left] = s[idx]; idx += 1
        top += 1; left += 1; bottom -= 1; right -= 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols)).rstrip('X')


# =============================================================================
# Extra classical ciphers
# =============================================================================

def ROT5_encode(text: str) -> str:
    out = []
    for ch in text:
        if ch.isdigit():
            out.append(str((int(ch) + 5) % 10))
        else:
            out.append(ch)
    return "".join(out)

def ROT5_decode(text: str) -> str:
    return ROT5_encode(text)

def ROT18_encode(text: str) -> str:
    return ROT5_encode(ROT13_encode(text))

def ROT18_decode(text: str) -> str:
    return ROT18_encode(text)

def _bifid_square(keyword: str = "KEYWORD") -> Tuple[Dict[str, Tuple[int,int]], Dict[Tuple[int,int], str]]:
    _, pos, rev = _key_square_5(keyword)
    return pos, rev

def Bifid_encode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    pos, rev = _bifid_square(key)
    s = only_alpha(text).replace('J', 'I')
    out = []
    for block in chunk(s, period):
        rows = []
        cols = []
        for ch in block:
            r, c = pos[ch]
            rows.append(r); cols.append(c)
        merged = rows + cols
        for i in range(0, len(merged), 2):
            out.append(rev[(merged[i], merged[i+1])])
    return "".join(out).lower()

def Bifid_decode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    pos, rev = _bifid_square(key)
    s = only_alpha(text).replace('J', 'I')
    out = []
    for block in chunk(s, period):
        coords = []
        for ch in block:
            coords.extend(pos[ch])
        half = len(block)
        rows = coords[:half]
        cols = coords[half:]
        for r, c in zip(rows, cols):
            out.append(rev[(r, c)])
    return "".join(out).lower()

def BifidNoPeriod_encode(text: str, key: str = "KEYWORD") -> str:
    s = only_alpha(text).replace('J', 'I')
    return Bifid_encode(s, key, max(1, len(s)))

def BifidNoPeriod_decode(text: str, key: str = "KEYWORD") -> str:
    s = only_alpha(text).replace('J', 'I')
    return Bifid_decode(s, key, max(1, len(s)))

def ConjugatedBifid_encode(text: str, plain_key: str = "PLAIN", cipher_key: str = "CIPHER", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    plain_pos, _plain_rev = _bifid_square(plain_key)
    _cipher_pos, cipher_rev = _bifid_square(cipher_key)
    s = only_alpha(text).replace('J', 'I')
    out = []
    for block in chunk(s, period):
        rows = []
        cols = []
        for ch in block:
            r, c = plain_pos[ch]
            rows.append(r); cols.append(c)
        merged = rows + cols
        for i in range(0, len(merged), 2):
            out.append(cipher_rev[(merged[i], merged[i+1])])
    return "".join(out).lower()

def ConjugatedBifid_decode(text: str, plain_key: str = "PLAIN", cipher_key: str = "CIPHER", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    _plain_pos, plain_rev = _bifid_square(plain_key)
    cipher_pos, _cipher_rev = _bifid_square(cipher_key)
    s = only_alpha(text).replace('J', 'I')
    out = []
    for block in chunk(s, period):
        coords = []
        for ch in block:
            coords.extend(cipher_pos[ch])
        half = len(block)
        rows = coords[:half]
        cols = coords[half:]
        for r, c in zip(rows, cols):
            out.append(plain_rev[(r, c)])
    return "".join(out).lower()

TRIFID_EXTRA = "."

def _trifid_alphabet(keyword: str = "KEYWORD") -> str:
    seen = set()
    out = []
    for ch in to_upper(keyword):
        if ch in ALPHA_SET or ch == TRIFID_EXTRA:
            if ch not in seen:
                out.append(ch); seen.add(ch)
    for ch in ALPHA + TRIFID_EXTRA:
        if ch not in seen:
            out.append(ch); seen.add(ch)
    return "".join(out[:27])

def _trifid_tables(keyword: str = "KEYWORD") -> Tuple[Dict[str, Tuple[int,int,int]], Dict[Tuple[int,int,int], str]]:
    alpha = _trifid_alphabet(keyword)
    pos: Dict[str, Tuple[int,int,int]] = {}
    rev: Dict[Tuple[int,int,int], str] = {}
    for i, ch in enumerate(alpha):
        layer = i // 9
        rem = i % 9
        row, col = divmod(rem, 3)
        pos[ch] = (layer, row, col)
        rev[(layer, row, col)] = ch
    return pos, rev

def Trifid_encode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    pos, rev = _trifid_tables(key)
    s = "".join(ch.upper() for ch in text if ch.upper() in ALPHA_SET or ch == TRIFID_EXTRA)
    out = []
    for block in chunk(s, period):
        coords = [[], [], []]
        for ch in block:
            a, b, c = pos[ch]
            coords[0].append(a); coords[1].append(b); coords[2].append(c)
        merged = coords[0] + coords[1] + coords[2]
        for i in range(0, len(merged), 3):
            out.append(rev[(merged[i], merged[i+1], merged[i+2])])
    return "".join(out).lower()

def Trifid_decode(text: str, key: str = "KEYWORD", period: int | str = 5) -> str:
    if isinstance(period, str):
        period = int(period.strip() or "5")
    period = max(1, period)
    pos, rev = _trifid_tables(key)
    s = "".join(ch.upper() for ch in text if ch.upper() in ALPHA_SET or ch == TRIFID_EXTRA)
    out = []
    for block in chunk(s, period):
        flat = []
        for ch in block:
            flat.extend(pos[ch])
        n = len(block)
        a = flat[:n]
        b = flat[n:2*n]
        c = flat[2*n:]
        for coords in zip(a, b, c):
            out.append(rev[coords])
    return "".join(out).lower()

def _parse_hill2_key(key: str) -> Tuple[int, int, int, int]:
    parts = [p.strip() for p in key.replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    if len(parts) == 4:
        nums = tuple(int(p) % 26 for p in parts)
    else:
        letters = only_alpha(key)
        if len(letters) < 4:
            raise ValueError("Hill 2x2 key must be four numbers or at least four letters")
        nums = tuple(ALPHA.index(ch) for ch in letters[:4])
    a, b, c, d = nums
    det = (a*d - b*c) % 26
    mod_inv(det, 26)  # validate invertible
    return a, b, c, d

def Hill2x2_encode(text: str, key: str = "3,3,2,5") -> str:
    a, b, c, d = _parse_hill2_key(key)
    s = only_alpha(text)
    if len(s) % 2:
        s += "X"
    out = []
    for x, y in chunk(s, 2):
        p0 = ALPHA.index(x); p1 = ALPHA.index(y)
        out.append(ALPHA[(a*p0 + b*p1) % 26])
        out.append(ALPHA[(c*p0 + d*p1) % 26])
    return "".join(out).lower()

def Hill2x2_decode(text: str, key: str = "3,3,2,5") -> str:
    a, b, c, d = _parse_hill2_key(key)
    det = (a*d - b*c) % 26
    inv_det = mod_inv(det, 26)
    ia = (d * inv_det) % 26
    ib = (-b * inv_det) % 26
    ic = (-c * inv_det) % 26
    id_ = (a * inv_det) % 26
    s = only_alpha(text)
    if len(s) % 2:
        s += "X"
    out = []
    for x, y in chunk(s, 2):
        c0 = ALPHA.index(x); c1 = ALPHA.index(y)
        out.append(ALPHA[(ia*c0 + ib*c1) % 26])
        out.append(ALPHA[(ic*c0 + id_*c1) % 26])
    return "".join(out).lower()


# =============================================================================
# Modern / recently created ciphers
# =============================================================================

def _xor_stream(data: bytes, stream: Iterable[int]) -> bytes:
    return bytes(b ^ k for b, k in zip(data, stream))

def _rc4_stream(key: bytes) -> Iterable[int]:
    if not key:
        key = bytes([0])
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        yield s[(s[i] + s[j]) % 256]

def RC4_hex_encode(text: str, key: str = "secret") -> str:
    data = text.encode("utf-8")
    cipher = _xor_stream(data, _rc4_stream(key.encode("utf-8")))
    return cipher.hex()

def RC4_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    plain = _xor_stream(data, _rc4_stream(key.encode("utf-8")))
    return plain.decode("utf-8", errors="replace")

_SOLITAIRE_JOKER_A = 53
_SOLITAIRE_JOKER_B = 54

def _solitaire_card_value(card: int) -> int:
    return 53 if card in (_SOLITAIRE_JOKER_A, _SOLITAIRE_JOKER_B) else card

def _solitaire_move(deck: List[int], card: int, steps: int) -> None:
    for _ in range(steps):
        i = deck.index(card)
        deck.pop(i)
        new_index = i + 1
        if new_index >= len(deck):
            new_index = 1
        deck.insert(new_index, card)

def _solitaire_triple_cut(deck: List[int]) -> None:
    a = min(deck.index(_SOLITAIRE_JOKER_A), deck.index(_SOLITAIRE_JOKER_B))
    b = max(deck.index(_SOLITAIRE_JOKER_A), deck.index(_SOLITAIRE_JOKER_B))
    deck[:] = deck[b+1:] + deck[a:b+1] + deck[:a]

def _solitaire_count_cut(deck: List[int], count: int) -> None:
    count = count % 54
    if count <= 0 or count >= 53:
        return
    deck[:] = deck[count:-1] + deck[:count] + deck[-1:]

def _solitaire_step(deck: List[int]) -> Optional[int]:
    while True:
        _solitaire_move(deck, _SOLITAIRE_JOKER_A, 1)
        _solitaire_move(deck, _SOLITAIRE_JOKER_B, 2)
        _solitaire_triple_cut(deck)
        _solitaire_count_cut(deck, _solitaire_card_value(deck[-1]))
        top = _solitaire_card_value(deck[0])
        card = deck[top]
        if card not in (_SOLITAIRE_JOKER_A, _SOLITAIRE_JOKER_B):
            return ((card - 1) % 26) + 1

def _solitaire_keyed_deck(key: str) -> List[int]:
    deck = list(range(1, 55))
    for ch in only_alpha(key):
        _solitaire_step(deck)
        _solitaire_count_cut(deck, ALPHA.index(ch) + 1)
    return deck

def Solitaire_encode(text: str, key: str = "CRYPTONOMICON") -> str:
    deck = _solitaire_keyed_deck(key)
    out = []
    for ch in only_alpha(text):
        p = ALPHA.index(ch) + 1
        k = _solitaire_step(deck) or 0
        out.append(ALPHA[(p + k - 1) % 26])
    return "".join(out).lower()

def Solitaire_decode(text: str, key: str = "CRYPTONOMICON") -> str:
    deck = _solitaire_keyed_deck(key)
    out = []
    for ch in only_alpha(text):
        c = ALPHA.index(ch) + 1
        k = _solitaire_step(deck) or 0
        out.append(ALPHA[(c - k - 1) % 26])
    return "".join(out).lower()

def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xffffffff) | (v >> (32 - n))

def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xffffffff; state[d] ^= state[a]; state[d] = _rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xffffffff; state[b] ^= state[c]; state[b] = _rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xffffffff; state[d] ^= state[a]; state[d] = _rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xffffffff; state[b] ^= state[c]; state[b] = _rotl32(state[b], 7)

def _le_words(data: bytes) -> List[int]:
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]

def _parse_chacha_nonce(nonce: str) -> bytes:
    s = str(nonce).strip()
    try:
        raw = bytes.fromhex(s)
        if len(raw) == 12:
            return raw
    except Exception:
        pass
    return hashlib.sha256(s.encode("utf-8")).digest()[:12]

def _chacha_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()

def _chacha20_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    constants = b"expand 32-byte k"
    state = _le_words(constants) + _le_words(key32) + [counter & 0xffffffff] + _le_words(nonce12)
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return b"".join(((working[i] + state[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))

def _chacha20_stream(key32: bytes, nonce12: bytes, counter: int = 1) -> Iterable[int]:
    block_counter = int(counter)
    while True:
        for b in _chacha20_block(key32, block_counter, nonce12):
            yield b
        block_counter = (block_counter + 1) & 0xffffffff

def ChaCha20_hex_encode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    counter = int(counter)
    nonce_bytes = _parse_chacha_nonce(nonce)
    cipher = _xor_stream(text.encode("utf-8"), _chacha20_stream(_chacha_key(key), nonce_bytes, counter))
    meta = {"nonce": nonce_bytes.hex(), "counter": counter}
    return "[CHACHA20]" + json.dumps(meta) + "|" + cipher.hex()

def ChaCha20_hex_decode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    body = text.strip()
    if body.startswith("[CHACHA20]"):
        try:
            meta_end = body.index("|", len("[CHACHA20]"))
            meta = json.loads(body[len("[CHACHA20]"):meta_end])
            nonce = meta.get("nonce", nonce)
            counter = meta.get("counter", counter)
            body = body[meta_end+1:]
        except Exception as e:
            return f"Err:{e}"
    try:
        data = bytes.fromhex(body)
    except Exception as e:
        return f"Err:{e}"
    nonce_bytes = _parse_chacha_nonce(str(nonce))
    plain = _xor_stream(data, _chacha20_stream(_chacha_key(key), nonce_bytes, int(counter)))
    return plain.decode("utf-8", errors="replace")


def _cryptography_missing(name: str) -> str:
    return f"Err:{name} requires the optional 'cryptography' package"

def _aead_key(key: str, sizes: Tuple[int, ...] = (16, 24, 32)) -> bytes:
    raw = (key or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]+", raw or "") and len(raw) % 2 == 0:
        data = bytes.fromhex(raw)
        if len(data) in sizes:
            return data
    return hashlib.sha256((key or "secret").encode("utf-8")).digest()[:max(sizes)]

def _nonce_bytes(nonce: str, size: int) -> bytes:
    raw = (nonce or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]+", raw or "") and len(raw) == size * 2:
        return bytes.fromhex(raw)
    return hashlib.sha256((nonce or "nonce").encode("utf-8")).digest()[:size]

def AESGCM_hex_encode(text: str, key: str = "secret", nonce: str = "nonce", aad: str = "") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-GCM")
    AESGCM = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").AESGCM
    nonce_bytes = _nonce_bytes(nonce, 12)
    aad_bytes = (aad or "").encode("utf-8")
    cipher = AESGCM(_aead_key(key)).encrypt(nonce_bytes, text.encode("utf-8"), aad_bytes)
    meta = {"nonce": nonce_bytes.hex(), "aad": aad}
    return "[AESGCM]" + json.dumps(meta, separators=(",", ":")) + "|" + cipher.hex()

def AESGCM_hex_decode(text: str, key: str = "secret", nonce: str = "nonce", aad: str = "") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-GCM")
    AESGCM = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").AESGCM
    body = text.strip()
    if body.startswith("[AESGCM]"):
        meta_end = body.index("|", len("[AESGCM]"))
        meta = json.loads(body[len("[AESGCM]"):meta_end])
        nonce = meta.get("nonce", nonce)
        aad = meta.get("aad", aad)
        body = body[meta_end+1:]
    plain = AESGCM(_aead_key(key)).decrypt(_nonce_bytes(str(nonce), 12), bytes.fromhex(body), (aad or "").encode("utf-8"))
    return plain.decode("utf-8")

def _aes_cipher(key: str, mode_obj):
    if importlib.util.find_spec("cryptography") is None:
        return None
    ciphers = importlib.import_module("cryptography.hazmat.primitives.ciphers")
    return ciphers.Cipher(ciphers.algorithms.AES(_aead_key(key)), mode_obj)

def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        return data
    return data[:-pad]

def AESECB_hex_encode(text: str, key: str = "secret") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-ECB")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    enc = _aes_cipher(key, modes.ECB()).encryptor()
    return "[AESECB]|" + (enc.update(_pkcs7_pad(text.encode("utf-8"))) + enc.finalize()).hex()

def AESECB_hex_decode(text: str, key: str = "secret") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-ECB")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    body = text.split("|", 1)[1] if text.startswith("[AESECB]|") else text
    dec = _aes_cipher(key, modes.ECB()).decryptor()
    plain = _pkcs7_unpad(dec.update(bytes.fromhex(body.strip())) + dec.finalize())
    return plain.decode("utf-8")

def AESCBC_hex_encode(text: str, key: str = "secret", iv: str = "iv") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-CBC")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    iv_bytes = _nonce_bytes(iv, 16)
    enc = _aes_cipher(key, modes.CBC(iv_bytes)).encryptor()
    cipher = enc.update(_pkcs7_pad(text.encode("utf-8"))) + enc.finalize()
    return "[AESCBC]" + json.dumps({"iv": iv_bytes.hex()}, separators=(",", ":")) + "|" + cipher.hex()

def AESCBC_hex_decode(text: str, key: str = "secret", iv: str = "iv") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-CBC")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    body = text.strip()
    if body.startswith("[AESCBC]"):
        meta_end = body.index("|", len("[AESCBC]"))
        meta = json.loads(body[len("[AESCBC]"):meta_end])
        iv = meta.get("iv", iv)
        body = body[meta_end+1:]
    dec = _aes_cipher(key, modes.CBC(_nonce_bytes(str(iv), 16))).decryptor()
    plain = _pkcs7_unpad(dec.update(bytes.fromhex(body)) + dec.finalize())
    return plain.decode("utf-8")

def AESCTR_hex_encode(text: str, key: str = "secret", nonce: str = "nonce") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-CTR")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    nonce_bytes = _nonce_bytes(nonce, 16)
    enc = _aes_cipher(key, modes.CTR(nonce_bytes)).encryptor()
    cipher = enc.update(text.encode("utf-8")) + enc.finalize()
    return "[AESCTR]" + json.dumps({"nonce": nonce_bytes.hex()}, separators=(",", ":")) + "|" + cipher.hex()

def AESCTR_hex_decode(text: str, key: str = "secret", nonce: str = "nonce") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("AES-CTR")
    modes = importlib.import_module("cryptography.hazmat.primitives.ciphers.modes")
    body = text.strip()
    if body.startswith("[AESCTR]"):
        meta_end = body.index("|", len("[AESCTR]"))
        meta = json.loads(body[len("[AESCTR]"):meta_end])
        nonce = meta.get("nonce", nonce)
        body = body[meta_end+1:]
    dec = _aes_cipher(key, modes.CTR(_nonce_bytes(str(nonce), 16))).decryptor()
    return (dec.update(bytes.fromhex(body)) + dec.finalize()).decode("utf-8")

def ChaCha20Poly1305_hex_encode(text: str, key: str = "secret", nonce: str = "nonce", aad: str = "") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("ChaCha20-Poly1305")
    ChaCha20Poly1305 = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").ChaCha20Poly1305
    nonce_bytes = _nonce_bytes(nonce, 12)
    aad_bytes = (aad or "").encode("utf-8")
    cipher = ChaCha20Poly1305(_aead_key(key, (32,))).encrypt(nonce_bytes, text.encode("utf-8"), aad_bytes)
    meta = {"nonce": nonce_bytes.hex(), "aad": aad}
    return "[CHACHA20POLY1305]" + json.dumps(meta, separators=(",", ":")) + "|" + cipher.hex()

def ChaCha20Poly1305_hex_decode(text: str, key: str = "secret", nonce: str = "nonce", aad: str = "") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("ChaCha20-Poly1305")
    ChaCha20Poly1305 = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").ChaCha20Poly1305
    body = text.strip()
    if body.startswith("[CHACHA20POLY1305]"):
        meta_end = body.index("|", len("[CHACHA20POLY1305]"))
        meta = json.loads(body[len("[CHACHA20POLY1305]"):meta_end])
        nonce = meta.get("nonce", nonce)
        aad = meta.get("aad", aad)
        body = body[meta_end+1:]
    plain = ChaCha20Poly1305(_aead_key(key, (32,))).decrypt(_nonce_bytes(str(nonce), 12), bytes.fromhex(body), (aad or "").encode("utf-8"))
    return plain.decode("utf-8")

def FernetToken_encode(text: str, password: str = "secret") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("Fernet")
    Fernet = importlib.import_module("cryptography.fernet").Fernet
    fkey = base64.urlsafe_b64encode(hashlib.sha256((password or "secret").encode("utf-8")).digest())
    return Fernet(fkey).encrypt(text.encode("utf-8")).decode("ascii")

def FernetToken_decode(text: str, password: str = "secret") -> str:
    if importlib.util.find_spec("cryptography") is None:
        return _cryptography_missing("Fernet")
    Fernet = importlib.import_module("cryptography.fernet").Fernet
    fkey = base64.urlsafe_b64encode(hashlib.sha256((password or "secret").encode("utf-8")).digest())
    return Fernet(fkey).decrypt(text.encode("ascii")).decode("utf-8")


def _parse_salsa_nonce(nonce: str) -> bytes:
    s = str(nonce).strip()
    try:
        raw = bytes.fromhex(s)
        if len(raw) == 8:
            return raw
    except Exception:
        pass
    return hashlib.sha256(s.encode("utf-8")).digest()[:8]

def _salsa20_quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[b] ^= _rotl32((state[a] + state[d]) & 0xffffffff, 7)
    state[c] ^= _rotl32((state[b] + state[a]) & 0xffffffff, 9)
    state[d] ^= _rotl32((state[c] + state[b]) & 0xffffffff, 13)
    state[a] ^= _rotl32((state[d] + state[c]) & 0xffffffff, 18)

def _salsa20_block(key32: bytes, nonce8: bytes, counter: int) -> bytes:
    constants = b"expand 32-byte k"
    c = _le_words(constants)
    k = _le_words(key32)
    n = _le_words(nonce8)
    state = [c[0], k[0], k[1], k[2], k[3], c[1], n[0], n[1], counter & 0xffffffff, (counter >> 32) & 0xffffffff, c[2], k[4], k[5], k[6], k[7], c[3]]
    working = state[:]
    for _ in range(10):
        _salsa20_quarter_round(working, 0, 4, 8, 12)
        _salsa20_quarter_round(working, 5, 9, 13, 1)
        _salsa20_quarter_round(working, 10, 14, 2, 6)
        _salsa20_quarter_round(working, 15, 3, 7, 11)
        _salsa20_quarter_round(working, 0, 1, 2, 3)
        _salsa20_quarter_round(working, 5, 6, 7, 4)
        _salsa20_quarter_round(working, 10, 11, 8, 9)
        _salsa20_quarter_round(working, 15, 12, 13, 14)
    return b"".join(((working[i] + state[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))

def _salsa20_stream(key32: bytes, nonce8: bytes, counter: int = 0) -> Iterable[int]:
    block_counter = int(counter)
    while True:
        for b in _salsa20_block(key32, nonce8, block_counter):
            yield b
        block_counter = (block_counter + 1) & 0xffffffffffffffff

def Salsa20_hex_encode(text: str, key: str = "secret", nonce: str = "0000000000000000", counter: int | str = 0) -> str:
    counter = int(counter)
    nonce_bytes = _parse_salsa_nonce(nonce)
    cipher = _xor_stream(text.encode("utf-8"), _salsa20_stream(_chacha_key(key), nonce_bytes, counter))
    meta = {"nonce": nonce_bytes.hex(), "counter": counter}
    return "[SALSA20]" + json.dumps(meta) + "|" + cipher.hex()

def Salsa20_hex_decode(text: str, key: str = "secret", nonce: str = "0000000000000000", counter: int | str = 0) -> str:
    body = text.strip()
    if body.startswith("[SALSA20]"):
        try:
            meta_end = body.index("|", len("[SALSA20]"))
            meta = json.loads(body[len("[SALSA20]"):meta_end])
            nonce = meta.get("nonce", nonce)
            counter = meta.get("counter", counter)
            body = body[meta_end+1:]
        except Exception as e:
            return f"Err:{e}"
    try:
        data = bytes.fromhex(body)
    except Exception as e:
        return f"Err:{e}"
    plain = _xor_stream(data, _salsa20_stream(_chacha_key(key), _parse_salsa_nonce(str(nonce)), int(counter)))
    return plain.decode("utf-8", errors="replace")

def _bytes_to_u32_list(data: bytes, include_length: bool) -> List[int]:
    n = len(data)
    if n % 4:
        data += bytes(4 - (n % 4))
    values = [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]
    if include_length:
        values.append(n)
    return values

def _u32_list_to_bytes(values: List[int], include_length: bool) -> bytes:
    if include_length:
        if not values:
            return b""
        n = values[-1]
        values = values[:-1]
    else:
        n = len(values) * 4
    data = b"".join((v & 0xffffffff).to_bytes(4, "little") for v in values)
    return data[:n]

def _xxtea_key(key: str) -> List[int]:
    digest = hashlib.md5(key.encode("utf-8")).digest()
    return [int.from_bytes(digest[i:i+4], "little") for i in range(0, 16, 4)]

def _xxtea_encrypt_words(v: List[int], k: List[int]) -> List[int]:
    n = len(v)
    if n < 2:
        return v
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    total = 0
    z = v[-1]
    for _ in range(rounds):
        total = (total + delta) & 0xffffffff
        e = (total >> 2) & 3
        for p_idx in range(n - 1):
            y = v[p_idx + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p_idx & 3) ^ e] ^ z))
            mx &= 0xffffffff
            v[p_idx] = (v[p_idx] + mx) & 0xffffffff
            z = v[p_idx]
        y = v[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[((n - 1) & 3) ^ e] ^ z))
        mx &= 0xffffffff
        v[-1] = (v[-1] + mx) & 0xffffffff
        z = v[-1]
    return v

def _xxtea_decrypt_words(v: List[int], k: List[int]) -> List[int]:
    n = len(v)
    if n < 2:
        return v
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    total = (rounds * delta) & 0xffffffff
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p_idx in range(n - 1, 0, -1):
            z = v[p_idx - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p_idx & 3) ^ e] ^ z))
            mx &= 0xffffffff
            v[p_idx] = (v[p_idx] - mx) & 0xffffffff
            y = v[p_idx]
        z = v[-1]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[e] ^ z))
        mx &= 0xffffffff
        v[0] = (v[0] - mx) & 0xffffffff
        y = v[0]
        total = (total - delta) & 0xffffffff
    return v

def XXTEA_hex_encode(text: str, key: str = "secret") -> str:
    values = _bytes_to_u32_list(text.encode("utf-8"), True)
    encrypted = _xxtea_encrypt_words(values[:], _xxtea_key(key))
    return _u32_list_to_bytes(encrypted, False).hex()

def XXTEA_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    values = _bytes_to_u32_list(data, False)
    decrypted = _xxtea_decrypt_words(values, _xxtea_key(key))
    return _u32_list_to_bytes(decrypted, True).decode("utf-8", errors="replace")

def _rotr16(v: int, n: int) -> int:
    return ((v >> n) | ((v << (16 - n)) & 0xffff)) & 0xffff

def _rotl16(v: int, n: int) -> int:
    return (((v << n) & 0xffff) | (v >> (16 - n))) & 0xffff

def _speck32_key_schedule(key: str) -> List[int]:
    digest = hashlib.sha256(key.encode("utf-8")).digest()[:8]
    words = [int.from_bytes(digest[i:i+2], "little") for i in range(0, 8, 2)]
    round_keys = [words[0]]
    l = words[1:]
    for i in range(21):
        new_l = ((_rotr16(l[i], 7) + round_keys[i]) & 0xffff) ^ i
        l.append(new_l)
        round_keys.append(_rotl16(round_keys[i], 2) ^ new_l)
    return round_keys

def _speck32_encrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    x = int.from_bytes(block[:2], "little")
    y = int.from_bytes(block[2:], "little")
    for k in round_keys:
        x = ((_rotr16(x, 7) + y) & 0xffff) ^ k
        y = _rotl16(y, 2) ^ x
    return x.to_bytes(2, "little") + y.to_bytes(2, "little")

def _speck32_decrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    x = int.from_bytes(block[:2], "little")
    y = int.from_bytes(block[2:], "little")
    for k in reversed(round_keys):
        y = _rotr16(y ^ x, 2)
        x = _rotl16(((x ^ k) - y) & 0xffff, 7)
    return x.to_bytes(2, "little") + y.to_bytes(2, "little")

def Speck32_hex_encode(text: str, key: str = "secret") -> str:
    data = len(text.encode("utf-8")).to_bytes(4, "little") + text.encode("utf-8")
    if len(data) % 4:
        data += bytes(4 - (len(data) % 4))
    round_keys = _speck32_key_schedule(key)
    return b"".join(_speck32_encrypt_block(data[i:i+4], round_keys) for i in range(0, len(data), 4)).hex()

def Speck32_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    if len(data) % 4:
        return "Err:ciphertext length must be a multiple of 4 bytes"
    round_keys = _speck32_key_schedule(key)
    plain = b"".join(_speck32_decrypt_block(data[i:i+4], round_keys) for i in range(0, len(data), 4))
    if len(plain) < 4:
        return ""
    n = int.from_bytes(plain[:4], "little")
    return plain[4:4+n].decode("utf-8", errors="replace")


def _tea_key(key: str) -> List[int]:
    digest = hashlib.sha256(key.encode("utf-8")).digest()[:16]
    return [int.from_bytes(digest[i:i+4], "little") for i in range(0, 16, 4)]

def _u32_pair_blocks(text: str, block_size: int = 8) -> bytes:
    data = len(text.encode("utf-8")).to_bytes(4, "little") + text.encode("utf-8")
    if len(data) % block_size:
        data += bytes(block_size - (len(data) % block_size))
    return data

def _decode_length_prefixed(data: bytes) -> str:
    if len(data) < 4:
        return ""
    n = int.from_bytes(data[:4], "little")
    return data[4:4+n].decode("utf-8", errors="replace")

def _tea_encrypt_block(block: bytes, k: List[int]) -> bytes:
    v0 = int.from_bytes(block[:4], "little")
    v1 = int.from_bytes(block[4:], "little")
    total = 0
    delta = 0x9E3779B9
    for _ in range(32):
        total = (total + delta) & 0xffffffff
        v0 = (v0 + ((((v1 << 4) & 0xffffffff) + k[0]) ^ (v1 + total) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) & 0xffffffff) + k[2]) ^ (v0 + total) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
    return v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

def _tea_decrypt_block(block: bytes, k: List[int]) -> bytes:
    v0 = int.from_bytes(block[:4], "little")
    v1 = int.from_bytes(block[4:], "little")
    delta = 0x9E3779B9
    total = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) & 0xffffffff) + k[2]) ^ (v0 + total) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
        v0 = (v0 - ((((v1 << 4) & 0xffffffff) + k[0]) ^ (v1 + total) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        total = (total - delta) & 0xffffffff
    return v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

def TEA_hex_encode(text: str, key: str = "secret") -> str:
    data = _u32_pair_blocks(text)
    k = _tea_key(key)
    return b"".join(_tea_encrypt_block(data[i:i+8], k) for i in range(0, len(data), 8)).hex()

def TEA_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    if len(data) % 8:
        return "Err:ciphertext length must be a multiple of 8 bytes"
    k = _tea_key(key)
    plain = b"".join(_tea_decrypt_block(data[i:i+8], k) for i in range(0, len(data), 8))
    return _decode_length_prefixed(plain)

def _xtea_encrypt_block(block: bytes, k: List[int]) -> bytes:
    v0 = int.from_bytes(block[:4], "little")
    v1 = int.from_bytes(block[4:], "little")
    total = 0
    delta = 0x9E3779B9
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + k[total & 3]))) & 0xffffffff
        total = (total + delta) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xffffffff
    return v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

def _xtea_decrypt_block(block: bytes, k: List[int]) -> bytes:
    v0 = int.from_bytes(block[:4], "little")
    v1 = int.from_bytes(block[4:], "little")
    delta = 0x9E3779B9
    total = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xffffffff
        total = (total - delta) & 0xffffffff
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + k[total & 3]))) & 0xffffffff
    return v0.to_bytes(4, "little") + v1.to_bytes(4, "little")

def XTEA_hex_encode(text: str, key: str = "secret") -> str:
    data = _u32_pair_blocks(text)
    k = _tea_key(key)
    return b"".join(_xtea_encrypt_block(data[i:i+8], k) for i in range(0, len(data), 8)).hex()

def XTEA_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    if len(data) % 8:
        return "Err:ciphertext length must be a multiple of 8 bytes"
    k = _tea_key(key)
    plain = b"".join(_xtea_decrypt_block(data[i:i+8], k) for i in range(0, len(data), 8))
    return _decode_length_prefixed(plain)

def _rotl32_var(v: int, n: int) -> int:
    n &= 31
    return ((v << n) & 0xffffffff) | (v >> ((32 - n) & 31)) if n else v & 0xffffffff

def _rotr32_var(v: int, n: int) -> int:
    n &= 31
    return (v >> n) | ((v << ((32 - n) & 31)) & 0xffffffff) if n else v & 0xffffffff

def _rc5_key_schedule(key: str, rounds: int = 12) -> List[int]:
    key_bytes = hashlib.sha256(key.encode("utf-8")).digest()[:16]
    words = [0] * 4
    for i in range(len(key_bytes) - 1, -1, -1):
        words[i // 4] = ((words[i // 4] << 8) + key_bytes[i]) & 0xffffffff
    s = [0] * (2 * (rounds + 1))
    s[0] = 0xB7E15163
    for i in range(1, len(s)):
        s[i] = (s[i - 1] + 0x9E3779B9) & 0xffffffff
    a = b = i = j = 0
    for _ in range(3 * max(len(words), len(s))):
        a = s[i] = _rotl32_var((s[i] + a + b) & 0xffffffff, 3)
        b = words[j] = _rotl32_var((words[j] + a + b) & 0xffffffff, (a + b) & 31)
        i = (i + 1) % len(s)
        j = (j + 1) % len(words)
    return s

def _rc5_encrypt_block(block: bytes, s: List[int], rounds: int = 12) -> bytes:
    a = int.from_bytes(block[:4], "little")
    b = int.from_bytes(block[4:], "little")
    a = (a + s[0]) & 0xffffffff
    b = (b + s[1]) & 0xffffffff
    for i in range(1, rounds + 1):
        a = (_rotl32_var(a ^ b, b) + s[2 * i]) & 0xffffffff
        b = (_rotl32_var(b ^ a, a) + s[2 * i + 1]) & 0xffffffff
    return a.to_bytes(4, "little") + b.to_bytes(4, "little")

def _rc5_decrypt_block(block: bytes, s: List[int], rounds: int = 12) -> bytes:
    a = int.from_bytes(block[:4], "little")
    b = int.from_bytes(block[4:], "little")
    for i in range(rounds, 0, -1):
        b = _rotr32_var((b - s[2 * i + 1]) & 0xffffffff, a) ^ a
        a = _rotr32_var((a - s[2 * i]) & 0xffffffff, b) ^ b
    b = (b - s[1]) & 0xffffffff
    a = (a - s[0]) & 0xffffffff
    return a.to_bytes(4, "little") + b.to_bytes(4, "little")

def RC5_32_hex_encode(text: str, key: str = "secret") -> str:
    data = _u32_pair_blocks(text)
    s = _rc5_key_schedule(key)
    return b"".join(_rc5_encrypt_block(data[i:i+8], s) for i in range(0, len(data), 8)).hex()

def RC5_32_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    if len(data) % 8:
        return "Err:ciphertext length must be a multiple of 8 bytes"
    s = _rc5_key_schedule(key)
    plain = b"".join(_rc5_decrypt_block(data[i:i+8], s) for i in range(0, len(data), 8))
    return _decode_length_prefixed(plain)


def _chacha_block_rounds(key32: bytes, counter: int, nonce12: bytes, rounds: int) -> bytes:
    constants = b"expand 32-byte k"
    state = _le_words(constants) + _le_words(key32) + [counter & 0xffffffff] + _le_words(nonce12)
    working = state[:]
    for _ in range(rounds // 2):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return b"".join(((working[i] + state[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))

def _chacha_stream_rounds(key32: bytes, nonce12: bytes, counter: int, rounds: int) -> Iterable[int]:
    block_counter = int(counter)
    while True:
        for b in _chacha_block_rounds(key32, block_counter, nonce12, rounds):
            yield b
        block_counter = (block_counter + 1) & 0xffffffff

def _chacha_variant_encode(text: str, key: str, nonce: str, counter: int | str, rounds: int, tag: str) -> str:
    counter = int(counter)
    nonce_bytes = _parse_chacha_nonce(nonce)
    cipher = _xor_stream(text.encode("utf-8"), _chacha_stream_rounds(_chacha_key(key), nonce_bytes, counter, rounds))
    meta = {"nonce": nonce_bytes.hex(), "counter": counter, "rounds": rounds}
    return f"[{tag}]" + json.dumps(meta) + "|" + cipher.hex()

def _chacha_variant_decode(text: str, key: str, nonce: str, counter: int | str, rounds: int, tag: str) -> str:
    body = text.strip()
    prefix = f"[{tag}]"
    if body.startswith(prefix):
        try:
            meta_end = body.index("|", len(prefix))
            meta = json.loads(body[len(prefix):meta_end])
            nonce = meta.get("nonce", nonce)
            counter = meta.get("counter", counter)
            body = body[meta_end+1:]
        except Exception as e:
            return f"Err:{e}"
    try:
        data = bytes.fromhex(body)
    except Exception as e:
        return f"Err:{e}"
    plain = _xor_stream(data, _chacha_stream_rounds(_chacha_key(key), _parse_chacha_nonce(str(nonce)), int(counter), rounds))
    return plain.decode("utf-8", errors="replace")

def ChaCha12_hex_encode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    return _chacha_variant_encode(text, key, nonce, counter, 12, "CHACHA12")

def ChaCha12_hex_decode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    return _chacha_variant_decode(text, key, nonce, counter, 12, "CHACHA12")

def ChaCha8_hex_encode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    return _chacha_variant_encode(text, key, nonce, counter, 8, "CHACHA8")

def ChaCha8_hex_decode(text: str, key: str = "secret", nonce: str = "000000000000000000000000", counter: int | str = 1) -> str:
    return _chacha_variant_decode(text, key, nonce, counter, 8, "CHACHA8")

def _simon_f(x: int) -> int:
    return (_rotl16(x, 1) & _rotl16(x, 8)) ^ _rotl16(x, 2)

def _simon32_key_schedule(key: str) -> List[int]:
    digest = hashlib.sha256(key.encode("utf-8")).digest()[:8]
    keys = [int.from_bytes(digest[i:i+2], "little") for i in range(0, 8, 2)]
    z0 = "11111010001001010110000111001101111101000100101011000011100110"
    for i in range(28):
        tmp = _rotr16(keys[i + 3], 3) ^ keys[i + 1]
        tmp ^= _rotr16(tmp, 1)
        zbit = int(z0[i % len(z0)])
        keys.append((0xfffc ^ zbit ^ keys[i] ^ tmp) & 0xffff)
    return keys[:32]

def _simon32_encrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    x = int.from_bytes(block[:2], "little")
    y = int.from_bytes(block[2:], "little")
    for k in round_keys:
        x, y = (y ^ _simon_f(x) ^ k) & 0xffff, x
    return x.to_bytes(2, "little") + y.to_bytes(2, "little")

def _simon32_decrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    x = int.from_bytes(block[:2], "little")
    y = int.from_bytes(block[2:], "little")
    for k in reversed(round_keys):
        x, y = y, (x ^ _simon_f(y) ^ k) & 0xffff
    return x.to_bytes(2, "little") + y.to_bytes(2, "little")

def Simon32_64_hex_encode(text: str, key: str = "secret") -> str:
    data = _u32_pair_blocks(text, block_size=4)
    round_keys = _simon32_key_schedule(key)
    return b"".join(_simon32_encrypt_block(data[i:i+4], round_keys) for i in range(0, len(data), 4)).hex()

def Simon32_64_hex_decode(text: str, key: str = "secret") -> str:
    try:
        data = bytes.fromhex(text.strip())
    except Exception as e:
        return f"Err:{e}"
    if len(data) % 4:
        return "Err:ciphertext length must be a multiple of 4 bytes"
    round_keys = _simon32_key_schedule(key)
    plain = b"".join(_simon32_decrypt_block(data[i:i+4], round_keys) for i in range(0, len(data), 4))
    return _decode_length_prefixed(plain)

# =============================================================================
# ADFGX / ADFGVX
# =============================================================================

def _columnar_route(s: str, key: str) -> str: return Columnar_encode(s, key)
def _columnar_unroute(s: str, key: str) -> str: return Columnar_decode(s, key)

def ADFGX_encode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER") -> str:
    labels = "ADFGX"
    sq, pos, rev = _key_square_5(square_key)
    s = []
    for ch in to_upper(text):
        if ch == 'J': ch = 'I'
        if ch in pos:
            r, c = pos[ch]; s.append(labels[r]); s.append(labels[c])
        elif ch.isdigit():
            word = {"0":"ZERO","1":"ONE","2":"TWO","3":"THREE","4":"FOUR","5":"FIVE",
                    "6":"SIX","7":"SEVEN","8":"EIGHT","9":"NINE"}[ch]
            for w in word:
                r, c = pos[w]; s.append(labels[r]); s.append(labels[c])
    frac = "".join(s)
    return _columnar_route(frac, route_key)

def ADFGX_decode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER") -> str:
    labels = "ADFGX"
    sq, pos, rev = _key_square_5(square_key)
    frac = _columnar_unroute(text, route_key)
    out = []
    for i in range(0, len(frac), 2):
        r = labels.index(frac[i]); c = labels.index(frac[i+1])
        out.append(rev[(r,c)])
    return "".join(out).lower()

def ADFGVX_encode(text: str, square_key: str = "KEYW0RD", route_key: str = "CIPHER") -> str:
    labels = "ADFGVX"
    sq, pos, rev = _key_square_6(square_key)
    s = []
    for ch in to_upper(text):
        if ch in pos:
            r, c = pos[ch]; s.append(labels[r]); s.append(labels[c])
    frac = "".join(s)
    return _columnar_route(frac, route_key)

def ADFGVX_decode(text: str, square_key: str = "KEYW0RD", route_key: str = "CIPHER") -> str:
    labels = "ADFGVX"
    sq, pos, rev = _key_square_6(square_key)
    frac = _columnar_unroute(text, route_key)
    out = []
    for i in range(0, len(frac), 2):
        r = labels.index(frac[i]); c = labels.index(frac[i+1])
        out.append(rev[(r,c)])
    return "".join(out).lower()

# =============================================================================
# Morse / Pigpen
# =============================================================================

MORSE_TABLE = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....',
    'I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.',
    'Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
    'Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....',
    '6':'-....','7':'--...','8':'---..','9':'----.',
    '.':'.-.-.-',',':'--..--','?':'..--..',"'":'.----.','!':'-.-.--','/':'-..-.',
    '(':'-.--.',')':'-.--.-','&':'.-...',':':'---...',';':'-.-.-.','=':'-...-',
    '+':'.-.-.','-':'-....-','_':'..--.-','"':'.-..-.','$':'...-..-','@':'.--.-.'
}
MORSE_REV = {v:k for k,v in MORSE_TABLE.items()}

def Morse_encode(text: str) -> str:
    out_words = []
    for word in text.split():
        signs = []
        for ch in word:
            cu = ch.upper()
            if cu in MORSE_TABLE:
                signs.append(MORSE_TABLE[cu])
        out_words.append(" ".join(signs))
    return "[MORSE]|" + " / ".join(out_words)

def Morse_decode(text: str) -> str:
    s = text
    if s.startswith("[MORSE]|"): s = s[len("[MORSE]|"):]
    words = s.split(" / ")
    out = []
    for w in words:
        chars = []
        for code in w.strip().split():
            ch = MORSE_REV.get(code, '')
            if ch: chars.append(ch)
        out.append("".join(chars))
    return " ".join(out)



def _morse_fraction(text: str) -> str:
    words = []
    for word in text.split():
        codes = [MORSE_TABLE[ch.upper()] for ch in word if ch.upper() in MORSE_TABLE]
        words.append("x".join(codes))
    return "xx".join(words)

def _morse_unfraction(frac: str) -> str:
    words = frac.strip("x").split("xx") if frac else []
    out = []
    for word in words:
        chars = [MORSE_REV.get(code, "") for code in word.split("x")]
        out.append("".join(chars))
    return " ".join(out).lower()

def KnockCode_encode(text: str) -> str:
    return TapCode_encode(text).replace(".", ",")

def KnockCode_decode(text: str) -> str:
    return TapCode_decode(text.replace(",", "."))

_MORBIT_PAIRS = ["..", ".-", ".x", "-.", "--", "-x", "x.", "x-", "xx"]

def _morbit_maps(key: str = "123456789") -> Tuple[Dict[str, str], Dict[str, str]]:
    digits = "".join(ch for ch in key if ch.isdigit() and ch != "0")
    digits = "".join(dict.fromkeys(digits + "123456789"))[:9]
    enc = {pair: digits[i] for i, pair in enumerate(_MORBIT_PAIRS)}
    return enc, {v: k for k, v in enc.items()}

def Morbit_encode(text: str, key: str = "123456789") -> str:
    frac = _morse_fraction(text)
    if len(frac) % 2:
        frac += "x"
    enc, _ = _morbit_maps(key)
    return "".join(enc[frac[i:i+2]] for i in range(0, len(frac), 2))

def Morbit_decode(text: str, key: str = "123456789") -> str:
    try:
        _, dec = _morbit_maps(key)
        frac = "".join(dec[ch] for ch in text if ch in dec)
        return _morse_unfraction(frac)
    except Exception as e:
        return f"Err:{e}"

_POLLUX_DOT = set("147")
_POLLUX_DASH = set("258")
_POLLUX_SEP = set("0369")

def Pollux_encode(text: str) -> str:
    frac = _morse_fraction(text)
    table = {".": "1", "-": "2", "x": "0"}
    return "".join(table[ch] for ch in frac)

def Pollux_decode(text: str) -> str:
    frac = []
    for ch in text:
        if ch in _POLLUX_DOT:
            frac.append(".")
        elif ch in _POLLUX_DASH:
            frac.append("-")
        elif ch in _POLLUX_SEP:
            frac.append("x")
    return _morse_unfraction("".join(frac))
PIGPEN_MAP = {
    'A':'A1','B':'A2','C':'A3','D':'A4','E':'A5','F':'A6',
    'G':'B1','H':'B2','I':'B3','J':'B3', 'K':'B4','L':'B5','M':'B6',
    'N':'C1','O':'C2','P':'C3','Q':'C4','R':'C5','S':'C6',
    'T':'D1','U':'D2','V':'D3','W':'D4','X':'D5','Y':'D6','Z':'E1'
}
PIGPEN_REV = {}
for k,v in PIGPEN_MAP.items():
    if v not in PIGPEN_REV: PIGPEN_REV[v]=k

def Pigpen_encode(text: str) -> str:
    out = []
    for ch in text:
        cu = ch.upper()
        if cu in PIGPEN_MAP:
            out.append(PIGPEN_MAP[cu])
        elif ch.isspace():
            out.append("/")
        else:
            out.append(ch)
    return "[PIG]|" + " ".join(out)

def Pigpen_decode(text: str) -> str:
    s = text
    if s.startswith("[PIG]|"):
        s = s[len("[PIG]|"):]
    tokens = s.replace("/", " / ").split()
    out = []
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        elif tok in PIGPEN_REV:
            out.append(PIGPEN_REV[tok])
        else:
            out.append(tok if len(tok) == 1 else "")
    return "".join(out)

# =============================================================================
# Quagmire I–VI
# =============================================================================

def _mixed_alpha(key: Optional[str]) -> str:
    return rotate_alpha_from_keyword(key) if key else ALPHA

def _quag_encrypt(text: str, runkey: str, plain_alpha: str, cipher_alpha: str) -> str:
    rk = only_alpha(runkey) or "A"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in plain_alpha:
            col = plain_alpha.index(cu)
            row = plain_alpha.index(rk[ki % len(rk)])
            row_alpha = cipher_alpha[row:] + cipher_alpha[:row]
            c = row_alpha[col]
            out.append(c if ch.isupper() else c.lower())
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

def _quag_decrypt(text: str, runkey: str, plain_alpha: str, cipher_alpha: str) -> str:
    rk = only_alpha(runkey) or "A"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in cipher_alpha:
            row = plain_alpha.index(rk[ki % len(rk)])
            row_alpha = cipher_alpha[row:] + cipher_alpha[:row]
            col = row_alpha.index(cu)
            p = plain_alpha[col]
            out.append(p if ch.isupper() else p.lower())
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

def QuagmireI_encode(text: str, runkey: str = "QUEENLY", cipher_key: str = "CIPHER") -> str:
    return _quag_encrypt(text, runkey, ALPHA, _mixed_alpha(cipher_key))

def QuagmireI_decode(text: str, runkey: str = "QUEENLY", cipher_key: str = "CIPHER") -> str:
    return _quag_decrypt(text, runkey, ALPHA, _mixed_alpha(cipher_key))

def QuagmireII_encode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN") -> str:
    return _quag_encrypt(text, runkey, _mixed_alpha(plain_key), ALPHA)

def QuagmireII_decode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN") -> str:
    return _quag_decrypt(text, runkey, _mixed_alpha(plain_key), ALPHA)

def QuagmireIII_encode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER") -> str:
    return _quag_encrypt(text, runkey, _mixed_alpha(plain_key), _mixed_alpha(cipher_key))

def QuagmireIII_decode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER") -> str:
    return _quag_decrypt(text, runkey, _mixed_alpha(plain_key), _mixed_alpha(cipher_key))

def QuagmireIV_encode(text: str, runkey: str = "QUEENLY", indicator: str = "INDICATOR", plain_key: str = "PLAIN", cipher_key: str = "CIPHER") -> str:
    pa = _mixed_alpha(plain_key)
    shift = pa.index(only_alpha(indicator)[:1] or 'A')
    rk = only_alpha(runkey)
    rk = rk[shift:] + rk[:shift]
    return _quag_encrypt(text, rk, pa, _mixed_alpha(cipher_key))

def QuagmireIV_decode(text: str, runkey: str = "QUEENLY", indicator: str = "INDICATOR", plain_key: str = "PLAIN", cipher_key: str = "CIPHER") -> str:
    pa = _mixed_alpha(plain_key)
    shift = pa.index(only_alpha(indicator)[:1] or 'A')
    rk = only_alpha(runkey)
    rk = rk[shift:] + rk[:shift]
    return _quag_decrypt(text, rk, pa, _mixed_alpha(cipher_key))


def _rotate_alpha_to_indicator(alpha: str, indicator: str) -> str:
    marker = only_alpha(indicator)[:1] or alpha[:1]
    if marker not in alpha:
        marker = alpha[:1]
    idx = alpha.index(marker)
    return alpha[idx:] + alpha[:idx]


def QuagmireV_encode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER", plain_indicator: str = "A", cipher_indicator: str = "A") -> str:
    plain_alpha = _rotate_alpha_to_indicator(_mixed_alpha(plain_key), plain_indicator)
    cipher_alpha = _rotate_alpha_to_indicator(_mixed_alpha(cipher_key), cipher_indicator)
    return _quag_encrypt(text, runkey, plain_alpha, cipher_alpha)


def QuagmireV_decode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER", plain_indicator: str = "A", cipher_indicator: str = "A") -> str:
    plain_alpha = _rotate_alpha_to_indicator(_mixed_alpha(plain_key), plain_indicator)
    cipher_alpha = _rotate_alpha_to_indicator(_mixed_alpha(cipher_key), cipher_indicator)
    return _quag_decrypt(text, runkey, plain_alpha, cipher_alpha)


def _quagmire_progressive(text: str, runkey: str, plain_alpha: str, cipher_alpha: str, step: int, enc: bool) -> str:
    rk = only_alpha(runkey) or "A"
    out = []
    ki = 0
    for ch in text:
        cu = ch.upper()
        if cu in ALPHA_SET:
            shift = (ki * step) % 26
            ca = cipher_alpha[shift:] + cipher_alpha[:shift]
            row = plain_alpha.index(rk[ki % len(rk)])
            row_alpha = ca[row:] + ca[:row]
            if enc:
                col = plain_alpha.index(cu)
                mapped = row_alpha[col]
            else:
                col = row_alpha.index(cu)
                mapped = plain_alpha[col]
            out.append(mapped if ch.isupper() else mapped.lower())
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def QuagmireVI_encode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER", indicator: str = "A", step: int | str = 1) -> str:
    plain_alpha = _mixed_alpha(plain_key)
    cipher_alpha = _rotate_alpha_to_indicator(_mixed_alpha(cipher_key), indicator)
    return _quagmire_progressive(text, runkey, plain_alpha, cipher_alpha, int(step), True)


def QuagmireVI_decode(text: str, runkey: str = "QUEENLY", plain_key: str = "PLAIN", cipher_key: str = "CIPHER", indicator: str = "A", step: int | str = 1) -> str:
    plain_alpha = _mixed_alpha(plain_key)
    cipher_alpha = _rotate_alpha_to_indicator(_mixed_alpha(cipher_key), indicator)
    return _quagmire_progressive(text, runkey, plain_alpha, cipher_alpha, int(step), False)

# =============================================================================
# Baconian / Grandpré / Nihilist / Homophonic / Fractionated Morse / Emoji /
# Whitespace / SCB / Rail Fence / XOR(hex) / Base3 / Base9 / Pig Latin / Semaphore
# =============================================================================

# Base3 / Base9
def Base3_encode(text: str) -> str:
    data = text.encode("utf-8")
    n = int.from_bytes(data, "big")
    if n == 0: return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 3)
        out.append("012"[r])
    return "".join(reversed(out))

def Base3_decode(text: str) -> str:
    s = text.strip(); n = 0
    for ch in s:
        if ch not in "012": return "Err:invalid ternary digit"
        n = n*3 + int(ch)
    blen = (n.bit_length() + 7)//8
    return n.to_bytes(blen, "big").decode("utf-8", errors="replace")

def Base9_encode(text: str) -> str:
    data = text.encode("utf-8")
    n = int.from_bytes(data, "big")
    if n == 0: return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 9)
        out.append("012345678"[r])
    return "".join(reversed(out))

def Base9_decode(text: str) -> str:
    s = text.strip(); n = 0
    for ch in s:
        if ch not in "012345678": return "Err:invalid base9 digit"
        n = n*9 + int(ch)
    blen = (n.bit_length() + 7)//8
    return n.to_bytes(blen, "big").decode("utf-8", errors="replace")

# Baconian (I/J combined)
BACON_ALPHA = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
def _bacon_map():
    codes = {}
    for i, ch in enumerate(BACON_ALPHA):
        bits = format(i, "05b")
        code = "".join('A' if b == '0' else 'B' for b in bits)
        codes[ch] = code
    return codes
BACON_CODES = _bacon_map()
BACON_REV = {v:k for k,v in BACON_CODES.items()}

def Baconian_encode(text: str) -> str:
    out = []
    for ch in to_upper(text):
        if ch == 'J': ch = 'I'
        if ch in BACON_CODES:
            out.append(BACON_CODES[ch])
        elif ch.isspace():
            out.append("/")
    return " ".join(out)

def Baconian_decode(text: str) -> str:
    tokens = text.replace("/", " / ").split()
    out = []
    for t in tokens:
        if t == "/": out.append(" "); continue
        if len(t) == 5 and set(t) <= {'A','B'}: out.append(BACON_REV.get(t,''))
    return "".join(out).lower()

# Grandpré
def Grandpre_encode(text: str, key: str = "GRANDPRE") -> str:
    _, pos, _ = _key_square_5(key)
    out = []
    for ch in to_upper(text):
        if ch == 'J': ch = 'I'
        if ch in pos:
            r,c = pos[ch]; out.append(f"{r+1}{c+1}")
        elif ch.isspace():
            out.append("/")
    return " ".join(out)

def Grandpre_decode(text: str, key: str = "GRANDPRE") -> str:
    _, _, rev = _key_square_5(key)
    tokens = text.replace("/", " / ").split()
    out = []
    for t in tokens:
        if t == "/": out.append(" "); continue
        if len(t) == 2 and t.isdigit():
            r = int(t[0])-1; c = int(t[1])-1
            out.append(rev.get((r,c), ''))
    return "".join(out).lower()

# Nihilist (classic)
def Nihilist_encode(text: str, alpha_key: str = "CIPHER", num_key: str = "KEY") -> str:
    _, pos, _ = _key_square_5(alpha_key)
    def numify(s: str) -> List[int]:
        nums = []
        for ch in only_alpha(s):
            r,c = pos['I' if ch=='J' else ch]
            nums.append((r+1)*10 + (c+1))
        return nums
    P = numify(text)
    K = numify(num_key) or [11]
    out = []
    for i, p in enumerate(P):
        out.append(str(p + K[i % len(K)]))
    return " ".join(out)

def Nihilist_decode(text: str, alpha_key: str = "CIPHER", num_key: str = "KEY") -> str:
    _, pos, rev = _key_square_5(alpha_key)
    def numify(s: str) -> List[int]:
        nums = []
        for ch in only_alpha(s):
            r,c = pos['I' if ch=='J' else ch]
            nums.append((r+1)*10 + (c+1))
        return nums
    K = numify(num_key) or [11]
    nums = [int(x) for x in text.replace(",", " ").split()]
    raw = [n - K[i % len(K)] for i, n in enumerate(nums)]
    out = []
    for val in raw:
        r = val // 10 - 1; c = val % 10 - 1
        out.append(rev.get((r,c), ''))
    return "".join(out).lower()

# Homophonic (seeded)
def _homophonic_build(seed: str = "SEED") -> Tuple[Dict[str,List[int]], Dict[int,str]]:
    rnd = random.Random(seed)
    pool = list(range(11, 200))
    rnd.shuffle(pool)
    slots_per = 3
    mapping: Dict[str, List[int]] = {}
    idx = 0
    for ch in ALPHA:
        mapping[ch] = pool[idx:idx+slots_per]; idx += slots_per
    rev = {num: ch for ch, nums in mapping.items() for num in nums}
    return mapping, rev

def HOMO_encode(text: str, seed: str = "SEED") -> str:
    mapping, _ = _homophonic_build(seed)
    rnd = random.Random(seed + "|enc")
    out_tokens = []
    for ch in to_upper(text):
        if ch in mapping:
            out_tokens.append(str(rnd.choice(mapping[ch])))
        elif ch.isspace():
            out_tokens.append("/")
    meta = {"seed": str(seed)}
    return "[HOMO]" + json.dumps(meta) + "|" + " ".join(out_tokens)

def HOMO_decode(text: str) -> str:
    if not text.startswith("[HOMO]"): return "Err:bad format"
    try:
        meta_end = text.index("|", len("[HOMO]"))
        meta_json = text[len("[HOMO]"):meta_end]
        meta = json.loads(meta_json)
        seed = str(meta.get("seed", "SEED"))
        _, rev = _homophonic_build(seed)
        body = text[meta_end+1:]
        out = []
        for tok in body.replace("/", " / ").split():
            if tok == "/": out.append(" "); continue
            try:
                n = int(tok); out.append(rev.get(n, ""))
            except: pass
        return "".join(out).lower()
    except Exception as e:
        return f"Err:{e}"

# Fractionated Morse (robust)
FM_TRIS = ['...','..-','..x','.-.','.--','.-x','.x.','.x-','.xx',
           '-..','-.-','-.x','--.','---','--x','-x.','-x-','-xx',
           'x..','x.-','x.x','x-.','x--','x-x','xx.','xx-','xxx']

def _fm_alpha(key: str) -> str:
    a = rotate_alpha_from_keyword(key)
    return a + "*"

def FM_encode(text: str, key: str = "KEYABCDFGHIJLMNOPQRSTUVWXZ") -> str:
    morse_words = []
    for word in text.split():
        codes = []
        for ch in word:
            cu = ch.upper()
            if cu in MORSE_TABLE:
                codes.append(MORSE_TABLE[cu])
        morse_words.append("x".join(codes))
    frac = "xx".join(morse_words)
    if len(frac) % 3 != 0:
        frac += "x" * (3 - (len(frac) % 3))
    A27 = _fm_alpha(key)
    out = []
    for i in range(0, len(frac), 3):
        tri = frac[i:i+3]
        idx = FM_TRIS.index(tri)
        out.append(A27[idx])
    meta = {"alpha": rotate_alpha_from_keyword(key)}
    return "[FM]" + json.dumps(meta) + "|" + "".join(out)

def FM_decode(text: str, key: str = None) -> str:
    if text.startswith("[FM]"):
        meta_end = text.index("|", len("[FM]"))
        meta = json.loads(text[len("[FM]"):meta_end])
        alpha26 = meta.get("alpha", ALPHA)
        A27 = alpha26 + "*"
        body = text[meta_end+1:]
    else:
        A27 = _fm_alpha(key or "KEY")
        body = text
    out_tris = []
    for ch in body:
        try:
            idx = A27.index(ch)
        except ValueError:
            continue
        out_tris.append(FM_TRIS[idx])
    frac = "".join(out_tris).rstrip('x')
    words = frac.split("xx") if "xx" in frac else [frac]
    out_words = []
    for w in words:
        letters = w.split("x") if w else []
        chars = []
        for sig in letters:
            ch = MORSE_REV.get(sig, '')
            if ch: chars.append(ch)
        out_words.append("".join(chars))
    return " ".join(out_words)

# Emoji (seeded)
EMOJI_POOL = [
    0x1F600,0x1F601,0x1F602,0x1F603,0x1F604,0x1F605,0x1F606,0x1F607,0x1F608,
    0x1F609,0x1F60A,0x1F60B,0x1F60C,0x1F60D,0x1F60E,0x1F60F,0x1F610,0x1F611,
    0x1F612,0x1F613,0x1F614,0x1F615,0x1F616,0x1F617,0x1F618,0x1F619,0x1F61A,
    0x1F61B,0x1F61C,0x1F61D,0x1F61E,0x1F61F,0x1F620,0x1F621,0x1F622,0x1F923,
    0x1F642,0x1F643,0x1F970,0x1F971,0x1F972
]
def _emoji_build(seed: str = "EMOJI") -> Tuple[Dict[str, int], Dict[int, str], List[int]]:
    rnd = random.Random(seed)
    pool = EMOJI_POOL[:]; rnd.shuffle(pool)
    pool = pool[:27]
    mapping = {}
    for i, ch in enumerate(ALPHA + " "):
        mapping[ch] = pool[i]
    rev = {cp: ch for ch, cp in mapping.items()}
    return mapping, rev, pool

def Emoji_encode(text: str, seed: str = "EMOJI") -> str:
    m, _, pool = _emoji_build(seed)
    out = []
    for ch in to_upper(text):
        if ch in m:
            out.append(chr(m[ch]))
        elif ch.isspace():
            out.append(chr(m[" "]))
        else:
            out.append(ch)
    meta = {"map": pool}
    return "[EMOJI]" + json.dumps(meta) + "|" + "".join(out)

def Emoji_decode(text: str) -> str:
    if not text.startswith("[EMOJI]"): return "Err:bad format"
    meta_end = text.index("|", len("[EMOJI]"))
    meta = json.loads(text[len("[EMOJI]"):meta_end])
    pool: List[int] = meta.get("map", [])
    mapping = {}
    for i, ch in enumerate(ALPHA + " "):
        if i < len(pool):
            mapping[pool[i]] = ch
    body = text[meta_end+1:]
    out = []
    for ch in body:
        cp = ord(ch)
        out.append(mapping.get(cp, "" if not ch.isspace() else " "))
    return "".join(out).lower()

# Whitespace
def WS_encode(text: str, n: int | str = None) -> str:
    data = text.encode("utf-8")
    lines = []
    for b in data:
        bits = format(b, "08b")
        line = "".join('\t' if bit == '1' else ' ' for bit in bits)
        lines.append(line)
    meta = {"n": len(data)}
    return "[WS]" + json.dumps(meta) + "|\n" + "\n".join(lines)

def WS_decode(text: str, n: int | str = None) -> str:
    if not text.startswith("[WS]"): return "Err:bad format"
    meta_end = text.index("|", len("[WS]"))
    body = text[meta_end+1:]
    bytes_out = []
    for line in body.splitlines():
        bits = "".join('1' if ch == '\t' else ('0' if ch == ' ' else '') for ch in line)
        if len(bits) == 8:
            bytes_out.append(int(bits, 2))
    return bytes(bytes_out).decode("utf-8", errors="replace")

# SCB
def _scb_tables(keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ",
                rowdigits: Tuple[int,int] = (3,7)) -> Tuple[Dict[str,str], Dict[str,str]]:
    header = "0123456789"
    rd1, rd2 = rowdigits
    first_cols = [d for d in header if d not in (str(rd1), str(rd2))]
    kw = rotate_alpha_from_keyword(keyword)
    firstrow_letters = list(kw[:len(first_cols)])
    remaining = [ch for ch in kw[len(first_cols):]]
    second = remaining[:10]
    third = remaining[10:20]
    enc: Dict[str,str] = {}; dec: Dict[str,str] = {}
    for d, ch in zip(first_cols, firstrow_letters):
        enc[ch] = d; dec[d] = ch
    for i, ch in enumerate(second):
        code = f"{rd1}{i}"; enc[ch] = code; dec[code] = ch
    for i, ch in enumerate(third):
        code = f"{rd2}{i}"; enc[ch] = code; dec[code] = ch
    return enc, dec

def SCB_encode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: Tuple[int,int]=(3,7)) -> str:
    enc, _ = _scb_tables(keyword, rowdigits)
    out_tokens = []
    for ch in to_upper(text):
        if ch in enc:
            out_tokens.append(enc[ch])
        elif ch.isspace():
            out_tokens.append("/")
    return " ".join(out_tokens)

def SCB_decode(text: str, keyword: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ", rowdigits: Tuple[int,int]=(3,7)) -> str:
    _, dec = _scb_tables(keyword, rowdigits)
    tokens = text.replace("/", " / ").split()
    out = []
    for t in tokens:
        if t == "/":
            out.append(" "); continue
        if t in dec: out.append(dec[t])
    return "".join(out).lower()

# Rail Fence
def RailFence_encode(text: str, rails: int | str = 3) -> str:
    if isinstance(rails, str): rails = int(rails)
    s = "".join(ch for ch in text if not ch.isspace())
    fence = [[] for _ in range(rails)]
    r = 0; dr = 1
    for ch in s:
        fence[r].append(ch); r += dr
        if r == 0 or r == rails-1: dr *= -1
    return "".join("".join(row) for row in fence)

def RailFence_decode(text: str, rails: int | str = 3) -> str:
    if isinstance(rails, str): rails = int(rails)
    s = text
    marks = [None]*len(s); r = 0; dr = 1
    for i in range(len(s)):
        marks[i] = r; r += dr
        if r == 0 or r == rails-1: dr *= -1
    counts = [marks.count(r) for r in range(rails)]
    idx = 0; rails_data = []
    for count in counts:
        rails_data.append(list(s[idx:idx+count])); idx += count
    out = []; r_pos = [0]*rails
    for i in range(len(s)):
        rail = marks[i]; out.append(rails_data[rail][r_pos[rail]]); r_pos[rail] += 1
    return "".join(out)


def _rail_marks(length: int, rails: int, offset: int = 0) -> List[int]:
    if rails <= 1:
        return [0] * length
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    return [cycle[(i + offset) % len(cycle)] for i in range(length)]

def RailFenceOffset_encode(text: str, rails: int | str = 3, offset: int | str = 0) -> str:
    rails = int(rails)
    offset = int(offset)
    s = "".join(ch for ch in text if not ch.isspace())
    marks = _rail_marks(len(s), rails, offset)
    return "".join(s[i] for rail in range(rails) for i, mark in enumerate(marks) if mark == rail)

def RailFenceOffset_decode(text: str, rails: int | str = 3, offset: int | str = 0) -> str:
    rails = int(rails)
    offset = int(offset)
    s = text
    marks = _rail_marks(len(s), rails, offset)
    counts = [marks.count(rail) for rail in range(rails)]
    idx = 0
    rails_data = []
    for count in counts:
        rails_data.append(list(s[idx:idx+count]))
        idx += count
    positions = [0] * rails
    out = []
    for mark in marks:
        out.append(rails_data[mark][positions[mark]])
        positions[mark] += 1
    return "".join(out)

def RailFenceSpaces_encode(text: str, rails: int | str = 3) -> str:
    encoded = RailFenceOffset_encode(text, rails, 0)
    spaces = [i for i, ch in enumerate(text) if ch.isspace()]
    return "[RFSPACE]" + json.dumps({"spaces": spaces}, separators=(",", ":")) + "|" + encoded

def RailFenceSpaces_decode(text: str, rails: int | str = 3) -> str:
    try:
        spaces = []
        body = text
        if text.startswith("[RFSPACE]"):
            sep = text.index("|", len("[RFSPACE]"))
            meta = json.loads(text[len("[RFSPACE]"):sep])
            spaces = [int(i) for i in meta.get("spaces", [])]
            body = text[sep+1:]
        plain = list(RailFenceOffset_decode(body, rails, 0))
        for pos in sorted(spaces):
            if 0 <= pos <= len(plain):
                plain.insert(pos, " ")
        return "".join(plain)
    except Exception as e:
        return f"Err:{e}"

def SkipPermutation_encode(text: str, step: int | str = 3) -> str:
    step = int(step)
    s = "".join(ch for ch in text if not ch.isspace())
    n = len(s)
    if n == 0:
        return ""
    if math.gcd(step, n) != 1:
        return f"Err:step {step} must be coprime with message length {n}"
    order = []
    pos = 0
    for _ in range(n):
        order.append(pos)
        pos = (pos + step) % n
    return "".join(s[i] for i in order)

def SkipPermutation_decode(text: str, step: int | str = 3) -> str:
    step = int(step)
    n = len(text)
    if n == 0:
        return ""
    if math.gcd(step, n) != 1:
        return f"Err:step {step} must be coprime with message length {n}"
    order = []
    pos = 0
    for _ in range(n):
        order.append(pos)
        pos = (pos + step) % n
    out = [""] * n
    for ch, original_pos in zip(text, order):
        out[original_pos] = ch
    return "".join(out)

def SpiralRoute_encode(text: str, rows: int | str = 5, cols: int | str = 5) -> str:
    rows = int(rows)
    cols = int(cols)
    data = "".join(ch for ch in text if not ch.isspace())
    padded = data.ljust(rows * cols, "X")
    return "[SPIRAL]" + json.dumps({"n": len(data), "rows": rows, "cols": cols}, separators=(",", ":")) + "|" + Route_encode(padded, rows, cols)

def SpiralRoute_decode(text: str, rows: int | str = 5, cols: int | str = 5) -> str:
    try:
        n = None
        body = text
        if text.startswith("[SPIRAL]"):
            sep = text.index("|", len("[SPIRAL]"))
            meta = json.loads(text[len("[SPIRAL]"):sep])
            n = int(meta.get("n", 0))
            rows = int(meta.get("rows", rows))
            cols = int(meta.get("cols", cols))
            body = text[sep+1:]
        decoded = Route_decode(body, rows, cols)
        return decoded[:n] if n is not None else decoded.rstrip("X")
    except Exception as e:
        return f"Err:{e}"

def VerticalTransposition_encode(text: str, key: str = "3142") -> str:
    s = "".join(ch for ch in text if not ch.isspace())
    cols = len(key)
    rows = math.ceil(len(s) / cols) if cols else 0
    padded = s.ljust(rows * cols, "X")
    order = _col_order(key)
    grid = [list(padded[r*cols:(r+1)*cols]) for r in range(rows)]
    body = "".join(grid[r][c] for _, c in sorted((order[c], c) for c in range(cols)) for r in range(rows))
    meta = json.dumps({"n": len(s), "key": key}, separators=(",", ":"))
    return "[VERT]" + meta + "|" + body

def VerticalTransposition_decode(text: str, key: str = "3142") -> str:
    try:
        n = None
        body = text
        if text.startswith("[VERT]"):
            sep = text.index("|", len("[VERT]"))
            meta = json.loads(text[len("[VERT]"):sep])
            n = int(meta.get("n", 0))
            key = meta.get("key", key)
            body = text[sep+1:]
        cols = len(key)
        rows = math.ceil(len(body) / cols) if cols else 0
        order = _col_order(key)
        grid = [[""] * cols for _ in range(rows)]
        idx = 0
        for _, c in sorted((order[c], c) for c in range(cols)):
            for r in range(rows):
                if idx < len(body):
                    grid[r][c] = body[idx]
                    idx += 1
        out = "".join(grid[r][c] for r in range(rows) for c in range(cols))
        return out[:n] if n is not None else out.rstrip("X")
    except Exception as e:
        return f"Err:{e}"

# XOR(hex)
def XOR_hex_encode(text: str, key: str = "key") -> str:
    data = text.encode("utf-8"); k = key.encode("utf-8") or b"\x00"
    out = bytes(data[i] ^ k[i % len(k)] for i in range(len(data)))
    return out.hex()

def XOR_hex_decode(text: str, key: str = "key") -> str:
    try:
        data = bytes.fromhex(text)
    except Exception as e:
        return f"Err:{e}"
    k = key.encode("utf-8") or b"\x00"
    out = bytes(data[i] ^ k[i % len(k)] for i in range(len(data)))
    return out.decode("utf-8", errors="replace")

# Pig Latin
VOWELS = set("AEIOU")
def PigLatin_encode(text: str) -> str:
    def enc_word(w: str) -> str:
        if not w: return w
        u = w.upper()
        if u[0] in VOWELS: return u + "-yay"
        i = 0
        while i < len(u) and u[i] not in VOWELS: i += 1
        return u[i:] + "-" + u[:i].lower() + "ay"
    out = []
    for tok in text.split(" "):
        out.append(enc_word(tok) if tok.strip() else "")
    return "[PL]|" + " ".join(out)

def PigLatin_decode(text: str) -> str:
    s = text
    if s.startswith("[PL]|"): s = s[len("[PL]|"):]
    def dec_word(w: str) -> str:
        if not w: return w
        if w.endswith("-yay"): return w[:-4]
        if w.endswith("ay") and "-" in w:
            base = w[:-2]; i = base.rfind("-")
            if i != -1:
                suffix = base[i+1:]; root = base[:i]
                return suffix.upper() + root
        return w
    return " ".join(dec_word(tok) for tok in s.split(" "))

# Semaphore (tokenized)
SEMAPHORE_MAP = {
    'A':'NW','B':'N','C':'NE','D':'W','E':'C','F':'E','G':'SW','H':'S','I':'SE','J':'W2',
    'K':'NE2','L':'E2','M':'S2','N':'SW2','O':'NW2','P':'N2','Q':'C2','R':'SE2','S':'W3','T':'E3',
    'U':'N3','V':'S3','W':'NW3','X':'NE3','Y':'SW3','Z':'SE3'
}
SEMAPHORE_REV = {v:k for k,v in SEMAPHORE_MAP.items()}

def Semaphore_encode(text: str) -> str:
    out = []
    for ch in to_upper(text):
        if ch in SEMAPHORE_MAP:
            out.append(SEMAPHORE_MAP[ch])
        elif ch.isspace():
            out.append("/")
    return "[SEM]|" + " ".join(out)

def Semaphore_decode(text: str) -> str:
    s = text
    if s.startswith("[SEM]|"):
        s = s[len("[SEM]|"):]
    out = []
    for tok in s.replace("/", " / ").split():
        if tok == "/": out.append(" ")
        else: out.append(SEMAPHORE_REV.get(tok, ""))
    return "".join(out).lower()

# =============================================================================
# Smart English scoring + SmartGuess + BruteForce (CORE)
# =============================================================================

# simple English letter frequency (percentages)
_EN_FREQ = {
    'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,'H':6.09,'R':5.99,'D':4.25,
    'L':4.03,'C':2.78,'U':2.76,'M':2.41,'W':2.36,'F':2.23,'G':2.02,'Y':1.97,'P':1.93,'B':1.49,
    'V':0.98,'K':0.77,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07
}

def _chi_squared_english(s: str) -> float:
    t = only_alpha(s)
    n = len(t)
    if n == 0: return float('inf')
    counts = {ch:0 for ch in ALPHA}
    for ch in t: counts[ch] += 1
    chi = 0.0
    for ch in ALPHA:
        expected = _EN_FREQ[ch] * n / 100.0
        diff = counts[ch] - expected
        chi += (diff*diff) / (expected if expected > 0 else 1e-9)
    # small penalty if few spaces in an otherwise long string
    space_penalty = 0.0
    # (Leave mild, spaces may have been stripped by some ciphers)
    return chi + space_penalty

def english_score(s: str) -> float:
    # combine chi-squared with a penalty for high non-printable ratio
    if not s: return float('inf')
    chi = _chi_squared_english(s)
    bad = sum(1 for ch in s if ord(ch) < 9 or (13 < ord(ch) < 32))
    return chi + bad*5.0

def is_printable_ratio_ok(s: str, thresh: float = 0.85) -> bool:
    if not s: return False
    vis = sum(1 for ch in s if (32 <= ord(ch) <= 126) or ch in "\n\r\t")
    return (vis / len(s)) >= thresh

def looks_hex(s: str) -> bool:
    s2 = s.strip().replace(" ", "")
    if len(s2) < 2 or len(s2)%2==1: return False
    return all(ch in "0123456789abcdefABCDEF" for ch in s2)

def looks_base64(s: str) -> bool:
    s2 = s.strip().replace("\n", "").replace(" ", "")
    if len(s2) % 4 != 0: return False
    return all(ch in (string.ascii_letters + string.digits + "+/=") for ch in s2)

def looks_dna(s: str) -> bool:
    s2 = s.strip().replace(" ", "")
    if not s2: return False
    return all(ch in "ACGTacgt" for ch in s2)

def looks_polybius_grandpre(s: str) -> bool:
    toks = s.replace("/", " / ").split()
    if not toks: return False
    return all((t==" / " or t=="/" or (t.isdigit() and 1 <= len(t) <= 2)) for t in toks)

def looks_bacon(s: str) -> bool:
    toks = s.replace("/", " / ").split()
    if not toks: return False
    return all((t==" / " or t=="/" or (len(t)==5 and set(t)<=set("AB"))) for t in toks)

def looks_morse(s: str) -> bool:
    return set(ch for ch in s if not ch.isspace()) <= set(".-//")

def looks_adfgx(s: str) -> bool:
    letters = set(ch for ch in s if ch.isalpha())
    return letters <= set("ADFGXadfgx")

def looks_adfgvx(s: str) -> bool:
    letters = set(ch for ch in s if ch.isalpha())
    return letters <= set("ADFGVXadfgvx")

def SmartGuess(text: str) -> List[Tuple[str, str, float]]:
    """
    Return ranked list of (label, plaintext, score) candidates.
    Detect tags first, then heuristics, else brute a few families.
    Lower score = better.
    """
    t = text.strip()
    candidates: List[Tuple[str,str,float]] = []

    # 1) Tagged formats — decode straight
    try:
        if t.startswith("[HOMO]"):
            pt = HOMO_decode(t); candidates.append(("Homophonic (tag)", pt, english_score(pt)))
        if t.startswith("[EMOJI]"):
            pt = Emoji_decode(t); candidates.append(("Emoji (tag)", pt, english_score(pt)))
        if t.startswith("[WS]"):
            pt = WS_decode(t); candidates.append(("Whitespace (tag)", pt, english_score(pt)))
        if t.startswith("[FM]"):
            pt = FM_decode(t); candidates.append(("Fractionated Morse (tag)", pt, english_score(pt)))
        if t.startswith("[MORSE]|"):
            pt = Morse_decode(t); candidates.append(("Morse (tag)", pt, english_score(pt)))
        if t.startswith("[PIG]|"):
            pt = Pigpen_decode(t); candidates.append(("Pigpen (tag)", pt, english_score(pt)))
        if t.startswith("[PL]|"):
            pt = PigLatin_decode(t); candidates.append(("Pig Latin (tag)", pt, english_score(pt)))
        if t.startswith("[SEM]|"):
            pt = Semaphore_decode(t); candidates.append(("Semaphore (tag)", pt, english_score(pt)))
        if t.startswith("[LEET]|"):
            pt = LEET_decode(t); candidates.append(("Leet (tag)", pt, english_score(pt)))
    except Exception:
        pass

    # 2) Pattern-based decodes
    try:
        if looks_hex(t):
            pt = Hex_decode(t); candidates.append(("Hex", pt, english_score(pt)))
            # XOR-hex single byte brute
            data = bytes.fromhex(t.strip().replace(" ",""))
            best = None
            for k in range(256):
                out = bytes(b ^ k for b in data)
                try:
                    s = out.decode("utf-8", errors="replace")
                except:
                    continue
                sc = english_score(s)
                if best is None or sc < best[2]:
                    best = (f"XOR-hex single-byte k={k}", s, sc)
            if best: candidates.append(best)
        if looks_base64(t):
            pt = Base64_decode(t); candidates.append(("Base64", pt, english_score(pt)))
        if looks_dna(t):
            pt = DNA_decode(t); candidates.append(("DNA", pt, english_score(pt)))
        if looks_bacon(t):
            pt = Baconian_decode(t); candidates.append(("Baconian", pt, english_score(pt)))
        if looks_polybius_grandpre(t):
            # Try both with default keys
            pt1 = Polybius_decode(t, "KEYWORD"); candidates.append(("Polybius (guess)", pt1, english_score(pt1)))
            pt2 = Grandpre_decode(t, "GRANDPRE"); candidates.append(("Grandpré (guess)", pt2, english_score(pt2)))
        if looks_morse(t) or t.startswith("[MORSE]|"):
            pt = Morse_decode(t); candidates.append(("Morse", pt, english_score(pt)))
        if looks_adfgx(t):
            pt = ADFGX_decode(t, "KEYWORD", "CIPHER"); candidates.append(("ADFGX default-keys", pt, english_score(pt)))
        if looks_adfgvx(t):
            pt = ADFGVX_decode(t, "KEYW0RD", "CIPHER"); candidates.append(("ADFGVX default-keys", pt, english_score(pt)))
    except Exception:
        pass

    # 3) Lightweight brute force: Caesar (all), Affine (coprimes), RailFence(2..8)
    #    + short Vigenère (keys length 1..2 from ETAOINSHRDLU), ROT13/47, Atbash
    sU = to_upper(t)
    # Caesar/ROT/Atbash
    for sh in range(26):
        pt = Caesar_decode(sU, sh); candidates.append((f"Caesar -{sh}", pt, english_score(pt)))
    candidates.append(("ROT13", ROT13_decode(t), english_score(ROT13_decode(t))))
    candidates.append(("ROT47", ROT47_decode(t), english_score(ROT47_decode(t))))
    candidates.append(("Atbash", Atbash_decode(t), english_score(Atbash_decode(t))))

    # Affine brute
    coprimes = [a for a in range(1,26) if math.gcd(a,26)==1]
    for a in coprimes:
        for b in range(26):
            try:
                pt = Affine_decode(sU, a, b, 26)
                candidates.append((f"Affine a={a} b={b}", pt, english_score(pt)))
            except Exception:
                pass

    # Rail Fence
    for rails in range(2, 9):
        try:
            pt = RailFence_decode(t.replace(" ",""), rails)
            candidates.append((f"RailFence rails={rails}", pt, english_score(pt)))
        except Exception:
            pass

    # Short-key Vigenère brute over ETAOINSHRDLU (length 1..2)
    pool = "ETAOINSHRDLU"
    keys = set()
    for a in pool:
        keys.add(a)
        for b in pool:
            keys.add(a+b)
    for k in keys:
        pt = Vigenere_decode(sU, k)
        candidates.append((f"Vigenere key={k}", pt, english_score(pt)))

    # Rank and return top
    # Remove exact duplicate plaintexts with worse scores
    best_map: Dict[str, Tuple[str,str,float]] = {}
    for label, pt, sc in candidates:
        if not pt: continue
        key = pt
        if key not in best_map or sc < best_map[key][2]:
            best_map[key] = (label, pt, sc)
    ranked = sorted(best_map.values(), key=lambda x: x[2])
    return ranked[:30]  # top 30 for inspection

def BruteForce(text: str, families: Optional[List[str]] = None) -> List[Tuple[str,str,float]]:
    """
    Explicit brute force across requested families (subset of):
      ["caesar","affine","railfence","vigenere-short","xor-hex"]
    Returns ranked list (label, plaintext, score).
    """
    fam = set((f or "").lower() for f in (families or ["caesar","affine","railfence","vigenere-short","xor-hex"]))
    t = text
    cands: List[Tuple[str,str,float]] = []

    if "caesar" in fam:
        sU = to_upper(t)
        for sh in range(26):
            pt = Caesar_decode(sU, sh); cands.append((f"Caesar -{sh}", pt, english_score(pt)))

    if "affine" in fam:
        sU = to_upper(t)
        for a in [a for a in range(1,26) if math.gcd(a,26)==1]:
            for b in range(26):
                try:
                    pt = Affine_decode(sU, a, b, 26)
                    cands.append((f"Affine a={a} b={b}", pt, english_score(pt)))
                except Exception:
                    pass

    if "railfence" in fam:
        s = t.replace(" ","")
        for rails in range(2, 11):
            try:
                pt = RailFence_decode(s, rails)
                cands.append((f"RailFence rails={rails}", pt, english_score(pt)))
            except Exception:
                pass

    if "vigenere-short" in fam:
        sU = to_upper(t)
        pool = "ETAOINSHRDLU"
        keys = set()
        for a in pool:
            keys.add(a)
            for b in pool:
                keys.add(a+b)
        for k in keys:
            pt = Vigenere_decode(sU, k)
            cands.append((f"Vigenere key={k}", pt, english_score(pt)))

    if "xor-hex" in fam and looks_hex(t):
        try:
            data = bytes.fromhex(t.strip().replace(" ",""))
            for k in range(256):
                out = bytes(b ^ k for b in data)
                s = out.decode("utf-8", errors="replace")
                sc = english_score(s)
                cands.append((f"XOR-hex single-byte k={k}", s, sc))
        except Exception:
            pass

    # rank, dedupe plaintext
    best_map: Dict[str, Tuple[str,str,float]] = {}
    for label, pt, sc in cands:
        if pt not in best_map or sc < best_map[pt][2]:
            best_map[pt] = (label, pt, sc)
    ranked = sorted(best_map.values(), key=lambda x: x[2])
    return ranked[:50]

# =============================================================================
# Patches / robustness tweaks (safe on odd-length inputs & edge cases)
# =============================================================================

def _pairwise(s: str) -> List[Tuple[str,str]]:
    L = len(s)
    # If odd, ignore last dangling char instead of raising
    rng = range(0, L - (L % 2), 2)
    return [(s[i], s[i+1]) for i in rng]

def ADFGX_decode(text: str, square_key: str = "KEYWORD", route_key: str = "CIPHER") -> str:
    labels = "ADFGX"
    sq, pos, rev = _key_square_5(square_key)
    frac = _columnar_unroute(text, route_key)
    out = []
    for a,b in _pairwise(frac):
        if a not in labels or b not in labels: continue
        r = labels.index(a); c = labels.index(b)
        out.append(rev.get((r,c), ''))
    return "".join(out).lower()

def ADFGVX_decode(text: str, square_key: str = "KEYW0RD", route_key: str = "CIPHER") -> str:
    labels = "ADFGVX"
    sq, pos, rev = _key_square_6(square_key)
    frac = _columnar_unroute(text, route_key)
    out = []
    for a,b in _pairwise(frac):
        if a not in labels or b not in labels: continue
        r = labels.index(a); c = labels.index(b)
        out.append(rev.get((r,c), ''))
    return "".join(out).lower()

def FM_decode(text: str, key: str = None) -> str:
    # Accept both tagged & raw bodies, tolerate unknown chars, ignore padding/dangling
    if text.startswith("[FM]"):
        meta_end = text.index("|", len("[FM]"))
        meta = json.loads(text[len("[FM]"):meta_end])
        alpha26 = meta.get("alpha", ALPHA)
        A27 = alpha26 + "*"
        body = text[meta_end+1:]
    else:
        A27 = _fm_alpha(key or "KEY")
        body = text
    out_tris = []
    for ch in body:
        try:
            idx = A27.index(ch)
        except ValueError:
            # ignore extraneous chars
            continue
        out_tris.append(FM_TRIS[idx])
    frac = "".join(out_tris).rstrip('x')
    # Split into words by 'xx' separators (if any)
    words = frac.split("xx") if "xx" in frac else [frac]
    out_words = []
    for w in words:
        # Split letters by single x (if any)
        letters = w.split("x") if w else []
        chars = []
        for sig in letters:
            ch = MORSE_REV.get(sig, '')
            if ch: chars.append(ch)
        out_words.append("".join(chars))
    return " ".join(out_words)

# =============================================================================
# Cipher registry (name -> encoder/decoder + param schema)
# =============================================================================

from dataclasses import dataclass, field
import os
from pathlib import Path
import argparse
import sys
import time

@dataclass
class Param:
    name: str
    label: str
    default: str
    tip: str = ""

@dataclass
class CipherEntry:
    name: str
    enc_fn: callable
    dec_fn: callable
    params: List[Param] = field(default_factory=list)

def get_registry() -> List[CipherEntry]:
    P = Param  # alias
    reg: List[CipherEntry] = [
        # Shifts / subs
        CipherEntry("Caesar", Caesar_encode, Caesar_decode, [P("shift","Shift","3","Integer")]),
        CipherEntry("ROT13", ROT13_encode, ROT13_decode, []),
        CipherEntry("ROT5", ROT5_encode, ROT5_decode, []),
        CipherEntry("ROT18", ROT18_encode, ROT18_decode, []),
        CipherEntry("ROT47", ROT47_encode, ROT47_decode, []),
        CipherEntry("Atbash", Atbash_encode, Atbash_decode, []),
        CipherEntry("Affine", Affine_encode, Affine_decode, [P("a","a","5"), P("b","b","8"), P("m","mod","26")]),
        CipherEntry("Keyword Shift", KeywordShift_encode, KeywordShift_decode, [P("keyword","Keyword","CIPHER")]),
        CipherEntry("Keyword Substitution", KeywordSubstitute_encode, KeywordSubstitute_decode, [P("keyword","Keyword","CIPHER")]),
        CipherEntry("Caesar Custom Alphabet", CaesarCustom_encode, CaesarCustom_decode, [P("shift","Shift","3"), P("alphabet","Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ")]),
        CipherEntry("Caesar Progressive", CaesarProgressive_encode, CaesarProgressive_decode, [P("start","Start","0"), P("step","Step","1")]),
        CipherEntry("Keyed Caesar", KeyedCaesar_encode, KeyedCaesar_decode, [P("keyword","Keyword","CIPHER"), P("shift","Shift","3")]),
        CipherEntry("Dvorak Keyboard", DvorakKeyboard_encode, DvorakKeyboard_decode, []),
        CipherEntry("Kamasutra", Kamasutra_encode, Kamasutra_decode, [P("key","Pair alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ")]),
        CipherEntry("Trithemius", Trithemius_encode, Trithemius_decode, [P("start","Start","0")]),
        CipherEntry("Variant Beaufort", VariantBeaufort_encode, VariantBeaufort_decode, [P("key","Key","FORT")]),
        CipherEntry("Word Caesar", WordCaesar_encode, WordCaesar_decode, [P("shift","Shift","1")]),
        CipherEntry("Latin Reverse Custom", LatinReverseCustom_encode, LatinReverseCustom_decode, [P("alphabet","Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ")]),
        CipherEntry("Keyed Alphabet Arbitrary", KeyedAlphabetArbitrary_encode, KeyedAlphabetArbitrary_decode, [P("source","Source alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ"), P("target","Target alphabet","QWERTYUIOPASDFGHJKLZXCVBNM")]),
        CipherEntry("Keyed Caesar Progressive", KeyedCaesarProgressive_encode, KeyedCaesarProgressive_decode, [P("keyword","Keyword","CIPHER"), P("start","Start","0"), P("step","Step","1")]),
        CipherEntry("Word Substitution", WordSubstitution_encode, WordSubstitution_decode, [P("mapping","Mapping","hello=hola,world=mundo")]),
        CipherEntry("Codebook Substitution", CodebookSubstitution_encode, CodebookSubstitution_decode, [P("codebook","Codebook","attack=17,dawn=42")]),
        CipherEntry("Book Cipher", BookCipher_encode, BookCipher_decode, [P("book","Book text",_BOOK_DEFAULT), P("sep","Fallback separator","-")]),
        CipherEntry("Dictionary Code", DictionaryCode_encode, DictionaryCode_decode, [P("dictionary","Dictionary text",_BOOK_DEFAULT), P("sep","Index separator",".")]),
        CipherEntry("Page-Line-Word-Letter", PageLineWordLetter_encode, PageLineWordLetter_decode, [P("book","Book text",_BOOK_DEFAULT), P("sep","Index separator",".")]),
        CipherEntry("Homophonic Substitution", HomophonicSubstitution_encode, HomophonicSubstitution_decode, []),
        CipherEntry("Headline Puzzle", HeadlinePuzzle_encode, HeadlinePuzzle_decode, [P("filler_word","Filler word","headline")]),
        CipherEntry("Della Porta Disk", DellaPortaDisk_encode, DellaPortaDisk_decode, [P("keyword","Disk keyword","CIPHER"), P("shift","Shift","0")]),
        CipherEntry("Wolseley Disk", WolseleyDisk_encode, WolseleyDisk_decode, [P("keyword","Disk keyword","WOLSELEY"), P("shift","Shift","0")]),
        CipherEntry("Dorabella", Dorabella_encode, Dorabella_decode, [P("sep","Separator"," ")]),
        CipherEntry("Gold-Bug", GoldBug_encode, GoldBug_decode, [P("sep","Separator"," ")]),
        CipherEntry("Dancing Men Tokenized", DancingMenTokenized_encode, DancingMenTokenized_decode, [P("sep","Separator"," ")]),
        CipherEntry("Mary Queen of Scots Nomenclator", MaryQueenScots_encode, MaryQueenScots_decode, [P("sep","Separator"," ")]),
        CipherEntry("SLIDEX", SLIDEX_encode, SLIDEX_decode, [P("key","Grid key","SLIDEX"), P("row_labels","Row labels","12345"), P("col_labels","Column labels","12345"), P("sep","Separator"," ")]),
        CipherEntry("Alberti Disk", AlbertiDisk_encode, AlbertiDisk_decode, [P("outer","Outer alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ"), P("inner_key","Inner key","CIPHER"), P("period","Period","5"), P("step","Step","1")]),
        CipherEntry("Wheatstone Cryptograph", WheatstoneCryptograph_encode, WheatstoneCryptograph_decode, [P("keyword","Keyword","WHEATSTONE"), P("indicator","Indicator","A")]),
        CipherEntry("Condi", Condi_encode, Condi_decode, [P("keyword","Keyword","CIPHER"), P("start","Start","0")]),
        CipherEntry("Ragbaby", Ragbaby_encode, Ragbaby_decode, [P("keyword","Keyword","RAGBABY")]),
        CipherEntry("Straddling Checkerboard", StraddlingCheckerboard_encode, StraddlingCheckerboard_decode, [P("keyword","Keyword","ETAOINSHRDLCUMWFGYPBVKJXQZ"), P("rowdigits","Row digits","3,7")]),
        CipherEntry("Monome-Dinome", MonomeDinome_encode, MonomeDinome_decode, [P("keyword","Keyword","ETAOINSHRDLCUMWFGYPBVKJXQZ"), P("rowdigits","Row digits","2,6")]),
        CipherEntry("Chaocipher", Chaocipher_encode, Chaocipher_decode, [P("left","Left alphabet","HXUCZVAMDSLKPEFJRIGTWOBNYQ"), P("right","Right alphabet","PTLNBQDEOYSFAVZKGJRIHWXUMC")]),
        CipherEntry("Nicodemus", Nicodemus_encode, Nicodemus_decode, [P("key","Transposition key","NICODEMUS"), P("vigenere_key","Vigenere key","KEY")]),
        CipherEntry("Phillips", Phillips_encode, Phillips_decode, [P("key","Square key","PHILLIPS"), P("period","Period","5")]),
        CipherEntry("Slidefair", Slidefair_encode, Slidefair_decode, [P("key","Key","SLIDE")]),
        CipherEntry("Redefence", Redefence_encode, Redefence_decode, [P("rails","Rails","3"), P("offset","Offset","1")]),
        CipherEntry("Checkerboard Transposition", CheckerboardTransposition_encode, CheckerboardTransposition_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("pad","Pad","X")]),
        CipherEntry("Jefferson Disk", JeffersonDisk_encode, JeffersonDisk_decode, [P("offset","Offset","6"), P("disks","Disks (blank/default, comma shifts, or ; alphabets)","")]),
        CipherEntry("Seriated Playfair", SeriatedPlayfair_encode, SeriatedPlayfair_decode, [P("key","Key","KEYWORD"), P("period","Period","5")]),
        CipherEntry("Tri-Square", TriSquare_encode, TriSquare_decode, [P("key1","Key 1","ALPHA"), P("key2","Key 2","BRAVO"), P("key3","Key 3","CHARLIE")]),
        CipherEntry("Cadenus", Cadenus_encode, Cadenus_decode, [P("key","Key","CADENUS"), P("height","Height","25"), P("pad","Pad","X")]),
        CipherEntry("Clave", Clave_encode, Clave_decode, [P("key","Key","CLAVE"), P("alphabet_key","Alphabet key","CIPHER")]),
        CipherEntry("Phillips RC", PhillipsRC_encode, PhillipsRC_decode, [P("key","Square key","PHILLIPS"), P("period","Period","5")]),
        CipherEntry("Swagman", Swagman_encode, Swagman_decode, [P("key","Permutation key","3142"), P("pad","Pad","X")]),
        CipherEntry("Alternating Columnar", AlternatingColumnar_encode, AlternatingColumnar_decode, [P("key","Key","CIPHER")]),
        CipherEntry("Boustrophedon Route", BoustrophedonRoute_encode, BoustrophedonRoute_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("pad","Pad","X")]),
        CipherEntry("Cistercian Numerals", CistercianNumerals_encode, CistercianNumerals_decode, []),
        CipherEntry("Lorenz Toy", LorenzToy_encode, LorenzToy_decode, [P("seed","Seed","LORENZ"), P("wheels","Wheel periods","41,31,29,26,23")]),
        CipherEntry("Complete Columnar", CompleteColumnar_encode, CompleteColumnar_decode, [P("key","Key","CIPHER"), P("pad","Pad","X")]),
        CipherEntry("Columnar Padded", ColumnarPadded_encode, ColumnarPadded_decode, [P("key","Key","CIPHER"), P("pad","Pad","X"), P("policy","Policy","minimal")]),
        CipherEntry("Keyphrase Transposition", KeyphraseTransposition_encode, KeyphraseTransposition_decode, [P("keyphrase","Keyphrase","THE QUICK BROWN FOX")]),
        CipherEntry("Spiral Inward Route", SpiralInwardRoute_encode, SpiralInwardRoute_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("pad","Pad","X")]),
        CipherEntry("Spiral Outward Route", SpiralOutwardRoute_encode, SpiralOutwardRoute_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("pad","Pad","X")]),
        CipherEntry("Reading Order Route", ReadingOrderRoute_encode, ReadingOrderRoute_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("preset","Preset","column"), P("pad","Pad","X")]),
        CipherEntry("Rotating Square Route", RotatingSquareRoute_encode, RotatingSquareRoute_decode, [P("size","Size","5"), P("turns","Turns","1"), P("pad","Pad","X")]),
        CipherEntry("Grille Mask", GrilleMask_encode, GrilleMask_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("mask","Mask","1000001000001000001000001"), P("pad","Pad","X")]),
        CipherEntry("Cardan Grille", CardanGrille_encode, CardanGrille_decode, [P("rows","Rows","5"), P("cols","Cols","5"), P("mask","Mask","1000001000001000001000001"), P("cover","Cover text",""), P("pad","Pad","X")]),
        CipherEntry("Fleissner Grille", FleissnerGrille_encode, FleissnerGrille_decode, [P("size","Size","4"), P("mask","Mask","1100110000000000"), P("pad","Pad","X")]),
        CipherEntry("Turning Cardan Grille", TurningCardanGrille_encode, TurningCardanGrille_decode, [P("size","Size","4"), P("mask","Mask","1100110000000000"), P("pad","Pad","X")]),
        CipherEntry("Raster Bits", RasterBits_encode, RasterBits_decode, [P("width","Width","8"), P("on","On char","#"), P("off","Off char",".")]),
        CipherEntry("Hagelin Toy", HagelinToy_encode, HagelinToy_decode, [P("seed","Seed","HAGELIN"), P("wheels","Wheels","17,19,21,23,25,26")]),
        CipherEntry("Enigma I", EnigmaI_encode, EnigmaI_decode, [P("rotors","Rotors","I II III"), P("reflector","Reflector","B"), P("ring","Ring setting","AAA"), P("setting","Message setting","AAA"), P("plugboard","Plugboard pairs","")]),
        CipherEntry("M-209", M209_encode, M209_decode, [P("key","Key","M209"), P("wheels","Wheel periods","26,25,23,21,19,17")]),
        CipherEntry("Typex", Typex_encode, Typex_decode, [P("rotors","Rotors","IV V II"), P("reflector","Reflector","C"), P("ring","Ring setting","AAA"), P("setting","Message setting","AAA"), P("plugboard","Plugboard pairs","")]),
        CipherEntry("SIGABA Toy", SIGABAToy_encode, SIGABAToy_decode, [P("key","Key","SIGABA"), P("control","Control key","CONTROL")]),
        CipherEntry("AMSCO", AMSCO_encode, AMSCO_decode, [P("key","Key","CIPHER"), P("start_len","Starting cell length","1")]),
        CipherEntry("Bazeries", Bazeries_encode, Bazeries_decode, [P("number","Number key","31415"), P("key","Alphabet key","BAZERIES")]),
        CipherEntry("Disrupted Transposition", DisruptedTransposition_encode, DisruptedTransposition_decode, [P("key","Key","DISRUPT"), P("pad","Pad","X")]),
        CipherEntry("Incomplete Columnar", IncompleteColumnar_encode, IncompleteColumnar_decode, [P("key","Key","CIPHER"), P("keep_spaces","Keep spaces","false")]),
        CipherEntry("Double Columnar Irregular", DoubleColumnarIrregular_encode, DoubleColumnarIrregular_decode, [P("key1","Key 1","ALPHA"), P("key2","Key 2","OMEGA")]),
        CipherEntry("Scytale Padded", ScytalePadded_encode, ScytalePadded_decode, [P("diameter","Diameter","5"), P("pad","Pad","X")]),
        CipherEntry("Gromark", Gromark_encode, Gromark_decode, [P("primer","Primer digits","12345"), P("key","Alphabet key","GROMARK")]),
        CipherEntry("Nihilist Substitution", NihilistSubstitution_encode, NihilistSubstitution_decode, [P("square_key","Square key","NIHILIST"), P("key","Additive key","KEY")]),

        # Vigenère family
        CipherEntry("Vigenere", Vigenere_encode, Vigenere_decode, [P("key","Key","LEMON")]),
        CipherEntry("Chiffre Indechiffrable", ChiffreIndechiffrable_encode, ChiffreIndechiffrable_decode, [P("key","Key","VIGENERE")]),
        CipherEntry("Vigenere Custom Alphabet", VigenereCustom_encode, VigenereCustom_decode, [P("key","Key","LEMON"), P("alphabet","Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ")]),
        CipherEntry("Vigenere Progressive", VigenereProgressive_encode, VigenereProgressive_decode, [P("key","Key","LEMON"), P("step","Step","1")]),
        CipherEntry("Autokey", Autokey_encode, Autokey_decode, [P("key","Key","QUEENLY")]),
        CipherEntry("Beaufort", Beaufort_encode, Beaufort_decode, [P("key","Key","FORT")]),
        CipherEntry("Gronsfeld", Gronsfeld_encode, Gronsfeld_decode, [P("key","Digits","314159")]),
        CipherEntry("Porta (historic)", PortaHistoric_encode, PortaHistoric_decode, [P("key","Key","PORTA")]),
        CipherEntry("Porta (table)", PortaTable_encode, PortaTable_decode, [P("key","Key","PORTA")]),
        CipherEntry("Running Key", RunningKey_encode, RunningKey_decode, [P("key","Key","THENEVERENDINGSTORY")]),
        CipherEntry("Running Key Book", RunningKeyBook_encode, RunningKeyBook_decode, [P("book","Book text","THENEVERENDINGSTORY")]),
        CipherEntry("Interrupted Key", InterruptedKey_encode, InterruptedKey_decode, [P("key","Key","CIPHER"), P("period","Period","5")]),
        CipherEntry("Progressive Key", ProgressiveKey_encode, ProgressiveKey_decode, [P("key","Key","LEMON"), P("increment","Increment","1"), P("group","Group","5")]),
        CipherEntry("Beaufort Autokey", BeaufortAutokey_encode, BeaufortAutokey_decode, [P("key","Key","FORT")]),
        CipherEntry("Variant Beaufort Autokey", VariantBeaufortAutokey_encode, VariantBeaufortAutokey_decode, [P("key","Key","FORT")]),
        CipherEntry("OTP (letters)", OTPLetters_encode, OTPLetters_decode, [P("key","Key","XMCKL")]),

        # Fun / novelty
        CipherEntry("Backslang", Backslang_encode, Backslang_decode, []),
        CipherEntry("Rövarspråket", Rovarspraket_encode, Rovarspraket_decode, []),
        CipherEntry("Tutnese", Tutnese_encode, Tutnese_decode, []),
        CipherEntry("Leet Speak", LEET_encode, LEET_decode, []),
        CipherEntry("Keyboard Substitution", KeyboardSub_encode, KeyboardSub_decode, []),
        CipherEntry("Keyboard Reversed", KeyboardReversed_encode, KeyboardReversed_decode, []),
        CipherEntry("Keyboard Coordinates", KeyboardCoordinate_encode, KeyboardCoordinate_decode, [P("sep","Separator",".")]),
        CipherEntry("QWERTY Adjacent", QWERTYAdjacent_encode, QWERTYAdjacent_decode, [P("direction","Direction","right")]),
        CipherEntry("Chessboard Coordinates", ChessboardCoordinate_encode, ChessboardCoordinate_decode, []),
        CipherEntry("A1Z26", A1Z26_encode, A1Z26_decode, []),
        CipherEntry("NATO Phonetic", NATO_encode, NATO_decode, []),
        CipherEntry("Multi-Tap Phone", MultiTap_encode, MultiTap_decode, []),
        CipherEntry("T9 Keypad", T9_encode, T9_decode, []),
        CipherEntry("Vanity Phone", VanityPhone_encode, VanityPhone_decode, [P("keep_punctuation","Keep punctuation","true")]),
        CipherEntry("Tap Code", TapCode_encode, TapCode_decode, []),
        CipherEntry("Braille Unicode", BrailleUnicode_encode, BrailleUnicode_decode, []),
        CipherEntry("Braille Grade 1", BrailleGrade1_encode, BrailleGrade1_decode, []),
        CipherEntry("APCO Phonetic", APCO_encode, APCO_decode, []),
        CipherEntry("Baudot ITA2", BaudotITA2_encode, BaudotITA2_decode, []),
        CipherEntry("Murray Code", MurrayCode_encode, MurrayCode_decode, []),
        CipherEntry("Semaphore Arms", SemaphoreArms_encode, SemaphoreArms_decode, []),
        CipherEntry("Pigpen Unicode", PigpenUnicode_encode, PigpenUnicode_decode, []),
        CipherEntry("Upside-down Text", UpsideDown_encode, UpsideDown_decode, []),
        CipherEntry("Mirror Text", MirrorText_encode, MirrorText_decode, []),
        CipherEntry("Zero-width Binary", ZeroWidthBinary_encode, ZeroWidthBinary_decode, []),
        CipherEntry("Bacon Biliteral", BaconBiliteral_encode, BaconBiliteral_decode, [P("a_char","A character","A"), P("b_char","B character","B")]),
        CipherEntry("Whitespace Binary", WhitespaceBinary_encode, WhitespaceBinary_decode, []),
        CipherEntry("Snow Steg", SnowSteg_encode, SnowSteg_decode, [P("cover","Cover text","snow")]),
        CipherEntry("Elder Futhark", ElderFuthark_encode, ElderFuthark_decode, []),
        CipherEntry("Younger Futhark", YoungerFuthark_encode, YoungerFuthark_decode, []),
        CipherEntry("Ogham", Ogham_encode, Ogham_decode, []),
        CipherEntry("Maritime Signal Flags", MaritimeFlags_encode, MaritimeFlags_decode, []),
        CipherEntry("International Code Signals", InternationalSignals_encode, InternationalSignals_decode, []),
        CipherEntry("Cirth", Cirth_encode, Cirth_decode, []),
        CipherEntry("Tengwar Tokens", TengwarTokens_encode, TengwarTokens_decode, []),
        CipherEntry("Zodiac Symbols", ZodiacSymbols_encode, ZodiacSymbols_decode, []),
        CipherEntry("Wingdings Tokens", WingdingsTokens_encode, WingdingsTokens_decode, []),
        CipherEntry("Aurebesh", Aurebesh_encode, Aurebesh_decode, []),
        CipherEntry("Theban", Theban_encode, Theban_decode, []),
        CipherEntry("Standard Galactic", StandardGalactic_encode, StandardGalactic_decode, []),
        CipherEntry("Dancing Men", DancingMen_encode, DancingMen_decode, []),
        CipherEntry("Moon Type", MoonType_encode, MoonType_decode, []),
        CipherEntry("Calculator Spelling", CalculatorSpelling_encode, CalculatorSpelling_decode, []),
        CipherEntry("Zalgo", Zalgo_encode, Zalgo_decode, [P("intensity","Intensity","2")]),
        CipherEntry("Invisible Unicode", InvisibleUnicode_encode, InvisibleUnicode_decode, [P("cover","Cover text","")]),
        CipherEntry("Null Acrostic", NullAcrostic_encode, NullAcrostic_decode, []),
        CipherEntry("Acrostic Generator", AcrosticGenerator_encode, AcrosticGenerator_decode, [P("filler_word","Filler word","cover")]),
        CipherEntry("Every Nth Hider", EveryNthHider_encode, EveryNthHider_decode, [P("n","N","3"), P("filler","Filler","x")]),
        CipherEntry("Solresol", Solresol_encode, Solresol_decode, []),
        CipherEntry("Music Notes", MusicNotes_encode, MusicNotes_decode, []),

        # Encodings
        CipherEntry("Binary", Binary_encode, Binary_decode, []),
        CipherEntry("Octal", Octal_encode, Octal_decode, []),
        CipherEntry("Hex", Hex_encode, Hex_decode, []),
        CipherEntry("Base32", Base32_encode, Base32_decode, []),
        CipherEntry("Base16 with separators", Base16Sep_encode, Base16Sep_decode, [P("sep","Separator"," ")]),
        CipherEntry("Base32hex", Base32Hex_encode, Base32Hex_decode, []),
        CipherEntry("Base64URL", Base64URL_encode, Base64URL_decode, []),
        CipherEntry("Base92", Base92_encode, Base92_decode, []),
        CipherEntry("yEnc", yEnc_encode, yEnc_decode, []),
        CipherEntry("Base32 Crockford", Base32Crockford_encode, Base32Crockford_decode, []),
        CipherEntry("Base36", Base36_encode, Base36_decode, []),
        CipherEntry("Base45", Base45_encode, Base45_decode, []),
        CipherEntry("Base58", Base58_encode, Base58_decode, []),
        CipherEntry("Base62", Base62_encode, Base62_decode, []),
        CipherEntry("Base91", Base91_encode, Base91_decode, []),
        CipherEntry("Z85", Z85_encode, Z85_decode, []),
        CipherEntry("RFC1924 Base85", RFC1924Base85_encode, RFC1924Base85_decode, []),
        CipherEntry("Base64", Base64_encode, Base64_decode, []),
        CipherEntry("Ascii85 (a85)", A85_encode, A85_decode, []),
        CipherEntry("Base85 (b85)", B85_encode, B85_decode, []),
        CipherEntry("Base3 (ternary)", Base3_encode, Base3_decode, []),
        CipherEntry("Base9", Base9_encode, Base9_decode, []),
        CipherEntry("URL", URL_encode, URL_decode, []),
        CipherEntry("HTML Entities", HTMLEntities_encode, HTMLEntities_decode, []),
        CipherEntry("Quoted-Printable", QuotedPrintable_encode, QuotedPrintable_decode, []),
        CipherEntry("Punycode", Punycode_encode, Punycode_decode, []),
        CipherEntry("Gray Code", GrayCode_encode, GrayCode_decode, []),
        CipherEntry("uuencode", UUEncode_encode, UUEncode_decode, []),
        CipherEntry("xxencode", XXEncode_encode, XXEncode_decode, []),
        CipherEntry("Netstring", Netstring_encode, Netstring_decode, []),
        CipherEntry("Bencode String", BencodeString_encode, BencodeString_decode, []),
        CipherEntry("MessagePack Hex", MessagePackHex_encode, MessagePackHex_decode, []),
        CipherEntry("PEM Armor", PEMArmor_encode, PEMArmor_decode, [P("label","Label","MESSAGE")]),
        CipherEntry("OpenPGP Armor", OpenPGPArmor_encode, OpenPGPArmor_decode, [P("label","Label","MESSAGE")]),
        CipherEntry("Intel HEX", IntelHex_encode, IntelHex_decode, [P("bytes_per_record","Bytes/record","16")]),
        CipherEntry("Motorola S-Record", MotorolaSRecord_encode, MotorolaSRecord_decode, [P("bytes_per_record","Bytes/record","16")]),
        CipherEntry("Base100 Emoji", Base100Emoji_encode, Base100Emoji_decode, []),
        CipherEntry("Parity Bits", ParityBits_encode, ParityBits_decode, []),
        CipherEntry("Hex Color", HexColor_encode, HexColor_decode, []),
        CipherEntry("RLE", RLE_encode, RLE_decode, []),
        CipherEntry("Burrows-Wheeler", BWT_encode, BWT_decode, []),
        CipherEntry("Move-to-front", MoveToFront_encode, MoveToFront_decode, []),
        CipherEntry("Zlib Base64", ZlibBase64_encode, ZlibBase64_decode, [P("level","Level","9")]),
        CipherEntry("Gzip Base64", GzipBase64_encode, GzipBase64_decode, [P("level","Level","9")]),
        CipherEntry("Binary Endian Words", BinaryEndianWords_encode, BinaryEndianWords_decode, [P("word_bytes","Word bytes","2"), P("endian","Endian","big")]),
        CipherEntry("C String Escapes", CStringEscapes_encode, CStringEscapes_decode, []),
        CipherEntry("Hamming(7,4)", Hamming74_encode, Hamming74_decode, []),
        CipherEntry("Luhn Check", Luhn_encode, Luhn_decode, []),
        CipherEntry("JSON String Escapes", JSONStringEscapes_encode, JSONStringEscapes_decode, []),
        CipherEntry("Octal Escapes", OctalEscapes_encode, OctalEscapes_decode, []),
        CipherEntry("Hexdump", Hexdump_encode, Hexdump_decode, []),
        CipherEntry("Data URI", DataURI_encode, DataURI_decode, [P("mime","MIME","text/plain;charset=utf-8")]),
        CipherEntry("URL Form", URLForm_encode, URLForm_decode, []),
        CipherEntry("CRC32", CRC32_encode, CRC32_decode, []),
        CipherEntry("Adler32", Adler32_encode, Adler32_decode, []),
        CipherEntry("CRC16-CCITT", CRC16CCITT_encode, CRC16CCITT_decode, []),
        CipherEntry("Fletcher16", Fletcher16_encode, Fletcher16_decode, []),
        CipherEntry("Fletcher32", Fletcher32_encode, Fletcher32_decode, []),
        CipherEntry("Verhoeff Check", Verhoeff_encode, Verhoeff_decode, []),
        CipherEntry("Damm Check", Damm_encode, Damm_decode, []),
        CipherEntry("Elias Gamma", EliasGamma_encode, EliasGamma_decode, []),
        CipherEntry("Fibonacci Code", FibonacciCode_encode, FibonacciCode_decode, []),
        CipherEntry("Hamming(15,11)", Hamming1511_encode, Hamming1511_decode, []),
        CipherEntry("LEB128", LEB128_encode, LEB128_decode, []),
        CipherEntry("Elias Delta", EliasDelta_encode, EliasDelta_decode, []),
        CipherEntry("Golomb", Golomb_encode, Golomb_decode, [P("m","Divisor m","10")]),
        CipherEntry("CRC8", CRC8_encode, CRC8_decode, []),
        CipherEntry("CRC64-ECMA", CRC64ECMA_encode, CRC64ECMA_decode, []),
        CipherEntry("MD5", MD5_encode, MD5_decode, []),
        CipherEntry("SHA1", SHA1_encode, SHA1_decode, []),
        CipherEntry("SHA256", SHA256_encode, SHA256_decode, []),
        CipherEntry("SHA3-256", SHA3_256_encode, SHA3_256_decode, []),
        CipherEntry("HMAC", HMAC_encode, HMAC_decode, [P("key","Key","secret"), P("algorithm","Algorithm","sha256")]),
        CipherEntry("PBKDF2", PBKDF2_encode, PBKDF2_decode, [P("salt","Salt","salt"), P("iterations","Iterations","100000"), P("algorithm","Algorithm","sha256"), P("dklen","Bytes","32")]),
        CipherEntry("BLAKE2b", BLAKE2b_encode, BLAKE2b_decode, []),
        CipherEntry("BLAKE2s", BLAKE2s_encode, BLAKE2s_decode, []),
        CipherEntry("scrypt", Scrypt_encode, Scrypt_decode, [P("salt","Salt","salt"), P("n","N","16384"), P("r","r","8"), P("p","p","1"), P("dklen","Bytes","32")]),
        CipherEntry("HKDF", HKDF_encode, HKDF_decode, [P("salt","Salt","salt"), P("info","Info",""), P("algorithm","Algorithm","sha256"), P("length","Bytes","32")]),
        CipherEntry("HOTP", HOTP_encode, HOTP_decode, [P("secret","Secret","secret"), P("counter","Counter","0"), P("digits","Digits","6"), P("algorithm","Algorithm","sha1"), P("base32_secret","Base32 secret","false")]),
        CipherEntry("TOTP", TOTP_encode, TOTP_decode, [P("secret","Secret","secret"), P("time_step","Time step","30"), P("digits","Digits","6"), P("algorithm","Algorithm","sha1"), P("for_time","Unix time (0=now)","0"), P("base32_secret","Base32 secret","false")]),
        CipherEntry("Unicode \\u Escapes", UEscapes_encode, UEscapes_decode, []),
        CipherEntry("ASCII Shift (hex)", AsciiShiftHex_encode, AsciiShiftHex_decode, [P("shift","Shift","1")]),
        CipherEntry("DNA Encoding", DNA_encode, DNA_decode, []),
        CipherEntry("DNA Codons", DNACodon_encode, DNACodon_decode, []),
        CipherEntry("RNA Codons", RNACodon_encode, RNACodon_decode, []),
        CipherEntry("Amino Acid 1/3", AminoAcid_encode, AminoAcid_decode, []),
        CipherEntry("I Ching Hexagrams", IChingHexagram_encode, IChingHexagram_decode, []),
        CipherEntry("Tarot Cards", TarotCard_encode, TarotCard_decode, []),

        # Polygraphic / transposition
        CipherEntry("Polybius", Polybius_encode, Polybius_decode, [P("key","Key","KEYWORD")]),
        CipherEntry("Polybius Custom Labels", PolybiusCustom_encode, PolybiusCustom_decode, [P("key","Key","KEYWORD"), P("row_labels","Row labels","12345"), P("col_labels","Column labels","12345"), P("sep","Separator"," ")]),
        CipherEntry("Polybius Columnar", PolybiusColumnar_encode, PolybiusColumnar_decode, [P("square_key","Square key","KEYWORD"), P("route_key","Route key","CIPHER"), P("row_labels","Row labels","12345"), P("col_labels","Column labels","12345")]),
        CipherEntry("Playfair", Playfair_encode, Playfair_decode, [P("key","Key","KEYWORD")]),
        CipherEntry("Playfair Q Omitted", PlayfairQOmitted_encode, PlayfairQOmitted_decode, [P("key","Key","KEYWORD"), P("filler","Filler","X")]),
        CipherEntry("Playfair Preserve", PlayfairPreserve_encode, PlayfairPreserve_decode, [P("key","Key","KEYWORD"), P("filler","Filler","X")]),
        CipherEntry("Playfair Padding", PlayfairPadding_encode, PlayfairPadding_decode, [P("key","Key","KEYWORD"), P("filler","Filler","X"), P("omit","Omit letter","J")]),
        CipherEntry("Double Playfair", DoublePlayfair_encode, DoublePlayfair_decode, [P("key1","Key 1","ALPHA"), P("key2","Key 2","OMEGA")]),
        CipherEntry("Four-Square", FourSquare_encode, FourSquare_decode, [P("key1","Key 1","EXAMPLE"), P("key2","Key 2","KEYWORD")]),
        CipherEntry("Two-Square", TwoSquare_encode, TwoSquare_decode, [P("key1","Key L","EXAMPLE"), P("key2","Key R","KEYWORD")]),
        CipherEntry("Two-Square Vertical", TwoSquareVertical_encode, TwoSquareVertical_decode, [P("key_top","Top key","EXAMPLE"), P("key_bottom","Bottom key","KEYWORD")]),
        CipherEntry("Columnar", Columnar_encode, Columnar_decode, [P("key","Key","CIPHER")]),
        CipherEntry("Myszkowski", Myszkowski_encode, Myszkowski_decode, [P("key","Key","TOMATO")]),
        CipherEntry("Caesar Box", CaesarBox_encode, CaesarBox_decode, [P("cols","Cols","4")]),
        CipherEntry("Scytale", Scytale_encode, Scytale_decode, [P("diameter","Diameter","5")]),
        CipherEntry("Double Transposition", DoubleTransposition_encode, DoubleTransposition_decode, [P("key1","Key 1","EXAMPLE"), P("key2","Key 2","KEYWORD")]),
        CipherEntry("Route Cipher", Route_encode, Route_decode, [P("rows","Rows","5"), P("cols","Cols","5")]),
        CipherEntry("Bifid", Bifid_encode, Bifid_decode, [P("key","Key","KEYWORD"), P("period","Period","5")]),
        CipherEntry("Bifid No Period", BifidNoPeriod_encode, BifidNoPeriod_decode, [P("key","Key","KEYWORD")]),
        CipherEntry("Conjugated Bifid", ConjugatedBifid_encode, ConjugatedBifid_decode, [P("plain_key","Plain key","PLAIN"), P("cipher_key","Cipher key","CIPHER"), P("period","Period","5")]),
        CipherEntry("Twin Bifid", TwinBifid_encode, TwinBifid_decode, [P("key1","Key 1","ALPHA"), P("key2","Key 2","OMEGA"), P("period","Period","5")]),
        CipherEntry("Trifid", Trifid_encode, Trifid_decode, [P("key","Key","KEYWORD"), P("period","Period","5")]),
        CipherEntry("Trifid Custom Alphabet", TrifidCustom_encode, TrifidCustom_decode, [P("alphabet","Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ."), P("period","Period","5")]),
        CipherEntry("Hill 2x2", Hill2x2_encode, Hill2x2_decode, [P("key","Matrix key","3,3,2,5")]),
        CipherEntry("Hill 3x3", Hill3x3_encode, Hill3x3_decode, [P("key","Matrix key","6,24,1,13,16,10,20,17,15")]),
        CipherEntry("Hill NxN", HillNxN_encode, HillNxN_decode, [P("key","Matrix key","6,24,1,13,16,10,20,17,15"), P("size","Size","3"), P("alphabet","Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZ")]),
        CipherEntry("Playfair 6x6", Playfair6x6_encode, Playfair6x6_decode, [P("key","Key","KEYWORD")]),
        CipherEntry("Four-Square 6x6", FourSquare6x6_encode, FourSquare6x6_decode, [P("key1","Key 1","EXAMPLE"), P("key2","Key 2","KEYWORD")]),
        CipherEntry("Two-Square 6x6", TwoSquare6x6_encode, TwoSquare6x6_decode, [P("key1","Key L","EXAMPLE"), P("key2","Key R","KEYWORD")]),
        CipherEntry("Bifid 6x6", Bifid6x6_encode, Bifid6x6_decode, [P("key","Key","KEYWORD"), P("period","Period","5")]),

        # ADFGX / ADFGVX
        CipherEntry("ADFGX", ADFGX_encode, ADFGX_decode, [P("square_key","Square Key","KEYWORD"), P("route_key","Route Key","CIPHER")]),
        CipherEntry("ADFGX Custom Labels", ADFGXCustom_encode, ADFGXCustom_decode, [P("square_key","Square Key","KEYWORD"), P("route_key","Route Key","CIPHER"), P("labels","Labels","ADFGX")]),
        CipherEntry("ADFGVX", ADFGVX_encode, ADFGVX_decode, [P("square_key","Square Key","KEYW0RD"), P("route_key","Route Key","CIPHER")]),
        CipherEntry("ADFGVX Escaped", ADFGVXEscaped_encode, ADFGVXEscaped_decode, [P("square_key","Square Key","KEYW0RD"), P("route_key","Route Key","CIPHER")]),

        # Morse / Pigpen
        CipherEntry("Morse", Morse_encode, Morse_decode, []),
        CipherEntry("Knock Code", KnockCode_encode, KnockCode_decode, []),
        CipherEntry("Morbit", Morbit_encode, Morbit_decode, [P("key","Digit key","123456789")]),
        CipherEntry("Pollux", Pollux_encode, Pollux_decode, []),
        CipherEntry("Pigpen", Pigpen_encode, Pigpen_decode, []),

        # Quagmire I–VI
        CipherEntry("Quagmire I", QuagmireI_encode, QuagmireI_decode, [P("runkey","Run-key","QUEENLY"), P("cipher_key","Cipher-key","CIPHER")]),
        CipherEntry("Quagmire II", QuagmireII_encode, QuagmireII_decode, [P("runkey","Run-key","QUEENLY"), P("plain_key","Plain-key","PLAIN")]),
        CipherEntry("Quagmire III", QuagmireIII_encode, QuagmireIII_decode, [P("runkey","Run-key","QUEENLY"), P("plain_key","Plain-key","PLAIN"), P("cipher_key","Cipher-key","CIPHER")]),
        CipherEntry("Quagmire IV", QuagmireIV_encode, QuagmireIV_decode, [P("runkey","Run-key","QUEENLY"), P("indicator","Indicator","INDICATOR"), P("plain_key","Plain-key","PLAIN"), P("cipher_key","Cipher-key","CIPHER")]),
        CipherEntry("Quagmire V", QuagmireV_encode, QuagmireV_decode, [P("runkey","Run-key","QUEENLY"), P("plain_key","Plain-key","PLAIN"), P("cipher_key","Cipher-key","CIPHER"), P("plain_indicator","Plain indicator","A"), P("cipher_indicator","Cipher indicator","A")]),
        CipherEntry("Quagmire VI", QuagmireVI_encode, QuagmireVI_decode, [P("runkey","Run-key","QUEENLY"), P("plain_key","Plain-key","PLAIN"), P("cipher_key","Cipher-key","CIPHER"), P("indicator","Indicator","A"), P("step","Step","1")]),

        # Numeric / fractionated
        CipherEntry("Baconian", Baconian_encode, Baconian_decode, []),
        CipherEntry("Grandpré", Grandpre_encode, Grandpre_decode, [P("key","Key","GRANDPRE")]),
        CipherEntry("Nihilist", Nihilist_encode, Nihilist_decode, [P("alpha_key","Alpha-key","CIPHER"), P("num_key","Num-key","KEY")]),
        CipherEntry("Homophonic", HOMO_encode, HOMO_decode, [P("seed","Seed","SEED")]),
        CipherEntry("Fractionated Morse", FM_encode, FM_decode, [P("key","Key","KEYABCDFGHIJLMNOPQRSTUVWXZ")]),

        # Modern / recently created
        CipherEntry("RC4 (hex)", RC4_hex_encode, RC4_hex_decode, [P("key","Key","secret")]),
        CipherEntry("Solitaire", Solitaire_encode, Solitaire_decode, [P("key","Key","CRYPTONOMICON")]),
        CipherEntry("ChaCha20 (hex)", ChaCha20_hex_encode, ChaCha20_hex_decode, [P("key","Key","secret"), P("nonce","Nonce","000000000000000000000000"), P("counter","Counter","1")]),
        CipherEntry("AES-GCM (hex)", AESGCM_hex_encode, AESGCM_hex_decode, [P("key","Key/hex key","secret"), P("nonce","Nonce/hex nonce","nonce"), P("aad","AAD","")]),
        CipherEntry("AES-ECB (hex)", AESECB_hex_encode, AESECB_hex_decode, [P("key","Key/hex key","secret")]),
        CipherEntry("AES-CBC (hex)", AESCBC_hex_encode, AESCBC_hex_decode, [P("key","Key/hex key","secret"), P("iv","IV/hex IV","iv")]),
        CipherEntry("AES-CTR (hex)", AESCTR_hex_encode, AESCTR_hex_decode, [P("key","Key/hex key","secret"), P("nonce","Nonce/hex nonce","nonce")]),
        CipherEntry("ChaCha20-Poly1305 (hex)", ChaCha20Poly1305_hex_encode, ChaCha20Poly1305_hex_decode, [P("key","Key/hex key","secret"), P("nonce","Nonce/hex nonce","nonce"), P("aad","AAD","")]),
        CipherEntry("Fernet Token", FernetToken_encode, FernetToken_decode, [P("password","Password","secret")]),
        CipherEntry("ChaCha12 (hex)", ChaCha12_hex_encode, ChaCha12_hex_decode, [P("key","Key","secret"), P("nonce","Nonce","000000000000000000000000"), P("counter","Counter","1")]),
        CipherEntry("ChaCha8 (hex)", ChaCha8_hex_encode, ChaCha8_hex_decode, [P("key","Key","secret"), P("nonce","Nonce","000000000000000000000000"), P("counter","Counter","1")]),
        CipherEntry("Salsa20 (hex)", Salsa20_hex_encode, Salsa20_hex_decode, [P("key","Key","secret"), P("nonce","Nonce","0000000000000000"), P("counter","Counter","0")]),
        CipherEntry("XXTEA (hex)", XXTEA_hex_encode, XXTEA_hex_decode, [P("key","Key","secret")]),
        CipherEntry("Speck32/64 (hex)", Speck32_hex_encode, Speck32_hex_decode, [P("key","Key","secret")]),
        CipherEntry("Simon32/64 (hex)", Simon32_64_hex_encode, Simon32_64_hex_decode, [P("key","Key","secret")]),
        CipherEntry("TEA (hex)", TEA_hex_encode, TEA_hex_decode, [P("key","Key","secret")]),
        CipherEntry("XTEA (hex)", XTEA_hex_encode, XTEA_hex_decode, [P("key","Key","secret")]),
        CipherEntry("RC5-32/12/16 (hex)", RC5_32_hex_encode, RC5_32_hex_decode, [P("key","Key","secret")]),

        # Novel tagged
        CipherEntry("Emoji Substitution", Emoji_encode, Emoji_decode, [P("seed","Seed","EMOJI")]),
        CipherEntry("Whitespace Encoding", WS_encode, WS_decode, []),
        CipherEntry("SCB Encode", SCB_encode, SCB_decode, [P("keyword","Keyword","ETAOINSHRDLCUMWFGYPBVKJXQZ"), P("rowdigits","RowDigits","3,7")]),
        CipherEntry("Rail Fence", RailFence_encode, RailFence_decode, [P("rails","Rails","3")]),
        CipherEntry("Rail Fence Offset", RailFenceOffset_encode, RailFenceOffset_decode, [P("rails","Rails","3"), P("offset","Offset","1")]),
        CipherEntry("Rail Fence Spaces", RailFenceSpaces_encode, RailFenceSpaces_decode, [P("rails","Rails","3")]),
        CipherEntry("Skip Permutation", SkipPermutation_encode, SkipPermutation_decode, [P("step","Step","3")]),
        CipherEntry("Spiral Route", SpiralRoute_encode, SpiralRoute_decode, [P("rows","Rows","5"), P("cols","Cols","5")]),
        CipherEntry("Vertical Transposition", VerticalTransposition_encode, VerticalTransposition_decode, [P("key","Numeric key","3142")]),
        CipherEntry("XOR (hex)", XOR_hex_encode, XOR_hex_decode, [P("key","Key","key")]),
        CipherEntry("Pig Latin", PigLatin_encode, PigLatin_decode, []),
        CipherEntry("Semaphore", Semaphore_encode, Semaphore_decode, []),
    ]
    return reg

# =============================================================================
# Helpers: call by name with param dict
# =============================================================================

def _parse_rowdigits(v: str) -> tuple[int,int]:
    try:
        a,b = v.split(",")
        return (int(a.strip()), int(b.strip()))
    except:
        return (3,7)

def call_encode(name: str, text: str, params: Dict[str,str]) -> str:
    for ce in get_registry():
        if ce.name == name:
            # Normalize param types for a couple of ciphers
            if name == "Affine":
                return ce.enc_fn(text, int(params.get("a","5")), int(params.get("b","8")), int(params.get("m","26")))
            if name == "ASCII Shift (hex)":
                return ce.enc_fn(text, int(params.get("shift","1")))
            if name == "Columnar":
                return ce.enc_fn(text, params.get("key","CIPHER"))
            if name == "Myszkowski":
                return ce.enc_fn(text, params.get("key","TOMATO"))
            if name == "Caesar Box":
                return ce.enc_fn(text, int(params.get("cols","4")))
            if name == "Scytale":
                return ce.enc_fn(text, int(params.get("diameter","5")))
            if name == "Route Cipher":
                return ce.enc_fn(text, int(params.get("rows","5")), int(params.get("cols","5")))
            if name == "ADFGX":
                return ce.enc_fn(text, params.get("square_key","KEYWORD"), params.get("route_key","CIPHER"))
            if name == "ADFGVX":
                return ce.enc_fn(text, params.get("square_key","KEYW0RD"), params.get("route_key","CIPHER"))
            if name == "SCB Encode":
                return ce.enc_fn(text, params.get("keyword","ETAOINSHRDLCUMWFGYPBVKJXQZ"), _parse_rowdigits(params.get("rowdigits","3,7")))
            if name == "Rail Fence":
                return ce.enc_fn(text, int(params.get("rails","3")))
            # Defaults: pass exactly as strings in declared order
            # Collect kwargs in order:
            ordered = []
            for p in ce.params:
                ordered.append(params.get(p.name, p.default))
            return ce.enc_fn(text, *ordered)
    raise ValueError(f"Unknown cipher: {name}")

def call_decode(name: str, text: str, params: Dict[str,str]) -> str:
    for ce in get_registry():
        if ce.name == name:
            if name == "Affine":
                return ce.dec_fn(text, int(params.get("a","5")), int(params.get("b","8")), int(params.get("m","26")))
            if name == "ASCII Shift (hex)":
                return ce.dec_fn(text, int(params.get("shift","1")))
            if name == "Columnar":
                return ce.dec_fn(text, params.get("key","CIPHER"))
            if name == "Myszkowski":
                return ce.dec_fn(text, params.get("key","TOMATO"))
            if name == "Caesar Box":
                return ce.dec_fn(text, int(params.get("cols","4")))
            if name == "Scytale":
                return ce.dec_fn(text, int(params.get("diameter","5")))
            if name == "Route Cipher":
                return ce.dec_fn(text, int(params.get("rows","5")), int(params.get("cols","5")))
            if name == "ADFGX":
                return ce.dec_fn(text, params.get("square_key","KEYWORD"), params.get("route_key","CIPHER"))
            if name == "ADFGVX":
                return ce.dec_fn(text, params.get("square_key","KEYW0RD"), params.get("route_key","CIPHER"))
            if name == "SCB Encode":
                return ce.dec_fn(text, params.get("keyword","ETAOINSHRDLCUMWFGYPBVKJXQZ"), _parse_rowdigits(params.get("rowdigits","3,7")))
            if name in {"Homophonic", "Emoji Substitution"}:
                return ce.dec_fn(text)
            if name == "Rail Fence":
                return ce.dec_fn(text, int(params.get("rails","3")))
            # Defaults
            ordered = []
            for p in ce.params:
                ordered.append(params.get(p.name, p.default))
            return ce.dec_fn(text, *ordered)
    raise ValueError(f"Unknown cipher: {name}")

# =============================================================================
# CLI
# =============================================================================

def parse_kv_list(kv_list: List[str]) -> Dict[str,str]:
    out = {}
    for kv in kv_list or []:
        if "=" in kv:
            k,v = kv.split("=",1)
            out[k.strip()] = v.strip()
    return out

def cli_main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="encripter", description="All-The-Ciphers — encode/decode/guess/bruteforce")
    sub = parser.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List ciphers")
    p_enc = sub.add_parser("encode", help="Encode text")
    p_enc.add_argument("cipher")
    p_enc.add_argument("text")
    p_enc.add_argument("-p","--param", action="append", help="key=value", default=[])

    p_dec = sub.add_parser("decode", help="Decode text")
    p_dec.add_argument("cipher")
    p_dec.add_argument("text")
    p_dec.add_argument("-p","--param", action="append", help="key=value", default=[])

    p_guess = sub.add_parser("guess", help="Smart guess")
    p_guess.add_argument("text")

    p_brute = sub.add_parser("brute", help="Brute force")
    p_brute.add_argument("text")
    p_brute.add_argument("-f","--family", action="append", help="Family name (repeatable)", default=[])

    if len(argv)==0:
        # no args: launch GUI if possible, else show help
        if tk is not None:
            launch_gui()
            return 0
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    if args.cmd == "list":
        for ce in get_registry():
            par = ", ".join(f"{p.name} (default={p.default})" for p in ce.params) or "-"
            print(f"{ce.name:24} params: {par}")
        return 0
    elif args.cmd == "encode":
        params = parse_kv_list(args.param)
        out = call_encode(args.cipher, args.text, params)
        print(out)
        return 0
    elif args.cmd == "decode":
        params = parse_kv_list(args.param)
        out = call_decode(args.cipher, args.text, params)
        print(out)
        return 0
    elif args.cmd == "guess":
        ranked = SmartGuess(args.text)
        for i,(label, pt, sc) in enumerate(ranked, 1):
            preview = pt[:80].replace("\n", " ")
            print(f"{i:2d}. {label:28} score={sc:8.2f} | {preview}")
        return 0
    elif args.cmd == "brute":
        fams = args.family or ["caesar","affine","railfence","vigenere-short","xor-hex"]
        ranked = BruteForce(args.text, fams)
        for i,(label, pt, sc) in enumerate(ranked, 1):
            preview = pt[:80].replace("\n", " ")
            print(f"{i:2d}. {label:28} score={sc:8.2f} | {preview}")
        return 0
    else:
        parser.print_help()
        return 0

# =============================================================================
# GUI (Tkinter) — with QoL improvements
# =============================================================================

APP_STATE_FILE = str(Path.home() / ".all_the_ciphers_gui.json")

class CipherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("All-The-Ciphers")
        root.geometry("1100x720")

        self.dark = False
        self.font_size = 12

        self.registry = get_registry()
        self.name_to_entry = {ce.name: ce for ce in self.registry}

        self._build_menu()
        self._build_layout()
        self._bind_keys()
        self._load_state()
        self._apply_theme()

        self._update_status()

    # --- UI build

    def _build_menu(self):
        m = tk.Menu(self.root)
        self.root.config(menu=m)

        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Open…  (Ctrl+O)", command=self.open_file)
        fm.add_command(label="Save Output…  (Ctrl+S)", command=self.save_output)
        fm.add_separator()
        fm.add_command(label="Exit", command=self.root.destroy)
        m.add_cascade(label="File", menu=fm)

        em = tk.Menu(m, tearoff=0)
        em.add_command(label="Copy Output", command=self.copy_output)
        em.add_command(label="Paste to Input", command=self.paste_input)
        em.add_command(label="Swap In/Out  (Ctrl+I)", command=self.swap_io)
        m.add_cascade(label="Edit", menu=em)

        tm = tk.Menu(m, tearoff=0)
        tm.add_command(label="Toggle Dark Mode", command=self.toggle_dark)
        tm.add_command(label="Bigger Font", command=lambda: self.adjust_font(1))
        tm.add_command(label="Smaller Font", command=lambda: self.adjust_font(-1))
        m.add_cascade(label="View", menu=tm)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="About", command=self.show_about)
        m.add_cascade(label="Help", menu=hm)

    def _build_layout(self):
        # Top row: cipher selector + params
        top = ttk.Frame(self.root)
        top.pack(side="top", fill="x", padx=8, pady=6)

        ttk.Label(top, text="Cipher:").pack(side="left")
        self.cipher_var = tk.StringVar(value=self.registry[0].name)
        self.cipher_cb = ttk.Combobox(top, textvariable=self.cipher_var, values=[ce.name for ce in self.registry], state="readonly", width=26)
        self.cipher_cb.pack(side="left", padx=6)
        self.cipher_cb.bind("<<ComboboxSelected>>", lambda e: self._rebuild_params())

        self.mode_var = tk.StringVar(value="encode")
        ttk.Radiobutton(top, text="Encode", variable=self.mode_var, value="encode").pack(side="left", padx=4)
        ttk.Radiobutton(top, text="Decode", variable=self.mode_var, value="decode").pack(side="left", padx=4)

        self.run_btn = ttk.Button(top, text="Run (Ctrl+E / Ctrl+D)", command=self.run_current)
        self.run_btn.pack(side="left", padx=8)

        ttk.Separator(self.root, orient="horizontal").pack(fill="x", pady=4)

        # Params row (dynamic)
        self.params_frame = ttk.Frame(self.root)
        self.params_frame.pack(side="top", fill="x", padx=8, pady=6)
        self.param_vars: Dict[str, tk.StringVar] = {}
        self._rebuild_params()

        # Middle: text areas + side buttons
        mid = ttk.Frame(self.root)
        mid.pack(side="top", fill="both", expand=True, padx=8, pady=6)

        self.input_txt = tk.Text(mid, wrap="word", height=12, undo=True)
        self.output_txt = tk.Text(mid, wrap="word", height=12, undo=True)

        self.input_txt.pack(side="left", fill="both", expand=True, padx=(0,4))
        right = ttk.Frame(mid); right.pack(side="left", fill="y")
        self.output_txt.pack(side="left", fill="both", expand=True, padx=(4,0))

        ttk.Button(right, text="Smart Guess (Ctrl+G)", command=self.smart_guess).pack(fill="x", pady=2)
        ttk.Button(right, text="Brute Force (Ctrl+B)", command=self.brute_force).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=4)
        ttk.Button(right, text="Swap In/Out (Ctrl+I)", command=self.swap_io).pack(fill="x", pady=2)
        ttk.Button(right, text="Copy Output", command=self.copy_output).pack(fill="x", pady=2)
        ttk.Button(right, text="Paste → Input", command=self.paste_input).pack(fill="x", pady=2)
        ttk.Button(right, text="Clear Both (Ctrl+L)", command=self.clear_both).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=4)
        ttk.Button(right, text="Open… (Ctrl+O)", command=self.open_file).pack(fill="x", pady=2)
        ttk.Button(right, text="Save Output… (Ctrl+S)", command=self.save_output).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=4)
        ttk.Button(right, text="Dark Mode", command=self.toggle_dark).pack(fill="x", pady=2)

        # Bottom: status
        self.status = ttk.Label(self.root, text="Ready", anchor="w")
        self.status.pack(side="bottom", fill="x")

        # events for status updates
        self.input_txt.bind("<<Modified>>", self._on_text_change)
        self.output_txt.bind("<<Modified>>", self._on_text_change)

        # Auto-detect: if tagged input, switch to Decode automatically when focusing output
        self.input_txt.bind("<FocusOut>", lambda e: self._auto_select_decoder())

        # Apply font size
        self._apply_font()

    def _rebuild_params(self):
        for w in self.params_frame.winfo_children():
            w.destroy()
        self.param_vars.clear()
        ce = self.name_to_entry[self.cipher_var.get()]
        if not ce.params:
            ttk.Label(self.params_frame, text="(No parameters)").pack(side="left")
            return
        for p in ce.params:
            ttk.Label(self.params_frame, text=p.label+":").pack(side="left", padx=(0,3))
            var = tk.StringVar(value=p.default)
            ent = ttk.Entry(self.params_frame, textvariable=var, width=max(8, len(p.default)+2))
            ent.pack(side="left", padx=(0,12))
            if p.tip:
                ent.tooltip = p.tip
            self.param_vars[p.name] = var

    def _bind_keys(self):
        self.root.bind("<Control-e>", lambda e: self._set_mode_and_run("encode"))
        self.root.bind("<Control-d>", lambda e: self._set_mode_and_run("decode"))
        self.root.bind("<Control-g>", lambda e: self.smart_guess())
        self.root.bind("<Control-b>", lambda e: self.brute_force())
        self.root.bind("<Control-l>", lambda e: self.clear_both())
        self.root.bind("<Control-i>", lambda e: self.swap_io())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_output())

    # --- Theme / State

    def _apply_font(self):
        f = ("Consolas", self.font_size)
        self.input_txt.configure(font=f)
        self.output_txt.configure(font=f)

    def _apply_theme(self):
        if self.dark:
            bg = "#0f1116"; fg = "#e6edf3"; acc = "#1f6feb"
            self.root.configure(bg=bg)
            for w in (self.input_txt, self.output_txt):
                w.configure(bg="#161b22", fg=fg, insertbackground=fg)
            style = ttk.Style()
            try:
                style.theme_use('clam')
            except:
                pass
            style.configure(".", background=bg, foreground=fg)
            style.configure("TButton", background="#21262d", foreground=fg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("TFrame", background=bg)
            style.configure("TEntry", fieldbackground="#161b22", foreground=fg)
            self.status.configure(background="#0b0d12", foreground=fg)
        else:
            # system default
            for w in (self.input_txt, self.output_txt):
                w.configure(bg="white", fg="black", insertbackground="black")
            style = ttk.Style()
            style.theme_use(style.theme_use())
            self.status.configure(background="", foreground="")

    def toggle_dark(self):
        self.dark = not self.dark
        self._apply_theme()
        self._save_state()

    def adjust_font(self, delta: int):
        self.font_size = max(8, min(24, self.font_size + delta))
        self._apply_font()
        self._save_state()

    def _state_dict(self) -> Dict[str, object]:
        return {
            "cipher": self.cipher_var.get(),
            "mode": self.mode_var.get(),
            "dark": self.dark,
            "font_size": self.font_size,
            "params": {k:v.get() for k,v in self.param_vars.items()},
            "input": self.input_txt.get("1.0", "end-1c"),
            "output": self.output_txt.get("1.0", "end-1c"),
        }

    def _apply_state(self, st: Dict[str, object]):
        if not st: return
        if "cipher" in st and st["cipher"] in self.name_to_entry:
            self.cipher_var.set(st["cipher"]); self._rebuild_params()
        if "mode" in st:
            self.mode_var.set(st["mode"])
        self.dark = bool(st.get("dark", False))
        self.font_size = int(st.get("font_size", 12))
        if "params" in st:
            for k,v in st["params"].items():
                if k in self.param_vars:
                    self.param_vars[k].set(v)
        if "input" in st:
            self.input_txt.delete("1.0","end"); self.input_txt.insert("1.0", st["input"])
        if "output" in st:
            self.output_txt.delete("1.0","end"); self.output_txt.insert("1.0", st["output"])

    def _save_state(self):
        try:
            with open(APP_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._state_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            # non-fatal
            pass

    def _load_state(self):
        try:
            if os.path.exists(APP_STATE_FILE):
                with open(APP_STATE_FILE, "r", encoding="utf-8") as f:
                    st = json.load(f)
                    self._apply_state(st)
        except Exception:
            pass

    # --- Actions

    def _read_params(self) -> Dict[str,str]:
        out = {}
        for k,var in self.param_vars.items():
            out[k] = var.get()
        return out

    def run_current(self):
        name = self.cipher_var.get()
        text = self.input_txt.get("1.0", "end-1c")
        params = self._read_params()
        t0 = time.time()
        try:
            if self.mode_var.get() == "encode":
                out = call_encode(name, text, params)
            else:
                out = call_decode(name, text, params)
        except Exception as e:
            out = f"Err:{e}"
        dt = (time.time()-t0)*1000
        self.output_txt.delete("1.0","end")
        self.output_txt.insert("1.0", out)
        self._status_ok(f"{name} {self.mode_var.get()} in {dt:.1f} ms")
        self._save_state()

    def _set_mode_and_run(self, mode: str):
        self.mode_var.set(mode)
        self.run_current()

    def smart_guess(self):
        text = self.input_txt.get("1.0", "end-1c")
        ranked = SmartGuess(text)
        self._show_ranked_window("Smart Guess — Top Candidates", ranked)

    def brute_force(self):
        text = self.input_txt.get("1.0", "end-1c")
        fams = self._ask_families()
        if fams is None: return
        ranked = BruteForce(text, fams)
        self._show_ranked_window("Brute Force — Top Candidates", ranked)

    def _ask_families(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Choose families")
        dlg.geometry("320x260")
        fams = [("caesar","Caesar"), ("affine","Affine"), ("railfence","Rail Fence"), ("vigenere-short","Vigenère (short keys)"), ("xor-hex","XOR hex (single byte)")]
        vars = []
        for key, label in fams:
            v = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(dlg, text=label, variable=v)
            chk.pack(anchor="w", padx=10, pady=4)
            vars.append((key,v))
        out = []
        def ok():
            out.clear()
            out.extend([k for k,v in vars if v.get()])
            dlg.destroy()
        ttk.Button(dlg, text="Run", command=ok).pack(pady=8)
        dlg.grab_set(); self.root.wait_window(dlg)
        return out if out else None

    def _show_ranked_window(self, title: str, ranked: List[Tuple[str,str,float]]):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("900x500")
        columns = ("rank","label","score","preview")
        tree = ttk.Treeview(win, columns=columns, show="headings")
        for c, w in zip(columns, (60, 260, 100, 420)):
            tree.heading(c, text=c.capitalize())
            tree.column(c, width=w, anchor="w")
        tree.pack(fill="both", expand=True)

        for i,(label, pt, sc) in enumerate(ranked, 1):
            preview = pt.replace("\n"," ")[:160]
            tree.insert("", "end", values=(i, label, f"{sc:.2f}", preview))

        def use_selection():
            sel = tree.selection()
            if not sel: return
            vals = tree.item(sel[0], "values")
            rank_idx = int(vals[0]) - 1
            _, pt, _ = ranked[rank_idx]
            self.output_txt.delete("1.0","end")
            self.output_txt.insert("1.0", pt)
            self._status_ok(f"Loaded candidate #{rank_idx+1} into Output")

        btns = ttk.Frame(win); btns.pack(fill="x")
        ttk.Button(btns, text="Use Selected → Output", command=use_selection).pack(side="left", padx=6, pady=6)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right", padx=6, pady=6)

    def copy_output(self):
        text = self.output_txt.get("1.0","end-1c")
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        self._status_ok("Output copied")

    def paste_input(self):
        try:
            text = self.root.clipboard_get()
        except Exception:
            text = ""
        self.input_txt.delete("1.0","end"); self.input_txt.insert("1.0", text)
        self._status_ok("Pasted to input")

    def swap_io(self):
        inp = self.input_txt.get("1.0","end-1c")
        out = self.output_txt.get("1.0","end-1c")
        self.input_txt.delete("1.0","end"); self.input_txt.insert("1.0", out)
        self.output_txt.delete("1.0","end"); self.output_txt.insert("1.0", inp)
        self._status_ok("Swapped input/output")
        self._save_state()

    def clear_both(self):
        self.input_txt.delete("1.0","end")
        self.output_txt.delete("1.0","end")
        self._status_ok("Cleared")

    def open_file(self):
        try:
            from tkinter import filedialog
            path = filedialog.askopenfilename(title="Open text", filetypes=[("Text files","*.txt *.log *.cfg *.json *.md"), ("All files","*.*")])
            if not path: return
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            self.input_txt.delete("1.0","end"); self.input_txt.insert("1.0", data)
            self._status_ok(f"Opened {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Open Failed", str(e))

    def save_output(self):
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(title="Save output", defaultextension=".txt", filetypes=[("Text files","*.txt"), ("All files","*.*")])
            if not path: return
            data = self.output_txt.get("1.0","end-1c")
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            self._status_ok(f"Saved {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Save Failed", str(e))

    def show_about(self):
        messagebox.showinfo("About", "All-The-Ciphers — full suite with Smart Guess & Brute Force\n© You + ChatGPT\nHotkeys: Ctrl+E / Ctrl+D / Ctrl+G / Ctrl+B / Ctrl+I / Ctrl+L / Ctrl+O / Ctrl+S")

    # --- Helpers

    def _status_ok(self, msg: str):
        self.status.config(text=msg)

    def _on_text_change(self, event):
        widget = event.widget
        widget.edit_modified(False)
        self._update_status()

    def _update_status(self):
        a = len(self.input_txt.get("1.0","end-1c"))
        b = len(self.output_txt.get("1.0","end-1c"))
        self.status.config(text=f"Input: {a} chars    Output: {b} chars")

    def _auto_select_decoder(self):
        # If input starts with known tag, flip to decode and pick the right cipher
        s = self.input_txt.get("1.0","end-1c").lstrip()
        tag_map = {
            "[HOMO]": "Homophonic",
            "[EMOJI]": "Emoji Substitution",
            "[WS]": "Whitespace Encoding",
            "[FM]": "Fractionated Morse",
            "[MORSE]": "Morse",
            "[PIG]": "Pigpen",
            "[PL]": "Pig Latin",
            "[SEM]": "Semaphore",
            "[LEET]": "Leet Speak",
        }
        for tag, name in tag_map.items():
            if s.startswith(tag) and name in self.name_to_entry:
                self.cipher_var.set(name)
                self._rebuild_params()
                self.mode_var.set("decode")
                self._status_ok(f"Detected tag {tag} → {name} (Decode)")
                return

# -----------------------------------------------------------------------------

def launch_gui():
    if tk is None:
        print("Tkinter is not available on this system.")
        sys.exit(1)
    root = tk.Tk()
    CipherGUI(root)
    root.mainloop()

# =============================================================================
# Self-test (light) — optional quick sanity on a few ciphers
# =============================================================================

def _selftest():
    tests = [
        ("Caesar", "encode", {"shift":"3"}, "HELLO WORLD", "KHOOR ZRUOG"),
        ("ROT13", "encode", {}, "HELLO", "URYYB"),
        ("Atbash", "encode", {}, "HELLO", "SVOOL"),
        ("Vigenere", "encode", {"key":"LEMON"}, "ATTACKATDAWN", "LXFOPVEFRNHR"),
        ("Rail Fence", "encode", {"rails":"3"}, "WEAREDISCOVEREDFLEEATONCE", "WECRLTEERDSOEEFEAOCAIVDEN"),
        ("ADFGX", "encode", {"square_key":"KEYWORD", "route_key":"CIPHER"}, "ATTACKATDAWN", None),
        ("Baconian", "encode", {}, "HELLO", None),
        ("Playfair", "encode", {"key":"KEYWORD"}, "HELLOWORLD", None),
        ("Emoji Substitution", "encode", {"seed":"SEED"}, "hello world", None),
        ("Whitespace Encoding", "encode", {}, "Hi", None),
        ("Fractionated Morse", "encode", {"key":"KEYABCDFGHIJLMNOPQRSTUVWXZ"}, "SOS", None),
    ]
    ok = 0
    for name, mode, params, pt, expect in tests:
        try:
            if mode=="encode":
                ct = call_encode(name, pt, params)
                if expect is None or ct.startswith(expect) or expect in ct:
                    ok += 1
            else:
                out = call_decode(name, pt, params)
                if expect is None or out == expect:
                    ok += 1
        except Exception as e:
            pass
    return ok, len(tests)

# =============================================================================
# ANALYSIS & SCORING EXTENSIONS
# Frequency graphs, Kasiski/Friedman aids, N-gram scoring sliders
# (Safe to drop before the main guard; this patches the existing GUI.)
# =============================================================================

from collections import Counter, defaultdict
import math

# --- Optional plotting (embedded in Tk) --------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")  # headless-safe; we'll embed via FigureCanvasTkAgg
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    _HAS_MPL = True
except Exception:
    _HAS_MPL = False

# =============================================================================
# N-GRAM SCORING (good English model, fast, tunable)
# =============================================================================

# Unigram probabilities (roughly English letter freq, A-Z only; normalized)
_UNI = {
    'E':0.12702,'T':0.09056,'A':0.08167,'O':0.07507,'I':0.06966,'N':0.06749,
    'S':0.06327,'H':0.06094,'R':0.05987,'D':0.04253,'L':0.04025,'C':0.02782,
    'U':0.02758,'M':0.02406,'W':0.02360,'F':0.02228,'G':0.02015,'Y':0.01974,
    'P':0.01929,'B':0.01492,'V':0.00978,'K':0.00772,'J':0.00153,'X':0.00150,
    'Q':0.00095,'Z':0.00074
}
# Bigram: a compact list of common ones (rest backoff to floor)
# Values are *relative*; we turn them into log-probs with smoothing.
_BI = {
    "TH":1.52,"HE":1.28,"IN":0.94,"ER":0.94,"AN":0.82,"RE":0.68,"ND":0.63,
    "AT":0.59,"ON":0.57,"NT":0.56,"HA":0.56,"ES":0.56,"ST":0.55,"EN":0.55,
    "ED":0.53,"TO":0.52,"IT":0.50,"OU":0.50,"EA":0.47,"HI":0.46,"IS":0.46,
    "OR":0.43,"TI":0.34,"AS":0.33,"TE":0.27,"ET":0.19,"NG":0.18,"OF":0.16
}
# Trigram: top frequent in English
_TRI = {
    "THE":1.81,"AND":0.73,"ING":0.72,"ION":0.42,"ENT":0.42,"HER":0.36,"FOR":0.34,
    "THA":0.33,"NTH":0.33,"INT":0.32,"ERE":0.31,"TIO":0.31,"TER":0.30,"EST":0.28,
    "ERS":0.28,"ATI":0.26,"HAT":0.26,"ATE":0.25,"ALL":0.25,"ETH":0.24,"HES":0.24
}

# Defaults: reasonably strong weight on tri/bi, lighter on uni.
_NGRAM_WEIGHTS = {1: 0.6, 2: 1.0, 3: 1.6}
# Floor log-prob for unseen n-grams. (Raise toward  -6  to be less penalizing.)
_NGRAM_FLOOR_LOGP = -8.5

# Build log tables (once). Unigram gets true log probs; bi/tri are scaled then log.
def _logp_tables():
    uni = {k: math.log(v) for k, v in _UNI.items()}
    # normalize BI/TRI rough counts -> probs (sum to 1 of listed items)
    def _to_logp(d):
        s = sum(d.values())
        return {k: math.log(v/s) for k,v in d.items()}
    return uni, _to_logp(_BI), _to_logp(_TRI)
_LOG_UNI, _LOG_BI, _LOG_TRI = _logp_tables()

def set_ngram_weights(w1: float = None, w2: float = None, w3: float = None, floor_logp: float = None):
    """Update n-gram weights or floor. Any None leaves current value."""
    global _NGRAM_WEIGHTS, _NGRAM_FLOOR_LOGP
    if w1 is not None: _NGRAM_WEIGHTS[1] = float(w1)
    if w2 is not None: _NGRAM_WEIGHTS[2] = float(w2)
    if w3 is not None: _NGRAM_WEIGHTS[3] = float(w3)
    if floor_logp is not None: _NGRAM_FLOOR_LOGP = float(floor_logp)

def get_ngram_weights():
    return dict(_NGRAM_WEIGHTS), _NGRAM_FLOOR_LOGP

def _letters_only(s: str) -> str:
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

def score_english_ngram(text: str) -> float:
    """Return a *higher is better* score based on uni/bi/tri log-prob sums."""
    s = _letters_only(text)
    n = len(s)
    if n == 0:
        return -1e9
    w1, w2, w3 = _NGRAM_WEIGHTS.get(1,1.0), _NGRAM_WEIGHTS.get(2,1.0), _NGRAM_WEIGHTS.get(3,1.0)

    # Unigram score
    su = 0.0
    for ch in s:
        su += _LOG_UNI.get(ch, _NGRAM_FLOOR_LOGP)

    # Bigram
    sb = 0.0
    for i in range(n-1):
        bg = s[i:i+2]
        sb += _LOG_BI.get(bg, _NGRAM_FLOOR_LOGP)

    # Trigram
    st = 0.0
    for i in range(n-2):
        tg = s[i:i+3]
        st += _LOG_TRI.get(tg, _NGRAM_FLOOR_LOGP)

    # Combine (weights)
    return w1*su + w2*sb + w3*st

# Try to make existing guessers use this automatically (covers common names).
globals()['ENGLISH_SCORE_FN'] = score_english_ngram
globals()['english_score']   = score_english_ngram
globals()['score_english']   = score_english_ngram
globals()['ScoreEnglish']    = score_english_ngram

# =============================================================================
# IC / Friedman; Kasiski examination
# =============================================================================

def index_of_coincidence(text: str) -> float:
    s = _letters_only(text)
    N = len(s)
    if N < 2: return 0.0
    counts = Counter(s)
    num = sum(c*(c-1) for c in counts.values())
    den = N*(N-1)
    return num/den if den else 0.0

def friedman_estimate_keylen(text: str) -> float:
    """Classic Friedman estimate for Vigenère key length (float)."""
    s = _letters_only(text)
    N = len(s)
    if N < 2:
        return 1.0
    IC = index_of_coincidence(s)
    # Using standard constants for English
    K0 = 0.0385
    K1 = 0.065
    if IC <= 0: return 1.0
    num = (K1 - K0) * N
    den = (N - 1) * IC - K0*N + K1
    if den <= 0:
        return 1.0
    return num/den

def split_cosets(s: str, m: int) -> list[str]:
    return ["".join(s[i] for i in range(j, len(s), m)) for j in range(m)]

def friedman_by_keylen(text: str, max_m: int = 20) -> list[tuple[int,float]]:
    s = _letters_only(text)
    out = []
    for m in range(1, max_m+1):
        cosets = split_cosets(s, m)
        ics = [index_of_coincidence(c) for c in cosets if len(c) > 1]
        avg_ic = sum(ics)/len(ics) if ics else 0.0
        out.append((m, avg_ic))
    # Sort by how close to ~0.065; could also rank by avg_ic desc
    out.sort(key=lambda t: abs(0.065 - t[1]))
    return out

def kasiski_examination(text: str, ngram_min: int = 3, ngram_max: int = 5, max_key: int = 20):
    """
    Return:
      repeats: list of (ngram, positions, distances)
      factors: Counter of factor frequencies (2..max_key)
    """
    s = _letters_only(text)
    pos_map = defaultdict(list)
    for n in range(ngram_min, ngram_max+1):
        for i in range(0, len(s)-n+1):
            gram = s[i:i+n]
            pos_map[gram].append(i)
    repeats = []
    for gram, pos in pos_map.items():
        if len(pos) >= 2:
            dists = []
            for i in range(1, len(pos)):
                dists.append(pos[i] - pos[i-1])
            if dists:
                repeats.append((gram, pos, dists))
    # Factor histogram
    fac = Counter()
    for _,_,dists in repeats:
        for d in dists:
            for k in range(2, max_key+1):
                if d % k == 0:
                    fac[k] += 1
    return repeats, fac

# =============================================================================
# GUI PATCHES: Tools menu, windows, sliders, and SmartGuess/BruteForce sync
# =============================================================================

def _format_pct(v: float) -> str:
    return f"{v*100:.2f}%"

def _mk_table(parent, columns, widths):
    tree = ttk.Treeview(parent, columns=columns, show="headings")
    for col, w in zip(columns, widths):
        tree.heading(col, text=col)
        tree.column(col, width=w, anchor="w")
    return tree

def _ngram_freqs(s: str):
    s = _letters_only(s)
    uni = Counter(s)
    bi = Counter(s[i:i+2] for i in range(len(s)-1))
    tri = Counter(s[i:i+3] for i in range(len(s)-2))
    return uni, bi, tri, len(s)

def _plot_bar(ax, labels, values, title):
    ax.clear()
    ax.bar(labels, values)
    ax.set_title(title)
    ax.set_ylim(0, max(values+[1]))
    ax.grid(True, axis="y", alpha=0.3)

def _install_tools_menu(self):
    try:
        m = self.root.nametowidget(self.root['menu'])
    except Exception:
        return
    tools = tk.Menu(m, tearoff=0)
    tools.add_command(label="Frequencies… (Ctrl+F)", command=self.open_freq_window)
    tools.add_command(label="Kasiski/Friedman… (Ctrl+K)", command=self.open_kasiski_window)
    tools.add_separator()
    tools.add_command(label="Scoring Weights… (Ctrl+T)", command=self.open_scoring_window)
    # NEW:
    tools.add_separator()
    tools.add_command(label="Test Bench…", command=lambda: _open_test_bench(self))
    m.add_cascade(label="Tools", menu=tools)


def _gui_open_freq_window(self):
    win = tk.Toplevel(self.root)
    win.title("Frequency Analysis")
    win.geometry("920x640")

    top = ttk.Frame(win); top.pack(fill="x", padx=8, pady=8)
    ttk.Label(top, text="Source:").pack(side="left")
    src = tk.StringVar(value="Input")
    ttk.Radiobutton(top, text="Input", variable=src, value="Input").pack(side="left", padx=6)
    ttk.Radiobutton(top, text="Output", variable=src, value="Output").pack(side="left", padx=6)

    if not _HAS_MPL:
        ttk.Label(win, text="matplotlib not available. Install it to see charts.").pack(pady=16)
        return

    fig = Figure(figsize=(9.2, 4.8))
    ax1 = fig.add_subplot(3,1,1)
    ax2 = fig.add_subplot(3,1,2)
    ax3 = fig.add_subplot(3,1,3)

    canvas = FigureCanvasTkAgg(fig, master=win)
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

    info = tk.Text(win, height=6, wrap="word"); info.pack(fill="x", padx=8, pady=(0,8))

    def refresh():
        text = self.input_txt.get("1.0","end-1c") if src.get()=="Input" else self.output_txt.get("1.0","end-1c")
        uni, bi, tri, N = _ngram_freqs(text)

        # Normalize to percentages for unigrams
        letters = [chr(i) for i in range(ord('A'), ord('Z')+1)]
        vals = [100.0*uni.get(ch,0)/max(1,N) for ch in letters]

        # Top 20 bigrams/trigrams
        top_bi = bi.most_common(20)
        top_tri = tri.most_common(20)
        bi_labels = [k for k,_ in top_bi] or ["(none)"]
        bi_vals   = [v for _,v in top_bi] or [0]
        tri_labels = [k for k,_ in top_tri] or ["(none)"]
        tri_vals   = [v for _,v in top_tri] or [0]

        _plot_bar(ax1, letters, vals, f"Letters (%) — N={N}")
        _plot_bar(ax2, bi_labels, bi_vals, "Top 20 Bigrams (counts)")
        _plot_bar(ax3, tri_labels, tri_vals, "Top 20 Trigrams (counts)")
        fig.tight_layout()
        canvas.draw()

        ic = index_of_coincidence(text)
        est = friedman_estimate_keylen(text)
        info.delete("1.0","end")
        info.insert("1.0", f"Index of Coincidence: {ic:.5f}\nFriedman Estimated Key Length: {est:.2f}\n")
        # Add a quick English/uniform ref
        info.insert("end", "Reference: English IC≈0.065, Uniform IC≈0.0385\n")

    btn = ttk.Button(top, text="Analyze", command=refresh)
    btn.pack(side="right")
    refresh()  # initial

def _gui_open_kasiski_window(self):
    win = tk.Toplevel(self.root)
    win.title("Kasiski + Friedman Aids")
    win.geometry("960x640")

    top = ttk.Frame(win); top.pack(fill="x", padx=8, pady=8)
    ttk.Label(top, text="Analyze from:").pack(side="left")
    src = tk.StringVar(value="Input")
    ttk.Radiobutton(top, text="Input", variable=src, value="Input").pack(side="left", padx=6)
    ttk.Radiobutton(top, text="Output", variable=src, value="Output").pack(side="left", padx=6)

    nmin = tk.IntVar(value=3); nmax = tk.IntVar(value=5); kmax = tk.IntVar(value=20)
    for lbl, var in (("n-min", nmin),("n-max", nmax),("max key", kmax)):
        ttk.Label(top, text=f"{lbl}:").pack(side="left", padx=(12,3))
        ttk.Entry(top, textvariable=var, width=4).pack(side="left")

    btn = ttk.Button(top, text="Run", command=lambda: run())
    btn.pack(side="right")

    # Tables
    mid = ttk.Frame(win); mid.pack(fill="both", expand=True, padx=8, pady=8)
    left = ttk.Frame(mid); left.pack(side="left", fill="both", expand=True)
    right = ttk.Frame(mid); right.pack(side="left", fill="both", expand=True, padx=(8,0))

    t_rep = _mk_table(left, ("ngram","positions","distances"), (160,220,220))
    t_rep.pack(fill="both", expand=True)
    ttk.Label(left, text="Repeating n-grams (positions, consecutive distances)").pack(anchor="w", pady=(4,0))

    t_fac = _mk_table(right, ("key_len","votes"), (120,100))
    t_fac.pack(fill="both", expand=True)
    ttk.Label(right, text="Factor votes (Kasiski)").pack(anchor="w", pady=(4,0))

    # Friedman detailed
    bot = ttk.Frame(win); bot.pack(fill="x", padx=8, pady=(0,8))
    t_fr = _mk_table(bot, ("key_len","avg_IC","Δ|IC-0.065|"), (120,120,140))
    t_fr.pack(fill="x")
    ttk.Label(win, text="Friedman by key length (sorted by closeness to English IC)").pack(anchor="w", padx=8)

    def run():
        text = self.input_txt.get("1.0","end-1c") if src.get()=="Input" else self.output_txt.get("1.0","end-1c")
        repeats, fac = kasiski_examination(text, ngram_min=nmin.get(), ngram_max=nmax.get(), max_key=kmax.get())
        # Fill repeats (limit for sanity)
        t_rep.delete(*t_rep.get_children())
        for gram, pos, dists in sorted(repeats, key=lambda r: (-len(r[2]), r[0]))[:80]:
            t_rep.insert("", "end", values=(gram, ", ".join(map(str,pos[:10])) + (" ..." if len(pos)>10 else ""),
                                            ", ".join(map(str,dists[:10])) + (" ..." if len(dists)>10 else "")))

        t_fac.delete(*t_fac.get_children())
        # Show top by votes
        for k, v in fac.most_common(20):
            t_fac.insert("", "end", values=(k, v))

        # Friedman sweep
        t_fr.delete(*t_fr.get_children())
        fr = friedman_by_keylen(text, max_m=kmax.get())
        for m, ic in fr[:25]:
            t_fr.insert("", "end", values=(m, f"{ic:.5f}", f"{abs(0.065-ic):.5f}"))

    run()

def _gui_open_scoring_window(self):
    win = tk.Toplevel(self.root)
    win.title("Scoring Weights (Smart Guess & Brute Force)")
    win.geometry("520x320")

    cur_w, cur_floor = get_ngram_weights()

    frm = ttk.Frame(win); frm.pack(fill="both", expand=True, padx=12, pady=12)

    ttk.Label(frm, text="Unigram weight").grid(row=0, column=0, sticky="w")
    s1 = tk.DoubleVar(value=cur_w.get(1,0.6))
    w1 = ttk.Scale(frm, from_=0.0, to=3.0, orient="horizontal", variable=s1)
    w1.grid(row=0, column=1, sticky="ew", padx=8)

    ttk.Label(frm, text="Bigram weight").grid(row=1, column=0, sticky="w")
    s2 = tk.DoubleVar(value=cur_w.get(2,1.0))
    w2 = ttk.Scale(frm, from_=0.0, to=4.0, orient="horizontal", variable=s2)
    w2.grid(row=1, column=1, sticky="ew", padx=8)

    ttk.Label(frm, text="Trigram weight").grid(row=2, column=0, sticky="w")
    s3 = tk.DoubleVar(value=cur_w.get(3,1.6))
    w3 = ttk.Scale(frm, from_=0.0, to=5.0, orient="horizontal", variable=s3)
    w3.grid(row=2, column=1, sticky="ew", padx=8)

    ttk.Label(frm, text="Floor log-prob (unseen grams)").grid(row=3, column=0, sticky="w")
    sf = tk.DoubleVar(value=cur_floor)
    wf = ttk.Scale(frm, from_=-12.0, to=-4.0, orient="horizontal", variable=sf)
    wf.grid(row=3, column=1, sticky="ew", padx=8)

    frm.columnconfigure(1, weight=1)

    out = ttk.Label(frm, text="")
    out.grid(row=4, column=0, columnspan=2, pady=(12,0), sticky="w")

    def apply_now():
        set_ngram_weights(s1.get(), s2.get(), s3.get(), sf.get())
        # Make sure Smart Guess / Brute Force will pick the scorer
        globals()['ENGLISH_SCORE_FN'] = score_english_ngram
        globals()['english_score']   = score_english_ngram
        globals()['score_english']   = score_english_ngram
        globals()['ScoreEnglish']    = score_english_ngram
        out.config(text=f"Applied: unigram={s1.get():.2f}, bigram={s2.get():.2f}, trigram={s3.get():.2f}, floor={sf.get():.2f}")
        try:
            # persist into the main app state
            self._save_state()
        except Exception:
            pass

    btns = ttk.Frame(win); btns.pack(fill="x", padx=12, pady=(0,12))
    ttk.Button(btns, text="Apply", command=apply_now).pack(side="left")
    ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

# ---- Patch CipherGUI: add menu, bind keys, extend state persistence ----------

def _patch_bind_keys(self):
    # call original
    try:
        self.__class__._bind_keys_original(self)
    except AttributeError:
        pass
    # New bindings
    self.root.bind("<Control-f>", lambda e: self.open_freq_window())
    self.root.bind("<Control-F>", lambda e: self.open_freq_window())
    self.root.bind("<Control-k>", lambda e: self.open_kasiski_window())
    self.root.bind("<Control-K>", lambda e: self.open_kasiski_window())
    self.root.bind("<Control-t>", lambda e: self.open_scoring_window())
    self.root.bind("<Control-T>", lambda e: self.open_scoring_window())

def _patch_build_menu(self):
    # call original
    try:
        self.__class__._build_menu_original(self)
    except AttributeError:
        pass
    _install_tools_menu(self)

def _state_dict_aug(self):
    # merge into base state dict
    try:
        base = self.__class__._state_dict_original(self)
    except AttributeError:
        base = {}
    w, floor = get_ngram_weights()
    base["ngram_weights"] = w
    base["ngram_floor"] = floor
    return base

def _apply_state_aug(self, st):
    try:
        self.__class__._apply_state_original(self, st)
    except AttributeError:
        pass
    try:
        w = st.get("ngram_weights", None)
        floor = st.get("ngram_floor", None)
        if w:
            set_ngram_weights(w.get(1), w.get(2), w.get(3))
        if floor is not None:
            set_ngram_weights(floor_logp=floor)
    except Exception:
        pass

def _smart_guess_wrap(self):
    # Ensure scorer is active before delegating
    globals()['ENGLISH_SCORE_FN'] = score_english_ngram
    globals()['english_score']   = score_english_ngram
    globals()['score_english']   = score_english_ngram
    globals()['ScoreEnglish']    = score_english_ngram
    # Call the original method (aliased)
    return self.__class__.smart_guess_original(self)

def _brute_force_wrap(self):
    globals()['ENGLISH_SCORE_FN'] = score_english_ngram
    globals()['english_score']   = score_english_ngram
    globals()['score_english']   = score_english_ngram
    globals()['ScoreEnglish']    = score_english_ngram
    return self.__class__.brute_force_original(self)

def install_analysis_extensions():
    """Patch the existing CipherGUI class with new menus, windows, and state."""
    if 'CipherGUI' not in globals():
        return  # nothing to patch yet

    # Attach new window openers
    CipherGUI.open_freq_window = _gui_open_freq_window
    CipherGUI.open_kasiski_window = _gui_open_kasiski_window
    CipherGUI.open_scoring_window = _gui_open_scoring_window

    # Keep originals and patch build_menu/bind_keys/state save+load
    if not hasattr(CipherGUI, "_build_menu_original"):
        CipherGUI._build_menu_original = CipherGUI._build_menu
        CipherGUI._bind_keys_original  = CipherGUI._bind_keys
        CipherGUI._state_dict_original = CipherGUI._state_dict
        CipherGUI._apply_state_original = CipherGUI._apply_state
        CipherGUI.smart_guess_original = CipherGUI.smart_guess
        CipherGUI.brute_force_original = CipherGUI.brute_force

        CipherGUI._build_menu = _patch_build_menu
        CipherGUI._bind_keys  = _patch_bind_keys
        CipherGUI._state_dict = _state_dict_aug
        CipherGUI._apply_state = _apply_state_aug
        CipherGUI.smart_guess = _smart_guess_wrap
        CipherGUI.brute_force = _brute_force_wrap

# Call immediately so main GUI uses the patched version
install_analysis_extensions()

# =============================================================================
# Entrypoint
# =============================================================================
# =============================================================================
# UNIVERSAL KEY-GUESSERS, IOC HEATMAP, RANKED CANDIDATE CAPTURE & EXPORT
# =============================================================================
# This block augments the previously-installed analysis extensions, wiring
# Smart Guess and Brute Force to:
#  - Generate/collect ranked candidates across many cipher families
#  - Display an IOC heatmap and export CSV of candidate lists
#  - Auto-suggest Vigenère/Autokey key lengths and feed them to the GUI
#
# Drop this in after the earlier "Analysis & Scoring Extensions" section.
# =============================================================================
# =============================================================================
# TIME-BOUNDED MONOALPHABETIC SUBSTITUTION + OPTIONS DIALOGS + PRESETS
# Extra guessers (ROT13/47, Playfair(seeded), ADFGX/ADFGVX(heuristic))
# =============================================================================

import math, random, time, json
from collections import Counter
try:
    from tkinter import filedialog as fd
except Exception:
    fd = None

# We will re-point the composite scorer here to allow preset tuning
SCORING_WEIGHTS = {
    "ngram": 1.00,   # main quadgram model (via existing score_english_ngram if available)
    "chi2":  0.20,   # letter-frequency chi^2 fallback
    "word":  0.15,   # common-words presence
    "ioc":   0.05,   # plaintext IC closeness to 0.066
}

COMMON_WORDS = [
    "THE","AND","THAT","HAVE","FOR","NOT","WITH","YOU","THIS","BUT","FROM",
    "THEY","SAY","HER","SHE","OR","WILL","MY","ONE","ALL","WOULD","THERE",
    "THEIR","WHAT","SO","UP","OUT","IF","ABOUT","WHO","GET","WHICH","GO",
    "ME","WHEN","MAKE","CAN","LIKE","TIME","NO","JUST","HIM","KNOW","TAKE",
    "PEOPLE","INTO","YEAR","YOUR","GOOD"
]

# --- If an earlier _score_pt exists, keep a reference --------------------------------
try:
    _old_score_pt = _score_pt
except Exception:
    _old_score_pt = None

def _chi2_score(pt_alpha: str) -> float:
    if not pt_alpha: return -1e9
    freq = Counter(pt_alpha)
    N = len(pt_alpha)
    expected = {
        'E': 12.702, 'T': 9.056, 'A': 8.167, 'O': 7.507, 'I': 6.966, 'N': 6.749,
        'S': 6.327, 'H': 6.094, 'R': 5.987, 'D': 4.253, 'L': 4.025, 'C': 2.782,
        'U': 2.758, 'M': 2.406, 'W': 2.360, 'F': 2.228, 'G': 2.015, 'Y': 1.974,
        'P': 1.929, 'B': 1.492, 'V': 0.978, 'K': 0.772, 'J': 0.153, 'X': 0.150,
        'Q': 0.095, 'Z': 0.074
    }
    chi = 0.0
    for ch in ALPHA:
        o = freq.get(ch,0) * 100.0 / N
        e = expected[ch]
        if e > 0:
            diff = o - e
            chi += (diff*diff)/e
    return -chi

def _ioc_closeness(pt_alpha: str) -> float:
    # reward closeness to typical English (~0.066)
    try:
        ic = index_of_coincidence(pt_alpha)
    except Exception:
        # simple IC
        N = len(pt_alpha)
        if N <= 1: return -1.0
        counts = Counter(pt_alpha)
        num = sum(v*(v-1) for v in counts.values())
        den = N*(N-1)
        ic = num/den if den else 0.0
    return -abs(0.066 - ic)*50.0

def _word_score(pt_upper: str) -> float:
    s = 0.0
    U = " " + pt_upper + " "
    for w in COMMON_WORDS:
        # crude boundaries to avoid counting sub-words in the middle
        c = U.count(" " + w + " ")
        if c:
            s += math.log(1+c) * 8.0
    return s

def _score_pt(pt: str) -> float:
    # Composite scoring under weights, falling back to old scorer if present.
    try:
        pt_upper = pt.upper()
        pt_alpha = _clean_alpha(pt_upper)
        total = 0.0
        if SCORING_WEIGHTS.get("ngram",0) > 0:
            try:
                base = score_english_ngram(pt)  # provided by the main app
            except Exception:
                base = 0.0
            total += SCORING_WEIGHTS["ngram"] * base
        if SCORING_WEIGHTS.get("chi2",0) > 0:
            total += SCORING_WEIGHTS["chi2"] * _chi2_score(pt_alpha)
        if SCORING_WEIGHTS.get("word",0) > 0:
            total += SCORING_WEIGHTS["word"] * _word_score(pt_upper)
        if SCORING_WEIGHTS.get("ioc",0) > 0:
            total += SCORING_WEIGHTS["ioc"] * _ioc_closeness(pt_alpha)
        # slight preference to printable/spacing balance
        bads = sum(1 for ch in pt if ord(ch) < 9)
        total -= bads * 5.0
        return total
    except Exception:
        if _old_score_pt:
            try: return _old_score_pt(pt)
            except Exception: pass
        return 0.0

# =============================================================================
# OPTIONS STORAGE + MINI DIALOGS
# =============================================================================
DEFAULT_OPTIONS = {
    "Caesar":     {"enabled": True},
    "Affine":     {"enabled": True},
    "Rail Fence": {"enabled": True, "min_rails": 2, "max_rails": 12},
    "Columnar":   {"enabled": True, "min_width": 2, "max_width": 14},
    "Vigenere":   {"enabled": True, "max_len": 16, "top_keys_per_len": 3},
    "Autokey":    {"enabled": True, "max_len": 12, "seed_try": 2},
    "Beaufort":   {"enabled": True, "max_len": 14},
    "Porta":      {"enabled": True, "max_len": 14},
    "ROT13":      {"enabled": True},
    "ROT47":      {"enabled": True},
    "Playfair":   {"enabled": True, "seed_words": "KEYWORD,SECRET,PASSWORD,MONARCHY,EXAMPLE", "max_variants": 8},
    "ADFGX":      {"enabled": True, "square_key": "KEYWORD", "min_klen": 4, "max_klen": 8},
    "ADFGVX":     {"enabled": True, "square_key": "KEYWORD", "min_klen": 4, "max_klen": 8},
    "Substitution": {"enabled": True, "time_sec": 6.0, "restarts": 8, "start_temp": 2.0, "end_temp": 0.05}
}

GUESSER_OPTIONS = json.loads(json.dumps(DEFAULT_OPTIONS))  # deep copy

SCORING_PRESETS = {
    "Balanced": {"ngram":1.00,"chi2":0.20,"word":0.15,"ioc":0.05},
    "Quadgram-heavy": {"ngram":1.20,"chi2":0.10,"word":0.10,"ioc":0.05},
    "Fast (chi² only)": {"ngram":0.00,"chi2":1.00,"word":0.00,"ioc":0.10},
    "Ciphertext-only": {"ngram":0.00,"chi2":0.35,"word":0.00,"ioc":0.25},
}

def apply_scoring_preset(name: str):
    if name not in SCORING_PRESETS:
        messagebox.showerror("Scoring Presets", f"Unknown preset: {name}")
        return
    SCORING_WEIGHTS.update(SCORING_PRESETS[name])

def save_preset_to_file():
    if fd is None:
        messagebox.showerror("Save Preset", "File dialog not available on this system.")
        return
    path = fd.asksaveasfilename(
        title="Save Scoring Preset",
        defaultextension=".json",
        filetypes=[("JSON", "*.json"), ("All files","*.*")]
    )
    if not path: return
    data = {"weights": SCORING_WEIGHTS, "options": GUESSER_OPTIONS}
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    messagebox.showinfo("Save Preset", f"Saved to:\n{path}")

def load_preset_from_file():
    if fd is None:
        messagebox.showerror("Load Preset", "File dialog not available on this system.")
        return
    path = fd.askopenfilename(
        title="Load Scoring Preset",
        filetypes=[("JSON", "*.json"), ("All files","*.*")]
    )
    if not path: return
    try:
        with open(path,"r",encoding="utf-8") as f:
            data = json.load(f)
        if "weights" in data:
            SCORING_WEIGHTS.update(data["weights"])
        if "options" in data:
            for k,v in data["options"].items():
                if k in GUESSER_OPTIONS and isinstance(v, dict):
                    GUESSER_OPTIONS[k].update(v)
        messagebox.showinfo("Load Preset", "Preset loaded.")
    except Exception as e:
        messagebox.showerror("Load Preset", f"Failed to load: {e}")

# Mini options dialog builder
def _open_options_dialog(self, family: str):
    if family not in GUESSER_OPTIONS:
        messagebox.showerror("Options", f"No options for '{family}'.")
        return
    opts = GUESSER_OPTIONS[family]
    win = tk.Toplevel(self.root)
    win.title(f"{family} Options")
    win.geometry("420x320")
    frm = ttk.Frame(win); frm.pack(fill="both", expand=True, padx=12, pady=12)

    entries = {}
    ttk.Label(frm, text=f"{family} Guesser Settings", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0,8))

    # enabled checkbox
    enabled_var = tk.BooleanVar(value=bool(opts.get("enabled", True)))
    ttk.Checkbutton(frm, text="Enable in Smart Guess / Brute Force", variable=enabled_var).pack(anchor="w", pady=(0,10))

    grid = ttk.Frame(frm); grid.pack(fill="x")
    r=0
    for k,v in opts.items():
        if k=="enabled": continue
        ttk.Label(grid, text=k).grid(row=r, column=0, sticky="w", padx=(0,8), pady=3)
        val = tk.StringVar(value=str(v))
        e = ttk.Entry(grid, width=24, textvariable=val)
        e.grid(row=r, column=1, sticky="w", pady=3)
        entries[k] = val
        r += 1

    btns = ttk.Frame(frm); btns.pack(fill="x", pady=(12,0))
    def save():
        opts["enabled"] = bool(enabled_var.get())
        for k,var in entries.items():
            raw = var.get().strip()
            # try numeric conversion when relevant
            if k.lower().endswith(("len","rails","width","klen","variants","restarts")):
                try: opts[k] = int(raw)
                except: pass
            elif "time" in k.lower() or "temp" in k.lower():
                try: opts[k] = float(raw)
                except: pass
            else:
                opts[k] = raw
        win.destroy()
    def defaults():
        GUESSER_OPTIONS[family] = json.loads(json.dumps(DEFAULT_OPTIONS[family]))
        win.destroy()
        _open_options_dialog(self, family)
    ttk.Button(btns, text="Restore Defaults", command=defaults).pack(side="left")
    ttk.Button(btns, text="Save", command=save).pack(side="right")

# attach menu items to open options
def _patch_options_menu(self):
    try:
        m = self.root.nametowidget(self.root['menu'])
    except Exception:
        return
    # Create or find "Analysis" cascade first (from previous patch)
    # Add "Options" and "Presets" submenus
    options_menu = tk.Menu(m, tearoff=0)
    for fam in ["Caesar","Affine","Rail Fence","Columnar","Vigenere","Autokey","Beaufort","Porta",
                "ROT13","ROT47","Playfair","ADFGX","ADFGVX","Substitution"]:
        options_menu.add_command(label=fam, command=lambda f=fam: _open_options_dialog(self, f))
    presets_menu = tk.Menu(m, tearoff=0)
    for name in SCORING_PRESETS.keys():
        presets_menu.add_command(label=name, command=lambda n=name: apply_scoring_preset(n))
    presets_menu.add_separator()
    presets_menu.add_command(label="Save Current…", command=save_preset_to_file)
    presets_menu.add_command(label="Load…", command=load_preset_from_file)

    # Add a new top-level "Options" and "Scoring Presets" under Analysis
    analysis = tk.Menu(m, tearoff=0)
    analysis.add_cascade(label="Options", menu=options_menu)
    analysis.add_cascade(label="Scoring Presets", menu=presets_menu)
    try:
        m.add_cascade(label="Configure", menu=analysis)
    except Exception:
        pass

def install_options_menu():
    if 'CipherGUI' not in globals():
        return
    if not hasattr(CipherGUI, "_build_menu_original_options"):
        CipherGUI._build_menu_original_options = CipherGUI._build_menu
        def _build_menu_wrap(self):
            CipherGUI._build_menu_original_options(self)
            _patch_options_menu(self)
        CipherGUI._build_menu = _build_menu_wrap

install_options_menu()

# =============================================================================
# MONOALPHABETIC SUBSTITUTION (time-bounded SA hill-climb)
# =============================================================================
def _substitution_decrypt(ct: str, mapping: list[int]) -> str:
    # mapping: index of cipher letter (A=0..Z=25) -> plaintext index (0..25)
    out=[]
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            i = ord(u) - 65
            p = mapping[i]
            pc = chr(p + (65 if ch.isupper() else 97))
            out.append(pc)
        else:
            out.append(ch)
    return "".join(out)

def _random_mapping() -> list[int]:
    m = list(range(26)); random.shuffle(m); return m

def _freq_init_mapping(ct: str) -> list[int]:
    # map sorted CT frequencies to ETAOIN… ordering
    s = _clean_alpha(ct)
    freq = Counter(s)
    ordered_ct = [k for k,_ in freq.most_common()] + [ch for ch in ALPHA if ch not in freq]
    eta = list("ETAOINSHRDLUCMWFGYPBVKJXQZ")
    while len(ordered_ct) < 26:
        ordered_ct.append(next(ch for ch in ALPHA if ch not in ordered_ct))
    while len(eta) < 26:
        eta.append(next(ch for ch in ALPHA if ch not in eta))
    # build mapping cipher->plain index
    m = [0]*26
    for cidx, cch in enumerate(ordered_ct[:26]):
        pch = eta[cidx]
        m[ord(cch)-65] = ord(pch)-65
    # random perturb a bit
    for _ in range(6):
        a,b = random.randrange(26), random.randrange(26)
        m[a],m[b] = m[b],m[a]
    return m

def _mapping_score(ct: str, mapping: list[int]) -> float:
    pt = _substitution_decrypt(ct, mapping)
    return _score_pt(pt)

def solve_substitution(ct: str, time_sec=6.0, restarts=8, start_temp=2.0, end_temp=0.05):
    best_map = None
    best_score = -1e99
    deadline = time.time() + max(0.3, float(time_sec))
    tries = 0
    while time.time() < deadline and tries < max(1,int(restarts)):
        tries += 1
        # initial mapping
        mapping = _freq_init_mapping(ct) if tries % 2 else _random_mapping()
        score = _mapping_score(ct, mapping)
        temp = float(start_temp)
        # SA parameters
        inner_deadline = min(deadline, time.time() + (time_sec / max(1,restarts)))
        while time.time() < inner_deadline and temp > end_temp:
            # try several random swaps per temperature step
            for _ in range(600):
                a,b = random.randrange(26), random.randrange(26)
                if a==b: continue
                mapping[a], mapping[b] = mapping[b], mapping[a]
                new_score = _mapping_score(ct, mapping)
                delta = new_score - score
                if delta >= 0 or random.random() < math.exp(delta/max(1e-6,temp)):
                    score = new_score
                    if score > best_score:
                        best_score = score
                        best_map = mapping[:]
                else:
                    # revert
                    mapping[a], mapping[b] = mapping[b], mapping[a]
            temp *= 0.88
    if best_map is None:
        best_map = _freq_init_mapping(ct)
        best_score = _mapping_score(ct, best_map)
    return best_map, best_score, _substitution_decrypt(ct, best_map)
# --- FIX: BaseGuesser + candidate plumbing + GUI bridge ----------------------
# Put this ABOVE any "class ...Guesser(BaseGuesser)" definitions.

# Base class for all guessers
if 'BaseGuesser' not in globals():
    class BaseGuesser:
        """Minimal abstract base for guessers used by Smart Guess/Brute Force."""
        name = "Base"
        def generate(self, ct: str, budget: int = 0):
            raise NotImplementedError

# Helper used by some guessers (alias to an alpha-only upper cleaner)
if '_clean_alpha' not in globals():
    def _clean_alpha(s: str) -> str:
        return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

# Shared candidate buffer + helpers (higher score = better; uses _score_pt)
_CAND_POOL = []

def begin_candidates():
    """Start a new candidate-collection session."""
    _CAND_POOL.clear()

def push_candidate(family: str, key: str, plaintext: str, score: float, meta: dict | None = None):
    """Append a candidate produced by any guesser."""
    try:
        sc = float(score)
    except Exception:
        sc = -1e99
    _CAND_POOL.append({
        "family": family,
        "key": key or "",
        "plaintext": plaintext or "",
        "score": sc,
        "meta": meta or {}
    })

def get_ranked_candidates(limit: int = 50):
    """Return de-duplicated candidates ranked by score (desc)."""
    best = {}
    for row in _CAND_POOL:
        pt = row["plaintext"]
        sc = row["score"]
        if pt not in best or sc > best[pt]["score"]:
            best[pt] = row
    ranked = sorted(best.values(), key=lambda r: r["score"], reverse=True)
    return [(f'{r["family"]} [{r["key"]}]', r["plaintext"], r["score"]) for r in ranked[:limit]]

# Registry + registration helpers for guessers (optional, convenient)
_GUESSERS = []
def register_guesser(cls):
    """Decorator to auto-register a guesser class."""
    try:
        _GUESSERS.append(cls())
    except Exception:
        pass
    return cls

def _try_register_existing(names: list[str]):
    for n in names:
        cls = globals().get(n)
        if isinstance(cls, type):
            try:
                _GUESSERS.append(cls())
            except Exception:
                pass

# GUI bridge: make Smart Guess run BOTH the legacy SmartGuess() and any new guessers
def _smart_guess_with_guessers(self):
    ct = self.input_txt.get("1.0", "end-1c")

    # 1) New-style guessers fill the shared pool
    begin_candidates()
    for g in _GUESSERS:
        try:
            g.generate(ct)
        except Exception:
            # Keep going; one bad guesser shouldn't kill the run
            pass

    # 2) Merge in results from the legacy SmartGuess() by rescoring with _score_pt
    try:
        legacy = SmartGuess(ct)  # returns (label, pt, legacy_score) with "lower is better"
        for label, pt, _legacy_sc in legacy:
            try:
                sc = _score_pt(pt)  # convert to our "higher is better" space
            except Exception:
                sc = 0.0
            push_candidate("Legacy " + label, "", pt, sc)
    except Exception:
        pass

    ranked = get_ranked_candidates(limit=50)
    self._show_ranked_window("Smart Guess — Unified Candidates", ranked)

# Install the GUI bridge once CipherGUI exists
def _install_gui_bridge_for_guessers():
    if 'CipherGUI' not in globals():
        return
    if not hasattr(CipherGUI, "_smart_guess_legacy"):
        CipherGUI._smart_guess_legacy = CipherGUI.smart_guess
        CipherGUI.smart_guess = _smart_guess_with_guessers

_install_gui_bridge_for_guessers()
# --- end fix block -----------------------------------------------------------

class SubstitutionGuesser(BaseGuesser):
    name = "Substitution"
    def generate(self, ct, budget=1):
        if not GUESSER_OPTIONS["Substitution"].get("enabled", True):
            return
        t  = float(GUESSER_OPTIONS["Substitution"].get("time_sec", 6.0))
        rs = int(GUESSER_OPTIONS["Substitution"].get("restarts", 8))
        t0 = float(GUESSER_OPTIONS["Substitution"].get("start_temp", 2.0))
        t1 = float(GUESSER_OPTIONS["Substitution"].get("end_temp", 0.05))
        m, sc, pt = solve_substitution(ct, time_sec=t, restarts=rs, start_temp=t0, end_temp=t1)
        key = "".join(ALPHA[i] for i in m)  # mapping row (C->P indexes as letters)
        push_candidate("Substitution", key, pt, sc, {"time":t,"restarts":rs})

# =============================================================================
# EXTRA GUESSERS: ROT13 / ROT47 / Playfair (seeded) / ADFGX / ADFGVX
# =============================================================================

# ROT13 / ROT47
def rot13_dec(s: str) -> str:
    out=[]
    for ch in s:
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-65-13)%26+65))
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-97-13)%26+97))
        else:
            out.append(ch)
    return "".join(out)

def rot47_dec(s: str) -> str:
    out=[]
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 - 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)

class ROT13Guesser(BaseGuesser):
    name = "ROT13"
    def generate(self, ct, budget=1):
        if not GUESSER_OPTIONS["ROT13"].get("enabled", True):
            return
        pt = rot13_dec(ct)
        sc = _score_pt(pt)
        push_candidate("ROT13", "rot13", pt, sc)

class ROT47Guesser(BaseGuesser):
    name = "ROT47"
    def generate(self, ct, budget=1):
        if not GUESSER_OPTIONS["ROT47"].get("enabled", True):
            return
        pt = rot47_dec(ct)
        sc = _score_pt(pt)
        push_candidate("ROT47", "rot47", pt, sc)

# --- Playfair helpers --------------------------------------------------------
def playfair_square_from_keyword(keyword: str):
    key = _clean_alpha(keyword).replace("J","I")
    seen=set(); letters=[]
    for ch in key + ALPHA:
        if ch=="J": ch="I"
        if ch not in seen and ch in ALPHA and ch!="J":
            seen.add(ch); letters.append(ch)
        if len(letters)==25: break
    table = [letters[i*5:(i+1)*5] for i in range(5)]
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[table[r][c]] = (r,c)
    return table, pos

def playfair_dec(ct: str, keyword: str) -> str:
    table, pos = playfair_square_from_keyword(keyword)
    def pf(c1,c2):
        r1,c1 = pos[c1]; r2,c2 = pos[c2]
        if r1 == r2:
            return table[r1][(c1-1)%5] + table[r2][(c2-1)%5]
        elif c1 == c2:
            return table[(r1-1)%5][c1] + table[(r2-1)%5][c2]
        else:
            return table[r1][c2] + table[r2][c1]
    # build digraphs from letters only, pairing as-is (ignore X insert nuance)
    s = _clean_alpha(ct)
    if len(s)%2==1: s += "X"
    out=[]
    for i in range(0,len(s),2):
        a,b = s[i], s[i+1]
        # merge Js to I
        a = "I" if a=="J" else a
        b = "I" if b=="J" else b
        out.append(pf(a,b))
    pt_alpha = "".join(out)
    # map back over original text preserving non-alpha and case
    res=[]; j=0
    for ch in ct:
        if ch.upper() in ALPHA:
            pc = pt_alpha[j]
            res.append(pc if ch.isupper() else pc.lower())
            j+=1
        else:
            res.append(ch)
    return "".join(res)

class PlayfairGuesser(BaseGuesser):
    name = "Playfair"
    def generate(self, ct, budget=80):
        if not GUESSER_OPTIONS["Playfair"].get("enabled", True):
            return
        # Try a small bank of seed keywords
        seeds = GUESSER_OPTIONS["Playfair"].get("seed_words","KEYWORD,SECRET,MONARCHY").split(",")
        seeds = [w.strip() for w in seeds if w.strip()]
        tried=set()
        for w in seeds[:16]:
            try:
                pt = playfair_dec(ct, w)
                sc = _score_pt(pt)
                push_candidate("Playfair", w, pt, sc)
                tried.add(w)
            except Exception:
                pass
        # Mutate seeds a bit by appending frequent letters - quick variants
        eta = "ETAOINSHRDLU"
        max_var = int(GUESSER_OPTIONS["Playfair"].get("max_variants", 8))
        for w in list(tried):
            for ch in eta[:6]:
                if len(tried) >= max_var + len(seeds): break
                k = w + ch
                try:
                    pt = playfair_dec(ct, k)
                    sc = _score_pt(pt)
                    push_candidate("Playfair", k, pt, sc)
                    tried.add(k)
                except Exception:
                    pass

# --- ADFGX / ADFGVX helpers --------------------------------------------------
ADFG = "ADFGX"
ADFGV = "ADFGVX"

def keyed_square_5x5(keyword: str):
    key = _clean_alpha(keyword).replace("J","I")
    seq=[]
    seen=set()
    for ch in key + ALPHA:
        if ch=="J": ch="I"
        if ch not in seen and ch!="J":
            seen.add(ch); seq.append(ch)
        if len(seq)==25: break
    return seq  # flat list

def keyed_square_6x6(keyword: str):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    key = "".join(ch for ch in _clean_alpha(keyword) if ch in ALPHA)
    seq=[]; seen=set()
    for ch in key + alpha:
        if ch not in seen:
            seen.add(ch); seq.append(ch)
        if len(seq)==36: break
    return seq

def _columnar_unpermute(ct: str, key: str):
    # Inverse of columnar transposition used by ADFGX/ADFGVX (read down columns by key order)
    w = len(key)
    n = len(ct)
    rows = math.ceil(n / w)
    short = (w*rows - n)
    col_len = [rows]*(w-short) + [rows-1]*short

    order = sorted(range(w), key=lambda i: (key[i], i))  # stable for dups
    cols = {}
    idx = 0
    for oi in order:
        L = col_len[oi]
        cols[oi] = list(ct[idx:idx+L]); idx += L
    # rebuild row-wise
    out=[]
    for r in range(rows):
        for c in range(w):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)

def adfgx_dec(ct: str, square_key="KEYWORD", trans_key="CIPHER"):
    # 1) strip to ADFGX letters
    s = "".join(ch for ch in ct.upper() if ch in ADFG)
    if len(s) % 2 != 0:
        s = s[:-1]
    if not s: return ""
    # 2) inverse columnar
    inter = _columnar_unpermute(s, trans_key)
    # 3) map pairs through 5x5 square
    sq = keyed_square_5x5(square_key)
    res=[]
    for i in range(0, len(inter), 2):
        r = ADFG.index(inter[i])
        c = ADFG.index(inter[i+1])
        ch = sq[r*5 + c]
        res.append(ch)
    # 4) case/punct reinsert (simple upper only)
    return "".join(res)

def adfgvx_dec(ct: str, square_key="KEYWORD", trans_key="CIPHER"):
    s = "".join(ch for ch in ct.upper() if ch in ADFGV)
    if len(s) % 2 != 0:
        s = s[:-1]
    if not s: return ""
    inter = _columnar_unpermute(s, trans_key)
    sq = keyed_square_6x6(square_key)
    res=[]
    for i in range(0, len(inter), 2):
        r = ADFGV.index(inter[i])
        c = ADFGV.index(inter[i+1])
        ch = sq[r*6 + c]
        res.append(ch)
    return "".join(res)

class ADFGXGuesser(BaseGuesser):
    name = "ADFGX"
    def generate(self, ct, budget=120):
        if not GUESSER_OPTIONS["ADFGX"].get("enabled", True):
            return
        S = "".join(ch for ch in ct.upper() if ch in ADFG)
        if len(S) < 10:  # likely not ADFGX
            return
        sq_key = GUESSER_OPTIONS["ADFGX"].get("square_key","KEYWORD")
        kmin = int(GUESSER_OPTIONS["ADFGX"].get("min_klen",4))
        kmax = int(GUESSER_OPTIONS["ADFGX"].get("max_klen",8))
        # try numeric keys (abcdef order) – simulate small widths
        for w in range(kmin, kmax+1):
            # try a small set of columnar keys by permuting alphabetically unique keys of len w
            base = "CIPHERKEYALNUMBADFGX"
            key = "".join(dict.fromkeys((base + sq_key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")) )[:w]
            pt_alpha = adfgx_dec(ct, sq_key, key)
            # score mapping letters as plaintext
            sc = _score_pt(pt_alpha)
            push_candidate("ADFGX", f"square={sq_key} trans={key}", pt_alpha, sc, {"klen":w})

class ADFGVXGuesser(BaseGuesser):
    name = "ADFGVX"
    def generate(self, ct, budget=120):
        if not GUESSER_OPTIONS["ADFGVX"].get("enabled", True):
            return
        S = "".join(ch for ch in ct.upper() if ch in ADFGV)
        if len(S) < 10:
            return
        sq_key = GUESSER_OPTIONS["ADFGVX"].get("square_key","KEYWORD")
        kmin = int(GUESSER_OPTIONS["ADFGVX"].get("min_klen",4))
        kmax = int(GUESSER_OPTIONS["ADFGVX"].get("max_klen",8))
        base = "CIPHERKEYALNUMADFGVX"
        for w in range(kmin, kmax+1):
            key = "".join(dict.fromkeys((base + sq_key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")) )[:w]
            pt_alpha = adfgvx_dec(ct, sq_key, key)
            sc = _score_pt(pt_alpha)
            push_candidate("ADFGVX", f"square={sq_key} trans={key}", pt_alpha, sc, {"klen":w})

# =============================================================================
# EXTEND GUESSERS REGISTRY + obey per-cipher options (enable, ranges)
# =============================================================================
# Reuse existing decoders from previous patch: caesar_dec, affine_dec, railfence_dec, columnar_dec,
# vigenere_dec, autokey_dec, beaufort_dec, porta_dec

# Rebuild/extend registry to include new guessers and option-gated ranges
class RailFenceGuesser(BaseGuesser):
    name = "Rail Fence"
    def generate(self, ct, budget=24):
        opts = GUESSER_OPTIONS["Rail Fence"]
        if not opts.get("enabled", True): return
        lo = max(2, int(opts.get("min_rails", 2)))
        hi = min(24, int(opts.get("max_rails", 12)))
        for rails in range(lo, hi+1):
            pt = railfence_dec(ct, rails)
            sc = _score_pt(pt)
            push_candidate("Rail Fence", f"rails={rails}", pt, sc)

class ColumnarGuesser(BaseGuesser):
    name = "Columnar"
    def generate(self, ct, budget=40):
        opts = GUESSER_OPTIONS["Columnar"]
        if not opts.get("enabled", True): return
        lo = max(2, int(opts.get("min_width",2)))
        hi = min(28, int(opts.get("max_width",14)))
        n = len(ct)
        for w in range(lo, min(hi, max(2, int(math.sqrt(max(1,n)))+8))+1):
            pt = columnar_dec(ct, w)
            sc = _score_pt(pt)
            push_candidate("Columnar", f"width={w}", pt, sc)

class VigenereGuesser(BaseGuesser):
    name = "Vigenere"
    def generate(self, ct, budget=200):
        opts = GUESSER_OPTIONS["Vigenere"]
        if not opts.get("enabled", True): return
        max_len = int(opts.get("max_len",16))
        topk    = int(opts.get("top_keys_per_len",3))
        lens = suggest_vigenere_key_lengths(ct, max_len=max_len)
        for m in lens[:8]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=topk)
            for k in keys:
                pt = vigenere_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Vigenere", k, pt, sc, {"len":m})

class AutokeyGuesser(BaseGuesser):
    name = "Autokey"
    def generate(self, ct, budget=80):
        opts = GUESSER_OPTIONS["Autokey"]
        if not opts.get("enabled", True): return
        max_len = int(opts.get("max_len",12))
        lens = suggest_vigenere_key_lengths(ct, max_len=max_len)
        for m in lens[:6]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=int(opts.get("seed_try",2)))
            for k in keys:
                seed = k[:max(3, min(6, len(k)))]
                pt = autokey_dec(ct, seed)
                sc = _score_pt(pt)
                push_candidate("Autokey", seed, pt, sc, {"seed_len":len(seed)})

class BeaufortGuesser(BaseGuesser):
    name = "Beaufort"
    def generate(self, ct, budget=120):
        opts = GUESSER_OPTIONS["Beaufort"]
        if not opts.get("enabled", True): return
        max_len = int(opts.get("max_len",14))
        lens = suggest_vigenere_key_lengths(ct, max_len=max_len)
        for m in lens[:6]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=2)
            for k in keys:
                pt = beaufort_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Beaufort", k, pt, sc)

class PortaGuesser(BaseGuesser):
    name = "Porta"
    def generate(self, ct, budget=80):
        opts = GUESSER_OPTIONS["Porta"]
        if not opts.get("enabled", True): return
        max_len = int(opts.get("max_len",14))
        lens = suggest_vigenere_key_lengths(ct, max_len=max_len)
        for m in lens[:6]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=2)
            for k in keys:
                pt = porta_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Porta", k, pt, sc)

class CaesarGuesser(BaseGuesser):
    name = "Caesar/ROT"
    def generate(self, ct, budget=40):
        if not GUESSER_OPTIONS["Caesar"].get("enabled", True): return
        for sh in range(26):
            pt = caesar_dec(ct, sh)
            sc = _score_pt(pt)
            push_candidate("Caesar", f"shift={sh}", pt, sc)

class AffineGuesser(BaseGuesser):
    name = "Affine"
    def generate(self, ct, budget=312):
        if not GUESSER_OPTIONS["Affine"].get("enabled", True): return
        m = 26
        for a in [x for x in range(1,m) if math.gcd(x,m)==1]:
            for b in range(m):
                pt = affine_dec(ct, a, b)
                sc = _score_pt(pt)
                push_candidate("Affine", f"a={a}, b={b}", pt, sc)

# Re-register guessers (preserving earlier ones but replacing with option-aware)
_GUESSERS = [
    CaesarGuesser(),
    ROT13Guesser(),
    ROT47Guesser(),
    AffineGuesser(),
    RailFenceGuesser(),
    ColumnarGuesser(),
    VigenereGuesser(),
    AutokeyGuesser(),
    BeaufortGuesser(),
    PortaGuesser(),
    PlayfairGuesser(),
    ADFGXGuesser(),
    ADFGVXGuesser(),
    SubstitutionGuesser(),
]

# =============================================================================
# Glue: make sure Smart Guess / Brute Force already wrapped collect candidates
# (previous block installed wrappers and candidates panel + CSV export)
# =============================================================================

# Nothing else to wire here; GUESSERS list is consumed by run_all_guessers().

# =============================================================================
# Optional: Add a toolbar row with quick preset buttons (nice QoL)
# =============================================================================
def _add_presets_toolbar(self):
    try:
        # place under existing toolbar/status if available
        container = ttk.Frame(self.left_pane)
        container.pack(fill="x", padx=8, pady=(0,6))
        ttk.Label(container, text="Scoring Presets:", font=("TkDefaultFont", 9)).pack(side="left")
        for name in ["Balanced","Quadgram-heavy","Fast (chi² only)"]:
            ttk.Button(container, text=name, command=lambda n=name: (apply_scoring_preset(n), messagebox.showinfo("Presets", f"Applied: {n}"))).pack(side="left", padx=4)
    except Exception:
        pass

def install_presets_toolbar():
    if 'CipherGUI' not in globals():
        return
    if not hasattr(CipherGUI, "_post_layout_original_presets"):
        old = getattr(CipherGUI, "_post_layout", lambda self: None)
        def _post_layout_wrap(self):
            try: old(self)
            except Exception: pass
            _add_presets_toolbar(self)
        CipherGUI._post_layout = _post_layout_wrap

install_presets_toolbar()

import time
import itertools
import json
try:
    from tkinter import filedialog as fd
except Exception:
    fd = None

# --- Matplotlib for heatmaps -------------------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    _HAS_MPL = True
except Exception:
    _HAS_MPL = False

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# -----------------------------------------------------------------------------
# Utility: normalization / sanitization
# -----------------------------------------------------------------------------
def _clean_alpha(s: str, keep_spaces=False):
    out = []
    for ch in s:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            out.append(u)
        elif keep_spaces and ch.isspace():
            out.append(' ')
    return "".join(out)

def _modinv(a, m):
    # Modular inverse for Affine
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse")

def _shift_char(c, k):
    return ALPHA[(ALPHA.index(c)+k) % 26]

def _deshift_char(c, k):
    return ALPHA[(ALPHA.index(c)-k) % 26]



# -----------------------------------------------------------------------------
# Candidate collection (used by patched SmartGuess/BruteForce + our engines)
# -----------------------------------------------------------------------------
class Candidate:
    __slots__ = ("cipher","key","plaintext","score","extra")
    def __init__(self, cipher, key, plaintext, score, extra=None):
        self.cipher = cipher
        self.key = key
        self.plaintext = plaintext
        self.score = float(score)
        self.extra = extra or {}
    def as_row(self):
        return {
            "cipher": self.cipher,
            "key": self.key,
            "score": f"{self.score:.6f}",
            "plaintext": self.plaintext,
            **{f"meta_{k}":v for k,v in self.extra.items()}
        }

class ResultCollector:
    def __init__(self):
        self._items = []
        self._start_ts = time.time()
    def clear(self):
        self._items.clear()
        self._start_ts = time.time()
    def push(self, cand: Candidate):
        self._items.append(cand)
    def items(self):
        return list(self._items)
    def best(self, n=1):
        return sorted(self._items, key=lambda c: c.score, reverse=True)[:n]
    def export_csv(self, path):
        import csv
        rows = [c.as_row() for c in self.best(99999)]
        if not rows:
            rows = [{"cipher":"","key":"","score":"","plaintext":""}]
        fieldnames = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)

# We keep one global collector and attach to GUI instances.
_GLOBAL_COLLECTOR = ResultCollector()

def clear_candidates():
    _GLOBAL_COLLECTOR.clear()

def push_candidate(cipher, key, plaintext, score, extra=None):
    _GLOBAL_COLLECTOR.push(Candidate(cipher, key, plaintext, score, extra))

# Expose to other parts of the codebase if needed
globals()['CANDIDATE_COLLECTOR'] = _GLOBAL_COLLECTOR
globals()['push_candidate'] = push_candidate
globals()['clear_candidates'] = clear_candidates

# -----------------------------------------------------------------------------
# Decoders (light, independent fallbacks for our guessers)
# -----------------------------------------------------------------------------
def caesar_dec(ct: str, shift: int) -> str:
    s = []
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            base = ord('A') if ch.isupper() else ord('a')
            s.append(chr((ord(ch)-base - shift) % 26 + base))
        else:
            s.append(ch)
    return "".join(s)

def affine_dec(ct: str, a: int, b: int) -> str:
    # y = a*x + b mod 26
    inv = _modinv(a, 26)
    out = []
    for ch in ct:
        if ch.upper() in ALPHA:
            alpha = ALPHA if ch.isupper() else ALPHA.lower()
            y = alpha.index(ch)
            x = (inv * (y - b)) % 26
            out.append(alpha[x])
        else:
            out.append(ch)
    return "".join(out)

def vigenere_dec(ct: str, key: str) -> str:
    key = _clean_alpha(key)
    if not key: return ct
    out = []
    ki = 0
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            shift = ALPHA.index(key[ki % len(key)])
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch)-base - shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

def autokey_dec(ct: str, key: str) -> str:
    # Vigenère where key extends with plaintext
    key = _clean_alpha(key)
    out = []
    kbuf = list(key)
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            shift = ALPHA.index(kbuf[0]) if kbuf else 0
            base = ord('A') if ch.isupper() else ord('a')
            p = chr((ord(ch)-base - shift) % 26 + base)
            out.append(p)
            # extend with plaintext letter upper
            kbuf.append(p.upper())
            kbuf.pop(0) if len(kbuf) > len(key) else None
        else:
            out.append(ch)
    return "".join(out)

def beaufort_dec(ct: str, key: str) -> str:
    # P = K - C mod 26, with Vigenère-like stepping
    key = _clean_alpha(key)
    out = []
    ki = 0
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            kc = key[ki % len(key)]
            p_idx = (ALPHA.index(kc) - ALPHA.index(u)) % 26
            out.append(ALPHA[p_idx] if ch.isupper() else ALPHA[p_idx].lower())
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

def porta_dec(ct: str, key: str) -> str:
    # Porta is reciprocal; implement classic digraph table as shifts of 13.. etc.
    key = _clean_alpha(key)
    def porta_map(kch):
        i = ALPHA.index(kch)//2  # A/B -> 0, C/D -> 1, ...
        left  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        right = "NOPQRSTUVWXYZABCDEFGHIJKLM"
        # rotate halves by i
        L = left[:13]; R = right[:13]
        Lr = L[i:]+L[:i]
        Rr = R[i:]+R[:i]
        table = {}
        for a,b in zip(Lr, Rr):
            table[a]=b; table[b]=a
        return table
    out=[]; ki=0
    for ch in ct:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            t = porta_map(key[ki % len(key)])
            m = t.get(u,u)
            out.append(m if ch.isupper() else m.lower())
            ki+=1
        else:
            out.append(ch)
    return "".join(out)

def railfence_dec(ct: str, rails: int) -> str:
    # Reconstruct zig-zag indices, then assign chars row-wise
    if rails <= 1: return ct
    n = len(ct)
    # pattern of rows visited
    pattern = list(range(rails)) + list(range(rails-2,0,-1))
    rows = [[] for _ in range(rails)]
    # count each row's length
    counts = [0]*rails
    r = 0
    for i in range(n):
        counts[pattern[r]] += 1
        r = (r+1) % len(pattern)
    # fill rows from ciphertext
    idx = 0
    for ri in range(rails):
        rows[ri] = list(ct[idx:idx+counts[ri]])
        idx += counts[ri]
    # read off zig-zag
    out=[]
    rptr = [0]*rails
    r=0
    for i in range(n):
        row = pattern[r]
        out.append(rows[row][rptr[row]])
        rptr[row]+=1
        r = (r+1) % len(pattern)
    return "".join(out)

def columnar_dec(ct: str, width: int, keyperm=None) -> str:
    # Simple columnar: fill columns top->bottom using key order; then read rows
    c = list(ct)
    n = len(c)
    w = max(1, width)
    rows = math.ceil(n / w)
    # determine column lengths (last row may be short)
    short = (w*rows - n)
    col_len = [rows]*(w-short) + [rows-1]*short
    # order of columns (if permutation not given, use numeric ascending)
    if keyperm is None:
        order = list(range(w))
    else:
        order = list(keyperm)
        if len(order)!=w: order = list(range(w))
    # slice ct into columns by order
    cols = [None]*w
    idx=0
    for k in order:
        L = col_len[k]
        cols[k] = c[idx:idx+L]
        idx += L
    # read row-wise
    out=[]
    for r in range(rows):
        for k in range(w):
            if r < len(cols[k]):
                out.append(cols[k][r])
    return "".join(out)

# -----------------------------------------------------------------------------
# Key length + key letter guessers (Vigenère family)
# -----------------------------------------------------------------------------
def _chi2_for_shift(coset: str, shift: int) -> float:
    # Shift coset backwards (decipher) then chi-squared
    pt = "".join(_deshift_char(c, shift) for c in coset)
    # chi-squared vs English
    freq = Counter(pt)
    N = len(pt) or 1
    expected = {
        'E': 12.702, 'T': 9.056, 'A': 8.167, 'O': 7.507, 'I': 6.966, 'N': 6.749,
        'S': 6.327, 'H': 6.094, 'R': 5.987, 'D': 4.253, 'L': 4.025, 'C': 2.782,
        'U': 2.758, 'M': 2.406, 'W': 2.360, 'F': 2.228, 'G': 2.015, 'Y': 1.974,
        'P': 1.929, 'B': 1.492, 'V': 0.978, 'K': 0.772, 'J': 0.153, 'X': 0.150,
        'Q': 0.095, 'Z': 0.074
    }
    chi = 0.0
    for ch in ALPHA:
        o = freq.get(ch,0) * 100.0 / N
        e = expected[ch]
        if e > 0:
            diff = o - e
            chi += (diff*diff)/e
    return chi

def guess_vigenere_key_by_len(ct: str, m: int, top_k: int = 3) -> list[str]:
    s = _clean_alpha(ct)
    cosets = split_cosets(s, m)
    # best shift per coset (min chi2)
    shifts = []
    for cos in cosets:
        if not cos:
            shifts.append(0); continue
        best = min(range(26), key=lambda sh: _chi2_for_shift(cos, sh))
        shifts.append(best)
    # produce a few alternates by allowing each coset to consider 2nd-best
    # compute per-coset ranked shifts
    ranked = []
    for cos in cosets:
        rnk = sorted(range(26), key=lambda sh: _chi2_for_shift(cos, sh))[:2]
        ranked.append(rnk)
    keys = set()
    for alt in itertools.product(*ranked):
        k = "".join(ALPHA[a] for a in alt)
        keys.add(k)
        if len(keys) >= top_k: break
    # ensure baseline
    if len(keys) < top_k:
        k0 = "".join(ALPHA[s] for s in shifts)
        keys.add(k0)
    return list(keys)[:top_k]

def suggest_vigenere_key_lengths(ct: str, max_len: int = 16) -> list[int]:
    # combine kasiski factor votes + friedman closeness
    _, fac = kasiski_examination(ct, 3, 5, max_len)
    fr = friedman_by_keylen(ct, max_len)
    # score lens: high votes + being close to 0.065
    votes = {k:v for k,v in fac.items()}
    lens = {}
    for m, ic in fr:
        lens[m] = lens.get(m, 0.0) + (max(0, 0.065 - abs(0.065-ic)) * 1000)
    for k,v in votes.items():
        lens[k] = lens.get(k, 0.0) + v * 50.0
    # rank
    ranked = sorted(lens.items(), key=lambda t: t[1], reverse=True)
    return [m for m,_ in ranked][:8]

# -----------------------------------------------------------------------------
# Guessers registry
# -----------------------------------------------------------------------------
class BaseGuesser:
    name = "Base"
    def generate(self, ct: str, budget: int = 200):
        return []  # yield Candidate

class CaesarGuesser(BaseGuesser):
    name = "Caesar/ROT"
    def generate(self, ct, budget=40):
        for sh in range(26):
            pt = caesar_dec(ct, sh)
            sc = _score_pt(pt)
            push_candidate("Caesar", f"shift={sh}", pt, sc)

class AffineGuesser(BaseGuesser):
    name = "Affine"
    def generate(self, ct, budget=312):
        m = 26
        for a in [x for x in range(1,m) if math.gcd(x,m)==1]:
            for b in range(m):
                pt = affine_dec(ct, a, b)
                sc = _score_pt(pt)
                push_candidate("Affine", f"a={a}, b={b}", pt, sc)

class RailFenceGuesser(BaseGuesser):
    name = "Rail Fence"
    def generate(self, ct, budget=24):
        n = len(ct)
        for rails in range(2, min(12, n//2+1)):
            pt = railfence_dec(ct, rails)
            sc = _score_pt(pt)
            push_candidate("Rail Fence", f"rails={rails}", pt, sc)

class ColumnarGuesser(BaseGuesser):
    name = "Columnar"
    def generate(self, ct, budget=40):
        n = len(ct)
        for w in range(2, min(14, max(3, int(math.sqrt(max(1,n)))) + 6)):
            pt = columnar_dec(ct, w)
            sc = _score_pt(pt)
            push_candidate("Columnar", f"width={w}", pt, sc)

class VigenereGuesser(BaseGuesser):
    name = "Vigenere"
    def generate(self, ct, budget=200):
        # lengths from suggestion, capped by budget
        lens = suggest_vigenere_key_lengths(ct, max_len=16)
        for m in lens[:8]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=3)
            for k in keys:
                pt = vigenere_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Vigenere", k, pt, sc, {"len":m})

class AutokeyGuesser(BaseGuesser):
    name = "Autokey"
    def generate(self, ct, budget=80):
        lens = suggest_vigenere_key_lengths(ct, max_len=12)
        # try initial seeds derived from Vigenère key guesses (first 3-6 chars)
        for m in lens[:6]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=2)
            for k in keys:
                seed = k[:max(3, min(6, len(k)))]
                pt = autokey_dec(ct, seed)
                sc = _score_pt(pt)
                push_candidate("Autokey", seed, pt, sc, {"seed_len":len(seed)})

class BeaufortGuesser(BaseGuesser):
    name = "Beaufort"
    def generate(self, ct, budget=120):
        lens = suggest_vigenere_key_lengths(ct, max_len=14)
        for m in lens[:6]:
            keys = guess_vigenere_key_by_len(ct, m, top_k=2)
            for k in keys:
                pt = beaufort_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Beaufort", k, pt, sc)

class PortaGuesser(BaseGuesser):
    name = "Porta"
    def generate(self, ct, budget=80):
        lens = suggest_vigenere_key_lengths(ct, max_len=14)
        for m in lens[:6]:
            # for Porta, key letters taken but algorithm is reciprocal
            keys = guess_vigenere_key_by_len(ct, m, top_k=2)
            for k in keys:
                pt = porta_dec(ct, k)
                sc = _score_pt(pt)
                push_candidate("Porta", k, pt, sc)

_GUESSERS = [
    CaesarGuesser(),
    AffineGuesser(),
    RailFenceGuesser(),
    ColumnarGuesser(),
    VigenereGuesser(),
    AutokeyGuesser(),
    BeaufortGuesser(),
    PortaGuesser(),
]

def run_all_guessers(ct: str, max_time_sec: float = 3.5, limit_per=9999):
    clear_candidates()
    t0 = time.time()
    for g in _GUESSERS:
        if time.time()-t0 > max_time_sec:
            break
        try:
            g.generate(ct)
        except Exception as e:
            # don't crash; just log a "meta" record for debugging
            push_candidate("ERROR", g.name, f"[{g.name}] failed: {e}", -1e9)

# -----------------------------------------------------------------------------
# IOC Heatmap GUI
# -----------------------------------------------------------------------------
def _gui_open_ic_heatmap_window(self):
    win = tk.Toplevel(self.root)
    win.title("IOC Heatmap (Key length × Coset)")
    win.geometry("920x680")

    top = ttk.Frame(win); top.pack(fill="x", padx=8, pady=8)
    ttk.Label(top, text="Analyze from:").pack(side="left")
    src = tk.StringVar(value="Input")
    ttk.Radiobutton(top, text="Input", variable=src, value="Input").pack(side="left", padx=6)
    ttk.Radiobutton(top, text="Output", variable=src, value="Output").pack(side="left", padx=6)

    ttk.Label(top, text="Min len").pack(side="left", padx=(12,3))
    vmin = tk.IntVar(value=1)
    ttk.Entry(top, textvariable=vmin, width=4).pack(side="left")
    ttk.Label(top, text="Max len").pack(side="left", padx=(12,3))
    vmax = tk.IntVar(value=16)
    ttk.Entry(top, textvariable=vmax, width=4).pack(side="left")

    runbtn = ttk.Button(top, text="Compute", command=lambda: compute())
    runbtn.pack(side="right")

    # figure
    if not _HAS_MPL:
        ttk.Label(win, text="matplotlib not available. Install it to see the heatmap.").pack(pady=16)
        return

    fig = Figure(figsize=(9.2,5.8))
    ax  = fig.add_subplot(1,1,1)
    canvas = FigureCanvasTkAgg(fig, master=win)
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

    info = tk.Text(win, height=6, wrap="word"); info.pack(fill="x", padx=8, pady=(0,8))

    def compute():
        text = self.input_txt.get("1.0","end-1c") if src.get()=="Input" else self.output_txt.get("1.0","end-1c")
        s = _clean_alpha(text)
        mn, mx = max(1, vmin.get()), max(vmin.get(), vmax.get())
        lens = list(range(mn, mx+1))
        heat = []
        best_rows = []
        for m in lens:
            cos = split_cosets(s, m)
            row = [index_of_coincidence(c) if len(c)>=2 else 0.0 for c in cos]
            heat.append(row + [None]*(mx - len(row)))  # pad to max width for imshow
            # record summary per length
            avg_ic = sum(v for v in row if v>0)/max(1,len([v for v in row if v>0]))
            best_rows.append((m, avg_ic))

        data = []
        max_cols = mx
        for r in heat:
            data.append([v if v is not None else 0.0 for v in r + [0.0]*(max_cols - len(r))])

        ax.clear()
        import numpy as np
        arr = np.array(data)
        im = ax.imshow(arr, aspect="auto", interpolation="nearest")
        ax.set_xlabel("Coset index")
        ax.set_ylabel("Key length")
        ax.set_yticks(range(len(lens)))
        ax.set_yticklabels([str(m) for m in lens])
        cb = fig.colorbar(im, ax=ax)
        cb.ax.set_ylabel("IC", rotation=90)
        fig.tight_layout()
        canvas.draw()

        info.delete("1.0","end")
        est = friedman_estimate_keylen(s)
        info.insert("1.0", f"Friedman est len ≈ {est:.2f}\n")
        info.insert("end", "Top lengths by avg IC:\n")
        for m,avg in sorted(best_rows, key=lambda t: t[1], reverse=True)[:10]:
            info.insert("end", f"  m={m:2d}  avgIC={avg:.5f}\n")

    compute()

# -----------------------------------------------------------------------------
# Export CSV + Auto-Suggest integration
# -----------------------------------------------------------------------------
def _export_candidates_csv(self):
    if fd is None:
        messagebox.showerror("Export CSV", "File dialog not available on this system.")
        return
    path = fd.asksaveasfilename(
        title="Export Ranked Candidates to CSV",
        defaultextension=".csv",
        filetypes=[("CSV file","*.csv"),("All files","*.*")]
    )
    if not path: return
    try:
        # Use global collector
        _GLOBAL_COLLECTOR.export_csv(path)
        messagebox.showinfo("Export CSV", f"Saved {len(_GLOBAL_COLLECTOR.items())} candidates.\n{path}")
    except Exception as e:
        messagebox.showerror("Export CSV", f"Failed to export: {e}")

def _apply_suggested_key_to_gui(self, key: str, mode: str = "Vigenere"):
    """
    Best-effort: try to set the cipher type and key field in the host GUI.
    We try several attribute conventions; fall back to clipboard + notice.
    """
    ok = False
    try:
        # cipher selection
        for attr in ("set_cipher","select_cipher","choose_cipher"):
            if hasattr(self, attr):
                getattr(self, attr)(mode)
                ok = True
                break
        # sometimes there's a tk variable
        if not ok and hasattr(self, "cipher_var"):
            try:
                self.cipher_var.set(mode); ok = True
            except Exception:
                pass
    except Exception:
        pass

    k_ok = False
    for attr in ("set_key","setKey","apply_key"):
        if hasattr(self, attr):
            try:
                getattr(self, attr)(key); k_ok = True; break
            except Exception:
                pass
    # common tk variable / entry field
    if not k_ok:
        if hasattr(self, "key_var"):
            try: self.key_var.set(key); k_ok=True
            except Exception: pass
        if hasattr(self, "key_entry"):
            try:
                self.key_entry.delete(0,"end")
                self.key_entry.insert(0,key)
                k_ok=True
            except Exception:
                pass

    if not (ok and k_ok):
        # fallback: copy to clipboard and notify
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
        except Exception:
            pass
        messagebox.showinfo("Key Suggested",
            f"Suggested key for {mode}: {key}\n"
            "I copied it to the clipboard. If it didn't auto-fill, paste it into the key box.")

def _autosuggest_buttons_in_kasiski(self, parent_frame):
    # Adds buttons into the existing Kasiski window footer (call from window code)
    # Not strictly required if we patch the Kasiski window creation below.
    pass  # we integrate in window construction patch

# Patch Kasiski window to include an "Auto-Suggest → Vigenère/Autokey" row
def _gui_open_kasiski_window_aug(self):
    # call the original window first (creates widgets we can extend)
    self.__class__.open_kasiski_window_original(self)
    # last created toplevel is the active one; scan for it
    try:
        win = self.root.winfo_children()[-1]
    except Exception:
        return
    # Find a place to add buttons (bottom)
    btnbar = ttk.Frame(win); btnbar.pack(fill="x", padx=8, pady=(0,8))
    ttk.Label(btnbar, text="Auto-Suggest Key Length →").pack(side="left")
    ttk.Button(btnbar, text="Vigenère", command=lambda: _do_autosuggest(self, "Vigenere")).pack(side="left", padx=6)
    ttk.Button(btnbar, text="Autokey", command=lambda: _do_autosuggest(self, "Autokey")).pack(side="left", padx=6)

def _do_autosuggest(self, mode="Vigenere"):
    # Read current source text (input by default)
    try:
        text = self.input_txt.get("1.0","end-1c")
    except Exception:
        text = ""
    # Suggest lengths, pick best, then build best key
    lens = suggest_vigenere_key_lengths(text, max_len=16)
    if not lens:
        messagebox.showwarning("Auto-Suggest", "No viable key lengths found.")
        return
    m = lens[0]
    keys = guess_vigenere_key_by_len(text, m, top_k=1)
    if not keys:
        messagebox.showwarning("Auto-Suggest", f"Unable to derive key for length {m}.")
        return
    key = keys[0]
    _apply_suggested_key_to_gui(self, key, "Vigenere" if mode=="Vigenere" else "Autokey")

# -----------------------------------------------------------------------------
# Smart Guess / Brute Force wrappers: run host + universal guessers + capture
# -----------------------------------------------------------------------------
def _wrap_smart_guess_collect(self):
    # 1) Clear collector
    clear_candidates()

    # 2) Call the host Smart Guess (if present)
    res = None
    try:
        res = self.__class__.smart_guess_original(self)
        # If host returns a ranked list, capture it.
        if isinstance(res, (list, tuple)):
            for item in res:
                try:
                    cipher = item.get("cipher") if isinstance(item, dict) else getattr(item, "cipher", "unknown")
                    key = item.get("key") if isinstance(item, dict) else getattr(item, "key", "")
                    pt = item.get("pt") if isinstance(item, dict) else getattr(item, "plaintext", "")
                    sc = item.get("score") if isinstance(item, dict) else getattr(item, "score", _score_pt(pt))
                    push_candidate(cipher or "Host", key, pt, sc, {"src":"host"})
                except Exception:
                    pass
    except Exception:
        # Don't block on host errors
        pass

    # 3) Run our universal guessers on the INPUT text (raw)
    try:
        text = self.input_txt.get("1.0","end-1c")
    except Exception:
        text = ""
    run_all_guessers(text, max_time_sec=4.0)

    # 4) Keep a ranked list on the GUI instance
    ranked = sorted(_GLOBAL_COLLECTOR.items(), key=lambda c: c.score, reverse=True)
    self._last_ranked_candidates = ranked

    # 5) If we have a best candidate, preview it in output (non-destructive)
    if ranked:
        top = ranked[0]
        try:
            self.output_preview_txt.delete("1.0","end")
            self.output_preview_txt.insert("1.0", f"[{top.cipher}] key={top.key}\n\n{top.plaintext}")
        except Exception:
            # Fallback: replace main output (comment if undesired)
            try:
                self.output_txt.delete("1.0","end")
                self.output_txt.insert("1.0", top.plaintext)
            except Exception:
                pass
    return res

def _wrap_bruteforce_collect(self):
    clear_candidates()
    res = None
    try:
        res = self.__class__.brute_force_original(self)
        if isinstance(res, (list, tuple)):
            for item in res:
                try:
                    cipher = item.get("cipher") if isinstance(item, dict) else getattr(item, "cipher", "unknown")
                    key = item.get("key") if isinstance(item, dict) else getattr(item, "key", "")
                    pt = item.get("pt") if isinstance(item, dict) else getattr(item, "plaintext", "")
                    sc = item.get("score") if isinstance(item, dict) else getattr(item, "score", _score_pt(pt))
                    push_candidate(cipher or "Host", key, pt, sc, {"src":"host"})
                except Exception:
                    pass
    except Exception:
        pass

    try:
        text = self.input_txt.get("1.0","end-1c")
    except Exception:
        text = ""
    # For brute force, allow a bit longer
    run_all_guessers(text, max_time_sec=6.0)

    ranked = sorted(_GLOBAL_COLLECTOR.items(), key=lambda c: c.score, reverse=True)
    self._last_ranked_candidates = ranked
    if ranked:
        top = ranked[0]
        try:
            self.output_preview_txt.delete("1.0","end")
            self.output_preview_txt.insert("1.0", f"[{top.cipher}] key={top.key}\n\n{top.plaintext}")
        except Exception:
            try:
                self.output_txt.delete("1.0","end")
                self.output_txt.insert("1.0", top.plaintext)
            except Exception:
                pass
    return res

# -----------------------------------------------------------------------------
# GUI wiring: add menu items + hotkeys; patch methods
# -----------------------------------------------------------------------------
def _patch_tools_menu_more(self):
    try:
        m = self.root.nametowidget(self.root['menu'])
    except Exception:
        return
    # find or add Tools menu
    # We re-add only once (idempotent-ish)
    # Append extra entries:
    tools = tk.Menu(m, tearoff=0)
    tools.add_command(label="IOC Heatmap… (Ctrl+I)", command=self.open_ic_heatmap_window)
    tools.add_separator()
    tools.add_command(label="Export Ranked Candidates…", command=self.export_candidates_csv)
    # Attach alongside existing "Tools" (won't duplicate text if already used)
    m.add_cascade(label="Analysis", menu=tools)

def _bind_more_hotkeys(self):
    try:
        self.__class__._bind_keys_original(self)
    except Exception:
        pass
    self.root.bind("<Control-i>", lambda e: self.open_ic_heatmap_window())
    self.root.bind("<Control-I>", lambda e: self.open_ic_heatmap_window())

def install_guessers_and_heatmap():
    if 'CipherGUI' not in globals():
        return
    # IOC Heatmap window
    CipherGUI.open_ic_heatmap_window = _gui_open_ic_heatmap_window
    # Export CSV method
    CipherGUI.export_candidates_csv = _export_candidates_csv

    # If Kasiski window exists, augment with autosuggest buttons by wrapping
    if not hasattr(CipherGUI, "open_kasiski_window_original"):
        CipherGUI.open_kasiski_window_original = CipherGUI.open_kasiski_window
        CipherGUI.open_kasiski_window = _gui_open_kasiski_window_aug

    # Extend menu and bindings (on top of earlier patches)
    if not hasattr(CipherGUI, "_build_menu_original_more"):
        CipherGUI._build_menu_original_more = CipherGUI._build_menu
        CipherGUI._build_menu = lambda self_: (CipherGUI._build_menu_original_more(self_), _patch_tools_menu_more(self_))
    if not hasattr(CipherGUI, "_bind_keys_original_more"):
        CipherGUI._bind_keys_original_more = CipherGUI._bind_keys
        CipherGUI._bind_keys = lambda self_: (CipherGUI._bind_keys_original_more(self_), _bind_more_hotkeys(self_))

    # Wrap smart_guess / brute_force again to collect + add our candidates
    if not hasattr(CipherGUI, "smart_guess_original2"):
        CipherGUI.smart_guess_original2 = CipherGUI.smart_guess
        CipherGUI.smart_guess = _wrap_smart_guess_collect
    if not hasattr(CipherGUI, "brute_force_original2"):
        CipherGUI.brute_force_original2 = CipherGUI.brute_force
        CipherGUI.brute_force = _wrap_bruteforce_collect

install_guessers_and_heatmap()

# =============================================================================
# OPTIONAL: small status panel showing top N candidates live (non-intrusive)
# (If your GUI already has a preview, this is skipped gracefully.)
# =============================================================================
def _attach_candidates_panel(self):
    try:
        container = ttk.Frame(self.right_pane)
    except Exception:
        return
    try:
        container.pack(fill="both", expand=False, padx=8, pady=(4,8))
        ttk.Label(container, text="Top Candidates (live)", font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
        tree = ttk.Treeview(container, columns=("rank","cipher","key","score"), show="headings", height=6)
        for col,w in (("rank",50),("cipher",120),("key",220),("score",100)):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w")
        tree.pack(fill="x", pady=(4,0))
        # attach as attribute
        self._cand_tree = tree
        # periodic updater
        def refresh():
            try:
                items = getattr(self, "_last_ranked_candidates", [])[:12]
                tree.delete(*tree.get_children())
                for i,c in enumerate(items, start=1):
                    tree.insert("", "end", values=(i, c.cipher, c.key, f"{c.score:.3f}"))
            except Exception:
                pass
            finally:
                try:
                    self.root.after(800, refresh)
                except Exception:
                    pass
        refresh()
    except Exception:
        pass

def install_candidates_panel():
    if 'CipherGUI' not in globals():
        return
    if not hasattr(CipherGUI, "_post_layout_original"):
        # Assume CipherGUI has a _post_layout hook after building widgets
        CipherGUI._post_layout_original = getattr(CipherGUI, "_post_layout", lambda self: None)
        def _post_layout_wrap(self):
            try:
                self._post_layout_original()
            except Exception:
                pass
            _attach_candidates_panel(self)
        CipherGUI._post_layout = _post_layout_wrap

install_candidates_panel()
# =============================================================================
# TEST BENCH (tab + window) — roundtrip + known-vector tests, CSV export
# =============================================================================
import time, csv, io, json, math, random
from collections import namedtuple

# ---- utilities ---------------------------------------------------------------
def _exists(fn_name: str) -> bool:
    return fn_name in globals() and callable(globals()[fn_name])

def _try(fn_name: str, default=None):
    try:
        return globals()[fn_name]
    except KeyError:
        return default

def _norm_alpha(s: str) -> str:
    # Normalize text for comparison: A..Z only
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

def _norm_words(s: str) -> str:
    # looser normalization: letters + spaces collapsed
    out=[]
    last_space=False
    for ch in s:
        u = ch.upper()
        if 'A' <= u <= 'Z':
            out.append(u); last_space=False
        elif ch.isspace():
            if not last_space:
                out.append(' ')
            last_space=True
    return "".join(out).strip()

def _norm_playfair(s: str) -> str:
    # Allow X padding and I/J conflation
    t = _norm_alpha(s).replace('J','I')
    # Remove probable padding X between duplicate letters or at end — heuristic
    # Keep it simple: just strip trailing X
    return t[:-1] if t.endswith('X') else t

def _ok_eq(a: str, b: str) -> bool:
    return _norm_alpha(a) == _norm_alpha(b)

def _ok_words(a: str, b: str) -> bool:
    return _norm_words(a) == _norm_words(b)

def _safe_call(fn, *args, **kwargs):
    try:
        return True, fn(*args, **kwargs)
    except Exception as e:
        return False, e

# ---- test model --------------------------------------------------------------
TestCase = namedtuple("TestCase",
    "family name mode enc_fn dec_fn params pt ref_ct normalizer")

# mode: "roundtrip" or "decode_only"
# enc_fn/dec_fn: callables or None
# params: dict merged into enc/dec kwargs
# pt: plaintext for roundtrip; ref_ct: known ciphertext for decode_only
# normalizer: one of (_norm_alpha, _norm_words, _norm_playfair) or custom

def _mk_roundtrip(family, name, enc, dec, pt, params=None, norm=None):
    return TestCase(family, name, "roundtrip", enc, dec, params or {}, pt, None, norm or _norm_words)

def _mk_decode_only(family, name, dec, ref_ct, exp_pt, params=None, norm=None):
    # piggy-back 'pt' to carry expected plaintext
    return TestCase(family, name, "decode_only", None, dec, params or {}, exp_pt, ref_ct, norm or _norm_words)

def _build_tests() -> List[TestCase]:
    """Build deterministic smoke tests for the GUI/CLI test bench."""
    T: List[TestCase] = []
    T.append(_mk_roundtrip("Substitution", "Caesar shift 1", Caesar_encode, Caesar_decode,
                           "THIS IS A SECRET", {"shift": 1}, _norm_words))
    T.append(_mk_roundtrip("Substitution", "Atbash", Atbash_encode, Atbash_decode,
                           "ATTACK AT DAWN", {}, _norm_words))
    T.append(_mk_roundtrip("Polyalphabetic", "Vigenere", Vigenere_encode, Vigenere_decode,
                           "ATTACKATDAWN", {"key": "LEMON"}, _norm_alpha))
    T.append(_mk_roundtrip("Transposition", "Rail Fence", RailFence_encode, RailFence_decode,
                           "WEAREDISCOVERED", {"rails": 3}, _norm_alpha))
    T.append(_mk_roundtrip("Encoding", "Base64", Base64_encode, Base64_decode,
                           "hello world", {}, lambda s: s))
    T.append(_mk_roundtrip("Rotor", "Enigma I", EnigmaI_encode, EnigmaI_decode,
                           "ATTACKATDAWN", {"rotors": "I II III", "reflector": "B", "ring": "AAA", "setting": "ABC", "plugboard": "AV BS CG DL FU HZ IN KM OW RX"}, _norm_alpha))
    T.append(_mk_roundtrip("Rotor", "Typex", Typex_encode, Typex_decode,
                           "ATTACKATDAWN", {"rotors": "IV V II", "reflector": "C", "ring": "AAA", "setting": "BDF", "plugboard": ""}, _norm_alpha))
    T.append(_mk_roundtrip("Rotor", "SIGABA Toy", SIGABAToy_encode, SIGABAToy_decode,
                           "ATTACKATDAWN", {"key": "SIGABA", "control": "CONTROL"}, _norm_alpha))
    T.append(_mk_roundtrip("Rotor", "M-209", M209_encode, M209_decode,
                           "ATTACKATDAWN", {"key": "SECRET", "wheels": "26,25,23,21,19,17"}, _norm_alpha))
    return T

# ---- runner -----------------------------------------------------------------
class TestResult:
    __slots__ = ("family","name","ok","pt","ct","err","elapsed","note")
    def __init__(self, family,name, ok, pt, ct, err, elapsed, note=""):
        self.family=family; self.name=name; self.ok=ok
        self.pt=pt; self.ct=ct; self.err=err; self.elapsed=elapsed; self.note=note

def _run_one_test(tc: TestCase) -> TestResult:
    t0 = time.time()
    note = ""
    try:
        if tc.mode == "roundtrip":
            if not (tc.enc_fn and tc.dec_fn):
                return TestResult(tc.family, tc.name, False, "", "", "Missing enc/dec", 0.0)
            ok, enc = _safe_call(tc.enc_fn, tc.pt, **tc.params)
            if not ok:
                return TestResult(tc.family, tc.name, False, "", "", f"EncErr:{enc}", time.time()-t0)
            ct = enc
            ok, dec = _safe_call(tc.dec_fn, ct, **tc.params)
            if not ok:
                return TestResult(tc.family, tc.name, False, "", ct if isinstance(ct,str) else str(ct),
                                  f"DecErr:{dec}", time.time()-t0)
            pt2 = dec
            good = (tc.normalizer(pt2) == tc.normalizer(tc.pt))
            return TestResult(tc.family, tc.name, good, str(pt2), str(ct), "" if good else "Mismatch", time.time()-t0)

        elif tc.mode == "decode_only":
            # Known CT -> expected PT (in tc.pt)
            dec_fn = tc.dec_fn
            if dec_fn is None:
                return TestResult(tc.family, tc.name, False, "", tc.ref_ct, "No decoder", time.time()-t0)
            ok, dec = _safe_call(dec_fn, tc.ref_ct, **tc.params)
            if not ok:
                return TestResult(tc.family, tc.name, False, "", tc.ref_ct, f"DecErr:{dec}", time.time()-t0)
            pt2 = dec
            good = (tc.normalizer(pt2) == tc.normalizer(tc.pt))
            return TestResult(tc.family, tc.name, good, str(pt2), str(tc.ref_ct), "" if good else "Mismatch", time.time()-t0)

        else:
            return TestResult(tc.family, tc.name, False, "", "", f"Unknown mode {tc.mode}", time.time()-t0)
    except Exception as e:
        return TestResult(tc.family, tc.name, False, "", "", f"Err:{e}", time.time()-t0)

# ---- GUI: Test Bench window / tab -------------------------------------------
class TestBench(ttk.Frame):
    COLS = ("Family","Name","OK","Ciphertext","Plaintext","Error","ms")
    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.tests = _build_tests()
        self.results = []
        self._make_ui()

    def _make_ui(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=(10,6))
        ttk.Label(top, text=f"Discovered tests: {len(self.tests)}", font=("TkDefaultFont",10,"bold")).pack(side="left")
        self.only_failed = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Show failed only", variable=self.only_failed, command=self._refresh_view).pack(side="left", padx=10)

        btns = ttk.Frame(top); btns.pack(side="right")
        ttk.Button(btns, text="Run All", command=self.run_all).pack(side="left", padx=4)
        ttk.Button(btns, text="Run Failed", command=self.run_failed).pack(side="left", padx=4)
        ttk.Button(btns, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(btns, text="Copy Console Summary", command=self.copy_console_summary).pack(side="left", padx=4)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=10, pady=6)
        self.tree = ttk.Treeview(mid, columns=self.COLS, show="headings", height=16)
        for c in self.COLS:
            self.tree.heading(c, text=c)
            width = 110 if c in ("Family","Name","OK","ms") else 300
            self.tree.column(c, width=width, anchor="w")
        yscroll = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="left", fill="y")

        # row styles
        style = ttk.Style(self)
        style.map("Ok.Treeview", background=[("selected","#2e7")])
        style.map("Fail.Treeview", background=[("selected","#f96")])
        # progress
        bottom = ttk.Frame(self); bottom.pack(fill="x", padx=10, pady=(0,10))
        self.pb = ttk.Progressbar(bottom, maximum=max(1,len(self.tests)))
        self.pb.pack(fill="x")

        self._refresh_view()

    def _refresh_view(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.results or []:
            if self.only_failed.get() and r.ok:
                continue
            tag = ("pass",) if r.ok else ("fail",)
            oktext = "✔" if r.ok else "✖"
            ms = f"{int(r.elapsed*1000)}"
            self.tree.insert("", "end", values=(r.family, r.name, oktext, r.ct, r.pt, r.err, ms), tags=tag)
        self.tree.tag_configure("pass", background="#eaffea")
        self.tree.tag_configure("fail", background="#ffecec")

    def run_all(self):
        self.results = []
        self.pb["value"]=0
        self.update_idletasks()
        out_lines=[]
        # Classic console banner (like user log)
        print("="*8, "TEST BENCH RUN", "="*8)
        fam_groups={}
        for i,tc in enumerate(self.tests, 1):
            r = _run_one_test(tc)
            self.results.append(r)
            fam_groups.setdefault(r.family, []).append(r)
            self.pb["value"]=i
            self._refresh_view()
            self.update_idletasks()
            # Print per-family line compactly like the original style
        # Emit a summary block per family to console
        for fam, rows in fam_groups.items():
            okc = sum(1 for x in rows if x.ok)
            tot = len(rows)
            # print a representative line (first) like earlier logs
            rep = rows[0]
            ct_show = (rep.ct[:60] + "…") if len(rep.ct)>60 else rep.ct
            pt_show = (rep.pt[:40] + "…") if len(rep.pt)>40 else rep.pt
            print(f"{fam:<13} ok={str(okc==tot):<5}  ct={ct_show}  pt={pt_show}")
        print("Summary:", f"Families tested: {len(fam_groups)}. Total cases: {len(self.tests)}. Passes:", sum(1 for r in self.results if r.ok), "/", len(self.tests))

    def run_failed(self):
        if not self.results:
            return self.run_all()
        failed = [t for t,r in zip(self.tests,self.results) if not r.ok]
        if not failed:
            messagebox.showinfo("Run Failed", "No failed tests to re-run.")
            return
        # temporarily restrict tests to failed, run, then re-expand
        orig_tests = self.tests
        self.tests = failed
        try:
            self.run_all()
        finally:
            self.tests = orig_tests

    def export_csv(self):
        if fd is None:
            messagebox.showerror("Export CSV", "File dialog not available.")
            return
        path = fd.asksaveasfilename(title="Export Test Results", defaultextension=".csv",
                                    filetypes=[("CSV","*.csv"),("All files","*.*")])
        if not path: return
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Family","Name","OK","Ciphertext","Plaintext","Error","ms"])
            for r in self.results:
                w.writerow([r.family, r.name, r.ok, r.ct, r.pt, r.err, int(r.elapsed*1000)])
        messagebox.showinfo("Export CSV", f"Saved to:\n{path}")

    def copy_console_summary(self):
        # Generate the classic console summary and copy to clipboard
        fam_groups={}
        for r in self.results:
            fam_groups.setdefault(r.family, []).append(r)
        buf = io.StringIO()
        for fam, rows in fam_groups.items():
            okc = sum(1 for x in rows if x.ok)
            tot = len(rows)
            rep = rows[0]
            ct_show = (rep.ct[:60] + "…") if isinstance(rep.ct,str) and len(rep.ct)>60 else rep.ct
            pt_show = (rep.pt[:40] + "…") if isinstance(rep.pt,str) and len(rep.pt)>40 else rep.pt
            buf.write(f"{fam:<13} ok={str(okc==tot):<5}  ct={ct_show}  pt={pt_show}\n")
        buf.write(f"Summary: Families tested: {len(fam_groups)}. Total cases: {len(self.tests)}. Passes: {sum(1 for r in self.results if r.ok)}/{len(self.tests)}\n")
        try:
            self.clipboard_clear()
            self.clipboard_append(buf.getvalue())
            messagebox.showinfo("Copied", "Console-style summary copied to clipboard.")
        except Exception:
            # fall back: print
            print(buf.getvalue())

# ---- hook into GUI: add tab if Notebook exists; otherwise a Tools→Test Bench ---
def _install_test_tab():
    if 'CipherGUI' not in globals():
        # fallback: create a simple launcher function
        def _open_standalone_test():
            root = tk.Toplevel()
            root.title("Test Bench")
            frm = TestBench(root)
            frm.pack(fill="both", expand=True)
            root.geometry("1024x520")
        globals()["_open_test_bench_window"] = _open_standalone_test
        return

    # Wrap the menu to add Tools → Test Bench
    if not hasattr(CipherGUI, "_build_menu_original_test"):
        CipherGUI._build_menu_original_test = CipherGUI._build_menu
        def _build_menu_wrap(self):
            CipherGUI._build_menu_original_test(self)
            mbar = self.root.nametowidget(self.root['menu'])
            # ensure a Tools menu exists
            tools = tk.Menu(mbar, tearoff=0)
            tools.add_command(label="Test Bench…", command=lambda: self.open_test_bench())
            mbar.add_cascade(label="Tools", menu=tools)
        CipherGUI._build_menu = _build_menu_wrap

    # Add method to open test bench window
    if not hasattr(CipherGUI, "open_test_bench"):
        def open_test_bench(self):
            win = tk.Toplevel(self.root)
            win.title("Test Bench")
            tab = TestBench(win)
            tab.pack(fill="both", expand=True)
            win.geometry("1100x560")
        CipherGUI.open_test_bench = open_test_bench

    # If the app uses a Notebook and has a known attribute, try adding a tab on startup
    if not hasattr(CipherGUI, "_post_layout_original_testtab"):
        old = getattr(CipherGUI, "_post_layout", lambda self: None)
        def _post_layout_wrap(self):
            try: old(self)
            except Exception: pass
            # attach as a tab if we can find a ttk.Notebook
            nb = None
            # try common attribute names
            for attr in ("notebook","nb","tabs","main_nb"):
                obj = getattr(self, attr, None)
                if isinstance(obj, ttk.Notebook):
                    nb = obj; break
            if nb is not None:
                frame = ttk.Frame(nb)
                bench = TestBench(frame)
                bench.pack(fill="both", expand=True)
                nb.add(frame, text="Tests")
        CipherGUI._post_layout = _post_layout_wrap

_install_test_tab()


if __name__ == "__main__":
    # If any CLI args: run CLI. Else: launch GUI (if available).
    if len(sys.argv) > 1:
        sys.exit(cli_main(sys.argv[1:]))
    else:
        try:
            if tk is not None:
                launch_gui()
            else:
                # Fallback: print list
                print("Tkinter not found. Use CLI. Example:")
                print("  python encripter.py list")
                print("  python encripter.py encode Caesar \"HELLO\" -p shift=5")
                print("  python encripter.py guess \"Gur dhvpx oebja sbk\"")
        except KeyboardInterrupt:
            pass
