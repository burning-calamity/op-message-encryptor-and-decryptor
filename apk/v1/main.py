"""Kivy APK entrypoint for the All-The-Ciphers toolkit.

This module intentionally avoids the desktop Tkinter GUI in encripter.py and
wraps the shared cipher registry with a small Android-friendly Kivy interface.
Buildozer treats a file named main.py as the application entrypoint.
"""

from __future__ import annotations

from typing import Dict

from kivy.app import App
from kivy.core.clipboard import Clipboard
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput

import encripter


class CipherMobileRoot(BoxLayout):
    """Minimal Kivy UI that exposes the encripter registry on Android."""

    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", padding=dp(8), spacing=dp(8), **kwargs)
        self.registry = encripter.get_registry()
        self.registry_by_name = {entry.name: entry for entry in self.registry}
        self.param_inputs: Dict[str, TextInput] = {}

        self.add_widget(self._build_filter_bar())
        self.add_widget(self._build_category_bar())
        self.add_widget(self._build_toolbar())
        self.add_widget(self._build_params_panel())
        self.add_widget(self._build_text_panels())
        self.add_widget(self._build_status_label())
        self.add_widget(self._build_actions())

        self._filter_ciphers()
        self._refresh_params()

    def _build_filter_bar(self) -> BoxLayout:
        bar = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        bar.add_widget(Label(text="Search", size_hint_x=0.18))
        self.search_input = TextInput(hint_text="Name, parameter, or default", multiline=False, size_hint_x=0.62)
        self.search_input.bind(text=lambda *_: self._filter_ciphers())
        bar.add_widget(self.search_input)
        clear_search_btn = Button(text="Clear", size_hint_x=0.2)
        clear_search_btn.bind(on_release=lambda *_: self._clear_search())
        bar.add_widget(clear_search_btn)
        return bar

    def _build_category_bar(self) -> BoxLayout:
        bar = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(42), spacing=dp(8))
        bar.add_widget(Label(text="Group", size_hint_x=0.18))
        self.category_spinner = Spinner(
            text="All",
            values=("All", "Classical", "Vigenere", "Transposition", "Morse/Symbol", "Encoding", "Checksums/Hash", "Modern", "Fun"),
            size_hint_x=0.82,
        )
        self.category_spinner.bind(text=lambda *_: self._filter_ciphers())
        bar.add_widget(self.category_spinner)
        return bar

    def _build_toolbar(self) -> BoxLayout:
        toolbar = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(48), spacing=dp(8))
        self.cipher_spinner = Spinner(
            text=self.registry[0].name,
            values=[entry.name for entry in self.registry],
            size_hint_x=0.7,
        )
        self.cipher_spinner.bind(text=lambda *_: self._refresh_params())
        self.mode_spinner = Spinner(text="encode", values=("encode", "decode"), size_hint_x=0.3)
        toolbar.add_widget(self.cipher_spinner)
        toolbar.add_widget(self.mode_spinner)
        return toolbar

    def _build_params_panel(self) -> ScrollView:
        scroll = ScrollView(size_hint_y=None, height=dp(96), do_scroll_x=False)
        self.params_box = BoxLayout(orientation="vertical", spacing=dp(4), size_hint_y=None)
        self.params_box.bind(minimum_height=self.params_box.setter("height"))
        scroll.add_widget(self.params_box)
        return scroll

    def _build_text_panels(self) -> BoxLayout:
        panels = BoxLayout(orientation="vertical", spacing=dp(8))
        panels.add_widget(Label(text="Input", size_hint_y=None, height=dp(24), halign="left"))
        self.input_text = TextInput(multiline=True, text="", size_hint_y=0.45)
        panels.add_widget(self.input_text)
        panels.add_widget(Label(text="Output", size_hint_y=None, height=dp(24), halign="left"))
        self.output_text = TextInput(multiline=True, readonly=True, text="", size_hint_y=0.45)
        panels.add_widget(self.output_text)
        return panels

    def _build_status_label(self) -> Label:
        self.status_label = Label(text="Ready", size_hint_y=None, height=dp(24), halign="left")
        return self.status_label

    def _build_actions(self) -> BoxLayout:
        actions = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(144), spacing=dp(8))
        left = BoxLayout(orientation="vertical", spacing=dp(6))
        middle = BoxLayout(orientation="vertical", spacing=dp(6))
        right = BoxLayout(orientation="vertical", spacing=dp(6))

        run_btn = Button(text="Run")
        run_btn.bind(on_release=lambda *_: self._run_cipher())
        guess_btn = Button(text="Guess")
        guess_btn.bind(on_release=lambda *_: self._smart_guess())
        analyze_btn = Button(text="Analyze")
        analyze_btn.bind(on_release=lambda *_: self._analyze_input())
        info_btn = Button(text="Info")
        info_btn.bind(on_release=lambda *_: self._show_cipher_info())
        selftest_btn = Button(text="Self-test")
        selftest_btn.bind(on_release=lambda *_: self._run_selftest())
        swap_btn = Button(text="Swap")
        swap_btn.bind(on_release=lambda *_: self._swap_text())
        paste_btn = Button(text="Paste")
        paste_btn.bind(on_release=lambda *_: self._paste_input())
        copy_btn = Button(text="Copy")
        copy_btn.bind(on_release=lambda *_: Clipboard.copy(self.output_text.text))
        clear_btn = Button(text="Clear")
        clear_btn.bind(on_release=lambda *_: self._clear_text())

        for button in (run_btn, guess_btn, analyze_btn):
            left.add_widget(button)
        for button in (info_btn, selftest_btn, swap_btn):
            middle.add_widget(button)
        for button in (paste_btn, copy_btn, clear_btn):
            right.add_widget(button)
        actions.add_widget(left)
        actions.add_widget(middle)
        actions.add_widget(right)
        return actions


    def _entry_search_blob(self, entry) -> str:
        param_bits = []
        for param in entry.params:
            param_bits.extend((param.name, param.label, param.default))
        return " ".join([entry.name, *param_bits]).lower()

    def _entry_matches_category(self, entry) -> bool:
        category = getattr(self, "category_spinner", None)
        selected = category.text if category else "All"
        if selected == "All":
            return True
        name = entry.name.lower()
        groups = {
            "Classical": ("caesar", "affine", "atbash", "substitution", "porta", "beaufort", "bacon", "nihilist", "chaocipher", "clave", "phillips"),
            "Vigenere": ("vigenere", "autokey", "running key", "gronsfeld", "quagmire", "trithemius", "progressive key"),
            "Transposition": ("rail", "route", "columnar", "scytale", "swagman", "cadenus", "checkerboard", "spiral", "boustrophedon", "redefence"),
            "Morse/Symbol": ("morse", "pigpen", "tap", "knock", "baudot", "braille", "semaphore", "cistercian", "nato", "apco"),
            "Encoding": ("base", "hex", "url", "unicode", "quoted", "punycode", "netstring", "bencode", "data uri", "z85", "ascii"),
            "Checksums/Hash": ("crc", "adler", "fletcher", "sha", "md5", "hmac", "pbkdf", "scrypt", "hkdf", "hotp", "totp", "luhn", "damm", "verhoeff"),
            "Modern": ("rc4", "chacha", "salsa", "tea", "speck", "simon", "rc5", "xxtea", "lorenz"),
            "Fun": ("leet", "emoji", "upside", "zalgo", "rune", "aurebesh", "theban", "ogham", "pig latin", "backslang", "calculator"),
        }
        return any(token in name for token in groups.get(selected, ()))

    def _filter_ciphers(self) -> None:
        query = getattr(self, "search_input", None)
        needle = query.text.strip().lower() if query else ""
        names = [
            entry.name
            for entry in self.registry
            if self._entry_matches_category(entry) and (not needle or needle in self._entry_search_blob(entry))
        ]
        if not names:
            names = [entry.name for entry in self.registry if self._entry_matches_category(entry)] or [entry.name for entry in self.registry]
        self.cipher_spinner.values = names
        if self.cipher_spinner.text not in names:
            self.cipher_spinner.text = names[0]
        if hasattr(self, "status_label"):
            self.status_label.text = f"{len(names)} / {len(self.registry)} ciphers"

    def _clear_search(self) -> None:
        self.search_input.text = ""
        self._filter_ciphers()

    def _refresh_params(self) -> None:
        self.params_box.clear_widgets()
        self.param_inputs.clear()
        entry = self.registry_by_name[self.cipher_spinner.text]
        if not entry.params:
            self.params_box.add_widget(Label(text="No parameters", size_hint_y=None, height=dp(32)))
            return
        for param in entry.params:
            row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(40), spacing=dp(6))
            row.add_widget(Label(text=param.label, size_hint_x=0.35))
            value = TextInput(text=param.default, multiline=False, size_hint_x=0.65)
            self.param_inputs[param.name] = value
            row.add_widget(value)
            self.params_box.add_widget(row)

    def _params(self) -> Dict[str, str]:
        return {name: widget.text for name, widget in self.param_inputs.items()}

    def _run_cipher(self) -> None:
        try:
            if self.mode_spinner.text == "decode":
                result = encripter.call_decode(self.cipher_spinner.text, self.input_text.text, self._params())
            else:
                result = encripter.call_encode(self.cipher_spinner.text, self.input_text.text, self._params())
            self.status_label.text = f"Ran {self.mode_spinner.text} with {self.cipher_spinner.text}"
        except Exception as exc:  # Surface errors in the mobile UI instead of crashing the Activity.
            result = f"Err:{exc}"
            self.status_label.text = "Error"
        self.output_text.text = result

    def _smart_guess(self) -> None:
        try:
            ranked = encripter.SmartGuess(self.input_text.text)[:10]
            lines = [f"{i+1}. {name} | score={score:.3f}\n{plain}" for i, (name, plain, score) in enumerate(ranked)]
            self.output_text.text = "\n\n".join(lines) if lines else "No candidates"
            self.status_label.text = f"SmartGuess: {len(ranked)} candidates shown"
        except Exception as exc:
            self.output_text.text = f"Err:{exc}"
            self.status_label.text = "SmartGuess error"

    def _analyze_input(self) -> None:
        text = self.input_text.text
        letters = [ch.upper() for ch in text if ch.isalpha()]
        counts = sorted(((ch, letters.count(ch)) for ch in set(letters)), key=lambda item: (-item[1], item[0]))
        try:
            ioc = encripter.index_of_coincidence(text)
        except Exception:
            ioc = 0.0
        top = ", ".join(f"{ch}:{count}" for ch, count in counts[:10]) or "none"
        self.output_text.text = (
            f"Characters: {len(text)}\n"
            f"Letters: {len(letters)}\n"
            f"Words: {len(text.split())}\n"
            f"Index of coincidence: {ioc:.4f}\n"
            f"Top letters: {top}"
        )
        self.status_label.text = "Analysis complete"

    def _show_cipher_info(self) -> None:
        entry = self.registry_by_name[self.cipher_spinner.text]
        if entry.params:
            params = "\n".join(f"- {p.label} ({p.name}) default={p.default!r}" for p in entry.params)
        else:
            params = "No parameters"
        self.output_text.text = (
            f"Cipher: {entry.name}\n"
            f"Mode: {self.mode_spinner.text}\n"
            f"Parameters:\n{params}"
        )
        self.status_label.text = f"Info for {entry.name}"

    def _run_selftest(self) -> None:
        try:
            passed, total = encripter._selftest()
            self.output_text.text = f"Self-test: {passed}/{total} checks passed"
            self.status_label.text = "Self-test complete"
        except Exception as exc:
            self.output_text.text = f"Err:{exc}"
            self.status_label.text = "Self-test error"

    def _paste_input(self) -> None:
        self.input_text.text = Clipboard.paste()
        self.status_label.text = "Pasted clipboard to input"

    def _swap_text(self) -> None:
        self.input_text.text, self.output_text.text = self.output_text.text, self.input_text.text
        self.mode_spinner.text = "decode" if self.mode_spinner.text == "encode" else "encode"
        self.status_label.text = "Swapped input/output and toggled mode"

    def _clear_text(self) -> None:
        self.input_text.text = ""
        self.output_text.text = ""
        self.status_label.text = "Cleared"


class AllTheCiphersApp(App):
    title = "All-The-Ciphers"

    def build(self):
        return CipherMobileRoot()


if __name__ == "__main__":
    AllTheCiphersApp().run()
