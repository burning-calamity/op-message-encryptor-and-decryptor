import importlib.util
import base64
import json
import re
from pathlib import Path


def test_import():
    import ars_occultandarum_litterarum as package

    assert package.__version__ == "0.1.4"


def test_cipher_engine_copies_are_synchronized():
    from ars_occultandarum_litterarum import core

    root = Path(__file__).resolve().parents[1]
    source = (root / "encripter.py").read_bytes()

    assert (root / "ars_occultandarum_litterarum" / "core.py").read_bytes() == source
    assert (root / "apk" / "v1" / "encripter.py").read_bytes() == source

    html = (root / "index.html").read_bytes()
    match = re.search(rb'const PY_B64 = "([A-Za-z0-9+/=]+)";', html)
    assert match is not None
    assert base64.b64decode(match.group(1)) == source

    manifest = json.loads((root / "ciphers_manifest.json").read_text(encoding="utf-8"))
    registry = core.get_registry()
    assert [entry["name"] for entry in manifest] == [entry.name for entry in registry]
    assert [
        [(parameter["name"], parameter["default"]) for parameter in entry["parameters"]]
        for entry in manifest
    ] == [
        [(parameter.name, str(parameter.default)) for parameter in entry.params]
        for entry in registry
    ]


def test_new_field_ciphers_round_trip():
    from ars_occultandarum_litterarum import core

    vectors = [
        (
            "DRYAD Numeral Simulator",
            "Grid 1945-0830",
            {"keyword": "NIGHT", "row": "D", "sep": ""},
        ),
        (
            "BATCO Field Code Simulator",
            "MOVE 2 UNITS!",
            {"keyword": "NIGHT", "indicator": "K", "sep": " "},
        ),
        (
            "Trifid 4x4x4",
            "Sector7G",
            {"key": "Field", "period": "5"},
        ),
    ]

    for cipher, plaintext, params in vectors:
        ciphertext = core.call_encode(cipher, plaintext, params)
        assert core.call_decode(cipher, ciphertext, params) == plaintext


def test_registry_audit():
    from ars_occultandarum_litterarum import core

    report = core.audit_registry()
    assert report["ok"] is True
    assert report["cipher_count"] == len(core.get_registry())
    assert report["errors"] == []


def test_enigma_m3_m4_and_position_search():
    from ars_occultandarum_litterarum import core

    assert core.EnigmaI_encode("AAAAA", setting="AAA") == "BDZGO"

    plaintext = "SECRETMESSAGE"
    params = {
        "rotors": "Beta I II III",
        "reflector": "BThin",
        "ring": "AAAA",
        "setting": "QWER",
        "plugboard": "AV BS CG DL FU HZ IN KM OW RX",
    }
    ciphertext = core.EnigmaM4_encode(plaintext, **params)
    assert core.EnigmaM4_decode(ciphertext, **params) == plaintext

    ciphertext = core.EnigmaI_encode("HELLOWORLD", setting="AAB")
    results = core.crack_enigma_positions(
        ciphertext,
        rotors="I II III",
        reflector="B",
        ring="AAA",
        plugboard="",
        crib="HELLOWORLD",
        max_results=3,
        max_trials=2,
    )
    assert results[0]["setting"] == "AAB"
    assert results[0]["plaintext"] == "HELLOWORLD"


def test_hash_identification_and_bounded_search():
    import hashlib
    from ars_occultandarum_litterarum import core

    assert "md5" in core.identify_hash(hashlib.md5(b"hello").hexdigest())
    assert "sha256" in core.identify_hash(hashlib.sha256(b"hello").hexdigest())
    assert core._fnv1a32_bytes(b"hello") == 0x4F9F2CAB
    assert core._murmur3_x86_32_bytes(b"hello") == 0x248BFA47
    assert core._crc32c_bytes(b"123456789") == 0xE3069283

    target = hashlib.sha256(b"cab").hexdigest()
    result = core.search_hash_preimage(target, "sha256", "abc", 3, 3, 27)
    assert result["found"] is True
    assert result["candidate"] == "cab"


def test_aead_automatic_nonces_are_unique_and_embedded():
    if importlib.util.find_spec("cryptography") is None:
        return

    from ars_occultandarum_litterarum import core

    for encode, decode, marker in (
        (core.AESGCM_hex_encode, core.AESGCM_hex_decode, "[AESGCM]"),
        (
            core.ChaCha20Poly1305_hex_encode,
            core.ChaCha20Poly1305_hex_decode,
            "[CHACHA20POLY1305]",
        ),
    ):
        first = encode("repeatable message", key="test key")
        second = encode("repeatable message", key="test key")
        first_meta = json.loads(first[len(marker):].split("|", 1)[0])
        second_meta = json.loads(second[len(marker):].split("|", 1)[0])

        assert first != second
        assert first_meta["nonce"] != second_meta["nonce"]
        assert len(bytes.fromhex(first_meta["nonce"])) == 12
        assert decode(first, key="test key") == "repeatable message"
        assert decode(second, key="test key") == "repeatable message"


def test_cli_without_tkinter_prints_help(monkeypatch, capsys):
    from ars_occultandarum_litterarum import core

    monkeypatch.setattr(core, "TK_AVAILABLE", False)

    def unexpected_gui_launch():
        raise AssertionError("headless CLI attempted to launch Tkinter")

    monkeypatch.setattr(core, "launch_gui", unexpected_gui_launch)
    assert core.cli_main([]) == 0
    assert "usage: encripter" in capsys.readouterr().out


def test_tools_menu_test_bench_callback(monkeypatch):
    from ars_occultandarum_litterarum import core

    commands = []

    class FakeMenu:
        def __init__(self, *_args, **_kwargs):
            pass

        def add_command(self, **kwargs):
            commands.append(kwargs)

        def add_separator(self):
            pass

        def add_cascade(self, **_kwargs):
            pass

    class FakeRoot:
        def __getitem__(self, _key):
            return "menu"

        def nametowidget(self, _name):
            return FakeMenu()

    opened = []
    fake_gui = type(
        "FakeGUI",
        (),
        {
            "root": FakeRoot(),
            "open_freq_window": lambda self: None,
            "open_kasiski_window": lambda self: None,
            "open_scoring_window": lambda self: None,
            "open_test_bench": lambda self: opened.append(True),
        },
    )()

    monkeypatch.setattr(core.tk, "Menu", FakeMenu)
    core._install_tools_menu(fake_gui)
    test_bench_command = next(
        command["command"]
        for command in commands
        if command.get("label") == "Test Bench…"
    )
    test_bench_command()
    assert opened == [True]
