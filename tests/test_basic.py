def test_import():
    import ars_occultandarum_litterarum


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
