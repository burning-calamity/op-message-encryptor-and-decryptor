package org.dslul.openboard.inputmethod.latin.ciphers;

/** Gronsfeld cipher, a Vigenere variant using digit shifts. */
public final class GronsfeldCipher implements MessageCipher {
    private final String mKey;

    public GronsfeldCipher(final String key) {
        final String normalized = key == null ? "" : key.replaceAll("[^0-9]", "");
        mKey = normalized.isEmpty() ? "31415" : normalized;
    }

    @Override
    public String encrypt(final String input) {
        return transform(input, false);
    }

    @Override
    public String decrypt(final String input) {
        return transform(input, true);
    }

    private String transform(final String input, final boolean decrypt) {
        final StringBuilder output = new StringBuilder(input.length());
        int keyIndex = 0;
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            final char upper = Character.toUpperCase(c);
            if (upper < 'A' || upper > 'Z') {
                output.append(c);
                continue;
            }
            final int shift = mKey.charAt(keyIndex % mKey.length()) - '0';
            final int value = upper - 'A';
            final char transformed =
                    (char)('A' + (decrypt ? value - shift + 26 : value + shift) % 26);
            output.append(Character.isLowerCase(c)
                    ? Character.toLowerCase(transformed) : transformed);
            keyIndex++;
        }
        return output.toString();
    }
}
