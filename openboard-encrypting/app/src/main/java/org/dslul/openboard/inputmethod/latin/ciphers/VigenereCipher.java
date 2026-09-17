package org.dslul.openboard.inputmethod.latin.ciphers;

import java.util.Locale;

/** Vigenere polyalphabetic cipher. */
public final class VigenereCipher implements PositionedMessageCipher {
    private final String mKeyword;

    public VigenereCipher(final String keyword) {
        final String cleaned = keyword == null ? "" : keyword.toUpperCase(Locale.US).replaceAll("[^A-Z]", "");
        mKeyword = cleaned.isEmpty() ? "KEY" : cleaned;
    }

    @Override
    public String encrypt(final String input) {
        return encrypt(input, 0);
    }

    @Override
    public String decrypt(final String input) {
        return decrypt(input, 0);
    }

    @Override
    public String encrypt(final String input, final int position) {
        return transform(input, false, position);
    }

    @Override
    public String decrypt(final String input, final int position) {
        return transform(input, true, position);
    }

    private String transform(final String input, final boolean decrypt, final int position) {
        final StringBuilder output = new StringBuilder(input.length());
        int letters = Math.max(0, position);
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            final char upper = Character.toUpperCase(c);
            if (upper < 'A' || upper > 'Z') {
                output.append(c);
                continue;
            }
            final int shift = mKeyword.charAt(letters % mKeyword.length()) - 'A';
            final int base = upper - 'A';
            final int transformed = decrypt ? (base - shift + 26) % 26 : (base + shift) % 26;
            final char result = (char)('A' + transformed);
            output.append(Character.isLowerCase(c) ? Character.toLowerCase(result) : result);
            letters++;
        }
        return output.toString();
    }
}
