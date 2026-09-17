package org.dslul.openboard.inputmethod.latin.ciphers;

/**
 * Caesar cipher implementation that shifts ASCII letters while leaving other characters unchanged.
 */
public final class CaesarCipher implements MessageCipher {
    private static final int ALPHABET_SIZE = 26;

    private final int mShift;

    public CaesarCipher(final int shift) {
        mShift = shift;
    }

    @Override
    public String encrypt(final String input) {
        return apply(input, mShift);
    }

    @Override
    public String decrypt(final String input) {
        return apply(input, -mShift);
    }

    private static String apply(final String input, final int shift) {
        final int normalizedShift = ((shift % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
        final StringBuilder result = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                result.append((char)('A' + (c - 'A' + normalizedShift) % ALPHABET_SIZE));
            } else if (c >= 'a' && c <= 'z') {
                result.append((char)('a' + (c - 'a' + normalizedShift) % ALPHABET_SIZE));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
