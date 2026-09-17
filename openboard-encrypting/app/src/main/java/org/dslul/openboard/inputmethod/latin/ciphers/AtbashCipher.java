package org.dslul.openboard.inputmethod.latin.ciphers;

/** Simple reciprocal Atbash substitution cipher. */
public final class AtbashCipher implements MessageCipher {
    @Override
    public String encrypt(final String input) {
        return transform(input);
    }

    @Override
    public String decrypt(final String input) {
        return transform(input);
    }

    private static String transform(final String input) {
        final StringBuilder output = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                output.append((char)('Z' - (c - 'A')));
            } else if (c >= 'a' && c <= 'z') {
                output.append((char)('z' - (c - 'a')));
            } else {
                output.append(c);
            }
        }
        return output.toString();
    }
}
