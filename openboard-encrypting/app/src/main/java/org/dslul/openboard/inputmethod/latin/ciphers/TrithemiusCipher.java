package org.dslul.openboard.inputmethod.latin.ciphers;

/** Trithemius progressive Caesar cipher. */
public final class TrithemiusCipher implements MessageCipher {
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
        int position = 0;
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            final char upper = Character.toUpperCase(c);
            if (upper < 'A' || upper > 'Z') {
                output.append(c);
                continue;
            }
            final int shift = position % 26;
            final int value = upper - 'A';
            final char transformed =
                    (char)('A' + (decrypt ? value - shift + 26 : value + shift) % 26);
            output.append(Character.isLowerCase(c)
                    ? Character.toLowerCase(transformed) : transformed);
            position++;
        }
        return output.toString();
    }
}
