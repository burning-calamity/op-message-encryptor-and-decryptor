package org.dslul.openboard.inputmethod.latin.ciphers;

/** Adds or removes deterministic Zalgo combining marks. */
public final class ZalgoCipher implements MessageCipher {
    private static final char[] MARKS = {
            '\u030d', '\u030e', '\u0304', '\u0305', '\u033f', '\u0311', '\u0306', '\u0310',
            '\u0352', '\u0357', '\u0351', '\u0307', '\u0308', '\u030a', '\u0342', '\u0343',
            '\u0344', '\u034a', '\u034b', '\u034c', '\u0303', '\u0302', '\u030c', '\u0350',
            '\u0300', '\u0301', '\u030b', '\u030f', '\u0312', '\u0313', '\u0314', '\u033D',
            '\u0315', '\u031b', '\u0346', '\u031a', '\u0316', '\u0317', '\u0318', '\u0319',
            '\u031c', '\u031d', '\u031e', '\u031f', '\u0320', '\u0324', '\u0325', '\u0326',
            '\u0329', '\u032a', '\u032b', '\u032c', '\u032d', '\u032e', '\u032f', '\u0330',
            '\u0331', '\u0332', '\u0333', '\u0339', '\u033a', '\u033b', '\u033c', '\u0345',
            '\u0347', '\u0348', '\u0349', '\u034d', '\u034e', '\u0353', '\u0354', '\u0355',
            '\u0356', '\u0359', '\u035a', '\u0323'
    };

    private final int mIntensity;

    public ZalgoCipher(final int intensity) {
        mIntensity = Math.max(0, intensity);
    }

    @Override
    public String encrypt(final String input) {
        final StringBuilder output = new StringBuilder(
                input.length() * Math.max(1, mIntensity));
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            output.append(c);
            if (Character.isWhitespace(c) || isCombiningMark(c)) {
                continue;
            }
            for (int markIndex = 0; markIndex < mIntensity; markIndex++) {
                output.append(MARKS[Math.abs(c + i * 31 + markIndex * 17) % MARKS.length]);
            }
        }
        return output.toString();
    }

    @Override
    public String decrypt(final String input) {
        final StringBuilder output = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (!isCombiningMark(c)) {
                output.append(c);
            }
        }
        return output.toString();
    }

    private static boolean isCombiningMark(final char c) {
        final int type = Character.getType(c);
        return type == Character.NON_SPACING_MARK
                || type == Character.COMBINING_SPACING_MARK
                || type == Character.ENCLOSING_MARK;
    }
}
