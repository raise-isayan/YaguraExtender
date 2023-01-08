package extension.helpers.charset;

import java.util.Arrays;

/**
 * base code https://sourceforge.net/projects/jutf7/
 */
public class Base64Util {

    private static final String BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "abcdefghijklmnopqrstuvwxyz" + "0123456789+/";

    private static final int ALPHABET_LENGTH = 64;
    private final char[] alphabet;
    private final int[] inverseAlphabet;

    Base64Util() {
        this(BASE64_ALPHABET);
    }

    /**
     * Initializes the class with the specified encoding/decoding alphabet.
     *
     * @param alphabet
     * @throws IllegalArgumentException if alphabet is not 64 characters long or
     * contains characters which are not 7-bit ASCII
     */
    Base64Util(final String alphabet) {
        this.alphabet = alphabet.toCharArray();
        if (alphabet.length() != ALPHABET_LENGTH) {
            throw new IllegalArgumentException("alphabet has incorrect length (should be 64, not "
                    + alphabet.length() + ")");
        }
        inverseAlphabet = new int[128];
        Arrays.fill(inverseAlphabet, -1);
        for (int i = 0; i < this.alphabet.length; i++) {
            final char ch = this.alphabet[i];
            if (ch >= 128) {
                throw new IllegalArgumentException("invalid character in alphabet: " + ch);
            }
            inverseAlphabet[ch] = i;
        }
    }

    /**
     * Returns the integer value of the six bits represented by the specified
     * character.
     *
     * @param ch The character, as a ASCII encoded byte
     * @return The six bits, as an integer value, or -1 if the byte is not in
     * the alphabet
     */
    int getSextet(final byte ch) {
        if (ch >= 128) {
            return -1;
        }
        return inverseAlphabet[ch];
    }

    /**
     * Tells whether the alphabet contains the specified character.
     *
     * @param ch The character
     * @return true if the alphabet contains <code>ch</code>, false otherwise
     */
    boolean contains(final char ch) {
        if (ch >= 128) {
            return false;
        }
        return inverseAlphabet[ch] >= 0;
    }

    /**
     * Encodes the six bit group as a character.
     *
     * @param sextet The six bit group to be encoded
     * @return The ASCII value of the character
     */
    byte getChar(final int sextet) {
        return (byte) alphabet[sextet];
    }

}
