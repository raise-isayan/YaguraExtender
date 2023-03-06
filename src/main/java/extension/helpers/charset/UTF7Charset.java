package extension.helpers.charset;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.Arrays;
import java.util.List;

/**
 * base code https://sourceforge.net/projects/jutf7/
 */
public class UTF7Charset extends Charset {

    private static final String SET_D = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),-./:?";
    private static final String SET_O = "!\"#$%&*;<=>@[]^_`{|}";
    private static final String RULE_3 = " \t\r\n";
    final String directlyEncoded;

    private static final List CONTAINED = Arrays.asList(new String[]{"US-ASCII", "ISO-8859-1",
        "UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE"});
    private final boolean strict;

    public UTF7Charset(String name, String[] aliases) {
        this(name, aliases, false);
    }

    public UTF7Charset(String name, String[] aliases, boolean includeOptional) {
        super(name, aliases);
        this.strict = false;
        if (includeOptional) {
            this.directlyEncoded = SET_D + SET_O + RULE_3;
        } else {
            this.directlyEncoded = SET_D + RULE_3;
        }
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.Charset#contains(java.nio.charset.Charset)
     */
    public boolean contains(final Charset cs) {
        return CONTAINED.contains(cs.name());
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.Charset#newDecoder()
     */
    public CharsetDecoder newDecoder() {
        return new UTF7Decoder(this);
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.Charset#newEncoder()
     */
    public CharsetEncoder newEncoder() {
        return new UTF7Encoder(this);
    }

    /**
     * Tells if a character can be encoded using simple (US-ASCII) encoding or
     * requires base 64 encoding.
     *
     * @param ch The character
     * @return True if the character can be encoded directly, false otherwise
     */
    boolean canEncodeDirectly(char ch) {
        return directlyEncoded.indexOf(ch) >= 0;
    }

    public static final char BEGIN_SHIFT = '+';
    public static final char END_SHIFT = '-';

}
