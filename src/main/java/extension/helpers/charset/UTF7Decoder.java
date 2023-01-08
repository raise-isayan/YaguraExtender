package extension.helpers.charset;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;

/**
 * base code https://sourceforge.net/projects/jutf7/
 */
public class UTF7Decoder extends CharsetDecoder {
    private final Base64Util base64;
    private final boolean strict;
    private boolean base64mode;
    private int bitsRead;
    private int tempChar;
    private boolean justShifted;
    private boolean justUnshifted;

    public UTF7Decoder(UTF7Charset cs) {
        super(cs, 0.6f, 1.0f);
        this.base64 = new Base64Util();
        this.strict = false;
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.CharsetDecoder#decodeLoop(java.nio.ByteBuffer, java.nio.CharBuffer)
     */
    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
        while (in.hasRemaining()) {
            byte b = in.get();
            if (base64mode) {
                if (b == UTF7Charset.END_SHIFT) {
                    if (base64bitsWaiting()) {
                        return malformed(in);
                    }
                    if (justShifted) {
                        if (!out.hasRemaining()) {
                            return overflow(in);
                        }
                        out.put((char) UTF7Charset.BEGIN_SHIFT);
                    } else {
                        justUnshifted = true;
                    }
                    setUnshifted();
                } else {
                    if (!out.hasRemaining()) {
                        return overflow(in);
                    }
                    CoderResult result = handleBase64(in, out, b);
                    if (result != null) {
                        return result;
                    }
                }
                justShifted = false;
            } else {
                if (b == UTF7Charset.BEGIN_SHIFT) {
                    base64mode = true;
                    if (justUnshifted && strict) {
                        return malformed(in);
                    }
                    justShifted = true;
                    continue;
                }
                if (!out.hasRemaining()) {
                    return overflow(in);
                }
                out.put((char) b);
                justUnshifted = false;
            }
        }
        return CoderResult.UNDERFLOW;
    }

    private CoderResult overflow(ByteBuffer in) {
        in.position(in.position() - 1);
        return CoderResult.OVERFLOW;
    }

    /**
     * <p>
     * Decodes a byte in <i>base 64 mode</i>. Will directly write a character to
     * the output buffer if completed.</p>
     *
     * @param in The input buffer
     * @param out The output buffer
     * @param lastRead Last byte read from the input buffer
     * @return CoderResult.malformed if a non-base 64 character was encountered
     * in strict mode, null otherwise
     */
    private CoderResult handleBase64(ByteBuffer in, CharBuffer out, byte lastRead) {
        CoderResult result = null;
        int sextet = base64.getSextet(lastRead);
        if (sextet >= 0) {
            bitsRead += 6;
            if (bitsRead < 16) {
                tempChar += sextet << (16 - bitsRead);
            } else {
                bitsRead -= 16;
                tempChar += sextet >> (bitsRead);
                out.put((char) tempChar);
                tempChar = (sextet << (16 - bitsRead)) & 0xFFFF;
            }
        } else {
            if (strict) {
                return malformed(in);
            }
            out.put((char) lastRead);
            if (base64bitsWaiting()) {
                result = malformed(in);
            }
            setUnshifted();
        }
        return result;
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.CharsetDecoder#implFlush(java.nio.CharBuffer)
     */
    protected CoderResult implFlush(CharBuffer out) {
        if ((base64mode && strict) || base64bitsWaiting()) {
            return CoderResult.malformedForLength(1);
        }
        return CoderResult.UNDERFLOW;
    }

    /* (non-Javadoc)
	 * @see java.nio.charset.CharsetDecoder#implReset()
     */
    protected void implReset() {
        setUnshifted();
        justUnshifted = false;
    }

    /**
     * <p>
     * Resets the input buffer position to just before the last byte read, and
     * returns a result indicating to skip the last byte.</p>
     *
     * @param in The input buffer
     * @return CoderResult.malformedForLength(1);
     */
    private CoderResult malformed(ByteBuffer in) {
        in.position(in.position() - 1);
        return CoderResult.malformedForLength(1);
    }

    /**
     * @return True if there are base64 encoded characters waiting to be written
     */
    private boolean base64bitsWaiting() {
        return tempChar != 0 || bitsRead >= 6;
    }

    /**
     * <p>
     * Updates internal state to reflect the decoder is no longer in <i>base 64
     * mode</i></p>
     */
    private void setUnshifted() {
        base64mode = false;
        bitsRead = 0;
        tempChar = 0;
    }
}