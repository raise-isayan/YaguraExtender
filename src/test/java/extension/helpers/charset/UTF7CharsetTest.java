package extension.helpers.charset;

import extension.helpers.StringUtil;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class UTF7CharsetTest {

    public UTF7CharsetTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    public static String toUTF7Encode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{}, false);
        ByteBuffer bb = utf7cs.encode(str);
        byte[] content = new byte[bb.limit()];
        System.arraycopy(bb.array(), 0, content, 0, content.length);
        return new String(content, StandardCharsets.US_ASCII);
    }

    public static String toUTF7Decode(String str) {
        UTF7Charset utf7cs = new UTF7Charset("UTF-7", new String[]{}, false);
        CharBuffer cb = utf7cs.decode(ByteBuffer.wrap(StringUtil.getBytesCharset(str, StandardCharsets.US_ASCII)));
        return cb.toString();
    }

    /**
     * Test of UTF7Decode method, of class TransUtil.
     */
    @Test
    public void testToUTF7Decode() {
        System.out.println("toUTF7Decode");
        assertEquals("<", toUTF7Decode("+ADw-"));
        assertEquals("<script>", toUTF7Decode("+ADw-script+AD4-"));
        assertEquals("+", toUTF7Decode("+-"));
        assertEquals("変換前の文字列", toUTF7Decode("+WQlj21JNMG5lh1tXUhc-"));
    }

    /**
     * Test of UTF7Decode method, of class TransUtil.
     */
    @Test
    public void testTotoUTF7Encode() {
        System.out.println("toUTF7Encode");
        assertEquals("+ADw-", toUTF7Encode("<"));
        assertEquals("+ADw-script+AD4-", toUTF7Encode("<script>"));
        assertEquals("+-", toUTF7Encode("+"));
        assertEquals("+WQlj21JNMG5lh1tXUhc-", toUTF7Encode("変換前の文字列"));
    }

}
