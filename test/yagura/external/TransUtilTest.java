package yagura.external;

import extend.util.ConvertUtil;
import extend.util.HttpUtil;
import extend.util.Util;
import yagura.external.TransUtil.EncodePattern;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import extend.util.HashUtil;
import java.time.LocalDate;
import java.time.Month;
import java.util.Locale;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author isayan
 */
public class TransUtilTest {

    public TransUtilTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testHexDump() {
        String output = ">あいうえお<";
        byte row[] = Util.getRawByte(output);
        System.out.println(row.length);
//        TransUtil.hexDump();
    }
    
    /**
     * Test of getSmartDecode method, of class TransUtil.
     */
    @Test
    public void testGetSmartDecode() {
        System.out.println("getSmartDecode");
        assertEquals(EncodePattern.URL_STANDARD, TransUtil.getSmartDecode("%21%22%23%24%25%26%27%28%29%3d%7e%7c%60%7b%7d*%2b%3c%3e%3f_%5cabcedf"));
        assertEquals(EncodePattern.URL_STANDARD, TransUtil.getSmartDecode("%21%22%23%24%25%26%27%28%29%3D%7E%7C%60%7B%7D*%2B%3C%3E%3F_%5cabcedf"));

        assertEquals(EncodePattern.URL_UNICODE, TransUtil.getSmartDecode("%u3042%u3044%u3046%u3048%u304a"));
        assertEquals(EncodePattern.URL_UNICODE, TransUtil.getSmartDecode("%U3042%U3044%U3046%U3048%U304A"));
        
        assertEquals(EncodePattern.BYTE_HEX, TransUtil.getSmartDecode("\\x82\\xa0\\x82\\xa2\\x82\\xa4\\x82\\xa6\\x82\\xa8"));
        assertEquals(EncodePattern.BYTE_HEX, TransUtil.getSmartDecode("\\x82\\xA0\\x82\\xA2\\x82\\xA4\\x82\\xA6\\x82\\xA8"));

        assertEquals(EncodePattern.BASE64, TransUtil.getSmartDecode("gqmCq4Ktgq+CsQ=="));
        assertEquals(EncodePattern.BASE64, TransUtil.getSmartDecode("pKukraSvpLGksw=="));
        assertEquals(EncodePattern.BASE64, TransUtil.getSmartDecode("44GL44GN44GP44GR44GT"));

        assertEquals(EncodePattern.HTML, TransUtil.getSmartDecode("&#33;&#34;&#35;&#36;&#37;&#38;&#39;&#40;&#41;&#61;&#126;&#124;&#96;&#123;&#125;&#42;&#43;&#60;&#62;&#63;&#95;&#92;&#97;&#98;&#99;&#101;&#100;&#102;"));

        assertEquals(EncodePattern.HTML, TransUtil.getSmartDecode("&#x21;&#x22;&#x23;&#x24;&#x25;&#x26;&#x27;&#x28;&#x29;&#x3d;&#x7e;&#x7c;&#x60;&#x7b;&#x7d;&#x2a;&#x2b;&#x3c;&#x3e;&#x3f;&#x5f;&#x5c;&#x61;&#x62;&#x63;&#x65;&#x64;&#x66;"));
        assertEquals(EncodePattern.HTML, TransUtil.getSmartDecode("&#X21;&#X22;&#X23;&#X24;&#X25;&#X26;&#X27;&#X28;&#X29;&#X3D;&#X7E;&#X7C;&#X60;&#X7B;&#X7D;&#X2A;&#X2B;&#X3C;&#X3E;&#X3F;&#X5F;&#X5C;&#X61;&#X62;&#X63;&#X65;&#X64;&#X66;"));
    
        assertEquals(EncodePattern.UNICODE, TransUtil.getSmartDecode("\\u3042\\u3044\\u3046\\u3048\\u304a"));
        assertEquals(EncodePattern.UNICODE, TransUtil.getSmartDecode("\\U3042\\U3044\\U3046\\U3048\\U304A"));        
    }
    
    /**
     * Test of toSmartDecode method, of class TransUtil.
     */
    @Test
    public void testToSmartDecode() {
        try {
            System.out.println("toSmartDecode");
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("%21%22%23%24%25%26%27%28%29%3d%7e%7c%60%7b%7d*%2b%3c%3e%3f_%5cabcedf"));
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("%21%22%23%24%25%26%27%28%29%3D%7E%7C%60%7B%7D*%2B%3C%3E%3F_%5cabcedf"));
            
            assertEquals("入口", TransUtil.toSmartDecode("%93%fc%8c%fb"));
            assertEquals("入口", TransUtil.toSmartDecode("%93%FC%8C%FB"));

            assertEquals("あいうえお", TransUtil.toSmartDecode("%82%a0%82%a2%82%a4%82%a6%82%a8"));
            assertEquals("あいうえお", TransUtil.toSmartDecode("%82%A0%82%A2%82%A4%82%A6%82%A8"));
            
            assertEquals("あいうえお", TransUtil.toSmartDecode("%a4%a2%a4%a4%a4%a6%a4%a8%a4%aa"));
            assertEquals("あいうえお", TransUtil.toSmartDecode("%A4%A2%A4%A4%A4%A6%A4%A8%A4%AA"));
            
            assertEquals("あいうえお", TransUtil.toSmartDecode("%e3%81%82%e3%81%84%e3%81%86%e3%81%88%e3%81%8a"));
            assertEquals("あいうえお", TransUtil.toSmartDecode("%E3%81%82%E3%81%84%E3%81%86%E3%81%88%E3%81%8A"));
            
            assertEquals("かきくけこ", TransUtil.toSmartDecode("gqmCq4Ktgq+CsQ=="));
            assertEquals("かきくけこ", TransUtil.toSmartDecode("pKukraSvpLGksw=="));
            assertEquals("かきくけこ", TransUtil.toSmartDecode("44GL44GN44GP44GR44GT"));
            
            assertEquals("かきくけこ", TransUtil.toSmartDecode("gqmCq\r\n4Ktgq+CsQ=="));
            
            System.out.println("getSmartDecode:" + TransUtil.getSmartDecode("&#33;&#34;&#35;&#36;&#37;&#38;&#39;&#40;&#41;&#61;&#126;&#124;&#96;&#123;&#125;&#42;&#43;&#60;&#62;&#63;&#95;&#92;&#97;&#98;&#99;&#101;&#100;&#102;"));
            
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("&#33;&#34;&#35;&#36;&#37;&#38;&#39;&#40;&#41;&#61;&#126;&#124;&#96;&#123;&#125;&#42;&#43;&#60;&#62;&#63;&#95;&#92;&#97;&#98;&#99;&#101;&#100;&#102;"));
            
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("&#x21;&#x22;&#x23;&#x24;&#x25;&#x26;&#x27;&#x28;&#x29;&#x3d;&#x7e;&#x7c;&#x60;&#x7b;&#x7d;&#x2a;&#x2b;&#x3c;&#x3e;&#x3f;&#x5f;&#x5c;&#x61;&#x62;&#x63;&#x65;&#x64;&#x66;"));
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("&#X21;&#X22;&#X23;&#X24;&#X25;&#X26;&#X27;&#X28;&#X29;&#X3D;&#X7E;&#X7C;&#X60;&#X7B;&#X7D;&#X2A;&#X2B;&#X3C;&#X3E;&#X3F;&#X5F;&#X5C;&#X61;&#X62;&#X63;&#X65;&#X64;&#X66;"));
            
            StringBuffer charset = new StringBuffer("Shift_JIS");
            assertEquals("あいうえお", TransUtil.toSmartDecode("\\x82\\xa0\\x82\\xa2\\x82\\xa4\\x82\\xa6\\x82\\xa8", EncodePattern.BYTE_HEX, charset));
            assertEquals("Shift_JIS", charset.toString());
            assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedfあいうえお!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toSmartDecode("!\"#$%&'()=~|`{}*+<>?_\\abcedf\\x82\\xa0\\x82\\xa2\\x82\\xa4\\x82\\xa6\\x82\\xa8!\"#$%&'()=~|`{}*+<>?_\\abcedf", EncodePattern.BYTE_HEX, charset));
            assertEquals("Shift_JIS", charset.toString());
            
            charset = new StringBuffer();
            assertEquals("あいうえお", TransUtil.toSmartDecode("\\x82\\xa0\\x82\\xa2\\x82\\xa4\\x82\\xa6\\x82\\xa8", EncodePattern.BYTE_HEX, charset));
            assertEquals("Shift_JIS", charset.toString());
            
            charset = new StringBuffer("8859_1");
            byte b[] = new byte[] {(byte)0x82,(byte)0xa0,(byte)0x82,(byte)0xa2,(byte)0x82,(byte)0xa4,(byte)0x82,(byte)0xa6,(byte)0x82,(byte)0xa8};
            assertEquals(new String(b, "8859_1"), TransUtil.toSmartDecode("\\x82\\xa0\\x82\\xa2\\x82\\xa4\\x82\\xa6\\x82\\xa8", EncodePattern.BYTE_HEX, charset));
            assertEquals("8859_1", charset.toString());
                        
            byte o[] = new byte[] {(byte)0202,(byte)0240,(byte)0202,(byte)0242,(byte)0202,(byte)0244,(byte)0202,(byte)0246,(byte)0202,(byte)0250,(byte)012};
            assertEquals(new String(o, "8859_1"), TransUtil.toSmartDecode("\\202\\240\\202\\242\\202\\244\\202\\246\\202\\250\\12", EncodePattern.BYTE_OCT, charset));
            assertEquals("8859_1", charset.toString());
            
            assertEquals("あいうえお", TransUtil.toSmartDecode("\\u3042\\u3044\\u3046\\u3048\\u304a"));
            assertEquals("あいうえお", TransUtil.toSmartDecode("\\U3042\\U3044\\U3046\\U3048\\U304A"));
            
            assertEquals("あいうえお", TransUtil.toSmartDecode("%u3042%u3044%u3046%u3048%u304a"));
            assertEquals("あいうえお", TransUtil.toSmartDecode("%U3042%U3044%U3046%U3048%U304A"));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
                
    }
    
    
    /**
     * Test of toMd5Sum method, of class TransUtil.
     */
    @Test
    public void testToMd5Sum() {
        System.out.println("toMd5Sum");
        assertEquals("098f6bcd4621d373cade4e832627b4f6", HashUtil.toMd5Sum("test", false));
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", HashUtil.toMd5Sum("", false));
    }

    /**
     * Test of toSHA1Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA1Sum() {
        System.out.println("toSHA1Sum");
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", HashUtil.toSHA1Sum("test", false));
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", HashUtil.toSHA1Sum("", false));
    }

    /**
     * Test of toSHA256Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA256Sum() {
        System.out.println("toSHA256Sum");
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", HashUtil.toSHA256Sum("test", false));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", HashUtil.toSHA256Sum("", false));
    }

    /**
     * Test of toSHA384Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA384Sum() {
        System.out.println("toSHA384Sum");
        assertEquals("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", HashUtil.toSHA384Sum("test", false));
        assertEquals("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", HashUtil.toSHA384Sum("", false));
    }

    /**
     * Test of toSHA512Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA512Sum() {
        System.out.println("toSHA512Sum");
        assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", HashUtil.toSHA512Sum("test", false));
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", HashUtil.toSHA512Sum("", false));
    }
    
    /**
     * Test of toInteger method, of class TransUtil.
     */
    @Test
    public void testToInteger() {
        System.out.println("toInteger");
        assertEquals(0x7fff, TransUtil.toInteger(new byte[]{(byte) 0x7f, (byte) 0xff}));
        assertEquals(0xff7f, TransUtil.toInteger(new byte[]{(byte) 0xff, (byte) 0x7f}));
        assertEquals(0x8080, TransUtil.toInteger(new byte[]{(byte) 0x80, (byte) 0x80}));
    }

    /**
     * Test of toBASE64Encoder method, of class TransUtil.
     */
    @Test
    public void testToBASE64Encoder() {
        try {
            System.out.println("toBASE64Encoder");
            assertEquals("PA==", ConvertUtil.toBase64Encode("<", "8859_1"));
            assertEquals("dGVzdA==", ConvertUtil.toBase64Encode("test", "8859_1"));
            assertEquals("ZnVnYWY=", ConvertUtil.toBase64Encode("fugaf", "8859_1"));
            assertEquals("aG9nZWhv", ConvertUtil.toBase64Encode("hogeho", "8859_1"));

            System.out.println(TransUtil.newLine("\r\n", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 76));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            assertTrue(false);
        }
    }

    /**
     * Test of toBASE64Decode method, of class TransUtil.
     */
    @Test
    public void testToBASE64Decoder() {
        try {
            System.out.println("toBASE64Decoder");
            assertEquals("<", ConvertUtil.toBase64Decode("PA==", "8859_1"));
            assertEquals("hogeho", ConvertUtil.toBase64Decode("aG9nZWhv", "8859_1"));
            assertEquals("fugaf", ConvertUtil.toBase64Decode("ZnVnYWY=", "8859_1"));
            assertEquals("test", ConvertUtil.toBase64Decode("dGVzdA==", "8859_1"));
            System.out.println(ConvertUtil.toBase64Decode("absdadbd", "8859_1"));
            byte[] bytes = DatatypeConverter.parseHexBinary("abdadb0d");           
            System.out.println(TransUtil.toHexString(bytes));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            assertTrue(false);
        }
    }


   
    /**
     * Test of UTF7Decode method, of class TransUtil.
     */
    @Test
    public void testToUTF7Decode() {
        System.out.println("toUTF7Decode");
        assertEquals("<", TransUtil.toUTF7Decode("+ADw-"));
        assertEquals("<script>", TransUtil.toUTF7Decode("+ADw-script+AD4-"));
        assertEquals("+", TransUtil.toUTF7Decode("+-"));
    }

    /**
     * Test of UTF7Decode method, of class TransUtil.
     */
    @Test
    public void testTotoUTF7Encode() {
        System.out.println("toUTF7Encode");
        assertEquals("+ADw-", TransUtil.toUTF7Encode("<"));
        assertEquals("+ADw-script+AD4-", TransUtil.toUTF7Encode("<script>"));
        assertEquals("+-", TransUtil.toUTF7Encode("+"));
    }

    /**
     * Test of toHtmlEncode method, of class TransUtil.
     */
    @Test
    public void testToHtmlEncode() {
        System.out.println("toHtmlEncode");
        assertEquals("!&quot;#$%&amp;&#39;()=~|`{}*+&lt;&gt;?_\\\r\nabcedf", TransUtil.toHtmlEncode("!\"#$%&'()=~|`{}*+<>?_\\\r\nabcedf"));
    }

    /**
     * Test of toHtmlDecode method, of class TransUtil.
     */
    @Test
    public void testToHtmlDecode() {
        System.out.println("toHtmlDecode");
        assertEquals("!\"#$%&'()=~|`{}*+<>?_\\abcedf", TransUtil.toHtmlDecode("!&quot;#$%&amp;&#39;()=~|`{}*+&lt;&gt;?_\\abcedf"));
        assertEquals("'''", TransUtil.toHtmlDecode("&#39;&#x27;&#X27;"));
        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals(x, TransUtil.toHtmlDecode("&#106;&#107;&#102;&#131083;&#135741;&#103;&#104;&#105;&#135963;&#136302;&#137405;&#134047;&#136884;&#138804;&#143812;&#144836;&#97;&#98;&#122;&#48;&#49;&#57;"));
        assertEquals(x, TransUtil.toHtmlDecode("&#x6a;&#x6b;&#x66;&#x2000b;&#x2123d;&#x67;&#x68;&#x69;&#x2131b;&#x2146e;&#x218bd;&#x20b9f;&#x216b4;&#x21e34;&#x231c4;&#x235c4;&#x61;&#x62;&#x7a;&#x30;&#x31;&#x39;"));
        assertEquals(x, TransUtil.toHtmlDecode("&#X6A;&#X6B;&#X66;&#X2000B;&#X2123D;&#X67;&#X68;&#X69;&#X2131B;&#X2146E;&#X218BD;&#X20B9F;&#X216B4;&#X21E34;&#X231C4;&#X235C4;&#X61;&#X62;&#X7A;&#X30;&#X31;&#X39;"));
    }

    /**
     * Test of toHtmlDecEncode method, of class TransUtil.
     */
    @Test
    public void testToHtmlDecEncode() {
        System.out.println("toHtmlDecEncode");
        assertEquals("&#33;&#34;&#35;&#36;&#37;&#38;&#39;&#40;&#41;&#61;&#126;&#124;&#96;&#123;&#125;&#42;&#43;&#60;&#62;&#63;_&#92;&#13;&#10;abcdef", TransUtil.toHtmlDecEncode("!\"#$%&'()=~|`{}*+<>?_\\\r\nabcdef"));
        assertEquals("&#33;&#34;&#35;&#36;&#37;&#38;&#39;&#40;&#41;&#61;&#126;&#124;&#96;&#123;&#125;&#42;&#43;&#60;&#62;&#63;&#95;&#92;&#13;&#10;&#97;&#98;&#99;&#101;&#100;&#101;&#102;", TransUtil.toHtmlDecEncode("!\"#$%&'()=~|`{}*+<>?_\\\r\nabcedef", TransUtil.PTN_ENCODE_ALL));
        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals("jkf&#131083;&#135741;ghi&#135963;&#136302;&#137405;&#134047;&#136884;&#138804;&#143812;&#144836;abz019", TransUtil.toHtmlDecEncode(x));
        assertEquals("&#106;&#107;&#102;&#131083;&#135741;&#103;&#104;&#105;&#135963;&#136302;&#137405;&#134047;&#136884;&#138804;&#143812;&#144836;&#97;&#98;&#122;&#48;&#49;&#57;", TransUtil.toHtmlDecEncode(x,TransUtil.PTN_ENCODE_ALL));
    }

    /**
     * Test of toHtmlHexEncode method, of class TransUtil.
     */
    @Test
    public void testToHtmlHexEncode() {
        System.out.println("toHtmlHexEncode");
        assertEquals("&#x21;&#x22;&#x23;&#x24;&#x25;&#x26;&#x27;&#x28;&#x29;&#x3d;&#x7e;&#x7c;&#x60;&#x7b;&#x7d;&#x2a;&#x2b;&#x3c;&#x3e;&#x3f;_&#x5c;&#xd;&#xa;abcedf", TransUtil.toHtmlHexEncode("!\"#$%&'()=~|`{}*+<>?_\\\r\nabcedf", false));
        assertEquals("&#X21;&#X22;&#X23;&#X24;&#X25;&#X26;&#X27;&#X28;&#X29;&#X3D;&#X7E;&#X7C;&#X60;&#X7B;&#X7D;&#X2A;&#X2B;&#X3C;&#X3E;&#X3F;_&#X5C;&#XD;&#XA;abcedf", TransUtil.toHtmlHexEncode("!\"#$%&'()=~|`{}*+<>?_\\\r\nabcedf", true));

        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        System.out.println("c:" + TransUtil.toHtmlHexEncode(x, false));
        assertEquals("jkf&#x2000b;&#x2123d;ghi&#x2131b;&#x2146e;&#x218bd;&#x20b9f;&#x216b4;&#x21e34;&#x231c4;&#x235c4;abz019", TransUtil.toHtmlHexEncode(x, false));
        assertEquals("jkf&#X2000B;&#X2123D;ghi&#X2131B;&#X2146E;&#X218BD;&#X20B9F;&#X216B4;&#X21E34;&#X231C4;&#X235C4;abz019", TransUtil.toHtmlHexEncode(x, true));
        assertEquals("&#x6a;&#x6b;&#x66;&#x2000b;&#x2123d;&#x67;&#x68;&#x69;&#x2131b;&#x2146e;&#x218bd;&#x20b9f;&#x216b4;&#x21e34;&#x231c4;&#x235c4;&#x61;&#x62;&#x7a;&#x30;&#x31;&#x39;", TransUtil.toHtmlHexEncode(x, TransUtil.PTN_ENCODE_ALL, false));
    }
    
    /**
     * Test of URLDecode method, of class TransUtil.
     */
    @Test
    public void testDecodeUrl() {
        System.out.println("URLDecode");
        try {
            assertEquals("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", TransUtil.decodeUrl("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Shift_JIS"));
            assertEquals("\r\n\t",  TransUtil.decodeUrl("%0d%0a%09", "Shift_JIS"));
            assertEquals("\r\n\t",  TransUtil.decodeUrl("%0D%0A%09", "Shift_JIS"));
            assertEquals("abc",  TransUtil.decodeUrl("%61%62%63", "Shift_JIS"));
            assertEquals("テスト", TransUtil.decodeUrl("%83e%83X%83g","Shift_JIS"));
            assertEquals(" + ",  TransUtil.decodeUrl("%20%2B+", "Shift_JIS"));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            assertTrue(false);
        }
    }

    /**
     * Test of URLEncode method, of class TransUtil.
     */
    @Test
    public void testEncodeUrl() {
        System.out.println("URLEncode");
        try {
            assertEquals("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", TransUtil.encodeUrl("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Shift_JIS", false));
            assertEquals("%61%62%63%64%65%66%67%68%69%6a%6b%6c%6d%6e%6f%70%71%72%73%74%75%76%77%78%79%7a%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e%4f%50%51%52%53%54%55%56%57%58%59%5a%30%31%32%33%34%35%36%37%38%39", TransUtil.encodeUrl("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Shift_JIS", TransUtil.PTN_ENCODE_ALL, false));
            assertEquals("%0D%0A%09",  TransUtil.encodeUrl("\r\n\t", "Shift_JIS", true));
            assertEquals("%0d%0a%09",  TransUtil.encodeUrl("\r\n\t", "Shift_JIS", false));
            assertEquals("%83e%83X%83g", TransUtil.encodeUrl("テスト","Shift_JIS", false));
            assertEquals("+%2b+",  TransUtil.encodeUrl(" + ", "Shift_JIS", false));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            assertTrue(false);
        }
   }
    
    /**
     * Test of toUnocodeEncode method, of class TransUtil.
     */
    @Test
    public void testToUnocodeEncode() {
        System.out.println("toUnocodeEncode");
        assertEquals("abcdef\\u000d\\u000a\\u0021\\u0022ghi\\u0023\\u0024\\u0025jkf", TransUtil.toUnocodeEncode("abcdef\r\n!\"ghi#$%jkf", false));
        assertEquals("\\u0061\\u0062\\u0063\\u0064\\u0065\\u0066\\u000d\\u000a\\u0021\\u0022\\u0067\\u0068\\u0069\\u0023\\u0024\\u0025\\u006a\\u006b\\u0066", TransUtil.toUnocodeEncode("abcdef\r\n!\"ghi#$%jkf", TransUtil.PTN_ENCODE_ALL, false));
        assertEquals("\\U0061\\U0062\\U0063\\U0064\\U0065\\U0066\\U000D\\U000A\\U0021\\U0022\\U0067\\U0068\\U0069\\U0023\\U0024\\U0025\\U006A\\U006B\\U0066", TransUtil.toUnocodeEncode("abcdef\r\n!\"ghi#$%jkf", TransUtil.PTN_ENCODE_ALL, true));
        
        assertEquals("\\u3042\\u3044\\u3046\\u3048\\u304a", TransUtil.toUnocodeEncode("あいうえお", false));
        assertEquals("\\U3042\\U3044\\U3046\\U3048\\U304A", TransUtil.toUnocodeEncode("あいうえお", true));

        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals("jkf\\ud840\\udc0b\\ud844\\ude3dghi\\ud844\\udf1b\\ud845\\udc6e\\ud846\\udcbd\\ud842\\udf9f\\ud845\\udeb4\\ud847\\ude34\\ud84c\\uddc4\\ud84d\\uddc4abz019", TransUtil.toUnocodeEncode(x, false));
        assertEquals("jkf\\UD840\\UDC0B\\UD844\\UDE3Dghi\\UD844\\UDF1B\\UD845\\UDC6E\\UD846\\UDCBD\\UD842\\UDF9F\\UD845\\UDEB4\\UD847\\UDE34\\UD84C\\UDDC4\\UD84D\\UDDC4abz019", TransUtil.toUnocodeEncode(x, true));

        assertEquals("\\u006a\\u006b\\u0066\\ud840\\udc0b\\ud844\\ude3d\\u0067\\u0068\\u0069\\ud844\\udf1b\\ud845\\udc6e\\ud846\\udcbd\\ud842\\udf9f\\ud845\\udeb4\\ud847\\ude34\\ud84c\\uddc4\\ud84d\\uddc4\\u0061\\u0062\\u007a\\u0030\\u0031\\u0039", TransUtil.toUnocodeEncode(x, TransUtil.PTN_ENCODE_ALL, false));
        assertEquals("\\U006A\\U006B\\U0066\\UD840\\UDC0B\\UD844\\UDE3D\\U0067\\U0068\\U0069\\UD844\\UDF1B\\UD845\\UDC6E\\UD846\\UDCBD\\UD842\\UDF9F\\UD845\\UDEB4\\UD847\\UDE34\\UD84C\\UDDC4\\UD84D\\UDDC4\\U0061\\U0062\\U007A\\U0030\\U0031\\U0039", TransUtil.toUnocodeEncode(x, TransUtil.PTN_ENCODE_ALL, true));
    }

    /**
     * Test of toUnocodeDecode method, of class TransUtil.
     */
    @Test
    public void testToUnocodeDecode() {
        System.out.println("toUnocodeDecode");
        assertEquals("abcdef!\"#$%", TransUtil.toUnocodeDecode("abcdef\\u0021\\u0022\\u0023\\u0024\\u0025"));
        assertEquals("abcdef!\"#$%", TransUtil.toUnocodeDecode("abcdef\\U0021\\U0022\\U0023\\U0024\\U0025"));

        assertEquals("あいうえお", TransUtil.toUnocodeDecode("\\u3042\\u3044\\u3046\\u3048\\u304a"));
        assertEquals("あいうえお", TransUtil.toUnocodeDecode("\\U3042\\U3044\\U3046\\U3048\\U304A"));

        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals(x, TransUtil.toUnocodeDecode("jkf\\ud840\\udc0b\\ud844\\ude3dghi\\ud844\\udf1b\\ud845\\udc6e\\ud846\\udcbd\\ud842\\udf9f\\ud845\\udeb4\\ud847\\ude34\\ud84c\\uddc4\\ud84d\\uddc4abz019"));
        assertEquals(x, TransUtil.toUnocodeDecode("jkf\\UD840\\UDC0B\\UD844\\UDE3Dghi\\UD844\\UDF1B\\UD845\\UDC6E\\UD846\\UDCBD\\UD842\\UDF9F\\UD845\\UDEB4\\UD847\\UDE34\\UD84C\\UDDC4\\UD84D\\UDDC4abz019"));
    }

    public final static Pattern ENCODE_JS = Pattern.compile("[^ !#-&(-/0-Z\\[\\]^-~]");
    
    /**
     * Test of testToHexEncode method, of class TransUtil.
     */
    @Test
    public void testToHexEncode() {
        try {
            System.out.println("testToHexEncode");
            assertEquals("abcdef\\x0d\\x0a\\x21\\x22ghi\\x23\\x24\\x25jkf", TransUtil.toByteHexEncode("abcdef\r\n!\"ghi#$%jkf", "8859_1", false));
            assertEquals("abcdef\\X0D\\X0A\\X21\\X22ghi\\X23\\X24\\X25jkf", TransUtil.toByteHexEncode("abcdef\r\n!\"ghi#$%jkf", "8859_1", true));
            
            assertEquals("\\x61\\x62\\x63\\x64\\x65\\x66\\x0d\\x0a\\x21\\x22\\x67\\x68\\x69\\x23\\x24\\x25\\x6a\\x6b\\x66", TransUtil.toByteHexEncode(Util.getRawByte("abcdef\r\n!\"ghi#$%jkf"), TransUtil.PTN_ENCODE_ALL, false));
            assertEquals("\\X61\\X62\\X63\\X64\\X65\\X66\\X0D\\X0A\\X21\\X22\\X67\\X68\\X69\\X23\\X24\\X25\\X6A\\X6B\\X66", TransUtil.toByteHexEncode(Util.getRawByte("abcdef\r\n!\"ghi#$%jkf"), TransUtil.PTN_ENCODE_ALL, true));
            
            System.out.println(TransUtil.toByteHexEncode(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "8859_1", ENCODE_JS, false));
            assertEquals(" !\\x22#$%&\\x27()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\x5c]^_`abcdefghijklmnopqrstuvwxyz{|}~", TransUtil.toByteHexEncode(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "8859_1", ENCODE_JS, false));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Test of toByteHexEncode method, of class TransUtil.
     */
    @Test
    public void testToByteArrayJsEncode() {
        System.out.println("toUnocodeEncode");
        byte [] b1 = new byte[] {(byte)0x0a, (byte)0x0f, (byte)0x25, (byte)0xff}; 
        assertEquals("[0x0a,0x0f,0x25,0xff]", TransUtil.toByteArrayJsEncode(b1, false));
        byte [] b2 = new byte[] {}; 
        assertEquals("[]", TransUtil.toByteArrayJsEncode(b2, false));
        byte [] b3 = new byte[] {(byte)0x00}; 
        assertEquals("[0x00]", TransUtil.toByteArrayJsEncode(b3, false));

        byte [] b11 = new byte[] {(byte)0x0a, (byte)0x0f, (byte)0x25, (byte)0xff}; 
        assertEquals("[0X0A,0X0F,0X25,0XFF]", TransUtil.toByteArrayJsEncode(b11, true));
        byte [] b12 = new byte[] {}; 
        assertEquals("[]", TransUtil.toByteArrayJsEncode(b12, true));
        byte [] b13 = new byte[] {(byte)0x00}; 
        assertEquals("[0X00]", TransUtil.toByteArrayJsEncode(b13, true));
    }
    
    /**
     * Test of toByteDecode method, of class TransUtil.
     */
    @Test
    public void testToUnocode2Decode() {
//        try {
            System.out.println("toUnocode4Decode");
            assertEquals("abcdef!\"#$%", TransUtil.toByteDecode("abcdef\\x21\\x22\\x23\\x24\\x25", "8859_1"));        
            assertEquals("abcdef!\"ghi#$%jkf", TransUtil.toByteDecode("\\x61\\x62\\x63\\x64\\x65\\x66\\x21\\x22\\x67\\x68\\x69\\x23\\x24\\x25\\x6a\\x6b\\x66", "8859_1"));
            assertEquals("abcdef!\"#$%", TransUtil.toByteDecode("abcdef\\41\\42\\43\\44\\45", "8859_1"));        

//        } catch (UnsupportedEncodingException ex) {
//            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
    }
    
    /**
     * Test of toUnocodeUrlEncode method, of class TransUtil.
     */
    @Test
    public void testToUnocodeUrlEncode() {
        System.out.println("toUnocodeUrlEncode");
        assertEquals("abcdef%u000d%u000a%u0021%u0022%u0023%u0024%u0025", TransUtil.toUnocodeUrlEncode("abcdef\r\n!\"#$%", false));
        assertEquals("%u3042%u3044%u3046%u3048%u304a", TransUtil.toUnocodeUrlEncode("あいうえお", false));
        assertEquals("%U3042%U3044%U3046%U3048%U304A", TransUtil.toUnocodeUrlEncode("あいうえお", true));
        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals("jkf%ud840%udc0b%ud844%ude3dghi%ud844%udf1b%ud845%udc6e%ud846%udcbd%ud842%udf9f%ud845%udeb4%ud847%ude34%ud84c%uddc4%ud84d%uddc4abz019", TransUtil.toUnocodeUrlEncode(x, false));
        assertEquals("jkf%UD840%UDC0B%UD844%UDE3Dghi%UD844%UDF1B%UD845%UDC6E%UD846%UDCBD%UD842%UDF9F%UD845%UDEB4%UD847%UDE34%UD84C%UDDC4%UD84D%UDDC4abz019", TransUtil.toUnocodeUrlEncode(x, true));
//        assertEquals("%u006a%u006b%u0066%ud840%udc0b%ud844%ude3d%u0067%u0068%u0069%ud844%udf1b%ud845%udc6e%ud846%udcbd%ud842%udf9f%ud845%udeb4%ud847%ude34%ud84c%uddc4%ud84d%uddc4%u0061%u0062%u007a%u0030%u0031%u0039", TransUtil.toUnocodeUrlEncode(x, false));
    }

    /**
     * Test of toUnocodeUrlDecode method, of class TransUtil.
     */
    @Test
    public void testToUnocodeUrlDecode() {
        System.out.println("toUnocodeUrlDecode");
        assertEquals("abcdef!\"#$%", TransUtil.toUnocodeUrlDecode("abcdef%u0021%u0022%u0023%u0024%u0025"));
        assertEquals("あいうえお", TransUtil.toUnocodeUrlDecode("%u3042%u3044%u3046%u3048%u304a"));
        int ch[] = new int[]{(int)'j', (int)'k', (int)'f', 0x2000B, 0x2123D, (int)'g', (int)'h', (int)'i', 0x2131B, 0x2146E, 0x218BD, 0x20B9F, 0x216B4, 0x21E34, 0x231C4, 0x235C4, (int)'a', (int)'b', (int)'z', (int)'0', (int)'1', (int)'9'};
        String x = new String(ch, 0, ch.length);
        assertEquals(x, TransUtil.toUnocodeUrlDecode("jkf%ud840%udc0b%ud844%ude3dghi%ud844%udf1b%ud845%udc6e%ud846%udcbd%ud842%udf9f%ud845%udeb4%ud847%ude34%ud84c%uddc4%ud84d%uddc4abz019"));
    }

    /**
     * Test of toBigDec method, of class TransUtil.
     */
    @Test
    public void testToBigDec() {
        System.out.println("toBigDec");
        assertEquals("123456789012345678901234567890123456789012345678901234567890", TransUtil.toBigDec("123456789012345678901234567890123456789012345678901234567890"));
        assertEquals("123456789012345678901234567890123456789012345678901234567890", TransUtil.toBigDec("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("123456789012345678901234567890123456789012345678901234567890", TransUtil.toBigDec("0X13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("123456789012345678901234567890123456789012345678901234567890", TransUtil.toBigDec("0235257240471136036304134774172206743033664471063177431331617605322"));
    }

    /**
     * Test of toBigHex method, of class TransUtil.
     */
    @Test
    public void testToBigHex() {
        System.out.println("toBigHex");
        assertEquals("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2", TransUtil.toBigHex("123456789012345678901234567890123456789012345678901234567890"));
        assertEquals("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2", TransUtil.toBigHex("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2", TransUtil.toBigHex("0X13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2", TransUtil.toBigHex("0235257240471136036304134774172206743033664471063177431331617605322"));
    }

    /**
     * Test of toBigOct method, of class TransUtil.
     */
    @Test
    public void testToBigOct() {
        System.out.println("toBigOct");
        assertEquals("0235257240471136036304134774172206743033664471063177431331617605322", TransUtil.toBigOct("123456789012345678901234567890123456789012345678901234567890"));
        assertEquals("0235257240471136036304134774172206743033664471063177431331617605322", TransUtil.toBigOct("0x13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("0235257240471136036304134774172206743033664471063177431331617605322", TransUtil.toBigOct("0X13aaf504e4bc1e62173f87a4378c37b49c8ccff196ce3f0ad2"));
        assertEquals("0235257240471136036304134774172206743033664471063177431331617605322", TransUtil.toBigOct("0235257240471136036304134774172206743033664471063177431331617605322"));
    }

    /**
     * Test of getGuessCode method, of class TransUtil.
     */
    @Test
    public void testGetGuessCode() {
        try {
            System.out.println("TransUtil");
            String str1 = new String(new byte [] {(byte)0xff}, "8859_1");
            String str2 = new String(new byte [] {(byte)0x7f}, "8859_1");
            String str3 = new String(new byte [] {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06}, "8859_1");
            String str4 = new String(new byte [] {(byte)0x1a, (byte)0x0a, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0d, (byte)0x49, (byte)0x48, (byte)0x44, (byte)0x52}, "8859_1");
            assertEquals(null, HttpUtil.getGuessCode(str1.getBytes("8859_1")));
            assertEquals(null, HttpUtil.getGuessCode(str2.getBytes("8859_1")));
            assertEquals(null, HttpUtil.getGuessCode(str3.getBytes("8859_1")));
            assertEquals(null, HttpUtil.getGuessCode(str4.getBytes("8859_1")));
            
            assertEquals("US-ASCII", HttpUtil.getGuessCode("0123456ABCDEF".getBytes("UTF-8")));
            assertEquals("Shift_JIS", HttpUtil.getGuessCode("入口入口入口入口".getBytes("Shift_JIS")));
            assertEquals("EUC-JP", HttpUtil.getGuessCode("入口入口入口入口".getBytes("EUC-JP")));
            assertEquals("UTF-8", HttpUtil.getGuessCode("入口入口入口入口".getBytes("UTF-8")));
            assertEquals("UTF-16", HttpUtil.getGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16BE")));
            assertEquals("UTF-16", HttpUtil.getGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16LE"))); // UTF-16LE になるのがベスト
            assertEquals("UTF-16", HttpUtil.getGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16")));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            assertTrue(false);
        }
    }

    /**
     * Test of encodeJsLangMeta,decodeJsLangMeta method, of class TransUtil.
     */
    @Test
    public void testJsLangMeta() {
        System.out.println("JsLangMeta");
        assertEquals("abc\rdef\nghi\tfgh\\IJK", TransUtil.decodeJsLangMeta("abc\\rdef\\nghi\\tfgh\\\\IJK"));
        assertEquals("abc" + Character.toString((char)0x08) + "def" + Character.toString((char)0x0c) +  "ghi"  + Character.toString((char)0x0b) + "IJK" , TransUtil.decodeJsLangMeta("abc\\bdef\\fghi\\vIJK"));
        assertEquals("abcdefghi\tIJK" , TransUtil.decodeJsLangMeta("\\x61bcdefghi\\x09I\\x4A\\x4b"));
        assertEquals("abcdefghi\tIJK" , TransUtil.decodeJsLangMeta("\\u0061bcdefghi\\u0009I\\u004A\\u004b"));
        assertEquals("あいうえお" , TransUtil.decodeJsLangMeta("\\u3042\\u3044\\u3046\\u3048\\u304a"));
        assertEquals("あ\r\nいうえお" , TransUtil.decodeJsLangMeta("\\u3042\\r\\n\\u3044\\u3046\\u3048\\u304a"));
        // regexp        
        assertEquals("\\$1", Matcher.quoteReplacement(TransUtil.decodeJsLangMeta("$1")));
        assertEquals("\\\\\\$1", Matcher.quoteReplacement(TransUtil.decodeJsLangMeta("\\$1")));
        assertEquals("\r\\\\\\$1", Matcher.quoteReplacement(TransUtil.decodeJsLangMeta("\\r\\$1")));        
    }
    
    /**
     * Test of encodeJsLangQuote,decodeJsLangQuote method, of class TransUtil.
     */
    @Test
    public void testJsLangQuote() {
        System.out.println("testJsLangQuote");
        assertEquals("host", TransUtil.encodeJsLangQuote("host"));
        assertEquals("\\\\123\\\"456\\\\", TransUtil.encodeJsLangQuote("\\123\"456\\"));
        assertEquals("\\\\123\\\'456\\\\", TransUtil.encodeJsLangQuote("\\123'456\\"));
        assertEquals("\\123\"456\\", TransUtil.decodeJsLangQuote("\\\\123\\\"456\\\\"));
        assertEquals("\\123\'456\\", TransUtil.decodeJsLangQuote("\\\\123\\\'456\\\\"));
    }
    
    /**
     * Test of encodeCLangQuote,decodeCLangQuote method, of class TransUtil.
     */
    @Test
    public void testCLangQuote() {
        System.out.println("testCLangQuote");
        assertEquals("\\\\123\\\"456\\\\", TransUtil.encodeCLangQuote("\\123\"456\\"));
        assertEquals("\\123\"456\\", TransUtil.decodeCLangQuote("\\\\123\\\"456\\\\"));
    }

    /**
     * Test of encodeSQLLangQuote,decodeSQLLangQuote method, of class TransUtil.
     */
    @Test
    public void testSQLLangQuote() {
        System.out.println("testSQLLangQuote");
        assertEquals("\\123\'\'456\\", TransUtil.encodeSQLLangQuote("\\123\'456\\"));
        assertEquals("\\123\'456\\", TransUtil.decodeSQLangQuote("\\123\'\'456\\"));
    }
    
    /**
     * // * Test of generaterList method, of class TransUtil.
     */
    @Test
    public void testGenerater_NumbersList() {
        System.out.println("testGenerater_NumbersList");
        {
            String list[] = TransUtil.generaterList("abc%02d", 4, 11, 2);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc04");
            assertEquals(list[1], "abc06");
            assertEquals(list[2], "abc08");
            assertEquals(list[3], "abc10");
        }
        {
            String list[] = TransUtil.generaterList("abc%02d", 4, 11, -2);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc11");
            assertEquals(list[1], "abc09");
            assertEquals(list[2], "abc07");
            assertEquals(list[3], "abc05");
        }
        {
            String list[] = TransUtil.generaterList("abc%02d",11, 4, -2);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc11");
            assertEquals(list[1], "abc09");
            assertEquals(list[2], "abc07");
            assertEquals(list[3], "abc05");
        }
        {
            String list[] = TransUtil.generaterList("abc%03x", 8, 20, 4);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc008");
            assertEquals(list[1], "abc00c");
            assertEquals(list[2], "abc010");
            assertEquals(list[3], "abc014");
        }
        {
            String list[] = TransUtil.generaterList("abc%03x", 8, 20, -4);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc014");
            assertEquals(list[1], "abc010");
            assertEquals(list[2], "abc00c");
            assertEquals(list[3], "abc008");
        }
        {
            String list[] = TransUtil.generaterList("abc%03x", 20, 8, -4);
            assertEquals(list.length, 4);
            assertEquals(list[0], "abc014");
            assertEquals(list[1], "abc010");
            assertEquals(list[2], "abc00c");
            assertEquals(list[3], "abc008");
        }
        try {
            String list[] = TransUtil.generaterList("abc%02d", 4, 11, 0);
            assertTrue(false);
        } catch (Exception e) {
            assertTrue(e.getMessage(), true);
        }
    }    

    /**
     * // * Test of generaterList method, of class TransUtil.
     */
    @Test
    public void testGenerater_DateList() {
        System.out.println("testGenerater_DateList");
        {
            String list[] = TransUtil.dateList("yyyy/MM/dd", LocalDate.of(2007, Month.OCTOBER, 28), LocalDate.of(2007, Month.NOVEMBER, 2), 1);
            assertEquals(list.length, 6);
            assertEquals(list[0], "2007/10/28");
            assertEquals(list[1], "2007/10/29");
            assertEquals(list[2], "2007/10/30");
            assertEquals(list[3], "2007/10/31");
            assertEquals(list[4], "2007/11/01");
            assertEquals(list[5], "2007/11/02");
        }
        {
            String list[] = TransUtil.dateList("yyyy/MM/dd", LocalDate.of(2007, Month.NOVEMBER, 2), LocalDate.of(2007, Month.OCTOBER, 28), -1);
            assertEquals(list.length, 6);
            assertEquals(list[0], "2007/11/02");
            assertEquals(list[1], "2007/11/01");
            assertEquals(list[2], "2007/10/31");
            assertEquals(list[3], "2007/10/30");
            assertEquals(list[4], "2007/10/29");
            assertEquals(list[5], "2007/10/28");
        }
    }
    
    @Test
    public void testByteBuffer() {
        ByteBuffer buff = ByteBuffer.allocate(10);
        buff.put((byte)10);
        buff.put((byte)20);
        buff.put((byte)30);
        buff.flip();
        byte [] b = buff.array();
        for (int i = 0; i < b.length; i++) {
            System.out.printf("\\%x\n", b[i]);
        }
    } 

    private final static Pattern REQUEST_URI = Pattern.compile("^(.*?\\s+)(.*?)(\\s+.*?)");
    
    @Test
    public void testURI() {
        String requestLine = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        Matcher m = REQUEST_URI.matcher(requestLine);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            sb.append(m.group(1));
            m.appendReplacement(sb, "aaaaaaaaaaaaaa");
            sb.append(m.group(3));
        }
        m.appendTail(sb);
    System.out.println(sb.toString());
    }

    /**
     */
    @Test
    public void testGetUniversalGuessCode() {

        {
            try {
                assertEquals("US-ASCII", TransUtil.getUniversalGuessCode("0123456ABCDEF".getBytes("UTF-8"), "US-ASCII"));
                assertEquals("Shift_JIS", TransUtil.getUniversalGuessCode("入口入口入口入口".getBytes("Shift_JIS")));
                assertEquals("EUC-JP", TransUtil.getUniversalGuessCode("入口入口入口入口".getBytes("EUC-JP")));
                assertEquals("UTF-8", TransUtil.getUniversalGuessCode("入口入口入口入口".getBytes("UTF-8")));
//                assertEquals("UTF-16", TransUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16BE")));
//                assertEquals("UTF-16", TransUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16LE"))); // UTF-16LE になるのがベスト
                assertEquals("UTF-16", TransUtil.getUniversalGuessCode("ABCDEFGHIJKLMNOPQRSTUVWXYZあいうえおかきくけこ".getBytes("UTF-16")));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        {
            try {
                String expResult = "Shift_JIS";
                String expValue = "あいうえお";
                String guessCharset = TransUtil.getUniversalGuessCode(expValue.getBytes("Shift_JIS"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            }        
        }

        {
            try {
                String expResult = "Shift_JIS";
                String expValue = "①②③④⑤⑥⑦ⅩⅨあいうえおかきくけこ";
                String guessCharset = TransUtil.getUniversalGuessCode(expValue.getBytes("MS932"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            }        
        }
        
        {
            try {
                String expResult = "EUC-JP";
                String expValue = "あいうえお";
                String guessCharset = TransUtil.getUniversalGuessCode(expValue.getBytes("EUC-JP"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            }        
        }

        {
            try {
                String expResult = "ISO-2022-JP";
                String expValue = "あいうえお";
                String guessCharset = TransUtil.getUniversalGuessCode(expValue.getBytes("ISO-2022-JP"), "UTF-8");
                assertEquals(expResult, guessCharset);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(TransUtilTest.class.getName()).log(Level.SEVERE, null, ex);
            }        
        }

    }
    
    /**
     */
    @Test
    public void testUniversalCharCode() {
        // Chinese
        String [] list = {
            "ISO-2022-CN",
            "BIG5",
            "EUC-TW",
            "GB18030",
            "HZ-GB-23121",
            // Cyrillic
            "ISO-8859-5",
            "KOI8-R",
            "WINDOWS-1251",
            // MACCYRILLIC
            "IBM866",
            "IBM855",
            // Greek
            "ISO-8859-7",
            "WINDOWS-1253",
            // Hebrew
            "ISO-8859-8",
            "WINDOWS-1255",
            // Japanese
            "ISO-2022-JP",
            "SHIFT_JIS",
            "EUC-JP",
            // Korean
            "ISO-2022-KR",
            "EUC-KR",
            // Unicode
            "UTF-8",
            "UTF-16BE",
            "UTF-16LE",
            "UTF-32BE",
            "UTF-32LE",
            "X-ISO-10646-UCS-4-34121", // unk
            "X-ISO-10646-UCS-4-21431", // unk
            // Others
            "WINDOWS-1252",
        };
        for (String l: list) {
            String normChar = HttpUtil.normalizeCharset(l);        
            if (normChar == null) {
                    System.out.println("unk="  + l);            
            
            }
            else {
                if (l.compareToIgnoreCase(normChar) != 0) {
                    System.out.println(l + "="  + normChar);            
                }            
            }
            
        }
        
    }

    @Test
    public void testLocale() {
        System.out.println(Locale.JAPANESE.toString());        
        System.out.println(Locale.JAPANESE.getCountry());
        System.out.println(Locale.JAPANESE.getDisplayLanguage());
        System.out.println(Locale.JAPANESE.getDisplayName());
        System.out.println(Locale.JAPANESE.toLanguageTag());
        System.out.println(Locale.JAPANESE.getISO3Language());
        System.out.println(Locale.JAPANESE.getLanguage());
        System.out.println(Locale.JAPANESE.getDisplayScript());
        System.out.println(Locale.JAPANESE.getVariant());
        System.out.println(Locale.JAPANESE.toLanguageTag());
    }
    
}