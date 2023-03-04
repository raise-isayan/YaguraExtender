package extension.helpers;

import java.nio.ByteOrder;
import java.text.ParseException;
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
public class IpUtilTest {

    public IpUtilTest() {
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

    /**
     * Test of parseIPv4Adress method, of class IpUtil.
     */
    @Test
    public void testParseIPv4Adress() {
        System.out.println("parseIPv4Adress");
        try {
            {
                // class A Private IP
                assertArrayEquals(new byte[]{(byte) 10, (byte) 168, (byte) 2, (byte) 1}, IpUtil.parseIPv4AddressByte("10.168.2.1"));
                // class B Private IP
                assertArrayEquals(new byte[]{(byte) 172, (byte) 16, (byte) 2, (byte) 1}, IpUtil.parseIPv4AddressByte("172.16.2.1"));
                // class C Private IP
                assertArrayEquals(new byte[]{(byte) 192, (byte) 168, (byte) 2, (byte) 1}, IpUtil.parseIPv4AddressByte("192.168.2.1"));

                assertArrayEquals(new byte[]{(byte) 8, (byte) 8, (byte) 8, (byte) 8}, IpUtil.parseIPv4AddressByte("8.8.8.8"));

                assertArrayEquals(new byte[]{(byte) 1, (byte) 1, (byte) 1, (byte) 1}, IpUtil.parseIPv4AddressByte("1.1.1.1"));

                assertArrayEquals(new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 1}, IpUtil.parseIPv4AddressByte("255.255.255.1"));

                assertArrayEquals(new byte[]{(byte) 169, (byte) 254, (byte) 0, (byte) 1}, IpUtil.parseIPv4AddressByte("169.254.0.1"));
            }

        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of parseIPv6Adress method, of class IpUtil.
     */
    @Test
    public void testParseIPv6Adress() {
        try {
            System.out.println("parseIPv6Adress");
            byte ip0[] = IpUtil.parseIPv6AddressByte("::");
            assertArrayEquals(new byte[]{(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0}, ip0);
            byte ip1[] = IpUtil.parseIPv6AddressByte("::1");
            assertArrayEquals(new byte[]{(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1}, ip1);
            byte ip2[] = IpUtil.parseIPv6AddressByte("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
            assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x8a, (byte) 0x2e, (byte) 0x03, (byte) 0x70, (byte) 0x73, (byte) 0x34}, ip2);
            byte ip3[] = IpUtil.parseIPv6AddressByte("2001:db8:85a3:0:0:8a2e:370:7334");
            assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x8a, (byte) 0x2e, (byte) 0x03, (byte) 0x70, (byte) 0x73, (byte) 0x34}, ip3);
            byte ip4[] = IpUtil.parseIPv6AddressByte("2001:db8:85a3::8a2e:370:7334");
            assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x8a, (byte) 0x2e, (byte) 0x03, (byte) 0x70, (byte) 0x73, (byte) 0x34}, ip4);
            byte ip5[] = IpUtil.parseIPv6AddressByte("2001:db8::1:0:0:1");
            assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1}, ip5);
            byte ip6[] = IpUtil.parseIPv6AddressByte("2001:0db8:0000:0000:3456::");
            assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0d, (byte) 0xb8, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x34, (byte) 0x56, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0}, ip6);

        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
        try {
            byte ip7[] = IpUtil.parseIPv6AddressByte("2001:0db8::3456::");
            fail();
        } catch (ParseException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testIPv4Valid() {
        System.out.println("isIPv4Valid");
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1"));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1:0"));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1:1"));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1:65535"));
        assertEquals(false, IpUtil.isIPv4Valid("10.168.2.1:65536"));
        assertEquals(false, IpUtil.isIPv4Valid(":65535"));

        assertEquals(false, IpUtil.isIPv4Valid("10.168.2.1", -1));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1", 0));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1", 1));
        assertEquals(true, IpUtil.isIPv4Valid("10.168.2.1", 65535));
        assertEquals(false, IpUtil.isIPv4Valid("10.168.2.1", 65536));
        assertEquals(false, IpUtil.isIPv4Valid(null, 65535));
    }

    @Test
    public void testIsIPv4Address() {
        System.out.println("isIPv4Address");
        // class A Private IP
        assertEquals(true, IpUtil.isIPv4Address("10.168.2.1"));
        // class B Private IP
        assertEquals(true, IpUtil.isIPv4Address("172.16.2.1"));
        // class C Private IP
        assertEquals(true, IpUtil.isIPv4Address("192.168.2.1"));
        assertEquals(true, IpUtil.isIPv4Address("8.8.8.8"));
        assertEquals(true, IpUtil.isIPv4Address("0.0.0.0"));
        assertEquals(true, IpUtil.isIPv4Address("1.1.1.1"));
        assertEquals(true, IpUtil.isIPv4Address("255.255.255.1"));
        assertEquals(true, IpUtil.isIPv4Address("255.255.255.255"));
        assertEquals(true, IpUtil.isIPv4Address("169.254.0.1"));
        assertEquals(false, IpUtil.isIPv4Address("256.256.256.256"));
        assertEquals(false, IpUtil.isIPv4Address(null));
    }

    @Test
    public void testIsIPv6Address() {
        System.out.println("isIPv6Address");
        assertEquals(true, IpUtil.isIPv6Address("::"));
        assertEquals(true, IpUtil.isIPv6Address("::1"));
        assertEquals(true, IpUtil.isIPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assertEquals(true, IpUtil.isIPv6Address("2001:db8:85a3:0:0:8a2e:370:7334"));
        assertEquals(true, IpUtil.isIPv6Address("2001:db8:85a3::8a2e:370:7334"));
        assertEquals(true, IpUtil.isIPv6Address("2001:db8::1:0:0:1"));
        assertEquals(true, IpUtil.isIPv6Address("2001:0db8:0000:0000:3456::"));
        assertEquals(true, IpUtil.isIPv6Address("2001:0112:0000:0000:0000:0000:0000:0030"));
        assertEquals(true, IpUtil.isIPv6Address("[2001:0112:0000:0000:0000:0000:0000:0030]"));
        assertEquals(false, IpUtil.isIPv6Address("2001:0db8::3456::"));
        assertEquals(false, IpUtil.isIPv6Address(null));

        assertEquals(false, IpUtil.isIPv6Valid("2001:0db8:85a3:0000:0000:8a2e:0370:7334", -1));
        assertEquals(true, IpUtil.isIPv6Valid("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 0));
        assertEquals(true, IpUtil.isIPv6Valid("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 1));
        assertEquals(true, IpUtil.isIPv6Valid("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 65535));
        assertEquals(false, IpUtil.isIPv6Valid("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 65536));
        assertEquals(false, IpUtil.isIPv6Valid(null, 65535));
    }

    /**
     * Test of isPrivateIP method, of class IpUtil.
     */
    @Test
    public void testIsPrivateIP() {
        System.out.println("isPrivateIP");
        // class A Private IP
        assertEquals(true, IpUtil.isPrivateIP("10.168.2.1"));
        // class B Private IP
        assertEquals(true, IpUtil.isPrivateIP("172.16.2.1"));
        // class C Private IP
        assertEquals(true, IpUtil.isPrivateIP("192.168.2.1"));

        assertEquals(false, IpUtil.isPrivateIP("127.0.0.1"));

        assertEquals(false, IpUtil.isPrivateIP("8.8.8.8"));

        assertEquals(false, IpUtil.isPrivateIP("0.0.0.0"));

        assertEquals(false, IpUtil.isPrivateIP("1.1.1.1"));

        assertEquals(false, IpUtil.isPrivateIP("255.255.255.1"));

        assertEquals(false, IpUtil.isPrivateIP("255.255.255.255"));

        assertEquals(false, IpUtil.isPrivateIP("169.254.0.1"));

        // class A Private IP
        assertEquals(true, IpUtil.isPrivateIP("10.168.2.1:8080"));
        // class B Private IP
        assertEquals(true, IpUtil.isPrivateIP("172.16.2.1:8080"));
        // class C Private IP
        assertEquals(true, IpUtil.isPrivateIP("192.168.2.1:80"));

        assertEquals(false, IpUtil.isPrivateIP("8.8.8.8:2222"));

        assertEquals(false, IpUtil.isPrivateIP("0.0.0.0:0"));

        assertFalse(IpUtil.isPrivateIP("localhost:8000"));
        assertFalse(IpUtil.isPrivateIP("localhost"));

        assertFalse(IpUtil.isPrivateIP("256.256.256.256"));
    }

    /**
     * Test of isLinkLocalIP method, of class IpUtil.
     */
    @Test
    public void testIsLinkLocalIP() {
        System.out.println("isLinkLocalIP");
        // class A Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("10.168.2.1"));
        // class B Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("172.16.2.1"));
        // class C Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("192.168.2.1"));

        assertEquals(false, IpUtil.isLinkLocalIP("127.0.0.1"));

        assertEquals(false, IpUtil.isLinkLocalIP("8.8.8.8"));

        assertEquals(false, IpUtil.isLinkLocalIP("1.1.1.1"));

        assertEquals(false, IpUtil.isLinkLocalIP("255.255.255.1"));

        assertEquals(false, IpUtil.isLinkLocalIP("255.255.255.255"));

        assertEquals(true, IpUtil.isLinkLocalIP("169.254.0.1"));

        // class A Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("10.168.2.1:8080"));
        // class B Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("172.16.2.1:8080"));
        // class C Private IP
        assertEquals(false, IpUtil.isLinkLocalIP("192.168.2.1:80"));

        assertEquals(false, IpUtil.isLinkLocalIP("8.8.8.8:2222"));

        assertEquals(false, IpUtil.isLinkLocalIP("0.0.0.0:0"));

        assertEquals(false, IpUtil.isLinkLocalIP("localhost:8000"));

        assertEquals(false, IpUtil.isLinkLocalIP("localhost"));

        assertEquals(false, IpUtil.isLinkLocalIP("256.256.256.256"));

    }

    /**
     * Test of IPv4ToDecimal method, of class IpUtil.
     */
    @Test
    public void testIPv4ToDecimal() {
        try {
            System.out.println("IPv4ToDecimal");
            String raw_ip = "10.1.1.100";
            long result = IpUtil.IPv4ToDecimal(raw_ip, ByteOrder.LITTLE_ENDIAN);
            assertEquals(1677787402L, result);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of decimalToIPv4 method, of class IpUtil.
     */
    @Test
    public void testDecimalToIPv4() {
        System.out.println("decimalToIPv4");
        String enc_ip = "1677787402";
        String result = IpUtil.decimalToIPv4(Long.parseLong(enc_ip), ByteOrder.LITTLE_ENDIAN);
        assertEquals("10.1.1.100", result);
    }

    /**
     * Test of hexToIPv4 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv4() {
        System.out.println("hexToIPv4");
        String enc_ip = "c0000201";
        String result = IpUtil.hexToIPv4(enc_ip, ByteOrder.BIG_ENDIAN);
        assertEquals("192.0.2.1", result);
    }

    /**
     * Test of hexToIPv6 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv6() {
        System.out.println("hexToIPv6");
        String enc_ip = "20010112000000000000000000000030";
        String result = IpUtil.hexToIPv6(enc_ip);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]", result);
    }

    /**
     * Test of decimalToPort method, of class IpUtil.
     */
    @Test
    public void testDecimalToPort() {
        System.out.println("decimalToPort");
        int enc_port = 36895;
        int result = IpUtil.decimalToPort(enc_port, ByteOrder.LITTLE_ENDIAN);
        assertEquals(8080, result);
    }

    /**
     * Test of testIpv4ToHex method, of class IpUtil.
     */
    @Test
    public void testIpv4ToHex() {
        System.out.println("ipv4ToHex");
        // 192,0,2,11
        assertEquals("0xc000020b", IpUtil.ipv4ToHex(192, 0, 2, 11));
        assertEquals("0xc0.0x00.0x02.0x0b", IpUtil.ipv4ToDotHex(192, 0, 2, 11));
        assertEquals("030000001013", IpUtil.ipv4ToOct(192, 0, 2, 11));
        assertEquals("0300.0000.0002.0013", IpUtil.ipv4ToDotOct(192, 0, 2, 11));
        assertEquals("3221225995", IpUtil.ipv4ToInt(192, 0, 2, 11));
        // 127.0.0.1
        assertEquals("0x7f000001", IpUtil.ipv4ToHex(127, 0, 0, 1));
        assertEquals("0x7f.0x00.0x00.0x01", IpUtil.ipv4ToDotHex(127, 0, 0, 1));
        assertEquals("017700000001", IpUtil.ipv4ToOct(127, 0, 0, 1));
        assertEquals("0177.0000.0000.0001", IpUtil.ipv4ToDotOct(127, 0, 0, 1));
        assertEquals("2130706433", IpUtil.ipv4ToInt(127, 0, 0, 1));
        // 127.10.172.192
        assertEquals("0x7f0aacc0", IpUtil.ipv4ToHex(127, 10, 172, 192));
        assertEquals("0x7f.0x0a.0xac.0xc0", IpUtil.ipv4ToDotHex(127, 10, 172, 192));
        assertEquals("017702526300", IpUtil.ipv4ToOct(127, 10, 172, 192));
        assertEquals("0177.0012.0254.0300", IpUtil.ipv4ToDotOct(127, 10, 172, 192));
        assertEquals("2131406016", IpUtil.ipv4ToInt(127, 10, 172, 192));

    }

}
