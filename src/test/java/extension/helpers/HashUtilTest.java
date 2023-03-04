package extension.helpers;

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
public class HashUtilTest {

    public HashUtilTest() {
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
     * Test of toMd2Sum method, of class HashUtil.
     */
    @Test
    public void testToMd2Sum_byteArr_boolean() {
        System.out.println("toMd2Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "95f20caa6709cbbaed9991ba9a104b81";
        String result = HashUtil.toMd2Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toMd2Sum method, of class HashUtil.
     */
    @Test
    public void testToMd2Sum_String_boolean() {
        System.out.println("toMd2Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "dd34716876364a02d0195e2fb9ae2d1b";
        String result = HashUtil.toMd2Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toMd2Sum method, of class HashUtil.
     */
    @Test
    public void testToMd2Sum_3args() throws Exception {
        System.out.println("toMd2Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "95f20caa6709cbbaed9991ba9a104b81";
        String result = HashUtil.toMd2Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toMd5Sum method, of class HashUtil.
     */
    @Test
    public void testToMd5Sum_byteArr_boolean() {
        System.out.println("toMd5Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "b0f1c5a480f416234a803b35d9932c57";
        String result = HashUtil.toMd5Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toMd5Sum method, of class HashUtil.
     */
    @Test
    public void testToMd5Sum_String_boolean() {
        System.out.println("toMd5Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "098f6bcd4621d373cade4e832627b4f6";
        String result = HashUtil.toMd5Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toMd5Sum method, of class HashUtil.
     */
    @Test
    public void testToMd5Sum_3args() throws Exception {
        System.out.println("toMd5Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "b0f1c5a480f416234a803b35d9932c57";
        String result = HashUtil.toMd5Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA1Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA1Sum_byteArr_boolean() {
        System.out.println("toSHA1Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "63b560db8849e08797624b58335240e0d06282bd";
        String result = HashUtil.toSHA1Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA1Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA1Sum_String_boolean() {
        System.out.println("toSHA1Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        String result = HashUtil.toSHA1Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA1Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA1Sum_3args() throws Exception {
        System.out.println("toSHA1Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "63b560db8849e08797624b58335240e0d06282bd";
        String result = HashUtil.toSHA1Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA256Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA256Sum_byteArr_boolean() {
        System.out.println("toSHA256Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "8a535a3f4dcd2c396db11b7c1e54221d04375c9f9be96bce47dc2fdb237e86c9";
        String result = HashUtil.toSHA256Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA256Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA256Sum_String_boolean() {
        System.out.println("toSHA256Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        String result = HashUtil.toSHA256Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA256Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA256Sum_3args() throws Exception {
        System.out.println("toSHA256Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "8a535a3f4dcd2c396db11b7c1e54221d04375c9f9be96bce47dc2fdb237e86c9";
        String result = HashUtil.toSHA256Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA384Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA384Sum_byteArr_boolean() {
        System.out.println("toSHA384Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "3502bb7d7f95ec11bff36f83defb88ad979ae68e996abac833e491a68caa499d5671e69a00479d7b40f0a0a206b1d17a";
        String result = HashUtil.toSHA384Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA384Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA384Sum_String_boolean() {
        System.out.println("toSHA384Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        String result = HashUtil.toSHA384Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA384Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA384Sum_3args() throws Exception {
        System.out.println("toSHA384Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "3502bb7d7f95ec11bff36f83defb88ad979ae68e996abac833e491a68caa499d5671e69a00479d7b40f0a0a206b1d17a";
        String result = HashUtil.toSHA384Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA512Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA512Sum_byteArr_boolean() {
        System.out.println("toSHA512Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        boolean upperCase = false;
        String expResult = "0b5d8c7fb5b942cb09b0390db6fd09ff77aa56270aae66ee139b890b163116610c915f1246c7204237e3224360a01ec1ad633918da919cbe2b24d5ba8c5b3ddc";
        String result = HashUtil.toSHA512Sum(body, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA512Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA512Sum_String_boolean() {
        System.out.println("toSHA512Sum");
        String str = "test";
        boolean upperCase = false;
        String expResult = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        String result = HashUtil.toSHA512Sum(str, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toSHA512Sum method, of class HashUtil.
     */
    @Test
    public void testToSHA512Sum_3args() throws Exception {
        System.out.println("toSHA512Sum");
        String str = "テスト";
        String enc = "UTF-8";
        boolean upperCase = false;
        String expResult = "0b5d8c7fb5b942cb09b0390db6fd09ff77aa56270aae66ee139b890b163116610c915f1246c7204237e3224360a01ec1ad633918da919cbe2b24d5ba8c5b3ddc";
        String result = HashUtil.toSHA512Sum(str, enc, upperCase);
        assertEquals(expResult, result);
    }

    /**
     * Test of toCRC32Sum method, of class HashUtil.
     */
    @Test
    public void testToCRC32Sum_String_String() throws Exception {
        System.out.println("toCRC32Sum");
        String str = "テスト";
        String enc = "UTF-8";
        long expResult = 2955268572L;
        long result = HashUtil.toCRC32Sum(str, enc);
        assertEquals(expResult, result);
    }

    /**
     * Test of toCRC32Sum method, of class HashUtil.
     */
    @Test
    public void testToCRC32Sum_byteArr() {
        System.out.println("toCRC32Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        long expResult = 2955268572L;
        long result = HashUtil.toCRC32Sum(body);
        assertEquals(expResult, result);
    }

    /**
     * Test of toAdler32Sum method, of class HashUtil.
     */
    @Test
    public void testToAdler32Sum_String_String() throws Exception {
        System.out.println("toAdler32Sum");
        String str = "テスト";
        String enc = "UTF-8";
        long expResult = 515704313L;
        long result = HashUtil.toAdler32Sum(str, enc);
        assertEquals(expResult, result);
    }

    /**
     * Test of toAdler32Sum method, of class HashUtil.
     */
    @Test
    public void testToAdler32Sum_byteArr() {
        System.out.println("toAdler32Sum");
        byte[] body = new byte[]{(byte) 0xe3, (byte) 0x83, (byte) 0x86, (byte) 0xe3, (byte) 0x82, (byte) 0xb9, (byte) 0xe3, (byte) 0x83, (byte) 0x88};
        long expResult = 515704313L;
        long result = HashUtil.toAdler32Sum(body);
        assertEquals(expResult, result);
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

}
