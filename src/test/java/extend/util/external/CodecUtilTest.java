package extend.util.external;

import extension.helpers.ConvertUtil;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.apache.commons.codec.digest.Blake3;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.apache.commons.codec.digest.UnixCrypt;

/**
 *
 * @author isayan
 */
public class CodecUtilTest {

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of toMd5Sum method, of class TransUtil.
     */
    @Test
    public void testToMd5Sum() {
        System.out.println("toMd5Sum");
        assertEquals("098f6bcd4621d373cade4e832627b4f6", CodecUtil.toMd5Sum("test", false));
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", CodecUtil.toMd5Sum("", false));
    }

    /**
     * Test of toSHA1Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA1Sum() {
        System.out.println("toSHA1Sum");
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", CodecUtil.toSHA1Sum("test", false));
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", CodecUtil.toSHA1Sum("", false));
    }

    /**
     * Test of toSHA256Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA256Sum() {
        System.out.println("toSHA256Sum");
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", CodecUtil.toSHA256Sum("test", false));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", CodecUtil.toSHA256Sum("", false));
    }

    /**
     * Test of toSHA384Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA384Sum() {
        System.out.println("toSHA384Sum");
        assertEquals("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", CodecUtil.toSHA384Sum("test", false));
        assertEquals("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", CodecUtil.toSHA384Sum("", false));
    }

    /**
     * Test of toSHA512Sum method, of class TransUtil.
     */
    @Test
    public void testToSHA512Sum() {
        System.out.println("toSHA512Sum");
        assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", CodecUtil.toSHA512Sum("test", false));
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", CodecUtil.toSHA512Sum("", false));
    }

    @Test
    public void testCrypt() {
        System.out.println("testCrypt");
        System.out.println(UnixCrypt.crypt("aaa"));
        System.out.println(UnixCrypt.crypt("aaa"));
    }

    @Test
    public void testSha2Crypt() {
        System.out.println("testSha2Crypt");
        System.out.println(Sha2Crypt.sha256Crypt("aaa".getBytes()));
        System.out.println(Sha2Crypt.sha256Crypt("aaa".getBytes()));
    }

   @Test
    public void testBlake3_x32() {
        System.out.println("testBlake3");
        Blake3 hasher = Blake3.initHash();
        hasher.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        byte[] hash = new byte[32];
        hasher.doFinalize(hash);
        System.out.println(ConvertUtil.toHexString(hash, true));
    }

    @Test
    public void testBlake3_x64() {
        System.out.println("testBlake3");
        Blake3 hasher = Blake3.initHash();
        hasher.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        byte[] hash = new byte[64];
        hasher.doFinalize(hash);
        System.out.println(ConvertUtil.toHexString(hash, true));
    }

}
