package extension.helpers;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;
import java.util.zip.CRC32;

/**
 *
 * @author isayan
 */
public final class HashUtil {

    /**
     * ハッシュ値の取得
     *
     * @param algorithm
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws java.security.NoSuchAlgorithmException
     */
    public static String toMessageDigest(String algorithm, String str, Charset charset, boolean upperCase)
            throws NoSuchAlgorithmException {
        return toMessageDigest(algorithm, StringUtil.getBytesCharset(str, charset), upperCase);
    }

    /**
     * ハッシュ値の取得
     *
     * @param algorithm
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static String toMessageDigest(String algorithm, String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return toMessageDigest(algorithm, StringUtil.getBytesCharset(str, charset), upperCase);
    }

    public static String toMessageDigest(String algorithm, byte body[], boolean upperCase)
            throws NoSuchAlgorithmException {
        String digeststr = "";
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.reset();
        md.update(body);
        digeststr = ConvertUtil.toHexString(md.digest());
        if (upperCase) {
            return digeststr;
        } else {
            return digeststr.toLowerCase();
        }
    }

    /**
     * MD2値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMd2Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("MD2", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMd2Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("MD2", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd2Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("MD2", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD5値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMd5Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("MD5", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toMd5Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("MD5", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd5Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("MD5", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA1Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("SHA-1", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA1Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA-1", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA1Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("SHA-1", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA256Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("SHA-256", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA256Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA-256", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("SHA-256", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA384Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("SHA-384", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA384Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA-384", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("SHA-384", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param body 対象バイト
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512Sum(byte[] body, boolean upperCase) {
        try {
            return toMessageDigest("SHA-512", body, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     */
    public static String toSHA512Sum(String str, boolean upperCase) {
        try {
            return toMessageDigest("SHA-512", str, StandardCharsets.ISO_8859_1, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase 大文字で出力
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        try {
            return toMessageDigest("SHA-512", str, charset, upperCase);
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    /**
     * CRC-32値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return CRC値
     * @throws UnsupportedEncodingException
     */
    public static long toCRC32Sum(String str, String charset) throws UnsupportedEncodingException {
        return toCRC32Sum(str.getBytes(charset));
    }

    /**
     * CRC-32値の取得
     *
     * @param body 対象バイト
     * @return ハッシュ値
     */
    public static long toCRC32Sum(byte[] body) {
        CRC32 crc = new CRC32();
        crc.reset();
        crc.update(body);
        return crc.getValue();
    }

    /**
     * Adler32値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return Adler値
     * @throws UnsupportedEncodingException
     */
    public static long toAdler32Sum(String str, String charset) throws UnsupportedEncodingException {
        return toAdler32Sum(StringUtil.getBytesCharset(str, charset));
    }

    /**
     * Adler32値の取得
     *
     * @param body 対象バイト
     * @return ハッシュ値
     */
    public static long toAdler32Sum(byte[] body) {
        Adler32 crc = new Adler32();
        crc.reset();
        crc.update(body);
        return crc.getValue();
    }

}
