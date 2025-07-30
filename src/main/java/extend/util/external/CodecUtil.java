package extend.util.external;

import extension.helpers.StringUtil;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base16;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.commons.codec.digest.MurmurHash2;
import org.apache.commons.codec.digest.MurmurHash3;
import org.apache.commons.codec.digest.XXHash32;

/**
 * Apache Common Codec Util
 *
 * @author isayan
 */
public class CodecUtil {

    private final static DigestUtils MD2_HASH = new DigestUtils(MessageDigestAlgorithms.MD2);

    /**
     * HashUtil
     *
     */
    /**
     * MD2値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd2Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return MD2_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return MD2_HASH.digestAsHex(binary);
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd2Sum(String str, boolean upperCase) {
        if (upperCase) {
            return MD2_HASH.digestAsHex(str).toUpperCase();
        } else {
            return MD2_HASH.digestAsHex(str);
        }
    }

    /**
     * MD2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd2Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return MD2_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return MD2_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils MD5_HASH = new DigestUtils(MessageDigestAlgorithms.MD5);

    /**
     * MD5値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd5Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return MD5_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return MD5_HASH.digestAsHex(binary);
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toMd5Sum(String str, boolean upperCase) {
        if (upperCase) {
            return MD5_HASH.digestAsHex(str).toUpperCase();
        } else {
            return MD5_HASH.digestAsHex(str);
        }
    }

    /**
     * MD5値の取得
     *
     * @param str 対象文字列
     * @param charset
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toMd5Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return MD5_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return MD5_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_1_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_1);

    /**
     * SHA-1値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA1Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_1_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_1_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA1Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_1_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_1_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-1値の取得
     *
     * @param str 対象文字列
     * @param charset
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA1Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_1_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_1_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_224);

    /**
     * SHA-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA224Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_256_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_256);

    /**
     * SHA-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_256_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_256_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA256Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_256_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_256_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_384_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_384);

    /**
     * SHA-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA384Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_384_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_384_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA384Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_384_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_384_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_512_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_512);

    /**
     * SHA-512値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_512_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_512_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_512_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_512_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_512_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_512_224);

    /**
     * SHA-512/224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-512/224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_224Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-512/224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_512_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_512_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA_512_256_HASH = new DigestUtils(MessageDigestAlgorithms.SHA_512_256);

    /**
     * SHA-512/256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA-512/256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA512_256Sum(String str, boolean upperCase) {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA-512/256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA512_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA_512_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA_512_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_224_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_224);

    /**
     * SHA3-224値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_224Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_224um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-224値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_224Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_224_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_256_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_256);

    /**
     * SHA3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_256Sum(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_256um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-256値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_256Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_256_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_512_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_512);

    /**
     * SHA3-256値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_512um(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_512um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-512値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_512Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_512_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    private final static DigestUtils SHA3_384_HASH = new DigestUtils(MessageDigestAlgorithms.SHA3_384);

    /**
     * SHA3-384値の取得
     *
     * @param binary 対象バイト
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_384um(byte[] binary, boolean upperCase) {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(binary).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(binary);
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param upperCase
     * @return ハッシュ値
     */
    public static String toSHA3_384um(String str, boolean upperCase) {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(str).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(str);
        }
    }

    /**
     * SHA3-384値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @param upperCase
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static String toSHA3_384Sum(String str, String charset, boolean upperCase)
            throws UnsupportedEncodingException {
        if (upperCase) {
            return SHA3_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset)).toUpperCase();
        } else {
            return SHA3_384_HASH.digestAsHex(StringUtil.getBytesCharset(str, charset));
        }
    }

    /**
     * XXHash32値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return CRC値
     * @throws UnsupportedEncodingException
     */
    public static long toXXHash32(String str, String charset) throws UnsupportedEncodingException {
        return toXXHash32(str.getBytes(charset));
    }

    /**
     * XXHash32値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static long toXXHash32(byte[] binary) {
        XXHash32 crc = new XXHash32();
        crc.reset();
        crc.update(binary);
        return crc.getValue();
    }

    /**
     * MurmurHash値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static int toMurmurHash2_32(byte[] binary) {
        return MurmurHash2.hash32(binary, binary.length);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static int toMurmurHash2_32(String str) {
        return MurmurHash2.hash32(str);
    }

    /**
     * MurmurHash2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static int toMurmurHash2_32(String str, String charset)
            throws UnsupportedEncodingException {
        byte[] body = StringUtil.getBytesCharset(str, charset);
        return MurmurHash2.hash32(body, body.length);
    }

    /**
     * MurmurHash2値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(byte[] binary) {
        return MurmurHash2.hash64(binary, binary.length);
    }

    /**
     * MurmurHash2値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(String str) {
        return MurmurHash2.hash64(str);
    }

    /**
     * MurmurHash2値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static long toMurmurHash2_64(String str, String charset)
            throws UnsupportedEncodingException {
        byte[] binary = StringUtil.getBytesCharset(str, charset);
        return MurmurHash2.hash64(binary, binary.length);
    }

    /**
     * MurmurHash3値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static int toMurmurHash3_32x86(byte[] binary) {
        return MurmurHash3.hash32x86(binary);
    }

    /**
     * MurmurHash3値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static int toMurmurHash3_32x86(String str) {
        return toMurmurHash3_32x86(StringUtil.getBytesRaw(str));
    }

    /**
     * MurmurHash3値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static int toMurmurHash3_32x86(String str, String charset)
            throws UnsupportedEncodingException {
        return toMurmurHash3_32x86(StringUtil.getBytesCharset(str, charset));
    }


    /**
     * MurmurHash3値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static BigInteger toMurmurHash3_128x64(byte[] binary) {
        long[] hash128x64 = MurmurHash3.hash128x64(binary);
        ByteBuffer sameBuffer = ByteBuffer.allocate(16);
        sameBuffer.putLong(hash128x64[1]);
        sameBuffer.putLong(hash128x64[0]);
        return new BigInteger(1, sameBuffer.array());
    }

    /**
     * MurmurHash3値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static BigInteger toMurmurHash3_128x64(String str) {
        return toMurmurHash3_128x64(StringUtil.getBytesRaw(str));
    }

    /**
     * MurmurHash3値の取得
     *
     * @param str 対象文字列
     * @param charset エンコーディング
     * @return ハッシュ値
     * @throws UnsupportedEncodingException
     */
    public static BigInteger toMurmurHash3_128x64(String str, String charset)
            throws UnsupportedEncodingException {
        return toMurmurHash3_128x64(StringUtil.getBytesCharset(str, charset));
    }

    public static boolean isBase64Encoded(String value) {
        return Base64.isBase64(value);
    }

    public static String toBase64Encode(String src, Charset charset) {
        return toBase64Encode(src, charset, true);
    }

    public static String toBase64Encode(String src, Charset charset, boolean padding, int lineLength, String lineSeparator) {
        final Base64 b64 = new Base64.Builder().setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase64Encode(src, charset, true);
    }

    public static String toBase64Encode(String src, String charset, boolean padding, int lineLength, String lineSeparator)
            throws UnsupportedEncodingException {
        final Base64 b64 = new Base64.Builder().setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase64Encode(src, true);
    }

    public static String toBase64Encode(byte[] src, boolean padding, int lineLength, String lineSeparator) {
        final Base64 b64 = new Base64.Builder().setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = Base64.encodeBase64(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(Base64.encodeBase64(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64Decode(String str, Charset charset) {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase64Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase64Decode(String str) {
        byte bytes[] = Base64.decodeBase64(str);
        return bytes;
    }

    public static String toBase64URLSafeEncode(String src, Charset charset) {
        byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset), false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeEncode(String src, Charset charset, boolean padding, int lineLength, String lineSeparator) {
        final Base64 b64 = new Base64.Builder().setUrlSafe(true).setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64URLSafeEncode(String src, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.encodeBase64(StringUtil.getBytesCharset(src, charset), false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeEncode(String src, String charset, boolean padding, int lineLength, String lineSeparator)
            throws UnsupportedEncodingException {
        final Base64 b64 = new Base64.Builder().setUrlSafe(true).setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64URLSafeEncode(byte[] src) {
        byte bytes[] = Base64.encodeBase64(src, false, true);
        return StringUtil.getBytesRawString(bytes);
    }

    public static String toBase64URLSafeEncode(byte[] src, boolean padding, int lineLength, String lineSeparator)
            throws UnsupportedEncodingException {
        final Base64 b64 = new Base64.Builder().setUrlSafe(true).setLineLength(lineLength).setLineSeparator(lineSeparator.getBytes(StandardCharsets.ISO_8859_1)).get();
        if (padding) {
            byte bytes[] = b64.encode(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(b64.encode(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase64URLSafeDecode(String str, Charset charset) {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase64URLSafeDecode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = Base64.decodeBase64(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase64URLSafeDecode(String str) {
        byte bytes[] = Base64.decodeBase64(str);
        return bytes;
    }

    public static String toBase32Encode(String src, Charset charset) {
        return toBase32Encode(src, charset, true);
    }

    public static String toBase32Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = toBase32Encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, charset, true);
    }

    public static String toBase32Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = toBase32Encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, true);
    }

    public static String toBase32Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = toBase32Encode(src);
            return StringUtil.getBytesRawString(bytes);
        } else {
            byte bytes[] = removePadding(toBase32Encode(src));
            return StringUtil.getBytesRawString(bytes);
        }
    }

    public static String toBase32Decode(String str, Charset charset) {
        byte bytes[] = toBase32Decode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase32Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = toBase32Decode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase32Decode(String str) {
        final Base32 b32 = new Base32();
        return b32.decode(str);
    }

    private static byte[] toBase32Encode(byte[] bytes) {
        final Base32 b32 = new Base32();
        return b32.encode(bytes);
    }

    public static String toBase16Encode(String src, Charset charset) {
        return toBase16Encode(src, charset, true);
    }

    public static String toBase16Encode(String src, Charset charset, boolean padding) {
        if (padding) {
            byte bytes[] = toBase16encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = removePadding(toBase16encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Encode(String src, String charset)
            throws UnsupportedEncodingException {
        return toBase16Encode(src, charset, true);
    }

    public static String toBase16Encode(String src, String charset, boolean padding)
            throws UnsupportedEncodingException {
        if (padding) {
            byte bytes[] = toBase16encode(StringUtil.getBytesCharset(src, charset));
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = removePadding(toBase16encode(StringUtil.getBytesCharset(src, charset)));
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Encode(byte[] src, String charset)
            throws UnsupportedEncodingException {
        return toBase32Encode(src, true);
    }

    public static String toBase16Encode(byte[] src, boolean padding) {
        if (padding) {
            byte bytes[] = toBase16encode(src);
            return StringUtil.getStringRaw(bytes);
        } else {
            byte bytes[] = toBase16encode(src);
            return StringUtil.getStringRaw(bytes);
        }
    }

    public static String toBase16Decode(String str, Charset charset) {
        byte bytes[] = toBase16encode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static String toBase16Decode(String str, String charset)
            throws UnsupportedEncodingException {
        byte bytes[] = toBase16encode(str);
        return StringUtil.getStringCharset(bytes, charset);
    }

    public static byte[] toBase16Decode(String str) {
        byte bytes[] = toBase16encode(str);
        return bytes;
    }

    private static byte[] toBase16encode(byte[] bytes) {
        final Base16 b16 = new Base16();
        return b16.encode(bytes);
    }

    private static byte[] toBase16encode(String str) {
        final Base16 b16 = new Base16();
        return b16.decode(str);
    }

    private static byte[] removePadding(byte[] vaule) {
        int len = vaule.length;
        while (len > 0 && vaule[len - 1] == (byte) '=') {
            len--;
        }
        return Arrays.copyOf(vaule, len);
    }

}
