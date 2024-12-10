package extend.util.external;

import extension.helpers.StringUtil;
import java.io.UnsupportedEncodingException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.commons.codec.digest.MurmurHash2;

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
     * MurmurHash値の取得
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
     * MurmurHash値の取得
     *
     * @param binary 対象バイト
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(byte[] binary) {
        return MurmurHash2.hash64(binary, binary.length);
    }

    /**
     * MurmurHash値の取得
     *
     * @param str 対象文字列
     * @return ハッシュ値
     */
    public static long toMurmurHash2_64(String str) {
        return MurmurHash2.hash64(str);
    }

    /**
     * MurmurHash値の取得
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


}
