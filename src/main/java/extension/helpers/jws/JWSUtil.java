package extension.helpers.jws;

import extension.helpers.BouncyUtil;
import extension.helpers.StringUtil;
import extension.view.base.CaptureItem;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;

/**
 *
 * @author isayan
 */
public class JWSUtil {

    private JWSUtil() {
    }

    private final static BouncyCastleProvider BC_PROVIDER_INSTANCE = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER_INSTANCE);
        }
    }

    private final static Pattern SPLIT_SEGMENT = Pattern.compile("\\.");

    public static String[] splitSegment(String token) {
        String[] segment = new String[]{"", "", ""};
        String[] split = SPLIT_SEGMENT.split(token, segment.length);
        System.arraycopy(split, 0, segment, 0, split.length);
        return segment;
    }

    public static int INCLUDE_SIGNATURE = 0x01;
    public static int FLASK_COMPRESS = 0x010;

    /**
     * 指定されたインデックスの文字または文字シーケンスが、JWTセグメントの有効な文字であるかを判定します。
     * Base64URL-safe文字に加え、URLエンコードされた例外文字を考慮します。
     *
     * @param text 入力文字列
     * @param index チェックを開始するインデックス
     * @param n 文字列の長さ
     * @return 有効な文字であればtrue
     */
    private static boolean isValidJwsChar(String text, int index, int n) {
        if (index >= n) {
            return false;
        }

        char c = text.charAt(index);

        // 1. 標準的なBase64URL-safe文字: A-Z, a-z, 0-9
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            return true;
        }
        // 2. 標準的なBase64URL-safe文字: - (ハイフン), _ (アンダースコア)
        if (c == '-' || c == '_') {
            return true;
        }
        // 3. URLエンコードされた例外文字: %2d (ハイフン), %5f (アンダースコア)
        if (c == '%' && index + 2 < n) {
            String encoded = text.substring(index, index + 3).toLowerCase();
            return encoded.equals("%2d") || encoded.equals("%5f");
        }
        return false;
    }

    /**
     * 指定されたインデックスの文字または文字シーケンスが、セグメント文字として占める長さを返します。
     *
     * @param text 入力文字列
     * @param index チェックを開始するインデックス
     * @param n 文字列の長さ
     * @return 長さ (1または3)。有効な文字でなければ0
     */
    private static int getCharLength(String text, int index, int n) {
        if (!isValidJwsChar(text, index, n)) {
            return 0;
        }
        // URLエンコードされた文字(%2d, %5f)は3文字、それ以外は1文字です。
        if (text.charAt(index) == '%') {
            return 3;
        }
        return 1;
    }

    /**
     * 指定されたインデックスの文字または文字シーケンスが、JWTのセグメント区切り文字 (`.` または `%2e`) である場合にその長さを返します。
     *
     * @param text 入力文字列
     * @param index チェックを開始するインデックス
     * @param n 文字列の長さ
     * @return 区切り文字の長さ (1または3)。区切り文字でなければ0
     */
    private static int getSeparatorLength(String text, int index, int n) {
        if (index >= n) {
            return 0;
        }
        char c = text.charAt(index);
        // 1. 標準の区切り文字: . (ドット)
        if (c == '.') {
            return 1;
        }
        // 2. URLエンコードされた区切り文字: %2e (ドット)
        if (c == '%' && index + 2 < n) {
            String encoded = text.substring(index, index + 3).toLowerCase();
            if (encoded.equals("%2e")) {
                return 3;
            }
        }
        return 0;
    }

    /**
     * 指定されたインデックスからJWTセグメントの終わり（区切り文字または文字列の終わり）を探し、 セグメントの直後のインデックスを返します。
     *
     * @param text 入力文字列
     * @param start セグメントの開始インデックス
     * @param n 文字列の長さ
     * @return セグメントの終了直後のインデックス (排他的)。セグメントの長さが0の場合はstartと同じ
     */
    private static int findPartEnd(String text, int start, int n) {
        int end = start;
        while (end < n) {
            int charLen = getCharLength(text, end, n);
            if (charLen == 0) {
                break; // 有効なセグメント文字ではない
            }
            end += charLen;
        }
        return end;
    }

    public static CaptureItem[] findTokenFormat(String text) {
        return findTokenFormat(text, 0);
    }

    /**
     * 文字列からJWSトークンの形式にマッチする部分をすべて検索します。 トークンは2パート (header.payload) または 3パート
     * (header.payload.signature) の形式です。 署名部が空のケース (header.payload.) もマッチします。
     *
     * @param text 検索対象の文字列
     * @param flags
     * @return マッチしたCaptureItemオブジェクトのリスト
     */
    public static CaptureItem[] findTokenFormat(String text, int flags) {
        List<CaptureItem> results = new ArrayList<>();
        int n = text.length();
        int i = 0; // 検索開始インデックス

        while (i < n) {
            int tokenStart = i;

            // --- Part 1 (Header) の検索 ---
            int part1End = findPartEnd(text, tokenStart, n);
            int part1Length = part1End - tokenStart;
            if (part1Length < 2) {
                i++; // Part 1が見つからない場合は次の文字から開始
                continue;
            }

            // --- Separator 1 の検索 ---
            int sep1Len = getSeparatorLength(text, part1End, n);
            if (sep1Len == 0) {
                i++; // 区切り文字が見つからない場合は次の文字から開始
                continue;
            }
            int part2Start = part1End + sep1Len;

            // --- Part 2 (Payload) の検索 ---
            int part2End = findPartEnd(text, part2Start, n);
            int part2Length = part2End - part2Start;
            if (part2Length < 0) {
                // JWTのHeaderとPayloadは非空である必要があるため、Part 2が空の場合は失敗
                // Part 1の途中にPart 2の開始があった可能性があるため、次の文字ではなく、Part 1の次の文字から再開
                i = tokenStart + 1;
                continue;
            }

            int tokenEnd = part2End;
            boolean foundToken = false;

            // --- Separator 2 のチェック ---
            int sep2Len = getSeparatorLength(text, part2End, n);

            if (sep2Len > 0) {
                // Case 3-part: header.payload.signature (署名部が空の場合も含む)
                int part3Start = part2End + sep2Len;
                int part3End = findPartEnd(text, part3Start, n);

                // Part 3 (Signature) の内容は空でも有効 (alg: "none")
                if ((flags & INCLUDE_SIGNATURE) == INCLUDE_SIGNATURE) {
                    foundToken = 20 < (part3End - part3Start);
                } else {
                    foundToken = true;
                }
                tokenEnd = part3End;
            }

            if (foundToken) {
                // 圧縮されている場合
                int offset = 0;
                if ((flags & FLASK_COMPRESS) == FLASK_COMPRESS) {
                    if (tokenStart >= 3 && getSeparatorLength(text, tokenStart - 3, n) == 3) {
                        offset = -3;
                    } else if (tokenStart >= 1 && getSeparatorLength(text, tokenStart - 1, n) == 1) {
                        offset = -1;
                    }
                }
                // トークンをキャプチャ
                String token = text.substring(tokenStart + offset, tokenEnd);

                // 終了インデックスは0-basedで最後の文字のインデックス+1
                CaptureItem item = new CaptureItem();
                item.setCaptureValue(token);
                item.setStart(tokenStart + offset);
                item.setEnd(tokenEnd);
                results.add(item);
                // 検索を、見つかったトークンの直後から再開
                i = tokenEnd;
            } else {
                // このルートは通常実行されないが、安全のためにインデックスを進める
                i = tokenStart + 1;
            }
        }
        return results.toArray(CaptureItem[]::new);
    }

    public static SecretKey toSecretKey(String secret) {
        return new SecretKeySpec(StringUtil.getBytesRaw(secret), "MAC");
    }

    public static SecretKey toSecretKey(byte[] secret) {
        return new SecretKeySpec(secret, "MAC");
    }

    public static PrivateKey toPrivateKey(String pemData) throws PEMException {
        return BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

    public static PublicKey toPublicKey(String pemData) throws PEMException {
        return BouncyUtil.loadPublicKeyFromPem(pemData);
    }

    public static RSAPrivateKey toRSAPrivateKey(String pemData) throws PEMException {
        return (RSAPrivateKey) BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

    public static RSAPublicKey toRSAPublicKey(String pemData) throws PEMException {
        return (RSAPublicKey) BouncyUtil.loadPublicKeyFromPem(pemData);
    }

    public static ECPrivateKey toECPrivateKey(String pemData) throws PEMException {
        return (ECPrivateKey) BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

    public static ECPublicKey toECPublicKey(String pemData) throws PEMException {
        return (ECPublicKey) BouncyUtil.loadPublicKeyFromPem(pemData);
    }

    public static EdECPrivateKey toEdECPrivateKey(String pemData) throws PEMException {
        return (EdECPrivateKey) BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

    public static EdECPublicKey toEdECPublicKey(String pemData) throws PEMException {
        return (EdECPublicKey) BouncyUtil.loadPublicKeyFromPem(pemData);
    }

}
