package extend.util.external.jws;

import extension.helpers.BouncyUtil;
import extension.helpers.StringUtil;
import extension.view.base.CaptureItem;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.openssl.PEMException;

/**
 *
 * @author isayan
 */
public class JWSUtil {

    private JWSUtil() {

    }

    private static boolean isValidBase64UrlSegment(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    /**
     * 指定されたセグメントがBase64URLセーフな文字セット（A-Z, a-z, 0-9, -, _）のみで
     * 構成され、かつBase64URLデコード可能かを確認します。
     *
     * * @param segment JWTセグメント
     * @return 有効なBase64URLセグメントの場合 true
     */
    private static boolean isValidBase64UrlSegment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return false;
        }

        // Base64URLセーフな文字セットチェック
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (!isValidBase64UrlSegment(c)) {
                return false;
            }
        }

        // デコード可能かチェック (妥当性検証の強化)
        try {
            // Base64URLデコーダーを使用
            Base64.getUrlDecoder().decode(segment);
            return true;
        } catch (IllegalArgumentException e) {
            // Base64URLとして有効な形式でない
            return false;
        }
    }

    private final static Pattern SPLIT_SEGMENT = Pattern.compile("\\.");

    public static String[] splitSegment(String token) {
        String[] segment = new String[]{"", "", ""};
        String[] split = SPLIT_SEGMENT.split(token, segment.length);
        System.arraycopy(split, 0, segment, 0, split.length);
        return segment;
    }

    /**
     * テキストからJWTトークンを検索する
     *
     * @param text
     * @return トークン、開始位置、終了位置を含むリスト
     */
    public static CaptureItem[] findToken(String text) {
        List<CaptureItem> tokens = new ArrayList<>();
        int length = text.length();

        for (int startIndex = 0; startIndex < length; startIndex++) {
            char c = text.charAt(startIndex);

            // トークンはBase64URL文字以外はスキップ
            if (!isValidBase64UrlSegment(c)) {
                continue;
            }

            int firstDotIndex = -1;
            int secondDotIndex = -1;

            // 最初のピリオド (セグメント区切り) を探す
            for (int i = startIndex + 1; i < length; i++) {
                if (text.charAt(i) == '.') {
                    firstDotIndex = i;
                    break;
                }
            }

            if (firstDotIndex == -1) {
                // 最初のピリオドが見つからなければ、トークンではないので、この開始位置をスキップ
                continue;
            }

            // 2番目のピリオドを探す
            for (int i = firstDotIndex + 1; i < length; i++) {
                if (text.charAt(i) == '.') {
                    secondDotIndex = i;
                    break;
                }
            }

            if (secondDotIndex == -1) {
                // 2番目のピリオドが見つからなければ、3セグメントのトークンではないのでスキップ
                continue;
            }

            // 3番目のセグメントの終了位置を見つける
            int endIndex = length;
            for (int i = secondDotIndex + 1; i < length; i++) {
                char nextChar = text.charAt(i);
                // Base64URL文字以外の文字に遭遇したら、そこでトークンが終了と見なす
                if (!isValidBase64UrlSegment(nextChar)) {
                    endIndex = i;
                    break;
                }
            }

            // 候補文字列を抽出
            String candidateToken = text.substring(startIndex, endIndex);

            // セグメントに分割
            String[] parts = SPLIT_SEGMENT.split(candidateToken);

            // 厳密に3セグメントであること
            if (parts.length == 3) {
                // 各セグメントのBase64URL妥当性を検証
                if (isValidBase64UrlSegment(parts[0]) && isValidBase64UrlSegment(parts[1])) {
                    // 3番目のセグメントは署名
                    if (parts[2].isEmpty() || isValidBase64UrlSegment(parts[2])) {
                        // 有効なJWTトークンとして結果に追加
                        CaptureItem item = new CaptureItem();
                        item.setCaptureValue(candidateToken);
                        item.setStart(startIndex);
                        item.setEnd(endIndex);
                        tokens.add(item);
                        // 見つかったトークンの後から検索を再開し、オーバーラップを防ぐ
                        startIndex = endIndex - 1;
                    }
                }
            } else if (parts.length == 2) {
                if (isValidBase64UrlSegment(parts[0]) && isValidBase64UrlSegment(parts[1])) {
                    // 有効なJWTトークンとして結果に追加
                    CaptureItem item = new CaptureItem();
                    item.setCaptureValue(candidateToken);
                    item.setStart(startIndex);
                    item.setEnd(endIndex);
                    tokens.add(item);
                    startIndex = endIndex - 1;
                }

            }
        }
        return tokens.toArray(CaptureItem[]::new);
    }

    public static boolean containsTokenFormat(String value) {
        CaptureItem[] tokens = findToken(value);
        return tokens.length > 0;
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

    public static RSAPrivateKey toRSAPrivateKey(String pemData) throws PEMException {
        return (RSAPrivateKey) BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

    public static ECPrivateKey toECPrivateKey(String pemData) throws PEMException {
        return (ECPrivateKey) BouncyUtil.loadPrivateKeyFromPem(pemData);
    }

}
