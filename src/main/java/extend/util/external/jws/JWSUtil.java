package extend.util.external.jws;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import extension.view.base.CaptureItem;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 */
public class JWSUtil {

    public JWSAlgorithm[] ALG_NAMES = new JWSAlgorithm[]{
        JWSAlgorithm.HS256,
        JWSAlgorithm.HS384,
        JWSAlgorithm.HS512,
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        //JWSAlgorithm.ES256K,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512, //JWSAlgorithm.EdDSA,
    //JWSAlgorithm.Ed25519,
    // JWSAlgorithm.Ed448;
    };

    private JWSUtil() {
    }

    public static JWSHeader toHeader(JWSAlgorithm alg) {
        JWSHeader.Builder token = new JWSHeader.Builder(alg);
        token.type(JOSEObjectType.JWT);
        return token.build();
    }

    public static String toHeaderJSON(JWSAlgorithm alg) {
        return toHeader(alg).toString();
    }

    private static Payload algHeader(String algo) {
        JWTClaimsSet header = new JWTClaimsSet.Builder()
                .claim("alg", algo)
                .claim("typ", "JWT")
                .build();
        return header.toPayload();
    }

    private static Payload algNoneHeader() {
        return algHeader(JWSAlgorithm.NONE.getName());
    }

    public static String algHeaderJSON(String algo) {
        return algHeader(algo).toString();
    }

    public static String algNoneHeaderJSON() {
        return algNoneHeader().toString();
    }

    public static String algNone(Payload payload) {
        return serialize(algNoneHeader().toBase64URL(), payload.toBase64URL());
    }

    public static String serialize(Base64URL header, Base64URL payload) {
        StringBuilder token = new StringBuilder();
        return token.append(header.toString()).append('.').append(payload.toString()).append('.').toString();
    }

    public static boolean isValidJWT(String token) {
        try {
            SignedJWT.parse(token);
            return true;
        } catch (ParseException ex) {
            return false;
        }
    }

    public static boolean isValidJWTSegment(String token) {
        try {
            JWTClaimsSet.parse(token);
            return true;
        } catch (ParseException ex) {
            return false;
        }
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
            String[] parts = candidateToken.split("\\.");

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
            }
        }
        return tokens.toArray(CaptureItem[]::new);
    }


}
