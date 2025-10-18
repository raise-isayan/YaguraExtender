package passive;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import extend.util.external.JWSUtil;
import extension.helpers.MatchUtil;
import extension.helpers.StringUtil;
import extension.view.base.CaptureItem;
import java.text.ParseException;
import java.util.logging.Logger;
import static passive.JWTToken.isTokenFormat;

/**
 *
 * @author isayan
 */
public class JWSToken implements JsonToken {

    private final static Logger logger = Logger.getLogger(JWSToken.class.getName());

    private final static JWSToken jwsInstance = new JWSToken();

    public JWSToken getInstance() {
        return jwsInstance;
    }

    private JWSToken() {
    }

    private Algorithm algorithm;
    private String header;
    private String payload;
    private String signature;

    /**
     * @return the signAlgorithm
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public JsonToken parseToken(String value, boolean matches) {
        JWSToken token = null;
        if (MatchUtil.isUrlencoded(value)) {
            value = JsonToken.decodeUrl(value);
        }
        CaptureItem[] items = null;
        boolean find = false;
        if (matches) {
            find = isTokenFormat(value);
            if (find) items = JWSUtil.findToken(value);
        } else {
            items = JWSUtil.findToken(value);
            find = items.length > 0;
        }
        if (items != null) {
            for (int i = 0; i < items.length; i++) {
                try {
                    SignedJWT jwt = SignedJWT.parse(items[i].getCaptureValue());
                    token = new JWSToken();
                    String header = jwt.getHeader().toBase64URL().toString();
                    String payload = jwt.getPayload().toBase64URL().toString();
                    String signature = jwt.getSignature().toString();
                    token.algorithm = Header.parse(header).getAlgorithm();
                    token.header = header;
                    token.payload = payload;
                    token.signature = signature;
                } catch (ParseException ex) {
                    //
                }
                break;
            }
        }
        return token;
    }

    @Override
    public boolean isValidFormat(String value) {
        try {
            JWSObject.parse(getToken());
            return true;
        } catch (ParseException ex) {
            return false;
        }
    }

    @Override
    public boolean isSignFormat() {
        return (this.algorithm.equals(JWSAlgorithm.ES256)
                || this.algorithm.equals(JWSAlgorithm.HS384)
                || this.algorithm.equals(JWSAlgorithm.ES256));
    }

    @Override
    public String getToken() {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        buff.append(".");
        buff.append(signature);
        return buff.toString();
    }

    @Override
    public String getData() {
        StringBuilder buff = new StringBuilder();
        buff.append(header);
        buff.append(".");
        buff.append(payload);
        return buff.toString();
    }

    /**
     * @return the header
     */
    public String getHeader() {
        return header;
    }

    @Override
    public String getPayload() {
        return payload;
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public boolean signatureEqual(final String secret) {
        try {
            return signatureEqual(Header.parse(this.header), this.getPayload(), this.getSignature(), secret);
        } catch (ParseException ex) {
            return false;
        }
    }

    public static boolean signatureEqual(Header header, String payload, String signature, String secret) {
        return signatureEqual(header, Base64URL.from(payload), Base64URL.from(signature), StringUtil.getBytesRaw(secret));
    }

    protected static boolean signatureEqual(Header header, Base64URL payload, final Base64URL signature, final byte[] secret) {
        Algorithm algo = header.getAlgorithm();
        if (algo.equals(JWSAlgorithm.ES256)
                || algo.equals(JWSAlgorithm.HS384)
                || algo.equals(JWSAlgorithm.ES256)) {
            try {
                JWSObject token = new JWSObject(header.toBase64URL(), payload, signature);
                JWSVerifier verifier = new MACVerifier(secret);
                return token.verify(verifier);
            } catch (ParseException | JOSEException ex) {
                return false;
            }
        }
        return false;
    }

}
