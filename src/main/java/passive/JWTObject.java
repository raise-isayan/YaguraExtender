package passive;

import java.io.IOException;
import extend.util.external.JsonUtil;

/**
 *
 * @author isayan
 */
public class JWTObject extends JWTToken {

    public JWTObject(JWTToken token) {
        super(token);
    }

    /**
     * @param pretty
     * @return the header
     */
    public String getHeaderJSON(boolean pretty) {
        return JsonUtil.prettyJson(decodeUrlSafe(this.getHeader()), pretty);
    }

    /**
     * @param pretty
     * @return the payload
     */
    public String getPayloadJSON(boolean pretty) {
        return JsonUtil.prettyJson(decodeUrlSafe(this.getPayload()), pretty);
    }

}
