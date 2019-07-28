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
        try {
            return JsonUtil.prettyJSON(decodeUrlSafe(this.getHeader()), pretty);
        } catch (IOException ex) {
            return null;
        }
    }

    /**
     * @param pretty
     * @return the payload
     */
    public String getPayloadJSON(boolean pretty) {
        try {
            return JsonUtil.prettyJSON(decodeUrlSafe(this.getPayload()), pretty);
        } catch (IOException ex) {
            return null;
        }
    }

}
