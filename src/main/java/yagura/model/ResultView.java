package yagura.model;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import extension.burp.HttpTarget;
import extension.helpers.StringUtil;

/**
 *
 * @author isayan
 */
public class ResultView extends HttpMessageItem implements TableMapBase {

    private final String[] columnsName = new String[]{
        null, "original", "host", "method", "URL", "status", "length", "notes", "listen port"
    };

    private final boolean [] canEdit = new boolean []{
       false, true, false, false, false, false, false, false, false
    };

    public ResultView(HttpMessageItem item) {
        super(item);
    }

    public ResultView(ProxyHttpRequestResponse item, int ordinal) {
        super(item, ordinal);
    }

    public String getHost() {
        return this.finalRequest().httpService().host();
    }

    public String getMethod() {
        return this.finalRequest().method();
    }

    public String getUrl() {
        String protocol = HttpTarget.getProtocol(this.finalRequest().httpService().secure());
        return protocol + "://" + this.getHost();
    }

    public int getStatus() {
        if (this.hasResponse()) {
            return (int) this.response().statusCode();
        }
        return -1;
    }

    public int getLength() {
        if (this.hasResponse()) {
            return this.getResponse().length;
        }
        return -1;
    }

}
