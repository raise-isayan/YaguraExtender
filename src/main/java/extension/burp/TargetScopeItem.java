package extension.burp;

import extension.helpers.HttpUtil;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class TargetScopeItem {

    private final static Logger logger = Logger.getLogger(TargetScopeItem.class.getName());

    private boolean enabled = false;
    private String protocol = HttpTarget.PROTOCOL_HTTP;
    private String host = "";
    private String port = "";
    private String file = "";

    private final Pattern regexAnyProtocol = Pattern.compile("(https|http)");
    private Pattern regexProtocol = regexAnyProtocol;
    private Pattern regexHost = Pattern.compile("");
    private Pattern regexPort = Pattern.compile("");
    private Pattern regexFile = Pattern.compile("");

    public TargetScopeItem() {

    }

    /**
     * @return the enabled
     */
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * @param enabled the enabled to set
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return the protocol
     */
    public String getProtocol() {
        return this.protocol;
    }

    /**
     * @param protocol the protocol to set
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
        if (HttpTarget.PROTOCOL_ANY.equals(protocol)) {
            this.regexProtocol = regexAnyProtocol;
        } else {
            this.regexProtocol = Pattern.compile(this.protocol);
        }
    }

    /**
     * @return the host
     */
    public String getHost() {
        return this.host;
    }

    /**
     * @param host the host to set
     */
    public void setHost(String host) {
        this.host = host;
        this.regexHost = Pattern.compile(this.host);
    }

    /**
     * @return the port
     */
    public String getPort() {
        return this.port;
    }

    /**
     * @param port the port to set
     */
    public void setPort(String port) {
        this.port = port;
        this.regexPort = Pattern.compile(this.port);
    }

    /**
     * @return the file
     */
    public String getFile() {
        return this.file;
    }

    /**
     * @param file the file to set
     */
    public void setFile(String file) {
        this.file = file;
        this.regexFile = Pattern.compile(this.file);
    }

    public boolean isMatch(URL url) {
        Matcher matchProtocol = this.regexProtocol.matcher(url.getProtocol());
        Matcher matchHost = this.regexHost.matcher(url.getHost());
        int urlPort = url.getPort();
        if (urlPort == -1) {
            urlPort = HttpUtil.getDefaultPort(url.getProtocol());
        }
        Matcher matchPort = this.regexPort.matcher(String.valueOf(urlPort));
        Matcher matchFile = this.regexFile.matcher(url.getFile());

        return (HttpTarget.PROTOCOL_ANY.equals(this.getProtocol()) || matchProtocol.matches())
                && ("".equals(this.getHost()) || matchHost.matches())
                && ("".equals(this.getPort()) || matchPort.matches())
                && ("".equals(this.getFile()) || matchFile.matches());
    }

    public void dump() {
        try {
            System.out.println(String.format("getProtocol=%s", this.getProtocol()));
            System.out.println(String.format("getHost=%s", this.getHost()));
            System.out.println(String.format("getPort=%s", this.getPort()));
            System.out.println(String.format("getFile=%s", this.getFile()));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder();
        buff.append(this.regexProtocol.pattern());
        buff.append("://");
        buff.append(this.regexHost.pattern());
        buff.append(":");
        buff.append(this.regexPort.pattern());
        buff.append("/");
        buff.append(this.regexFile.pattern());
        return buff.toString();
    }

    public static TargetScopeItem parseURL(URL url) {
        TargetScopeItem item = new TargetScopeItem();
        String protcol = HttpTarget.PROTOCOL_HTTP.equals(url.getProtocol()) ? HttpTarget.PROTOCOL_HTTP : HttpTarget.PROTOCOL_HTTPS;
        item.setProtocol(protcol);
        item.setHost(String.format("^%s$", Pattern.quote(url.getHost())));
        int urlPort = url.getPort();
        if (urlPort == -1) {
            urlPort = HttpUtil.getDefaultPort(url.getProtocol());
        }
        item.setPort(String.valueOf(urlPort));
        if ("".equals(url.getFile())) {
            item.setFile("^/.*");
        } else {
            item.setFile((String.format("^%s.*", Pattern.quote(url.getFile()))));
        }
        return item;
    }

}
