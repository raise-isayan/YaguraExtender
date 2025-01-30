package yagura.dynamic;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapNode;
import burp.api.montoya.utilities.Utilities;
import extension.burp.FilterProperty;

/**
 *
 * @author isayan
 */
public class BambdaCompole {

    public String BAMBDA_DEFAULT = "return true;";

    private final static String proxyFilterFmt
            = """
            public class BambdaProxyFilterImpl%s implements BambdaProxyFilter {
                public boolean matches(ProxyHttpRequestResponse requestRespose, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String websocketFilterFmt
            = """
            public class BambdaProxyWebSocketFilterImpl%s implements BambdaWebSocketFilter {
                public boolean matches(ProxyWebSocketMessage requestRespose, burp.api.montoya.utilities.Utilities utilities);
                    %s
                }
            }
            """;

    private final static String siteMapFilterFmt
            = """
            public class BambdaProxyFilterImpl%s implements BambdaProxyFilter {
                public boolean matches(burp.api.montoya.proxy.ProxyHttpRequestResponse requestRespose, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    public static String createTemplate(String className, String content, FilterProperty.FilterCategory category) {
        String template = null;
        switch (category) {
        case HTTP:
            template =  String.format(proxyFilterFmt, className, content);
            break;
        case WEBSOCKET:
            template =  String.format(websocketFilterFmt, className, content);
            break;
        case SITE_MAP:
            template =  String.format(siteMapFilterFmt, className, content);
            break;
        }
        return template;
    }

}
