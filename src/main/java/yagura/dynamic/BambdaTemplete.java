package yagura.dynamic;

import extension.burp.FilterProperty;
import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticListener;

/**
 *
 * @author isayan
 */
public class BambdaTemplete {

    private final static Logger logger = Logger.getLogger(BambdaTemplete.class.getName());

    public final static String BAMBDA_DEFAULT = "return true;";

    private final static String PROXY_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaProxyFilter {
                public boolean matches(burp.api.montoya.proxy.ProxyHttpRequestResponse requestResponse, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String WEBSOCKET_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaWebSocketFilter {
                public boolean matches(burp.api.montoya.proxy.ProxyWebSocketMessage message, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String SITEMAP_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaSiteMapFilter {
               public boolean matches(burp.api.montoya.sitemap.SiteMapNode node, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String LOGGER_CAPTURE_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaLoggerCaptureFilter {
                public boolean matches(burp.api.montoya.logger.LoggerCaptureHttpRequestResponse requestResponse, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String LOGGER_HTTP_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaLoggerHttpFilter {
                public boolean matches(burp.api.montoya.proxy.LoggerHttpRequestResponse requestResponse, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String REQUESWT_REPLACE_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaRequestReplaceFilter {
                public burp.api.montoya.http.message.requests.HttpRequest replace(burp.api.montoya.proxy.ProxyHttpRequestResponse requestResponse, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String RESPONSE_REPLACE_FILTER_FMT
            = """
            import java.util.function.*;
            import burp.api.montoya.core.*;
            import burp.api.montoya.http.message.*;
            import burp.api.montoya.http.message.params.*;
            import burp.api.montoya.http.message.requests.*;
            import burp.api.montoya.http.message.responses.*;
            public class %s implements yagura.dynamic.BambdaRequestReplaceFilter {
                public burp.api.montoya.http.message.responses.HttpResponse replace(burp.api.montoya.proxy.ProxyHttpRequestResponse requestResponse, burp.api.montoya.utilities.Utilities utilities) {
                    %s
                }
            }
            """;

    private final static String HTTP_MESSAGE = "boolean matches(ProxyHttpRequestResponse requestResponse, Utilities utilities)";
    private final static String WEBSOCKET_MESSAGE = "boolean matches(ProxyWebSocketMessage messsage, Utilities utilities)";
    private final static String SITE_MAP_MESSAGE = "boolean matches(SiteMapNode node, Utilities utilities)";
    private final static String REQUEST_REPLACE_MESSAGE = "HttpRequest replace(ProxyHttpRequestResponse requestResponse, Utilities utilities)";
    private final static String RESPONSE_REPLACE_MESSAGE = "HttpResponse replace(ProxyHttpRequestResponse requestResponse, Utilities utilities)";

    public static String getFunctionMessage(FilterProperty.FilterCategory filterCategory) {
        String message = "";
        switch (filterCategory) {
            case HTTP:
                message = HTTP_MESSAGE;
                break;
            case WEBSOCKET:
                message = WEBSOCKET_MESSAGE;
                break;
            case SITE_MAP:
                message = SITE_MAP_MESSAGE;
                break;
            case REQUEST_REPLACE:
                message = REQUEST_REPLACE_MESSAGE;
                break;
            case RESPONSE_REPLACE:
                message = RESPONSE_REPLACE_MESSAGE;
                break;
        }
        return message;
    }

    public static String getFunctionName(String functionName, FilterProperty.FilterCategory category) {
        String template = null;
        switch (category) {
            case HTTP:
                template = String.format("BambdaProxyFilterImpl%s", functionName);
                break;
            case WEBSOCKET:
                template = String.format("BambdaProxyWebSocketFilterImpl%s", functionName);
                break;
            case SITE_MAP:
                template = String.format("BambdaProxyFilterImpl%s", functionName);
                break;
            case LOGGER_CAPTURE:
                template = String.format("BambdaLoggerCaptureFilterImpl%s", functionName);
                break;
            case LOGGER_DISPLAY:
                template = String.format("BambdaLoggerHttpFilterImpl%s", functionName);
                break;
            case REQUEST_REPLACE:
                template = String.format("BambdaRequestReplaceFilter%s", functionName);
                break;
            case RESPONSE_REPLACE:
                template = String.format("BambdaResponseReplaceFilter%s", functionName);
                break;
        }
        return template;
    }

    public static BambdaTemplete create(String functionName, String content, FilterProperty.FilterCategory category) {
        BambdaTemplete templete = null;
        switch (category) {
            case HTTP:
                templete = new BambdaTemplete(functionName, String.format(PROXY_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case WEBSOCKET:
                templete = new BambdaTemplete(functionName, String.format(WEBSOCKET_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case SITE_MAP:
                templete = new BambdaTemplete(functionName, String.format(SITEMAP_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case LOGGER_CAPTURE:
                templete = new BambdaTemplete(functionName, String.format(LOGGER_CAPTURE_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case LOGGER_DISPLAY:
                templete = new BambdaTemplete(functionName, String.format(LOGGER_HTTP_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case REQUEST_REPLACE:
                templete = new BambdaTemplete(functionName, String.format(REQUESWT_REPLACE_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
            case RESPONSE_REPLACE:
                templete = new BambdaTemplete(functionName, String.format(RESPONSE_REPLACE_FILTER_FMT.replaceAll("[\\r\\n]", " "), functionName, content));
                break;
        }
        return templete;
    }

    private final SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();

    public BambdaFilter getBambaFilter(BambdaTemplete templete) {
        Object inst = null;
        try {
            DiagnosticListener listener = new DiagnosticListener() {
                @Override
                public void report(Diagnostic diagnostic) {

                }
            };
            Class defineClass = this.engine.compile(templete.getFunctionName(), templete.getContent(), listener);
            inst = defineClass.getDeclaredConstructor().newInstance();
        } catch (NoSuchMethodException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (SecurityException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (InstantiationException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IllegalAccessException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (InvocationTargetException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        if (inst instanceof BambdaFilter filter) {
            return filter;
        }
        else {
            return null;
        }
    }

    private final String functionName;
    private final String content;

    public BambdaTemplete(String functionName, String content) {
        this.functionName = functionName;
        this.content = content;
    }

    /**
     * @return the functionName
     */
    public String getFunctionName() {
        return this.functionName;
    }

    /**
     * @return the content
     */
    public String getContent() {
        return this.content;
    }

}
