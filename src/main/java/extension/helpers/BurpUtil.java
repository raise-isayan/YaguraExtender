package extension.helpers;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.HttpHandler;
import burp.api.montoya.http.RequestResult;
import burp.api.montoya.http.ResponseResult;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.InterceptedHttpRequest;
import burp.api.montoya.proxy.InterceptedHttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestHandler;
import burp.api.montoya.proxy.ProxyHttpResponseHandler;
import burp.api.montoya.proxy.RequestFinalInterceptResult;
import burp.api.montoya.proxy.RequestInitialInterceptResult;
import burp.api.montoya.proxy.ResponseFinalInterceptResult;
import burp.api.montoya.proxy.ResponseInitialInterceptResult;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import extension.burp.BurpConfig;
import extension.burp.IBurpTab;
import java.awt.Color;
import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;
import javax.swing.JTabbedPane;

/**
 *
 * @author isayan
 */
public class BurpUtil {
    private final static Logger logger = Logger.getLogger(BurpUtil.class.getName());

    public EditorOptions [] EDITOR_READ_ONLY = new EditorOptions[] {EditorOptions.READ_ONLY};

    public static String parseFilterPattern(String pattern) {
        String[] extentions = pattern.split(",");
        StringBuilder buff = new StringBuilder();
        if (extentions.length == 1 && extentions[0].equals("")) {
            return buff.toString();
        }
        buff.append("\\.");
        buff.append("(");
        for (int i = 0; i < extentions.length; i++) {
            if (extentions[i].length() > 0) {
                if (i > 0) {
                    buff.append("|");
                }
                buff.append(extentions[i]);
            }
        }
        buff.append(")$");
        return buff.toString();
    }

    public static String copySelectionData(ContextMenuEvent contextMenu, boolean selectionTextOnly) {
        String text = null;
        InvocationType context = contextMenu.invocationType();
        if (contextMenu.messageEditorRequestResponse().isEmpty() && selectionTextOnly) {
            return null;
        }
        MessageEditorHttpRequestResponse messageInfo = contextMenu.messageEditorRequestResponse().get();
        byte message[] = new byte[0];
        if (context == InvocationType.MESSAGE_EDITOR_REQUEST || context == InvocationType.MESSAGE_VIEWER_REQUEST) {
            message = messageInfo.getRequestResponse().httpRequest().asBytes().getBytes();
        } else if (context == InvocationType.MESSAGE_EDITOR_RESPONSE || context == InvocationType.MESSAGE_EDITOR_RESPONSE) {
            message = messageInfo.getRequestResponse().httpResponse().asBytes().getBytes();
        }
        Range range = messageInfo.selectionOffsets().get();
        if (message != null) {
            if (range == null) {
                text = StringUtil.getStringRaw(message);
            } else {
                text = StringUtil.getStringCharset(message, range.startIndexInclusive(), range.endIndexExclusive() - range.startIndexInclusive(), StandardCharsets.ISO_8859_1);
            }
        }
        return text;
    }

    public static void pasteSelectionData(ContextMenuEvent contextMenu, String text, boolean selectionTextOnly) {
        InvocationType context = contextMenu.invocationType();
        if (contextMenu.messageEditorRequestResponse().isEmpty() && selectionTextOnly) {
            return;
        }
        MessageEditorHttpRequestResponse messageInfo = contextMenu.messageEditorRequestResponse().get();

        byte message[] = new byte[0];
        if (context == InvocationType.MESSAGE_EDITOR_REQUEST || context == InvocationType.MESSAGE_VIEWER_REQUEST) {
            message = messageInfo.getRequestResponse().httpRequest().asBytes().getBytes();
        } else if (context == InvocationType.MESSAGE_EDITOR_RESPONSE || context == InvocationType.MESSAGE_VIEWER_RESPONSE) {
            message = messageInfo.getRequestResponse().httpResponse().asBytes().getBytes();
        }
        Range range = messageInfo.selectionOffsets().get();
        if (message != null) {
            if (range == null) {
                // nothing
            } else {
                text = StringUtil.getStringRaw(ConvertUtil.replaceByte(message, range.startIndexInclusive(), range.endIndexExclusive(), StringUtil.getBytesRaw(text)));
            }
        }
    }

    public static void sendToTextHighlight(IBurpTab tab) {
        final Color burpTextHighlightColor = BurpConfig.getTabFlashColor();
        if (tab.getUiComponent() == null) return;
        Container container = tab.getUiComponent().getParent();
        if (container instanceof JTabbedPane) {
            final JTabbedPane tabbet = (JTabbedPane) container;
            final int index = tabbet.indexOfTab(tab.getTabCaption());
            if (index > -1) {
                tabbet.setBackgroundAt(index, burpTextHighlightColor);
                // 解除
                final Timer timer = new Timer(false);
                TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        tabbet.setForegroundAt(index, null);
                        tabbet.setBackgroundAt(index, null);
                    }
                };
                timer.schedule(task, 5000);
            }
        }
    }

    public static class HttpHandlerAdapter implements HttpHandler {
        @Override
        public RequestResult handleHttpRequest(HttpRequest httpRequest, Annotations annotations, ToolSource toolSource) {
            return RequestResult.requestResult(httpRequest, annotations);
        }

        @Override
        public ResponseResult handleHttpResponse(HttpResponse httpResponse, HttpRequest httpRequest, Annotations annotations, ToolSource toolSource) {
            return ResponseResult.responseResult(httpResponse, annotations);
        }
    }

    public static class ProxyHttpRequestHandlerAdapter implements ProxyHttpRequestHandler {

        @Override
        public RequestInitialInterceptResult handleReceivedRequest(InterceptedHttpRequest interceptedHttpRequest, Annotations annotations) {
            return RequestInitialInterceptResult.doNotIntercept(interceptedHttpRequest, annotations);
        }

        @Override
        public RequestFinalInterceptResult handleRequestToIssue(InterceptedHttpRequest httpRequest, Annotations annotations) {
            return RequestFinalInterceptResult.continueWith(httpRequest, annotations);
        }

    }


    public static class ProxyHttpResponseHandlerAdapter implements ProxyHttpResponseHandler {
        @Override
        public ResponseInitialInterceptResult handleReceivedResponse(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {
            return ResponseInitialInterceptResult.doNotIntercept(interceptedHttpResponse, annotations);
        }

        @Override
        public ResponseFinalInterceptResult handleResponseToReturn(InterceptedHttpResponse interceptedHttpResponse, HttpRequest httpRequest, Annotations annotations) {
            return ResponseFinalInterceptResult.continueWith(interceptedHttpResponse, annotations);
        }

    }


}
