package extend.util.external;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import extension.burp.HttpTarget;
import extension.burp.MessageType;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTable;
import javax.swing.table.TableModel;

/**
 *
 * @author isayan
 */
public class ExtensionHelper {
    private final static Logger logger = Logger.getLogger(ExtensionHelper.class.getName());
    private final MontoyaApi api;

    public ExtensionHelper(MontoyaApi api) {
        this.api = api;
    }

    public void applyThemeToComponent(Component component) {
        api.userInterface().applyThemeToComponent(component);
    }

    public boolean isInScope(URL url) {
        return isInScope(url.toString());
    }

    public boolean isInScope(String url) {
        if (api != null) {
            return api.scope().isInScope(url);
        }
        else {
            throw new NullPointerException();
        }
    }

    public void outPrintln(String message) {
        outPrint(message + "\n");
    }

    public void outPrint(String message) {
        try {
            if (api != null) {
                api.logging().logToOutput(message);
            }
            else {
                System.out.print(message);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void errPrintln(String message) {
        errPrint(message + "\n");
    }

    public void errPrint(String message) {
        try {
            if (api != null) {
                api.logging().logToError(message);
            }
            else {
                System.err.print(message);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    /**
     * burp alert 通知
     *
     * @param caption キャプション
     * @param text テキスト
     * @param messageType メッセージタイプ
     */
    public void issueAlert(String caption, String text, MessageType messageType) {
        String msg = String.format("%s:%s", caption, text);
        switch (messageType) {
        case CRITICAL:
            api.logging().raiseCriticalEvent(msg);
            break;
        case ERROR:
            api.logging().raiseErrorEvent(msg);
            break;
        case DEBUG:
            api.logging().raiseDebugEvent(msg);
            break;
        case INFO:
            api.logging().raiseInfoEvent(msg);
            break;
        }
    }

    /**
     * Add Host To Scope
     *
     * @param contextMenuEvent
     */
    public void sendToAddHostIncludeToScope(ContextMenuEvent contextMenuEvent) {
        final List<HttpRequestResponse> messageList = contextMenuEvent.selectedRequestResponses();
        for (HttpRequestResponse messageInfo : messageList) {
            api.scope().includeInScope(HttpTarget.toURLString(messageInfo.httpRequest().httpService()));
        }
    }

    /**
     * Add Host To Exclude Scope
     *
     * @param contextMenuEvent
     */
    public void sendToAddHostToExcludeScope(ContextMenuEvent contextMenuEvent) {
        final List<HttpRequestResponse> messageList = contextMenuEvent.selectedRequestResponses();
        for (HttpRequestResponse messageInfo : messageList) {
            api.scope().excludeFromScope(HttpTarget.toURLString(messageInfo.httpRequest().httpService()));
        }
    }

    /**
     * Add Url To Exclude Scope
     *
     * @param contextMenuEvent
     */
    public void sendToAddToExcludeScope(ContextMenuEvent contextMenuEvent) {
        final List<HttpRequestResponse> messageList = contextMenuEvent.selectedRequestResponses();
        for (HttpRequestResponse messageInfo : messageList) {
            api.scope().excludeFromScope(messageInfo.httpRequest().url());
        }
    }

    /**
     * Message Info Copy
     *
     * @param contextMenuEvent
     */
    public void sendToMessageInfoCopy(ContextMenuEvent contextMenuEvent) {
        final List<HttpRequestResponse> messageList = contextMenuEvent.selectedRequestResponses();
        StringBuilder buff = new StringBuilder();
        try {
            buff.append("url\tquery\tmethod\tstatus\tlength\r\n");
            for (HttpRequestResponse messageInfo : messageList) {
//                IRequestInfo reqInfo = api.getHelpers().analyzeRequest(messageInfo);
                URL url = new URL(messageInfo.httpRequest().url());
                buff.append(HttpUtil.toURL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath()));
                buff.append("\t");
                buff.append(url.getQuery());
                buff.append("\t");
                buff.append(messageInfo.httpRequest().method());
                if (messageInfo.httpResponse() != null) {
                    buff.append("\t");
                    buff.append(messageInfo.httpResponse().statusCode());
                    buff.append("\t");
                    buff.append(messageInfo.httpResponse().body().length());
                }
                buff.append("\r\n");
            }
        } catch (MalformedURLException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        SwingUtil.systemClipboardCopy(buff.toString());
    }

    public void sendToTableInfoCopy(ContextMenuEvent contextMenuEvent) {
        StringBuilder buff = new StringBuilder();
        Component c = KeyboardFocusManager.getCurrentKeyboardFocusManager().getPermanentFocusOwner();
        if (c instanceof JTable table) {
            buff.append(copyJTable(table));
        }
        SwingUtil.systemClipboardCopy(buff.toString());
    }

    public String copyJTable(JTable table) {
        StringBuilder export = new StringBuilder();
        TableModel model = table.getModel();
        int colcount = table.getColumnCount();
        boolean[] cols = new boolean[colcount];
        for (int i = 0; i < cols.length; i++) {
            cols[i] = false;
            if (String.class.isAssignableFrom(table.getColumnClass(i))) {
                table.getColumnClass(i).asSubclass(String.class);
                cols[i] = true;
            } else if (Integer.class.isAssignableFrom(table.getColumnClass(i))) {
                table.getColumnClass(i).asSubclass(Integer.class);
                cols[i] = true;
            } else if (Long.class.isAssignableFrom(table.getColumnClass(i))) {
                table.getColumnClass(i).asSubclass(Long.class);
                cols[i] = true;
            }
            if (cols[i]) {
                export.append(table.getColumnName(i));
                export.append("\t");
            }
        }
        export.append("\r\n");
        int[] rows = table.getSelectedRows();
        for (int k = 0; k < rows.length; k++) {
            for (int i = 0; i < colcount; i++) {
                if (cols[i]) {
                    int rawRow = table.convertRowIndexToModel(rows[k]);
                    Object data = model.getValueAt(rawRow, i);
                    export.append(StringUtil.toString(data));
                    export.append("\t");
                }
            }
            export.append("\r\n");
        }
        return export.toString();
    }

}
