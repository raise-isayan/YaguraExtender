package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import extension.helpers.FileUtil;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public abstract class SendToMenuItem
        extends SendToItem implements java.awt.event.ActionListener {

    private final static Logger logger = Logger.getLogger(SendToMenuItem.class.getName());

    protected ContextMenuEvent contextMenu = null;

    public SendToMenuItem(SendToItem item) {
        super(item);
    }

    public SendToMenuItem(SendToItem item, ContextMenuEvent contextMenu) {
        super(item);
        this.contextMenu = contextMenu;
    }

    /**
     * @return the contextMenu
     */
    protected ContextMenuEvent getContextMenu() {
        return contextMenu;
    }

    /**
     * @param contextMenu the contextMenu to set
     */
    protected void setContextMenu(ContextMenuEvent contextMenu) {
        this.contextMenu = contextMenu;
    }

    public abstract void menuItemClicked(String menuItemCaption, SendToMessage sendToMessage);

    public abstract boolean isEnabled();

    protected File tempMessageFile(HttpRequestResponse messageInfo, int index) {
        File file = null;
        try {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(messageInfo.request());
            file = File.createTempFile(HttpUtil.getBaseName(URI.create(wrapRequest.url()).toURL()) + "." + index + ".", ".tmp");
            file.deleteOnExit();
            try (BufferedOutputStream fostm = new BufferedOutputStream(new FileOutputStream(file, true))) {
                if ((this.isRequestHeader() || this.isRequestBody()) && wrapRequest.hasHttpRequest()) {
                    byte[] reqMessage = wrapRequest.getMessageByte();
                    if (!(this.isRequestHeader() && this.isRequestBody())) {
                        if (this.isRequestHeader()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, 0, wrapRequest.bodyOffset());
                        } else if (this.isRequestBody()) {
                            reqMessage = Arrays.copyOfRange(reqMessage, wrapRequest.bodyOffset(), reqMessage.length);
                        }
                    }
                    fostm.write(reqMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
                HttpResponseWapper wrapResponse = new HttpResponseWapper(messageInfo.response());
                if ((this.isResponseHeader() || this.isResponseBody()) && wrapResponse.hasHttpResponse()) {
                    byte resMessage[] = wrapResponse.getMessageByte();
                    if (!(this.isResponseHeader() && this.isResponseBody())) {
                        if (this.isResponseHeader()) {
                            resMessage = Arrays.copyOfRange(resMessage, 0, wrapResponse.bodyOffset());
                        } else if (this.isResponseBody()) {
                            resMessage = Arrays.copyOfRange(resMessage, wrapResponse.bodyOffset(), resMessage.length);
                        }
                    }
                    fostm.write(resMessage);
                    fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
                }
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return file;
    }

    public void sendToEvent(List<HttpRequestResponse> messageInfo) {
        menuItemClicked(getCaption(), SendToMessage.newSendToMessage(messageInfo, this.isEnabled()));
    }

    public List<String> executeArgumentFormat(HttpRequestResponse httpRequestResponse, String selectedText, String [] formats) throws MalformedURLException {
        final List<String> argsList = new ArrayList<>();
        try {
            for (int i = 0; i < formats.length; i++) {
                StringBuilder buff = new StringBuilder();
                URL url = new URL(httpRequestResponse.request().url());
                Pattern p = Pattern.compile("%([HPTUAQCMSFRN%])");
                Matcher m = p.matcher(formats[i]);
                while (m.find()) {
                    String replace = m.group(0);
                    String opt = m.group(1);
                    switch (opt.charAt(0)) {
                        case 'H': // %H: will be replaced with the host
                        {
                            replace = httpRequestResponse.httpService().host();
                            break;
                        }
                        case 'P': // %P: will be replaced with the port
                        {
                            replace = String.valueOf(httpRequestResponse.httpService().port());
                            break;
                        }
                        case 'T': // %T: will be replaced with the protocol
                        {
                            replace = url.getProtocol();
                            break;
                        }
                        case 'U': // %U: will be replaced with the url
                        {
                            replace = url.toExternalForm();
                            break;
                        }
                        case 'A': // %A: will be replaced with the url path
                        {
                            replace = url.getPath();
                            break;
                        }
                        case 'Q': // %Q: will be replaced with the url query
                        {
                            replace = url.getQuery();
                            break;
                        }
                        case 'C': // %C: will be replaced with the cookies
                        {
                            if (httpRequestResponse.request().hasHeader("Cookie")) {
                                replace = httpRequestResponse.request().header("Cookie").value();
                            }
                            break;
                        }
                        case 'M': // %M: will be replaced with the HTTP-method
                        {
                            replace = httpRequestResponse.request().method();
                            break;
                        }
                        case 'S': // %S: will be replaced with the selected text
                        {
                            if (selectedText != null) {
                                replace = selectedText;
                            }
                            break;
                        }
                        case 'F': // %F: will be replaced with the path to a temporary file containing the selected text
                        {
                            if (selectedText != null) {
                                File file = FileUtil.tempFile(StringUtil.getBytesRaw(selectedText), "burp");
                                replace = file.getAbsolutePath();
                            }
                            break;
                        }
                        case 'R': // %R: will be replaced with the path to a temporary file containing the content of the focused request/response
                        {
                            File file = tempMessageFile(httpRequestResponse, httpRequestResponse.hashCode());
                            replace = file.getAbsolutePath();
                            break;
                        }
                        case 'N': // %N: will be replaced with the notes
                        {
                            File file = FileUtil.tempFile(StringUtil.getBytesUTF8(httpRequestResponse.annotations().notes()), "burp");
                            replace = file.getAbsolutePath();
                            break;
                        }
                        case '%': // escape
                        {
                            replace = "%";
                            break;
                        }
                    }
                    m.appendReplacement(buff, Matcher.quoteReplacement(replace));
                }
                m.appendTail(buff);
                argsList.add(buff.toString());
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return argsList;
    }

}
