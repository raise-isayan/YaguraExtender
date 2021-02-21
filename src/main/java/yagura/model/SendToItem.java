package yagura.model;

import com.google.gson.annotations.Expose;
import extension.helpers.StringUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.event.EventListenerList;

/**
 *
 * @author isayan
 */
public class SendToItem {
    private final static Logger logger = Logger.getLogger(SendToItem.class.getName());

    public enum MessageType {
        REQUEST, RESPONSE, REQUEST_AND_RESPONSE;

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }
    };

    public enum ExtendType {
        SEND_TO_JTRANSCODER,
        REQUEST_AND_RESPONSE_TO_FILE,
        RESPONSE_BODY_TO_FILE,
        PASTE_FROM_JTRANSCODER,
        PASTE_FROM_CLIPBOARD,
        MESSAGE_INFO_COPY,
        ADD_HOST_TO_INCLUDE_SCOPE,
        ADD_HOST_TO_EXCLUDE_SCOPE,
        ADD_TO_EXCLUDE_SCOPE;

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }

    };

   @Expose
   private ExtendType sendExtend = null;

    public SendToItem() {
    }

    public SendToItem(SendToItem item) {
        this.selected = item.selected;
        this.caption = item.caption;
        this.target = item.target;
        this.requestHeader = item.requestHeader;
        this.requestBody = item.requestBody;
        this.responseHeader = item.responseHeader;
        this.responseBody = item.responseBody;
        this.reverseOrder = item.reverseOrder;
        this.sendExtend = item.sendExtend;
        this.extendProperties.clear();
        this.extendProperties.putAll(item.extendProperties);
    }

   @Expose
    private boolean selected = false;

    /**
     * @return the selected
     */
    public boolean isSelected() {
        return this.selected;
    }

    /**
     * @param selected the selected to set
     */
    public void setSelected(boolean selected) {
        this.selected = selected;
    }

   @Expose
    private String caption;

    /**
     * @return the caption
     */
    public String getCaption() {
        return this.caption;
    }

    /**
     * @param caption the caption to set
     */
    public void setCaption(String caption) {
        this.caption = caption;
    }

   @Expose
    private boolean server;

    /**
     * @return the server
     */
    public boolean isServer() {
        return this.server;
    }

    /**
     * @param server the server to set
     */
    public void setServer(boolean server) {
        this.server = server;
    }

   @Expose
    private String target;

    /**
     * @return the target
     */
    public String getTarget() {
        return this.target;
    }

    /**
     * @param target the target to set
     */
    public void setTarget(String target) {
        this.target = target;
    }

    /**
     * @return the request
     */
    public boolean isRequest() {
        return this.requestHeader && this.requestBody;
    }

   @Expose
    private boolean requestHeader = true;

    /**
     * @return the requestHeader
     */
    public boolean isRequestHeader() {
        return requestHeader;
    }

    /**
     * @param requestHeader the requestHeader to set
     */
    public void setRequestHeader(boolean requestHeader) {
        this.requestHeader = requestHeader;
    }

   @Expose
    private boolean requestBody = true;

    /**
     * @return the requestBody
     */
    public boolean isRequestBody() {
        return requestBody;
    }

    /**
     * @param requestBody the requestBody to set
     */
    public void setRequestBody(boolean requestBody) {
        this.requestBody = requestBody;
    }

    /**
     * @return the response
     */
    public boolean isResponse() {
        return this.responseHeader && this.responseBody;
    }

   @Expose
    private boolean responseHeader = true;

    /**
     * @return the responseHeader
     */
    public boolean isResponseHeader() {
        return responseHeader;
    }

    /**
     * @param responseHeader the responseHeader to set
     */
    public void setResponseHeader(boolean responseHeader) {
        this.responseHeader = responseHeader;
    }

   @Expose
    private boolean responseBody = true;

    /**
     * @return the responseBody
     */
    public boolean isResponseBody() {
        return responseBody;
    }

    /**
     * @param responseBody the responseBody to set
     */
    public void setResponseBody(boolean responseBody) {
        this.responseBody = responseBody;
    }

   @Expose
    private boolean reverseOrder = false;

    /**
     * @return the reverseOrder
     */
    public boolean isReverseOrder() {
        return reverseOrder;
    }

    /**
     * @param reverseOrder the reverseOrder to set
     */
    public void setReverseOrder(boolean reverseOrder) {
        this.reverseOrder = reverseOrder;
    }

   @Expose
    private final Properties extendProperties = new Properties();

    public Properties getExtendProperty() {
        return extendProperties;
    }

    public String getExtendPropertyString() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            this.extendProperties.storeToXML(os, "");
        } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        return StringUtil.getStringUTF8(os.toByteArray());
    }

    public void setExtendPropertyString(String propString) {
        try {
            ByteArrayInputStream is = new ByteArrayInputStream(StringUtil.getBytesUTF8(propString));
            this.extendProperties.loadFromXML(is);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }


    /**
     * @return the extend
     */
    public ExtendType getExtend() {
        return this.sendExtend;
    }

    /**
     * @param sendExtend the extend to set
     */
    public void setExtend(ExtendType sendExtend) {
        this.sendExtend = sendExtend;
    }

    private final EventListenerList sendToEventList = new EventListenerList();

    protected void fireSendToCompleteEvent(SendToEvent evt) {
        Object[] listeners = this.sendToEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SendToListener.class) {
                ((SendToListener) listeners[i + 1]).complete(evt);
            }
        }
    }

    protected void fireSendToWarningEvent(SendToEvent evt) {
        Object[] listeners = this.sendToEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SendToListener.class) {
                ((SendToListener) listeners[i + 1]).warning(evt);
            }
        }
    }

    protected void fireSendToErrorEvent(SendToEvent evt) {
        Object[] listeners = this.sendToEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SendToListener.class) {
                ((SendToListener) listeners[i + 1]).error(evt);
            }
        }
    }

    public void addSendToListener(SendToListener l) {
        this.sendToEventList.add(SendToListener.class, l);
    }

    public void removeSendToListener(SendToListener l) {
        this.sendToEventList.remove(SendToListener.class, l);
    }

    public static Object[] toObjects(SendToItem sendTo) {
        Object[] beans = new Object[11];
        beans[0] = sendTo.isSelected();
        beans[1] = sendTo.getCaption();
        beans[2] = sendTo.isServer();
        beans[3] = sendTo.getTarget();
        beans[4] = sendTo.isRequestHeader();
        beans[5] = sendTo.isRequestBody();
        beans[6] = sendTo.isResponseHeader();
        beans[7] = sendTo.isResponseBody();
        beans[8] = sendTo.isReverseOrder();
        beans[9] = sendTo.getExtendPropertyString();
        beans[10] = sendTo.getExtend();
        return beans;
    }

    public static SendToItem fromObjects(Object[] rows) {
        SendToItem sendTo = new SendToItem();
        sendTo.setSelected((Boolean) rows[0]);
        sendTo.setCaption((String) rows[1]);
        sendTo.setServer((Boolean) rows[2]);
        sendTo.setTarget((String) rows[3]);
        sendTo.setRequestHeader((Boolean) rows[4]);
        sendTo.setRequestBody((Boolean) rows[5]);
        sendTo.setResponseHeader((Boolean) rows[6]);
        sendTo.setResponseBody((Boolean) rows[7]);
        sendTo.setReverseOrder((Boolean) rows[8]);
        sendTo.setExtendPropertyString((String) rows[9]);
        sendTo.setExtend((ExtendType) rows[10]);
        return sendTo;
    }

}
