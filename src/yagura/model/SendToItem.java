/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package yagura.model;

import javax.swing.event.EventListenerList;

/**
 *
 * @author isayan
 */
public class SendToItem {
    
    public enum MessageType {
        REQUEST, RESPONSE, REQUEST_AND_RESPONSE;

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
        }
    };
    
    public enum ExtendType { 
        REQUEST_AND_RESPONSE_TO_FILE,
        SEND_TO_JTRANSCODER,
        PASTE_FROM_JTRANSCODER,
        MESSAGE_INFO_COPY,
        ADD_HOST_TO_SCOPE;

        @Override
	public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', ' ');
	}
    };
        
    private ExtendType sendExtend = null;
    
    public SendToItem() {
    }

    public SendToItem(SendToItem item) {
        this.selected = item.selected;
        this.caption = item.caption;
        this.target = item.target;
        this.sendExtend = item.sendExtend;
    }
    
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

    private boolean request = true;
    /**
     * @return the request
     */
    public boolean isRequest() {
        return this.request;
    }

    /**
     * @param request the request to set
     */
    public void setRequest(boolean request) {
        this.request = request;
    }

    private boolean response = true;
    /**
     * @return the response
     */
    public boolean isResponse() {
        return this.response;
    }

    /**
     * @param response the response to set
     */
    public void setResponse(boolean response) {
        this.response = response;
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
                ((SendToListener)listeners[i + 1]).complete(evt);
            }
        }
    }

    protected void fireSendToWarningEvent(SendToEvent evt) {
        Object[] listeners = this.sendToEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SendToListener.class) {
                ((SendToListener)listeners[i + 1]).warning(evt);
            }
        }
    }

    protected void fireSendToErrorEvent(SendToEvent evt) {
        Object[] listeners = this.sendToEventList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == SendToListener.class) {
                ((SendToListener)listeners[i + 1]).error(evt);
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
        Object[] beans = new Object[7];
        beans[0] = sendTo.isSelected();
        beans[1] = sendTo.getCaption();
        beans[2] = sendTo.isServer();
        beans[3] = sendTo.getTarget();
        beans[4] = sendTo.isRequest();
        beans[5] = sendTo.isResponse();
        beans[6] = sendTo.getExtend();
        return beans;
    }

    public static SendToItem fromObjects(Object[] rows) {
        SendToItem sendTo = new SendToItem();
        sendTo.setSelected((Boolean)rows[0]);
        sendTo.setCaption((String)rows[1]);
        sendTo.setServer((Boolean)rows[2]);
        sendTo.setTarget((String)rows[3]);
        sendTo.setRequest((Boolean)rows[4]);
        sendTo.setResponse((Boolean)rows[5]);
        sendTo.setExtend((ExtendType)rows[6]);
        return sendTo;
    }
    
}
