package yagura.model;

import burp.BurpExtender;
import extend.util.SwingUtil;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.HashMap;
import java.util.Map;
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

    private static class HotKey extends KeyEvent {

        private final static int KEY_CODES[] = {
            VK_ENTER,
            VK_BACK_SPACE,
            VK_TAB,
            VK_CANCEL,
            VK_CLEAR,
            VK_COMPOSE,
            VK_PAUSE,
            VK_CAPS_LOCK,
            VK_ESCAPE,
            VK_SPACE,
            VK_PAGE_UP, VK_PAGE_DOWN,
            VK_END, VK_HOME,
            VK_LEFT, VK_UP, VK_RIGHT, VK_DOWN,
            VK_BEGIN,
            // modifiers
            VK_SHIFT, VK_CONTROL, VK_ALT, VK_META, VK_ALT_GRAPH,
            // punctuation
            VK_COMMA,
            VK_PERIOD,
            VK_SLASH,
            VK_SEMICOLON,
            VK_EQUALS,
            VK_OPEN_BRACKET,
            VK_BACK_SLASH,
            VK_CLOSE_BRACKET,
            // numpad numeric keys handled below
            VK_MULTIPLY,
            VK_ADD,
            VK_SEPARATOR,
            VK_SUBTRACT,
            VK_DECIMAL,
            VK_DIVIDE,
            VK_DELETE,
            VK_NUM_LOCK,
            VK_SCROLL_LOCK,
            VK_WINDOWS, VK_CONTEXT_MENU,
            VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9,
            VK_F10, VK_F11, VK_F12, VK_F13, VK_F14, VK_F15, VK_F16, VK_F17, VK_F18, VK_F19,
            VK_F20, VK_F21, VK_F22, VK_F23, VK_F24,
            VK_PRINTSCREEN,
            VK_INSERT,
            VK_HELP,
            VK_BACK_QUOTE,
            VK_QUOTE,
            VK_KP_UP, VK_KP_DOWN,
            VK_KP_LEFT, VK_KP_RIGHT,
            VK_DEAD_GRAVE,
            VK_DEAD_ACUTE,
            VK_DEAD_CIRCUMFLEX,
            VK_DEAD_TILDE,
            VK_DEAD_MACRON,
            VK_DEAD_BREVE,
            VK_DEAD_ABOVEDOT,
            VK_DEAD_DIAERESIS,
            VK_DEAD_ABOVERING,
            VK_DEAD_DOUBLEACUTE,
            VK_DEAD_CARON,
            VK_DEAD_CEDILLA,
            VK_DEAD_OGONEK,
            VK_DEAD_IOTA,
            VK_DEAD_VOICED_SOUND,
            VK_DEAD_SEMIVOICED_SOUND,
            VK_AMPERSAND,
            VK_ASTERISK,
            VK_QUOTEDBL,
            VK_LESS,
            VK_GREATER,
            VK_BRACELEFT,
            VK_BRACERIGHT,
            VK_AT,
            VK_COLON,
            VK_CIRCUMFLEX,
            VK_DOLLAR,
            VK_EURO_SIGN,
            VK_EXCLAMATION_MARK,
            VK_INVERTED_EXCLAMATION_MARK,
            VK_LEFT_PARENTHESIS,
            VK_NUMBER_SIGN,
            VK_MINUS,
            VK_PLUS,
            VK_RIGHT_PARENTHESIS,
            VK_UNDERSCORE,
            VK_FINAL,
            VK_CONVERT,
            VK_NONCONVERT,
            VK_ACCEPT,
            VK_MODECHANGE,
            VK_KANA,
            VK_KANJI,
            VK_ALPHANUMERIC,
            VK_KATAKANA,
            VK_HIRAGANA,
            VK_FULL_WIDTH,
            VK_HALF_WIDTH,
            VK_ROMAN_CHARACTERS,
            VK_ALL_CANDIDATES,
            VK_PREVIOUS_CANDIDATE,
            VK_CODE_INPUT,
            VK_JAPANESE_KATAKANA,
            VK_JAPANESE_HIRAGANA,
            VK_JAPANESE_ROMAN,
            VK_KANA_LOCK,
            VK_INPUT_METHOD_ON_OFF,
            VK_AGAIN,
            VK_UNDO,
            VK_COPY,
            VK_PASTE,
            VK_CUT,
            VK_FIND,
            VK_PROPS,
            VK_STOP,};

        private final static Map<String, Integer> HOT_KEY_MAP = new HashMap<>();

        static {
            for (int key = VK_0; key <= VK_9; key++) {
                HOT_KEY_MAP.put(KeyEvent.getKeyText(key), key);            
            }
            for (int key = VK_A; key <= VK_Z; key++) {
                HOT_KEY_MAP.put(KeyEvent.getKeyText(key), key);            
            }
            for (int key : KEY_CODES) {
                HOT_KEY_MAP.put(KeyEvent.getKeyText(key), key);
            }
            for (int key = VK_NUMPAD0; key <= VK_NUMPAD9; key++) {
                HOT_KEY_MAP.put(KeyEvent.getKeyText(key), key);            
            }
        }

        public HotKey(KeyEvent evt) {
            super(evt.getComponent(), evt.getID(), evt.getWhen(), evt.getModifiers(), evt.getKeyCode(), evt.getKeyChar(), evt.getKeyLocation());
        }

        @Override
        public String toString() {
            return SwingUtil.getKeyText(this);
        }

        public static KeyEvent parseHotkey(String value) {
            String hotkeys[] = value.split("\\+");
            int modifiers  = 0;
            int keyCode = 0;
            for (String hotkey : hotkeys) {
                Integer key = HOT_KEY_MAP.get(hotkey);
                if (key != null) {
                    int mask =getKeyModifierMask(key);
                    if (mask != 0) {
                        modifiers |= mask;
                    }
                    else {
                        keyCode = key;
                    }
                }                
            }          
            return new KeyEvent(BurpExtender.getInstance().getUiComponent(), KEY_PRESSED, System.currentTimeMillis(), modifiers, keyCode, (char)keyCode);
        }

        public static int getKeyModifierMask(int keyCode) {
            int mask = 0;
            switch (keyCode) {
            case VK_SHIFT:
                mask = InputEvent.SHIFT_MASK;
                break;
            case VK_CONTROL:
                mask = InputEvent.CTRL_MASK;
                break;
            case VK_ALT:
                mask = InputEvent.ALT_MASK;
                break;
            case VK_META:
                mask = InputEvent.META_MASK;
                break;
            case VK_ALT_GRAPH:
                mask = InputEvent.ALT_GRAPH_MASK;
                break;
            }
            return mask;
        }
        
    }

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
        this.hotkey = item.hotkey;
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

    /**
     * @return the request
     */
    public boolean isRequest() {
        return this.requestHeader && this.requestBody;
    }

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

    private KeyEvent hotkey = null;

    public KeyEvent getHotkey() {
        return (hotkey == null) ? null : new HotKey(hotkey);
    }

    public void setHotkey(KeyEvent keyEvent) {
        this.hotkey = keyEvent;
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

    public static KeyEvent parseHotkey(String value) {
        return HotKey.parseHotkey(value);
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
        beans[9] = sendTo.getHotkey();
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
        sendTo.setHotkey((KeyEvent) rows[9]);
        sendTo.setExtend((ExtendType) rows[10]);
        return sendTo;
    }

}
