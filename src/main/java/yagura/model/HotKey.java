package yagura.model;

import burp.BurpExtender;
import extend.util.SwingUtil;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author isayan
 */
public class HotKey extends KeyEvent {

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
        int modifiers = 0;
        int keyCode = 0;
        for (String hotkey : hotkeys) {
            Integer key = HOT_KEY_MAP.get(hotkey);
            if (key != null) {
                int mask = getKeyModifierMask(key);
                if (mask != 0) {
                    modifiers |= mask;
                } else {
                    keyCode = key;
                }
            }
        }
        return new KeyEvent(BurpExtender.getInstance().getUiComponent(), KEY_PRESSED, System.currentTimeMillis(), modifiers, keyCode, (char) keyCode);
    }

    public static int getKeyModifierMask(int keyCode) {
        int mask = 0;
        switch (keyCode) {
            case VK_SHIFT:
                mask = InputEvent.SHIFT_DOWN_MASK;
                break;
            case VK_CONTROL:
                mask = InputEvent.CTRL_DOWN_MASK;
                break;
            case VK_ALT:
                mask = InputEvent.ALT_DOWN_MASK;
                break;
            case VK_META:
                mask = InputEvent.META_DOWN_MASK;
                break;
            case VK_ALT_GRAPH:
                mask = InputEvent.ALT_DOWN_MASK;
                break;
        }
        return mask;
    }

}
