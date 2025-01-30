package yagura.dynamic;

import burp.api.montoya.proxy.ProxyWebSocketMessage;
import javax.swing.text.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaWebSocketFilter {

    public boolean matches(ProxyWebSocketMessage requestRespose, Utilities utilities);

}
