package yagura.dynamic;

import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaWebSocketFilter extends BambdaFilter {

    public boolean matches(ProxyWebSocketMessage message, Utilities utilities);

}
