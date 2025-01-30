package yagura.dynamic;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import javax.swing.text.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaProxyFilter {

    public boolean matches(ProxyHttpRequestResponse requestRespose, Utilities utilities);

}
