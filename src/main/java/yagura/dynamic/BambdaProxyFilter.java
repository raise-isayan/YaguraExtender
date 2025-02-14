package yagura.dynamic;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaProxyFilter extends BambdaFilter {

    public boolean matches(ProxyHttpRequestResponse requestResponse, Utilities utilities);

}
