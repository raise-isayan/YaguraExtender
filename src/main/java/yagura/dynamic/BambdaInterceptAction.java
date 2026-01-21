package yagura.dynamic;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;

/**
 *
 * @author isayan
 */
public interface BambdaInterceptAction extends BambdaFilter {

    public ProxyRequestReceivedAction interceptReceived(InterceptedRequest interceptedRequest);

}
