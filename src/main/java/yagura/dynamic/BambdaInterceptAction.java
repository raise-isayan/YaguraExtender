package yagura.dynamic;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaInterceptAction extends BambdaFilter {

    public ProxyRequestReceivedAction interceptReceived(InterceptedRequest interceptedRequest, Utilities utilities);

}
