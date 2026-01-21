package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class InterceptHandle implements ProxyRequestHandler {

    private final static Logger logger = Logger.getLogger(InterceptHandle.class.getName());

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;

    public InterceptHandle(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest, interceptedRequest.annotations());
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest, interceptedRequest.annotations());
    }

}
