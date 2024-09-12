package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import extension.burp.BurpConfig;
import extension.burp.HttpTarget;
import extension.helpers.HttpUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;

/**
 *
 * @author isayan
 */
public class AutoResponderHandler implements HttpHandler, ProxyRequestHandler, ExtensionUnloadingHandler {

    private final static Logger logger = Logger.getLogger(AutoResponderHandler.class.getName());

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;

    private final List resolvHost = new ArrayList<>();

    public AutoResponderHandler(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
        api.http().registerHttpHandler(this);
        api.proxy().registerRequestHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        // Autoresponder
        if (extenderImpl.getProperty().getAutoResponderProperty().getAutoResponderEnable()) {
            final String url = httpRequestToBeSent.url();
            AutoResponderItem item = extenderImpl.getProperty().getAutoResponderProperty().findItem(url, httpRequestToBeSent.method());
            if (item != null) {
                HttpTarget httpTarget = new HttpTarget(extenderImpl.getTabbetOption().getMockServer().serviceURL());
                HttpRequest updatedHttpServiceRequest = httpRequestToBeSent.withService(httpTarget).withAddedHeader(AutoResponderProperty.AUTO_RESPONDER_HEADER, url);
                return RequestToBeSentAction.continueWith(updatedHttpServiceRequest);
            }
        }
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (extenderImpl.getProperty().getAutoResponderProperty().getAutoResponderEnable() && extenderImpl.getProperty().getAutoResponderProperty().isHostNameForceResolv()) {
            final String url = interceptedRequest.url();
            AutoResponderItem item = extenderImpl.getProperty().getAutoResponderProperty().findItem(url, interceptedRequest.method());
            if (item != null) {
                if (!HttpUtil.isInetAddressByName(interceptedRequest.httpService().host())) {
                    BurpExtension.helpers().issueAlert("MockServer", "resolv:" + interceptedRequest.httpService().host(), extension.burp.MessageType.INFO);
                    this.resolvHost.add(new BurpConfig.HostnameResolution(true, interceptedRequest.httpService().host(), "127.0.0.1"));
                    BurpConfig.configHostnameResolution(this.api, this.resolvHost);
                }
            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    @Override
    public void extensionUnloaded() {
        BurpConfig.configHostnameResolution(this.api, this.resolvHost, true);
    }
}
