package yagura.dynamic;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaRequestReplaceFilter {

    public HttpRequest replace(ProxyHttpRequestResponse requestResponse, Utilities utilities);

}
