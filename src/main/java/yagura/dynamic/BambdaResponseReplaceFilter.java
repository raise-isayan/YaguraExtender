package yagura.dynamic;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaResponseReplaceFilter {

    public HttpResponse replace(ProxyHttpRequestResponse requestResponse, Utilities utilities);

}
