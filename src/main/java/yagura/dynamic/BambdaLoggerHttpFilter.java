package yagura.dynamic;

import burp.api.montoya.logger.LoggerHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaLoggerHttpFilter extends BambdaFilter {

    public boolean matches(LoggerHttpRequestResponse requestResponse, Utilities utilities);

}
