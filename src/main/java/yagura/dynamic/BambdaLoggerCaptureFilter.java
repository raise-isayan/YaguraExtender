package yagura.dynamic;

import burp.api.montoya.logger.LoggerCaptureHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaLoggerCaptureFilter extends BambdaFilter {

    public boolean matches(LoggerCaptureHttpRequestResponse requestResponse, Utilities utilities);

}
