package yagura.dynamic;

import burp.api.montoya.logger.LoggerCaptureHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaLoggerCaptureFilter {

    public boolean matches(LoggerCaptureHttpRequestResponse requestResponse, Utilities utilities);

}
