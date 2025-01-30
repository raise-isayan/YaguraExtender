package yagura.dynamic;

import burp.api.montoya.logger.LoggerHttpRequestResponse;
import javax.swing.text.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaLoggerFilter {

    public boolean matches(LoggerHttpRequestResponse requestRespose, Utilities utilities);

}
