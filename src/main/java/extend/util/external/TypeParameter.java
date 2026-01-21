package extend.util.external;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;

/**
 *
 * @author isayan
 */
public class TypeParameter implements HttpParameter {

    private final HttpParameterType type;
    private final String name;
    private final String value;

    public TypeParameter(HttpParameterType type, String name, String value) {
        this.type = type;
        this.name = name;
        this.value = value;
    }

    @Override
    public HttpParameterType type() {
        return this.type;
    }

    @Override
    public String name() {
        return this.name;
    }

    @Override
    public String value() {
        return this.value;
    }

}
