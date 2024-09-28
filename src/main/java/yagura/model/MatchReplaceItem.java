package yagura.model;

import burp.api.montoya.websocket.Direction;
import com.google.gson.annotations.Expose;
import extension.burp.ProtocolType;
import extension.helpers.ConvertUtil;
import extension.helpers.MatchUtil;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import extension.view.base.MatchItem;

/**
 * @author isayan
 */
public class MatchReplaceItem extends MatchItem {

    public MatchReplaceItem() {
        super();
        this.setType((this.protocolType == ProtocolType.HTTP) ? http_types[0] : websocket_types[0]);
    }

    public static final String TYPE_REQUEST_HEADER = "request header";
    public static final String TYPE_REQUEST_BODY = "request body";
    public static final String TYPE_RESPONSE_HEADER = "response header";
    public static final String TYPE_RESPONSE_BODY = "response body";
    public static final String TYPE_REQUEST_PARAM_NAME = "request param name";
    public static final String TYPE_REQUEST_PARAM_VALUE = "request param value";
    public static final String TYPE_REQUEST_FIRST_LINE = "request first line";

    private static final String http_types[] = {TYPE_REQUEST_HEADER, TYPE_REQUEST_BODY, TYPE_RESPONSE_HEADER, TYPE_RESPONSE_BODY, TYPE_REQUEST_FIRST_LINE};

    public static final String TYPE_CLIENT_TO_SERVER = Direction.CLIENT_TO_SERVER.name().toLowerCase().replace('_', ' ');
    public static final String TYPE_SERVER_TO_CLIENT = Direction.SERVER_TO_CLIENT.name().toLowerCase().replace('_', ' ');

    private static final String websocket_types[] = {TYPE_CLIENT_TO_SERVER, TYPE_SERVER_TO_CLIENT};

    public static String[] getTypes(ProtocolType protocolType) {
        if (protocolType == ProtocolType.HTTP) {
            return http_types;
        } else {
            return websocket_types;
        }
    }

    @Expose
    private ProtocolType protocolType = ProtocolType.HTTP;

    public ProtocolType getProtocolType() {
        return this.protocolType;
    }

    public void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }

    @Override
    public Pattern compileRegex(boolean quote) {
        return MatchUtil.compileRegex(this.getMatch(), this.isSmartMatch(), !quote, this.isIgnoreCase(), Pattern.MULTILINE);
    }

    /**
     * @param quote
     * @param metachar
     * @return the replace
     */
    public String getReplace(boolean quote, boolean metachar) {
        if (quote) {
            if (metachar) {
                return Matcher.quoteReplacement(ConvertUtil.decodeJsLangMeta(this.getReplace()));
            } else {
                return Matcher.quoteReplacement(this.getReplace());
            }
        } else {
            if (metachar) {
                return ConvertUtil.decodeJsLangMeta(this.getReplace());
            } else {
                return this.getReplace();
            }
        }
    }

    @Expose
    private boolean smartMatch = false;

    public void setSmartMatch(boolean value) {
        this.smartMatch = value;
    }

    public boolean isSmartMatch() {
        return this.smartMatch;
    }

    @Expose
    private boolean metaChar = false;

    /**
     * @return the metaChar
     */
    public boolean isMetaChar() {
        return this.metaChar;
    }

    /**
     * @param metachar the metaChar to set
     */
    public void setMetaChar(boolean metachar) {
        this.metaChar = metachar;
    }

    public boolean isRequestLine() {
        return this.getType().startsWith(TYPE_REQUEST_FIRST_LINE);
    }

    public boolean isRequest() {
        return this.getType().startsWith("request");
    }

    public boolean isResponse() {
        return this.getType().startsWith("response");
    }

    public boolean isHeader() {
        return this.getType().endsWith("header");
    }

    public boolean isBody() {
        return this.getType().endsWith("body");
    }

    public boolean isClientToServer() {
        return this.getType().equals(TYPE_CLIENT_TO_SERVER);
    }

    public boolean isServerToClient() {
        return this.getType().equals(TYPE_SERVER_TO_CLIENT);
    }

    public void setProperty(MatchReplaceItem item) {
        this.setProperty((MatchItem) item);
        this.setProtocolType(item.getProtocolType());
        this.setMetaChar(item.isMetaChar());
        this.setSmartMatch(item.isSmartMatch());
    }

    public static Object[] toObjects(MatchReplaceItem matchReplace) {
        Object[] beans = new Object[9];
        beans[0] = matchReplace.isSelected();
        beans[1] = matchReplace.getProtocolType().name();
        beans[2] = matchReplace.getType();
        beans[3] = matchReplace.getMatch();
        beans[4] = matchReplace.isSmartMatch();
        beans[5] = matchReplace.isRegexp();
        beans[6] = matchReplace.isIgnoreCase();
        beans[7] = matchReplace.getReplace();
        beans[8] = matchReplace.isMetaChar();
        return beans;
    }

    public static MatchReplaceItem fromObjects(Object[] rows) {
        MatchReplaceItem matchReplace = new MatchReplaceItem();
        matchReplace.setSelected(((Boolean) rows[0]));
        matchReplace.setProtocolType(ProtocolType.valueOf((String) rows[1]));
        matchReplace.setType((String) rows[2]);
        matchReplace.setMatch((String) rows[3]);
        matchReplace.setSmartMatch((Boolean) rows[4]);
        matchReplace.setRegexp((Boolean) rows[5]);
        matchReplace.setIgnoreCase((Boolean) rows[6]);
        matchReplace.setReplace((String) rows[7]);
        matchReplace.setMetaChar((Boolean) rows[8]);
        matchReplace.recompileRegex(!matchReplace.isRegexp());
        return matchReplace;
    }

}
