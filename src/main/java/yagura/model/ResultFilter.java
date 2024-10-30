package yagura.model;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;
import extension.burp.BurpExtensionImpl;
import extension.burp.BurpUtil;
import extension.burp.FilterProperty;
import extension.burp.MessageHighlightColor;
import extension.helpers.StringUtil;
import java.net.HttpURLConnection;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.RowFilter;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 *
 * @author isayan
 */
public class ResultFilter {

    private final static Logger logger = Logger.getLogger(ResultFilter.class.getName());

    public static class PropertyRowHttpFilter extends RowFilter<Object, Object> {

        private final FilterProperty filterProp;

        public PropertyRowHttpFilter(FilterProperty filterProp) {
            this.filterProp = filterProp;
        }

        @Override
        public boolean include(RowFilter.Entry<? extends Object, ? extends Object> entry) {
            boolean allFilter = false;
            try {
                ProxyHttpRequestResponse item = (ProxyHttpRequestResponse) entry.getValue(0);
                allFilter = include(item, this.filterProp);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
            return allFilter;
        }

        public static boolean include(ProxyHttpRequestResponse item, FilterProperty filterProp) {
            boolean allFilter = false;
            {
                boolean showOnlyScopFilter = true;
                // Show only in-scope items
                if (filterProp.isShowOnlyScopeItems()) {
                    showOnlyScopFilter = BurpExtensionImpl.helpers().isInScope(item.request().url());
                }
                // Hide items without responses
                boolean hideItemsWithoutResponses = true;
                if (filterProp.isHideItemsWithoutResponses()) {
                    hideItemsWithoutResponses = (item.response() != null);
                }
                // chkShowOnlyParameterizedRequests
                boolean parameterizedRequests = true;
                if (filterProp.isShowOnlyParameterizedRequests()) {
                    parameterizedRequests = item.request().hasParameters(HttpParameterType.URL) || item.request().hasParameters(HttpParameterType.BODY);
                }
                // Show only edited message
                boolean editedMessage = true;
                if (filterProp.isShowOnlyEditedMessage()) {
                    editedMessage = item.edited();
                }

                // Status Filter
                boolean statusFilter = false;
                if (showOnlyScopFilter) {
                    // Response Status がない場合は無条件で含める
                    if (!item.hasResponse()) {
                        statusFilter = true;
                    } else {
                        if (item.response().statusCode() == 0) {
                            statusFilter = true;
                        }
                        if (filterProp.getStat2xx() && (HttpURLConnection.HTTP_OK <= item.response().statusCode() && item.response().statusCode() < HttpURLConnection.HTTP_MULT_CHOICE)) {
                            statusFilter = true;
                        }
                        if (filterProp.getStat3xx() && (HttpURLConnection.HTTP_MULT_CHOICE <= item.response().statusCode() && item.response().statusCode() < HttpURLConnection.HTTP_BAD_REQUEST)) {
                            statusFilter = true;
                        }
                        if (filterProp.getStat4xx() && (HttpURLConnection.HTTP_BAD_REQUEST <= item.response().statusCode() && item.response().statusCode() < HttpURLConnection.HTTP_INTERNAL_ERROR)) {
                            statusFilter = true;
                        }
                        if (filterProp.getStat5xx() && (HttpURLConnection.HTTP_INTERNAL_ERROR <= item.response().statusCode() && item.response().statusCode() < 600)) {
                            statusFilter = true;
                        }
                    }
                }
                // Highlight Color
                boolean colorFilter = true;
                if (statusFilter && showOnlyScopFilter) {
                    // cololr
                    if (filterProp.getShowOnlyHighlightColors()) {
                        EnumSet<MessageHighlightColor> colors = filterProp.getHighlightColors();
                        MessageHighlightColor hc = MessageHighlightColor.valueOf(item.annotations().highlightColor());
                        colorFilter = colors.contains(hc);
                    }
                }
                // Comment Filter
                boolean commentFilter = true;
                if (statusFilter && showOnlyScopFilter) {
                    // comment
                    if (filterProp.getShowOnlyComment()) {
                        commentFilter = (item.annotations().hasNotes());
                    }
                }
                boolean matchFilter = true;
                if (statusFilter && showOnlyScopFilter && colorFilter) {
                    // showOnly Filter
                    if (filterProp.getShowOnly()) {
                        Pattern patternShowOnly = Pattern.compile(BurpUtil.parseFilterPattern(filterProp.getShowOnlyExtension()), Pattern.CASE_INSENSITIVE);
                        Matcher matchShowOnly = patternShowOnly.matcher(item.request().pathWithoutQuery());
                        if (!matchShowOnly.find()) {
                            matchFilter = false;
                        }
                    } else {
                        // Hide Filter
                        if (filterProp.getHide()) {
                            Pattern patternHide = Pattern.compile(BurpUtil.parseFilterPattern(filterProp.getHideExtension()), Pattern.CASE_INSENSITIVE);
                            Matcher matchHide = patternHide.matcher(item.request().pathWithoutQuery());
                            if (matchHide.find()) {
                                matchFilter = false;
                            }
                        }
                    }
                }
                // request method
                boolean requestMethod = true;
                if (!filterProp.getMethod().isEmpty()) {
                    Pattern patternMethod = Pattern.compile(BurpUtil.parseFilterPattern(filterProp.getMethod()), Pattern.CASE_INSENSITIVE);
                    Matcher matchHide = patternMethod.matcher(item.request().method());
                    if (matchHide.find()) {
                        requestMethod = false;
                    }
                }
                // request path
                boolean requestURL = true;
                if (!filterProp.getPath().isEmpty()) {
                    requestURL = item.request().path().contains(filterProp.getPath());
                }
                // request
                boolean request = true;
                if (!filterProp.getRequest().isEmpty()) {
                    if (filterProp.isRequestRegex()) {
                        request = item.request().contains(Pattern.compile(filterProp.getRequest(), filterProp.isRequestIgnoreCase() ? Pattern.DOTALL : Pattern.DOTALL | Pattern.CASE_INSENSITIVE));
                    } else {
                        request = item.request().contains(filterProp.getRequest(), filterProp.isRequestIgnoreCase());
                    }
                }
                // response
                boolean response = true;
                if (!filterProp.getResponse().isEmpty()) {
                    if (item.hasResponse()) {
                        if (filterProp.isResponseRegex()) {
                            response = item.response().contains(filterProp.getResponse(), filterProp.isResponseIgnoreCase());
                        } else {
                            response = item.response().contains(Pattern.compile(filterProp.getResponse(), filterProp.isResponseIgnoreCase() ? Pattern.DOTALL : Pattern.DOTALL | Pattern.CASE_INSENSITIVE));
                        }
                    }
                }
                // ListenerPort
                boolean listenerPort = true;
                if (filterProp.getListenerPort() > -1) {
                    listenerPort = filterProp.getListenerPort() == item.listenerPort();
                }
                // 条件のAND
                allFilter = (statusFilter && colorFilter && commentFilter && matchFilter && showOnlyScopFilter && hideItemsWithoutResponses && parameterizedRequests && editedMessage && requestMethod && requestURL && request && response && listenerPort);
            }
            return allFilter;
        }

    }

    public static class PropertyRowWebSocetFilter extends RowFilter<Object, Object> {

        private final FilterProperty filterProp;

        public PropertyRowWebSocetFilter(FilterProperty filterProp) {
            this.filterProp = filterProp;
        }

        @Override
        public boolean include(RowFilter.Entry<? extends Object, ? extends Object> entry) {
            boolean allFilter = false;
            try {
                ProxyWebSocketMessage item = (ProxyWebSocketMessage) entry.getValue(0);
                allFilter = include(item, this.filterProp);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
            return allFilter;
        }

        public static boolean include(ProxyWebSocketMessage item, FilterProperty filterProp) {
            boolean allFilter = false;
            {
                boolean showOnlyScopFilter = true;
                // Show only in-scope items
                if (filterProp.isShowOnlyScopeItems()) {
                    showOnlyScopFilter = BurpExtensionImpl.helpers().isInScope(item.upgradeRequest().url());
                }
                // Hide Incoming Message
                boolean hideIncomingMessage = true;
                if (filterProp.isHideIncomingMessage()) {
                    hideIncomingMessage = (item.direction() != Direction.SERVER_TO_CLIENT);
                }
                // Hide Outgoing Message
                boolean hideOutgoingMessage = true;
                if (filterProp.isHideOutgoingMessage()) {
                    hideOutgoingMessage = (item.direction() != Direction.CLIENT_TO_SERVER);
                }
                // ShowOnlyEditedMessage
                boolean showOnlyEditedMessage = true;
                if (filterProp.isShowOnlyEditedMessage()) {
                    showOnlyEditedMessage = (item.editedPayload() != null);
                }

                // Highlight Color
                boolean colorFilter = true;
                if (showOnlyScopFilter) {
                    // cololr
                    if (filterProp.getShowOnlyHighlightColors()) {
                        EnumSet<MessageHighlightColor> colors = filterProp.getHighlightColors();
                        MessageHighlightColor hc = MessageHighlightColor.valueOf(item.annotations().highlightColor());
                        colorFilter = colors.contains(hc);
                    }
                }
                // Comment Filter
                boolean commentFilter = true;
                if (showOnlyScopFilter) {
                    // comment
                    if (filterProp.getShowOnlyComment()) {
                        commentFilter = (item.annotations().hasNotes());
                    }
                }
                // message
                boolean message = true;
                if (!filterProp.getRequest().isEmpty()) {
                    if (filterProp.isRequestRegex()) {
                        message = item.contains(Pattern.compile(filterProp.getMessage(), filterProp.isMessageIgnoreCase() ? Pattern.DOTALL : Pattern.DOTALL | Pattern.CASE_INSENSITIVE));
                    } else {
                        message = item.contains(filterProp.getMessage(), filterProp.isMessageIgnoreCase());
                    }
                }
                // ListenerPort
                boolean listenerPort = true;
                if (filterProp.getListenerPort() > -1) {
                    listenerPort = filterProp.getListenerPort() == item.listenerPort();
                }
                // 条件のAND
                allFilter = (colorFilter && commentFilter && showOnlyScopFilter && hideIncomingMessage && hideOutgoingMessage && showOnlyEditedMessage && message && message && listenerPort);

            }
            return allFilter;
        }

    }

    public static class PropertyRowSorter<M extends TableModel> extends TableRowSorter<M> {

        public PropertyRowSorter(M model) {
            super(model);
        }

        private final NumberComparator numberComparator = new NumberComparator();

        @Override
        public Comparator<?> getComparator(int column) {
            if (column == 1) {
                return numberComparator;
            } else {
                return super.getComparator(column);
            }
        }
    }

    private static class NumberComparator implements Comparator {

        @SuppressWarnings("unchecked")
        @Override
        public int compare(Object o1, Object o2) {
            try {
                int parseIntA = Integer.parseInt(o1.toString());
                int parseIntB = Integer.parseInt(o2.toString());
                return parseIntA - parseIntB;
            } catch (NumberFormatException e) {
                if (o1 instanceof Comparator comparator) {
                    return comparator.compare(o1, o2);
                } else {
                    return StringUtil.compareToString(o1.toString(), o2.toString());
                }
            }
        }
    }

}
