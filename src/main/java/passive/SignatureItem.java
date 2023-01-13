package passive;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import extension.burp.ScannerCheckAdapter;
import extension.burp.Severity;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.swing.event.EventListenerList;

/**
 *
 * @author raise.isayan
 * @param <M>
 */
public class SignatureItem<M extends IssueItem> implements ISignatureItem {

    public SignatureItem(String issueName, Severity serverity) {
        this.issueName = issueName;
        this.serverity = serverity;
    }

    @Expose
    @SerializedName("selected")
    private boolean selected = true;

    /**
     * @return the selected
     */
    @Override
    public boolean isSelected() {
        return this.selected;
    }

    /**
     * @param selected the selected to set
     */
    @Override
    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    @Expose
    @SerializedName("issueName")
    private final String issueName;

    @Override
    public String getIssueName() {
        return issueName;
    }

    private final Severity serverity;

    @Override
    public Severity getServerity() {
        return serverity;
    }

    public AuditIssue makeScanIssue(HttpRequestResponse messageInfo, List<M> issueItem) {
        return null;
    }

    public ScanCheck passiveScanCheck() {
        return new ScannerCheckAdapter();
    }

    public HttpRequestResponse applyMarkers(HttpRequestResponse baseRequestResponse, List<M> issueList) {
        List<Marker> requestMarkers = new ArrayList<>();
        List<Marker> responseMarkers = new ArrayList<>();
        for (IssueItem issue : issueList) {
            if (issue.isCapture()) {
                if (issue.isMessageIsRequest()) {
                    requestMarkers.add(Marker.marker(Range.range(issue.start(), issue.end())));
                } else {
                    responseMarkers.add(Marker.marker(Range.range(issue.start(), issue.end())));
                }
            }
        }
        if (!(requestMarkers.isEmpty() || responseMarkers.isEmpty())) {
            List<Marker> markers = new ArrayList<>();
            markers.addAll(requestMarkers);
            markers.addAll(responseMarkers);
            return baseRequestResponse.withRequestMarkers(markers);
        }
        else if (!requestMarkers.isEmpty()) {
            return baseRequestResponse.withRequestMarkers(requestMarkers);
        }
        else if (!responseMarkers.isEmpty()) {
            return baseRequestResponse.withResponseMarkers(responseMarkers);
        }
        return baseRequestResponse;
    }

    private final static Comparator<Range> COMPARE_MARKS = new Comparator<>() {
        @Override
        public int compare(Range o1, Range o2) {
            if ((o1 == null || o2 == null)) return 0;
            int cmp = Integer.compare(o1.startIndexInclusive(), o2.startIndexInclusive());
            if (cmp == 0)
                return Integer.compare(o2.endIndexExclusive(), o1.endIndexExclusive());
            else
                return cmp;
        }
    };

    protected static void markerSortOrder(List<Range> applyRequestMarkers, List<Range> applyResponseMarkers) {
        // ソートする
        if (applyRequestMarkers != null) applyRequestMarkers.sort(COMPARE_MARKS);
        if (applyResponseMarkers != null) applyResponseMarkers.sort(COMPARE_MARKS);
    }

    protected static List<Range> markerUnionRegion(List<Range> markers) {
        // 領域が重なってる場合に除外
        // A の領域のなかに B が一部でも含まれる場合にはBを含めない
        List<Range> regions = new ArrayList<>();
        NEXT: for (Range mark : markers) {
            for (Range reg : regions) {
                if (reg.startIndexInclusive() <= mark.startIndexInclusive() && mark.startIndexInclusive() <= reg.endIndexExclusive()) continue NEXT;
            }
            regions.add(mark);
        }
        return regions;
    }

    private final EventListenerList propertyChangeList  = new EventListenerList();

    public final void firePropertyChange(String propertyName, Object oldValue, Object newValue) {
        Object[] listeners = this.propertyChangeList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == PropertyChangeListener.class) {
                ((PropertyChangeListener) listeners[i + 1]).propertyChange(new PropertyChangeEvent(this, propertyName ,oldValue ,newValue));
            }
        }
    }

    public final void addPropertyChangeListener(PropertyChangeListener listener) {
        this.propertyChangeList.add(PropertyChangeListener.class, listener);
    }

    public final void removePropertyChangeListener(PropertyChangeListener listener) {
        this.propertyChangeList.remove(PropertyChangeListener.class, listener);
    }

}
