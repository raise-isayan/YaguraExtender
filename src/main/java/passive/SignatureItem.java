package passive;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IScanIssue;
import burp.IScannerCheck;
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

    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<M> issueItem) {
        return null;
    }

    public IScannerCheck passiveScanCheck() {
        return new ScannerCheckAdapter();
    }

    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse baseRequestResponse, List<M> issueList) {
        List<int[]> requestMarkers = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        for (IssueItem issue : issueList) {
            if (issue.isCapture()) {
                if (issue.isMessageIsRequest()) {
                    requestMarkers.add(new int[]{issue.start(), issue.end()});
                } else {
                    responseMarkers.add(new int[]{issue.start(), issue.end()});
                }
            }
        }
        List<int[]> applyRequestMarkers = (requestMarkers.size() > 0) ? requestMarkers : null;
        List<int[]> applyResponseMarkers = (responseMarkers.size() > 0) ? responseMarkers : null;
        return BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, applyRequestMarkers, applyResponseMarkers);
    }

    private final static Comparator<int[]> COMPARE_MARKS = new Comparator<int[]>() {
        @Override
        public int compare(int[] o1, int[] o2) {
            if (!(o1.length == 2 && o2.length == 2)) return 0;
            int cmp = Integer.compare(o1[0], o2[0]);
            if (cmp == 0)
                return Integer.compare(o2[1], o1[1]);
            else
                return cmp;
        }
    };

    protected static void markerSortOrder(List<int[]> applyRequestMarkers, List<int[]> applyResponseMarkers) {
        // ソートする
        if (applyRequestMarkers != null) applyRequestMarkers.sort(COMPARE_MARKS);
        if (applyResponseMarkers != null) applyResponseMarkers.sort(COMPARE_MARKS);
    }

    protected static List<int[]> markerUnionRegion(List<int[]> markers) {
        // 領域が重なってる場合に除外
        // A の領域のなかに B が一部でも含まれる場合にはBを含めない
        List<int[]> regions= new ArrayList<>();
        NEXT: for (int[] mark : markers) {
            for (int[] reg : regions) {
                if (reg[0] <= mark[0] && mark[0] <= reg[1]) continue NEXT;
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
