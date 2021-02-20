package passive;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IScanIssue;
import burp.IScannerCheck;
import extension.burp.Severity;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 *
 * @author raise.isayan
 */
public class SignatureItem<M extends IssueItem> implements ISignatureItem {

    public SignatureItem(String issueName, Severity serverity) {
        this.issueName = issueName;
        this.serverity = serverity;
    }

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
        return new PassiveCheckAdapter();
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
            if (!(o1.length == 2 && o2.length == 2)) {
                return 0;
            }
            int cmp = Integer.compare(o1[0], o2[0]);
            if (cmp == 0) {
                return Integer.compare(o2[1], o1[1]);
            } else {
                return cmp;
            }
        }
    };

    protected static void markerSortOrder(List<int[]> applyRequestMarkers, List<int[]> applyResponseMarkers) {
        // ソートする
        if (applyRequestMarkers != null) {
            applyRequestMarkers.sort(COMPARE_MARKS);
        }
        if (applyResponseMarkers != null) {
            applyResponseMarkers.sort(COMPARE_MARKS);
        }
    }

    protected static List<int[]> markerUnionRegion(List<int[]> markers) {
        // 領域が重なってる場合に除外
        // A の領域のなかに B が一部でも含まれる場合にはBを含めない
        List<int[]> regions = new ArrayList<>();
        NEXT:
        for (int[] mark : markers) {
            for (int[] reg : regions) {
                if (reg[0] <= mark[0] && mark[0] <= reg[1]) {
                    continue NEXT;
                }
            }
            regions.add(mark);
        }
        return regions;
    }

}
