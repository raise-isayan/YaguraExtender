package extension.view.base;

/**
 *
 * @author isayan
 */
public class CaptureItem {

    private String captureValue = "";

    public boolean isCapture() {
        return startPos < endPos;
    }

    /**
     * @return the captureValue
     */
    public String getCaptureValue() {
        return captureValue;
    }

    /**
     * @param captureValue the captureValue to set
     */
    public void setCaptureValue(String captureValue) {
        this.captureValue = captureValue;
    }

    private int startPos = -1;
    private int endPos = -1;

    public void setStart(int startPos) {
        this.startPos = startPos;
    }

    public void setEnd(int endPos) {
        this.endPos = endPos;
    }

    public int start() {
        return this.startPos;
    }

    public int end() {
        return this.endPos;
    }

}
