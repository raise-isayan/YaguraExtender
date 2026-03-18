package passive.signature;

import extension.view.base.CaptureItem;

/**
 *
 * @author isayan
 */
public class RegExPattermItem extends CaptureItem {

    private String regexPattern = "";
    private String regexFlag = "";

    /**
     * @return the regexPattern
     */
    public String getRegExPattern() {
        return regexPattern;
    }

    /**
     * @param regexPattern the regexPattern to set
     */
    public void setRegExPattern(String regexPattern) {
        this.regexPattern = regexPattern;
    }

    /**
     * @return the regexFlag
     */
    public String getRegExFlag() {
        return regexFlag;
    }

    /**
     * @param regexFlag the regexFlag to set
     */
    public void setRegExFlag(String regexFlag) {
        this.regexFlag = regexFlag;
    }

}
