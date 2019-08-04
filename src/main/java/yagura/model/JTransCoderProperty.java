package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.external.TransUtil.ConvertCase;
import extend.util.external.TransUtil.EncodeType;
import extend.util.external.TransUtil.NewLine;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author isayan
 */
public class JTransCoderProperty {

    @Expose
    private EncodeType encodeType = EncodeType.ALL;

    /**
     * @return the encodeType
     */
    public EncodeType getEncodeType() {
        return encodeType;
    }

    /**
     * @param encodeType the encodeType to set
     */
    public void setEncodeType(EncodeType encodeType) {
        this.encodeType = encodeType;
    }

    @Expose
    private NewLine newLine = NewLine.NONE;

    /**
     * @return the newLine
     */
    public NewLine getNewLine() {
        return newLine;
    }

    /**
     * @param newLine the newLine to set
     */
    public void setNewLine(NewLine newLine) {
        this.newLine = newLine;
    }

    @Expose
    private ConvertCase convertCase = ConvertCase.LOWLER;

    /**
     * @return the convertCase
     */
    public ConvertCase getConvertCase() {
        return convertCase;
    }

    /**
     * @param convertCase the convertCase to set
     */
    public void setConvertCase(ConvertCase convertCase) {
        this.convertCase = convertCase;
    }

    @Expose
    private boolean lineWrap = false;

    /**
     * @return the lineWrap
     */
    public boolean isLineWrap() {
        return lineWrap;
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    public void setLineWrap(boolean lineWrap) {
        this.lineWrap = lineWrap;
    }

    @Expose
    private boolean rawEncoding = false;

    /**
     * @return the rawEncoding
     */
    public boolean isRawEncoding() {
        return rawEncoding;
    }

    /**
     * @param rawEncoding the rawEncoding to set
     */
    public void setRawEncoding(boolean rawEncoding) {
        this.rawEncoding = rawEncoding;
    }

    @Expose
    private boolean guessEncoding = false;

    /**
     * @return the guessEncoding
     */
    public boolean isGuessEncoding() {
        return guessEncoding;
    }

    /**
     * @param guessEncoding the guessEncoding to set
     */
    public void setGuessEncoding(boolean guessEncoding) {
        this.guessEncoding = guessEncoding;
    }

    @Expose
    private String selectEncoding = StandardCharsets.UTF_8.toString();

    /**
     * @return the selectEncoding
     */
    public String getSelectEncoding() {
        return selectEncoding;
    }

    /**
     * @param selectEncoding the selectEncoding to set
     */
    public void setSelectEncoding(String selectEncoding) {
        this.selectEncoding = selectEncoding;
    }

    private String currentInput = "";

    /**
     *
     * @param property
     * @return
     */
    public String getCurrentInput() {
        return currentInput;
    }

    public void setCurrentInput(String currentInput) {
        this.currentInput = currentInput;
    }

    public void setProperty(JTransCoderProperty property) {
        this.setEncodeType(property.getEncodeType());
        this.setNewLine(property.getNewLine());
        this.setConvertCase(property.getConvertCase());
        this.setLineWrap(property.isLineWrap());
        this.setRawEncoding(property.isRawEncoding());
        this.setGuessEncoding(property.isGuessEncoding());
        this.setSelectEncoding(property.getSelectEncoding());
        this.setCurrentInput(property.getCurrentInput());
    }

    @Override
    public String toString() {
        return this.getCurrentInput();
    }

}
