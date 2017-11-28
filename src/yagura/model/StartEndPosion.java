/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

/**
 *
 * @author isayan
 */
public class StartEndPosion {
    private int startPos = 0;
    private int endPos = 0;
        
    public StartEndPosion(int s, int e) {
        this.setPosision(s, e);
    }

    /**
     * @param s
     * @param e
     */
    public void setPosision(int s, int e) {
        if (s > e) throw new IllegalArgumentException("start > end position to set");
        startPos = s;
        endPos = e;
    }
    
    /**
     * @return the startPos
     */
    public int getStartPos() {
        return this.startPos;
    }

    /**
     * @return the endPos
     */
    public int getEndPos() {
        return this.endPos;
    }

    
    public int getLength() 
    {
        return this.endPos - this.startPos;
    }
    
}
