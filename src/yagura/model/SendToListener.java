/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package yagura.model;

import java.util.EventListener;

/**
 *
 * @author isayan
 */
public interface SendToListener extends EventListener {

    public void complete(SendToEvent evt);

    public void warning(SendToEvent evt);

    public void error(SendToEvent evt);

}
