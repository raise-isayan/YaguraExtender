/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.external;

import java.security.Key;
import java.security.cert.X509Certificate;

/**
 *
 * @author isayan
 */
public class CertificateInKey {
    private final Key privateKey;
    private final X509Certificate x509cert;
    
    public CertificateInKey(Key privateKey, X509Certificate x509cert) {
        this.privateKey = privateKey;
        this.x509cert = x509cert;
    }

    /**
     * @return the privateKey
     */
    public Key getPrivateKey() {
        return privateKey;
    }

    /**
     * @return the get x509 Certificate
     */
    public X509Certificate getX509Certificate() {
        return x509cert;
    }
    
}
