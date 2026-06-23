/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pqc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class Signer {

    private final String provider;

    public Signer(String provider) {
        this.provider = provider;
    }

    public byte[] sign(String algorithm, byte[] data, PrivateKey privateKey){
        byte[] signature = null;
        try {
            Signature signer = Signature.getInstance(algorithm, provider);
            signer.initSign(privateKey);
            signer.update(data);
            signature = signer.sign();
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(Signer.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(Signer.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(Signer.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (SignatureException ex) {
            System.getLogger(Signer.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return signature;
    }
}
