/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pqc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class Verifier {

    private final String provider;

    public Verifier(String provider) {
        this.provider = provider;
    }

    public boolean verify(String algorithm, byte[] data, byte[] signature, PublicKey publicKey){
        boolean verified = false;
        try {
            Signature verifier = Signature.getInstance(algorithm, provider);
            verifier.initVerify(publicKey);
            verifier.update(data);
            verified = verifier.verify(signature);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(Verifier.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(Verifier.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(Verifier.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (SignatureException ex) {
            System.getLogger(Verifier.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return verified;
    }
}
