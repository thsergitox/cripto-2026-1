/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class KeyGenerator {

    private final String provider;

    public KeyGenerator(String provider) {
        this.provider = provider;
    }

    public KeyPair generate(String algorithm, AlgorithmParameterSpec parameter){
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            kpg.initialize(parameter);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyGenerator.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KeyGenerator.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            System.getLogger(KeyGenerator.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return kp;
    }
}
