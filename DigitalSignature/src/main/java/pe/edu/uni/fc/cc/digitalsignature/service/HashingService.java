/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalsignature.service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static pe.edu.uni.fc.cc.common.Constants.SHA_256_ALGORITHM;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class HashingService {

    private MessageDigest messageDigest;

    public HashingService() {
        try {
            this.messageDigest = MessageDigest.getInstance(SHA_256_ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(HashingService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }

    public BigInteger calculateHash(String message) {
        if (message == null) {
            return null;
        }
        messageDigest.reset();
        byte[] digestBytes = messageDigest.digest(message.getBytes());
        return new BigInteger(1, digestBytes);
    }
}
