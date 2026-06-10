/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalsignature.service;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class ProtocolDigitalSignatureService {

    public BigInteger signDigest(BigInteger digest, RSAPrivateKey privateKey) {
        if (digest == null || privateKey == null) {
            return null;
        }
        BigInteger d = privateKey.getPrivateExponent();
        BigInteger n = privateKey.getModulus();
        return digest.modPow(d, n);
    }

    public BigInteger recoverDigest(BigInteger signedDigest, RSAPublicKey publicKey) {
        if (signedDigest == null || publicKey == null) {
            return null;
        }
        BigInteger e = publicKey.getPublicExponent();
        BigInteger n = publicKey.getModulus();
        return signedDigest.modPow(e, n);
    }

    public boolean verify(BigInteger recoveredDigest, BigInteger calculatedDigest) {
        if (recoveredDigest == null || calculatedDigest == null) {
            return false;
        }
        return recoveredDigest.equals(calculatedDigest);
    }
}
