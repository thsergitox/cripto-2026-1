/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalsignature;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constants.SHA_256_ALGORITHM;

/**
 *
 * @author docente
 */
public class HashDigitalSignature {

    public static void main(String[] args) {
        System.out.println("Hash Digital Signature !!!");
        // mensaje a firmar y enviar
        String originalMessage = "Hash Digital Signature";
        // llaves RSA
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(BasicDigitalSignature.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        // par de llaves
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();
        // visualizar los componentes de las llaves RSA
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;   // (d,n)
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;       // (e,n)
        // componentes o parametros de la llave privada
        BigInteger d = rsaPrivateKey.getPrivateExponent();
        BigInteger n = rsaPrivateKey.getModulus();
        // mensaje como expresion numerica
        BigInteger originalBigIntegerDigest = null;
        // obtener el resumen
        MessageDigest mdMachine = null;
        try {
            mdMachine = MessageDigest.getInstance(SHA_256_ALGORITHM);
            byte[] originalDigest = mdMachine.digest(originalMessage.getBytes());
            originalBigIntegerDigest = new BigInteger(1, originalDigest);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(HashDigitalSignature.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        if (originalBigIntegerDigest == null) return;
        // firmar el resumen
        BigInteger signature = originalBigIntegerDigest.modPow(d, n);
        System.out.println("Firma del resumen del mensaje: " + signature);
        // el emisor envia al receptor el mensaje y la firma
        // proceso de verificacion
        // obtener el parametro e desde la llave publica
        BigInteger e = rsaPublicKey.getPublicExponent();
        // recuperar el hash firmado
        BigInteger recoveredBigIntegerDigest = signature.modPow(e, n);
        // el receptor calcula el hash del mensaje original
        byte[] newDigest = mdMachine.digest(originalMessage.getBytes());
        BigInteger newBigIntegerDigest = new BigInteger(1, newDigest);
        // comparar
        boolean verified = recoveredBigIntegerDigest.equals(newBigIntegerDigest);
        // imprimir
        System.out.println("Resumen recuperado: " + recoveredBigIntegerDigest.toString(16));
        System.out.println("Resumen calculado: " + newBigIntegerDigest.toString(16));
        System.out.println("Firma validada? " + verified);
    }
}
