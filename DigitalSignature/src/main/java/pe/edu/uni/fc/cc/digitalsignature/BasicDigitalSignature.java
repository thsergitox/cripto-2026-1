/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalsignature;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_2048;

/**
 *
 * @author docente
 */
public class BasicDigitalSignature {

    public static void main(String[] args) {
        System.out.println("Basic Digital Signature!");
        // mensaje a firmar y enviar
        String originalMessage = "Basic Digital Signature";
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
        // visualizan los componentes de las llaves RSA
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;   // (d,n)
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;       // (e,n)
        // componentes o parametros de la llave privada
        BigInteger d = rsaPrivateKey.getPrivateExponent();
        BigInteger n = rsaPrivateKey.getModulus();
        // mensaje como expresion numerica
        BigInteger originalBigIntegerMessage = new BigInteger(1, originalMessage.getBytes());
        // firmar el mensaje
        BigInteger signature = originalBigIntegerMessage.modPow(d, n);   // s = c^d mod n
        // proceso de verificacion
        // obtener el parametro e desde la llave publica
        BigInteger e = rsaPublicKey.getPublicExponent();
        // recuperar el mensaje firmado con la llave publica (e, n)
        BigInteger recoveredMessage = signature.modPow(e, n);   // m = s^e mod n
        // comparar el mensaje recuperado con el original
        boolean verified = recoveredMessage.equals(originalBigIntegerMessage);
        // resultados
        System.out.println("Mensaje original: " + originalMessage);
        System.out.println("Mensaje numerico: " + originalBigIntegerMessage);
        System.out.println("Firma digital: " + signature);
        System.out.println("Modulo (n) : " + n);
        System.out.println("Mensaje recuperado: " + recoveredMessage);
        System.out.println("Firma validada? " + verified);
    }
}
