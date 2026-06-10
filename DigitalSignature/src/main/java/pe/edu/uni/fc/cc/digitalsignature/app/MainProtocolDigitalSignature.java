/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.digitalsignature.app;

import java.math.BigInteger;
import pe.edu.uni.fc.cc.digitalsignature.service.HashingService;
import pe.edu.uni.fc.cc.digitalsignature.service.ProtocolDigitalSignatureService;
import pe.edu.uni.fc.cc.digitalsignature.service.RSAKeyGeneratorService;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class MainProtocolDigitalSignature {

    public static void main(String[] args) {
        System.out.println("Main Protocol Digital Signature !!!");
        String originalMessage = "Main Protocol Digital Signature !!!";

        // instanciar los servicios
        RSAKeyGeneratorService rsaKeyGeneratorService = new RSAKeyGeneratorService();
        HashingService hashingService = new HashingService();
        ProtocolDigitalSignatureService protocolDigitalSignatureService = new ProtocolDigitalSignatureService();

        // Generar llaves
        rsaKeyGeneratorService.generateKeyPair();
        if (rsaKeyGeneratorService.getRsaPrivateKey() == null) {
            System.err.println("[Error critico] No se pudieron generar las llaves criptograficas!");
            return;
        }

        // calcular el hash del mensaje original
        BigInteger originalHash = hashingService.calculateHash(originalMessage);
        if (originalHash == null) {
            System.err.println("[Error] No se pudo generar el hash solicitado!");
            return;
        }

        // firmar el hash
        BigInteger signedDigest = protocolDigitalSignatureService.signDigest(originalHash, rsaKeyGeneratorService.getRsaPrivateKey());
        // emisor envia al receptor el dato (originalMessage) y la firma del dato (signedDigest)

        // recuperamos el hash desde el dato firmado
        BigInteger recoveredDigest = protocolDigitalSignatureService.recoverDigest(signedDigest, rsaKeyGeneratorService.getRsaPublicKey());
        // calculamos el nuevo digest
        BigInteger newCalculatedDigest = hashingService.calculateHash(originalMessage);
        // verificar
        boolean verified = protocolDigitalSignatureService.verify(recoveredDigest, newCalculatedDigest);

        // resultados
        System.out.println("Resumen recuperado: " + recoveredDigest.toString(16));
        System.out.println("Resumen calculado : " + newCalculatedDigest.toString(16));
        System.out.println("Firma verificada  : " + verified);
    }
}
