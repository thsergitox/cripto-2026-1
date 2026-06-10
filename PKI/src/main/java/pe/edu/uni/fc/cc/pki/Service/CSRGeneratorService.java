/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.Service;

/**
 *
 * @author JUAN
 */
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import static pe.edu.uni.fc.cc.common.Constants.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constants.RSA_SIGN_ALGORITHM;

public class CSRGeneratorService {
    public KeyPair generateKeyPair(){
        KeyPair keyPair = null;

        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM, BCFIPS_PROVIDER);
            keyPairGenerator.initialize(RSA_KEY_SIZE_2048);
            keyPair = keyPairGenerator.generateKeyPair();

        } catch ( NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.getLogger(CSRGeneratorService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }

        return keyPair;
    }

    public PKCS10CertificationRequest createCSR(KeyPair userKeyPair, String userDN){
        PKCS10CertificationRequest csr = null;

        X500Name SubjectDN = new X500Name(userDN);
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(SubjectDN, userKeyPair.getPublic());

        try {

            ContentSigner userSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM)
                    .setProvider(BCFIPS_PROVIDER)
                    .build(userKeyPair.getPrivate());
            csr = csrBuilder.build(userSigner);

        } catch (OperatorCreationException e) {
            System.getLogger(CSRGeneratorService.class.getName()).log(System.Logger.Level.ERROR, (String) null, e);
        }


        return csr;
    }
}
