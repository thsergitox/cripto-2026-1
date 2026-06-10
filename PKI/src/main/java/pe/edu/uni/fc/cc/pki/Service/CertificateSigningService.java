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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import static pe.edu.uni.fc.cc.common.Constants.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constants.RSA_SIGN_ALGORITHM;

public class CertificateSigningService {

    public X509Certificate signCsr(PKCS10CertificationRequest csr, KeyStoreStorageService.Credential caCredential, int validityDays) {
        X509Certificate certificate = null;
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        try {
            PublicKey userPublicKey = jcaCsr.getPublicKey();
            X500Name issuerDN = X500Name.getInstance(caCredential.getCertificate().getSubjectX500Principal().getEncoded());
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date startDate = new Date(System.currentTimeMillis());
            Date endDate = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerDN,
                    serialNumber,
                    startDate,
                    endDate,
                    csr.getSubject(),
                    userPublicKey);
            ContentSigner certSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM)
                    .setProvider(BCFIPS_PROVIDER)
                    .build(caCredential.getPrivateKey());
            X509CertificateHolder certHolder = certBuilder.build(certSigner);
            certificate = new JcaX509CertificateConverter()
                    .setProvider(BCFIPS_PROVIDER)
                    .getCertificate(certHolder);
        } catch (InvalidKeyException | NoSuchAlgorithmException | OperatorCreationException | CertificateException ex) {
            System.getLogger(CertificateSigningService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return certificate;
    }

}
