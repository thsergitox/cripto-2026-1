/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import static pe.edu.uni.fc.cc.common.Constants.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constants.RSA_SIGN_ALGORITHM;

/**
 *
 * @author JUAN
 */
public class CertificationAuthorityGenerationService {
    
    public X509Certificate createSelfSignedCertficate(KeyPair caKeyPair, String caDn, int validityYears){
        X509Certificate caCer = null;
        X500Name dnName = new X500Name(caDn);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + (validityYears * 365L * 24 * 60 * 60 * 1000));
        
        //constructores
        X509v3CertificateBuilder cerBuilder = new JcaX509v3CertificateBuilder(dnName, serialNumber, startDate, endDate, dnName, caKeyPair.getPublic());
        
        try {
            ContentSigner caSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM).setProvider(BCFIPS_PROVIDER).build(caKeyPair.getPrivate());
            X509CertificateHolder ceHolder = cerBuilder.build(caSigner);
            caCer = new JcaX509CertificateConverter().setProvider(BCFIPS_PROVIDER).getCertificate(ceHolder);
            
        } catch (OperatorCreationException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        
        return caCer;
    }
    
    public KeyPair generateKeyPair() {
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM,BCFIPS_PROVIDER);
            kpg.initialize(RSA_KEY_SIZE_2048);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(CertificationAuthorityGenerationService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        return kp;
        
    }
}
