/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.edu.uni.fc.cc.pki;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import static pe.edu.uni.fc.cc.common.Constants.BCFIPS_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_2048;
import static pe.edu.uni.fc.cc.common.Constants.RSA_SIGN_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.USER_CD_FILENAME;
import static pe.edu.uni.fc.cc.common.Constants.USER_CD_FILENAME2;

/**
 *
 * @author JUAN
 */
public class PKI {

    public static void main(String[] args) {
        System.out.println("Hello World!");
        
        // agregando el proveedor criptográfico
        Security.addProvider(new BouncyCastleFipsProvider());
        
        try {
            // Generar llaves
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            kpg.initialize(RSA_KEY_SIZE_2048);
            KeyPair userKeyPair = kpg.generateKeyPair();
            
            // Elaborar el DN del subject del usuario
            String user_dn = "CN=Juan Silva, OU=Facultad de Ciencias, O=UNI, C=PE";
            X500Name subjectDN = new X500Name(user_dn);
            
            // Generación del CSR
            JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectDN, userKeyPair.getPublic());
            ContentSigner userSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM).build(userKeyPair.getPrivate());
            PKCS10CertificationRequest csr = csrBuilder.build(userSigner);
            System.out.println("CSR generado: " + csr.getSubject().toString());
            
            // En la CA se recibe el csr, se valida, y se emite el CD
            // Simular la CA
            KeyPair caKeyPair = kpg.generateKeyPair();
            String ca_dn = "CN=UNI Root, O=UNI, C=PE";
            X500Name issuerDN = new X500Name(ca_dn);
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date startDate = new Date();
            Date endDate = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));
            
            // Obteniendo la llave publica del usuario desde el CSR
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr).setProvider(BCFIPS_PROVIDER);
            PublicKey userPublicKey = jcaCsr.getPublicKey();
            
            // Contruir el formato X.509v3 para firmar el CD del usuario
            X509v3CertificateBuilder crtBuilder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber, startDate, endDate, csr.getSubject(), userPublicKey);
            
            // Firmar el CD utilizando la llave privada de la CA
            ContentSigner caSigner = new JcaContentSignerBuilder(RSA_SIGN_ALGORITHM).build(caKeyPair.getPrivate());
            
            // Guardamos el CD en:
            X509CertificateHolder crtHolder = crtBuilder.build(caSigner);
            
            // Convertir al estándar JAVA
            X509Certificate userDC = new JcaX509CertificateConverter().setProvider(BCFIPS_PROVIDER).getCertificate(crtHolder);
            System.out.println("Issuer: " + userDC.getIssuerX500Principal());
            System.out.println("Subject: " + userDC.getSubjectX500Principal());
            
            // Guardar el CD en archivo
            try (FileOutputStream fos = new FileOutputStream(USER_CD_FILENAME)) {
                fos.write(userDC.getEncoded());
                System.out.println("Archivo almacenado: " + USER_CD_FILENAME);
            } 
            
            
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (OperatorCreationException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (InvalidKeyException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (FileNotFoundException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(PKI.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
