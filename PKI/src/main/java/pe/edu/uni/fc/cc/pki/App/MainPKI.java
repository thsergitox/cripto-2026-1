/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.App;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import static pe.edu.uni.fc.cc.common.Constants.CA_ROOT_CONTAINER_FILENAME;
import static pe.edu.uni.fc.cc.common.Constants.CA_ROOT_ALIAS;
import static pe.edu.uni.fc.cc.common.Constants.END_USER_ALIAS;
import pe.edu.uni.fc.cc.pki.Service.CSRGeneratorService;
import pe.edu.uni.fc.cc.pki.Service.CertificateSigningService;
import pe.edu.uni.fc.cc.pki.Service.CertificationAuthorityGenerationService;
import pe.edu.uni.fc.cc.pki.Service.KeyStoreStorageService;

/**
 *
 * @author JUAN
 */
public class MainPKI {

    public static void main(String[] args) {
        System.out.println("Main PKI!!");

        // registrar el proveedor BC-FIPS
        Security.addProvider(new BouncyCastleFipsProvider());

        // Instanciar servicios
        CertificationAuthorityGenerationService caService = new CertificationAuthorityGenerationService();
        KeyStoreStorageService storageService = new KeyStoreStorageService();
        CSRGeneratorService csrService = new CSRGeneratorService();
        CertificateSigningService signService = new CertificateSigningService();

        // Parametros de archivos o credenciales
        String caPKCS12Path = CA_ROOT_CONTAINER_FILENAME;
        String endUserPKCS12Path = CA_ROOT_CONTAINER_FILENAME;
        String globalPassword = "key-use-password";

        // Generar CA autofirmada (ROOT)
        KeyPair caKeyPair = caService.generateKeyPair();
        String caDn = "CN = ECERNEP ROOT CA, O = Estado Peruano, C = PE";
        X509Certificate caCert = caService.createSelfSignedCertficate(caKeyPair, caDn, 10);
        System.out.println("CA subjectDn: " + caCert.getSubjectX500Principal());

        // Almacenar
        storageService.saveToPKCS12File(caPKCS12Path, globalPassword, CA_ROOT_ALIAS, caKeyPair.getPrivate(), caCert); // Que devuelva un bool y sea True si pasa False si no...
        System.out.println("Contenedor de la CA: " + caCert);

        // Generar el CSR del usuario
        KeyPair userKeyPair = csrService.generateKeyPair();
        String userDN = "CN=Juan Silva, OU=Facultad de Ciencias, O=UNI, C=PE";
        PKCS10CertificationRequest userCsr = csrService.createCSR(userKeyPair, userDN);
        System.out.println("CSR del usuario generado!");
        System.out.println("SubjectDN = " + userCsr.getSubject());

        // Cargar la CA desde el container
        KeyStoreStorageService.Credential credential = storageService.loadKeyMaterialFromPCKS12File(caPKCS12Path, globalPassword, CA_ROOT_ALIAS);
        System.out.println("CA cargada desde el container...");

        // Firmar el CSR del usuario final
        X509Certificate userCert = signService.signCsr(userCsr, credential, 365);

        // Almacenar llaves y CD del usuario final
        storageService.saveToPKCS12File(endUserPKCS12Path,
                globalPassword,
                END_USER_ALIAS,
                userKeyPair.getPrivate(),
                userCert);
    }
}
