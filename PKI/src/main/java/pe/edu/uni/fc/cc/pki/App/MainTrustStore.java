/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.App;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static pe.edu.uni.fc.cc.common.Constants.CLIENT_TLS_ALIAS;
import static pe.edu.uni.fc.cc.common.Constants.CLIENT_TLS_FILENAME;
import static pe.edu.uni.fc.cc.common.Constants.KEY_USE_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constants.SERVER_TLS_ALIAS;
import static pe.edu.uni.fc.cc.common.Constants.SERVER_TLS_FILENAME;
import pe.edu.uni.fc.cc.pki.Service.CertificationAuthorityGenerationService;
import pe.edu.uni.fc.cc.pki.Service.KeyStoreStorageService;
import pe.edu.uni.fc.cc.pki.Service.TrustStoreService;

/**
 * Bootstrap del entorno TLS:
 *  - Genera un par RSA + certificado X.509 autofirmado para el servidor.
 *  - Almacena (cert + privada) en server-tls.p12  -> identidad del servidor.
 *  - Almacena solo el cert en client-tls.p12       -> trust store del cliente.
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class MainTrustStore {

    public static void main(String[] args) {
        System.out.println("Main Trust Store !!!");

        // registrar el proveedor BCFIPS
        Security.addProvider(new BouncyCastleFipsProvider());

        // instanciar servicios
        CertificationAuthorityGenerationService caService = new CertificationAuthorityGenerationService();
        KeyStoreStorageService storageService = new KeyStoreStorageService();
        TrustStoreService trustStoreService = new TrustStoreService();

        // parametros de archivos y credenciales
        String serverTlsPKCS12Path = SERVER_TLS_FILENAME;
        String clientTlsPKCS12Path = CLIENT_TLS_FILENAME;
        String globalPassword = KEY_USE_PASSWORD;

        // Generar CD autofirmado
        KeyPair keyPair = caService.generateKeyPair();
        String dn = "CN=localhost, O=UNI, OU=FC, C=PE";
        X509Certificate cert = caService.createSelfSignedCertficate(keyPair, dn, 1);
        System.out.println("Container TLS server generado");

        // almacenar el CD autofirmado (cert + llave privada del servidor)
        storageService.saveToPKCS12File(serverTlsPKCS12Path, globalPassword, SERVER_TLS_ALIAS, keyPair.getPrivate(), cert);
        System.out.println("Container TLS server almacenado en: " + serverTlsPKCS12Path);

        // almacenar el TrustStore (solo cert del servidor, para el cliente)
        trustStoreService.saveToTrustStore(clientTlsPKCS12Path, globalPassword, CLIENT_TLS_ALIAS, cert);
        System.out.println("Container TLS client almacenado en: " + clientTlsPKCS12Path);
    }
}
