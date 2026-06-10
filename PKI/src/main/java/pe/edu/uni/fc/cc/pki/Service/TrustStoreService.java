/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import static pe.edu.uni.fc.cc.common.Constants.PKCS12_KEYSTORE_TYPE;

/**
 * Guarda un TrustStore (PKCS#12) que contiene SOLO el certificado publico
 * (sin llave privada). Lo usa el cliente TLS como ancla de confianza.
 *
 * Nota: se usa el provider por defecto (SunJSSE) y NO BCFIPS porque
 * BCFIPS no marca las entradas como "trusted certificate" en un formato
 * que SunJSSE reconozca al cargar el TrustStore desde el cliente.
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class TrustStoreService {

    public void saveToTrustStore(String filePath, String password, String alias, X509Certificate certificate) {
        try {
            KeyStore ks = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            ks.load(null, null);
            ks.setCertificateEntry(alias, certificate);
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                ks.store(fos, password.toCharArray());
            }
        } catch (KeyStoreException ex) {
            System.getLogger(TrustStoreService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(TrustStoreService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(TrustStoreService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(TrustStoreService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
