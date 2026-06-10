/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pki.Service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import static pe.edu.uni.fc.cc.common.Constants.BCFIPS_PROVIDER;

/**
 *
 * @author JUAN
 */
public class KeyStoreStorageService {
    
    public void saveToPKCS12File(String filePath, String password, String alias, PrivateKey privateKey, X509Certificate certificate){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BCFIPS_PROVIDER);
            ks.load(null,null);
            Certificate[] chain = new Certificate[]{certificate};
            ks.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
            try(FileOutputStream fos = new FileOutputStream(filePath)){
                ks.store(fos, password.toCharArray());
            }
        } catch (KeyStoreException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
    
    public Credential loadKeyMaterialFromPCKS12File(String filePath, String password, String alias){
        Credential credential = null;
        
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BCFIPS_PROVIDER);
            try(FileInputStream fis = new FileInputStream(filePath)){
                ks.load(fis, password.toCharArray());
            } 
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
            X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
            credential = new Credential(privateKey, certificate);
        } catch (KeyStoreException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchProviderException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }catch (FileNotFoundException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }catch (NoSuchAlgorithmException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (UnrecoverableKeyException ex) { 
            System.getLogger(KeyStoreStorageService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
        
        return credential;
    }
    
    public static class Credential {
        private final PrivateKey privateKey;
        private final X509Certificate certificate;
        
        public Credential(PrivateKey privateKey, X509Certificate certificate){
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
        
        public PrivateKey getPrivateKey() {
            return privateKey;
        }
        
        public X509Certificate getCertificate(){
            return certificate;
        }
    }
}
