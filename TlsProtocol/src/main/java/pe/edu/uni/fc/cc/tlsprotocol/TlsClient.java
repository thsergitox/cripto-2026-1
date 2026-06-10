/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tlsprotocol;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import static pe.edu.uni.fc.cc.common.Constants.CLIENT_TLS_FILENAME;
import static pe.edu.uni.fc.cc.common.Constants.KEY_USE_PASSWORD;
import static pe.edu.uni.fc.cc.common.Constants.PKCS12_KEYSTORE_TYPE;
import static pe.edu.uni.fc.cc.common.Constants.TLS_PORT;
import static pe.edu.uni.fc.cc.common.Constants.TLS_VERSION_1_3;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class TlsClient {

    public static void main(String[] args) {
        System.out.println("Tls Client!");
        String host = "localhost";
        int puerto = TLS_PORT;
        String trustStorePath = CLIENT_TLS_FILENAME;
        String trustStorePassword = KEY_USE_PASSWORD;

        try {
            // cargar el trust store del cliente
            KeyStore trustStore = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
            // inicializar el TrustManager con el trust store
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            // inicializar contexto TLS 1.3 (KeyManagers null = sin identidad propia)
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION_1_3);
            sslContext.init(null, tmf.getTrustManagers(), null);
            // crear el socket TLS
            SSLSocketFactory sf = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) sf.createSocket(host, puerto)) {
                // forzar TLS 1.3
                socket.setEnabledProtocols(new String[]{TLS_VERSION_1_3});
                // iniciar handshake explicitamente
                socket.startHandshake();
                System.out.println("[Cliente] Handshake TLS 1.3 OK con " + host + ":" + puerto);
                System.out.println("[Cliente] Cipher suite negociada: " + socket.getSession().getCipherSuite());

                try (
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
                ) {
                    String mensaje = "hola servidor desde el cliente TLS 1.3";
                    System.out.println("[Cliente] Enviando: " + mensaje);
                    out.println(mensaje);
                    String respuesta = in.readLine();
                    System.out.println("[Cliente] Respuesta del servidor: " + respuesta);
                }
            }
        } catch (KeyStoreException ex) {
            System.getLogger(TlsClient.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (IOException ex) {
            System.getLogger(TlsClient.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (NoSuchAlgorithmException ex) {
            System.getLogger(TlsClient.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (CertificateException ex) {
            System.getLogger(TlsClient.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } catch (KeyManagementException ex) {
            System.getLogger(TlsClient.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
