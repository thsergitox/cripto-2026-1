/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tlsprotocol;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;
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
        // correccion de configuracion UTF-8
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        //
        System.out.println("Tls Client !!!");
        // datos de la comunicacion
        String host = "localhost";
        int puerto = TLS_PORT;
        String trustStorePath = CLIENT_TLS_FILENAME;
        String password = KEY_USE_PASSWORD;

        try {
            // configurar los datos para la conexion segura en el cliente
            KeyStore ts = KeyStore.getInstance(PKCS12_KEYSTORE_TYPE);
            ts.load(new FileInputStream(trustStorePath), password.toCharArray());
            // Capa de la gestion de confianza
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // inicializar el TrustManager
            tmf.init(ts);
            // Capa de infraestructura y configuracion SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION_1_3);
            sslContext.init(null, tmf.getTrustManagers(), null);
            // Capa de abstraccion de red
            SSLSocketFactory sf = sslContext.getSocketFactory();
            // Captura de datos desde la consola
            Scanner scanner = new Scanner(System.in);
            System.out.println("[Cliente] Ingresa el texto a enviar (de manera segura) al servidor");
            String messageToBeSent = scanner.nextLine();
            // conectar al servidor (localhost)
            // Capa de transporte seguro
            try (
                SSLSocket socket = (SSLSocket) sf.createSocket(host, puerto);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ) {
                // establecer la version del protocolo
                socket.setEnabledProtocols(new String[]{TLS_VERSION_1_3});
                // Ejecutar el handshake TLS
                System.out.println("[Cliente] Ejecutando handshake TLS ...");
                socket.startHandshake();
                System.out.println("[Cliente] Handshake ejecutado satisfactoriamente!");
                System.out.println("[Cliente] Conectado mediante la suite: " + socket.getSession().getCipherSuite());
                // enviamos el texto capturado
                out.println(messageToBeSent);
                System.out.println("[Cliente] Mensaje enviado!");
                // Esperamos la respuesta
                String response = in.readLine();
                if (response == null || response.isBlank()) {
                    System.out.println("[Cliente] El servidor no proceso el texto enviado!");
                } else {
                    System.out.println("[Cliente] Respuesta descifrada desde el Servidor: " + response);
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
