/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tlsprotocol;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import javax.net.ssl.SSLSocket;

/**
 * Maneja UNA conexion TLS entrante en un hilo dedicado. Lee el texto del
 * cliente, lo procesa (uppercase), y responde por el mismo canal cifrado.
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class ClientHandler implements Runnable {

    private final SSLSocket socketClient;

    public ClientHandler(SSLSocket socketClient) {
        this.socketClient = socketClient;
    }

    @Override
    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socketClient.getInputStream()));
            PrintWriter out = new PrintWriter(socketClient.getOutputStream(), true)
        ) {
            String textoCifrado = in.readLine();
            System.out.println("[ClientHandler] Texto recibido: " + textoCifrado);

            String respuesta = (textoCifrado == null) ? "" : textoCifrado.toUpperCase();
            out.println(respuesta);
            System.out.println("[ClientHandler] Respuesta enviada: " + respuesta);
        } catch (IOException ex) {
            System.getLogger(ClientHandler.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        } finally {
            try {
                socketClient.close();
            } catch (IOException ex) {
                System.getLogger(ClientHandler.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        }
    }
}
