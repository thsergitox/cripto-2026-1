/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.tlsprotocol;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Maneja UNA conexion TLS entrante en un hilo dedicado. Lee el texto del
 * cliente, lo procesa (uppercase), y responde por el mismo canal cifrado.
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class ClientHandler implements Runnable {

    private final SSLSocket socket;

    public ClientHandler(SSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        ) {
            // Protocolo TLS establecido
            SSLSession session = socket.getSession();
            System.out.println("[Hilo Servidor] Protocolo establecido: " + session.getProtocol());
            System.out.println("[Hilo Servidor] Suite de cifrado establecido: " + session.getCipherSuite());
            // comunicacion con confidencialidad e integridad
            String messageIn = in.readLine();
            if (messageIn == null || messageIn.isBlank()) {
                System.out.println("[Hilo Servidor] El mensaje recibido es invalido! No es procesado");
            } else {
                System.out.println("[Hilo Servidor] Mensaje seguro recibido desde el cliente: " + messageIn);
                // Procesamiento de datos en la Aplicacion
                String messageOut = messageIn.toUpperCase();
                System.out.println("[Hilo Servidor] Mensaje fue procesado exitosamente!");
                // escribir el mensaje de salida
                out.println(messageOut);
                System.out.println("[Hilo Servidor] Respuesta cifrada enviada al cliente");
            }
            // cierre seguro del protocolo
            System.out.println("[Hilo Servidor] Conexion segura con el cliente finalizada.");
        } catch (IOException ex) {
            System.getLogger(ClientHandler.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }
}
