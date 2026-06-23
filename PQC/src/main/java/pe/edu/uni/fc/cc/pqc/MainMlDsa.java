/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pqc;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import static pe.edu.uni.fc.cc.common.Constants.BC_PROVIDER;
import static pe.edu.uni.fc.cc.common.Constants.ML_DSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_ALGORITHM;
import static pe.edu.uni.fc.cc.common.Constants.RSA_KEY_SIZE_3072;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class MainMlDsa {

    public static void main(String[] args) {
        // corrección de configuración UTF-8
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.out.println("Main ML DSA!");
        ProviderConfig.initialize();

        // Datos a firmar
        String document = "Criptografía Post Cuántica !!!";
        byte[] data = document.getBytes();

        // servicios
        KeyGenerator generator;
        Signer signer;
        Verifier verifier;
        // inicializar servicios
        generator = new KeyGenerator(BC_PROVIDER);
        signer = new Signer(BC_PROVIDER);
        verifier = new Verifier(BC_PROVIDER);

        // generación de llaves ML-DSA
        // parámetro ML DSA
        AlgorithmParameterSpec ml_dsa_parameter = MLDSAParameterSpec.ml_dsa_44;
        // parámetro RSA
        AlgorithmParameterSpec rsa_parameter = new RSAKeyGenParameterSpec(RSA_KEY_SIZE_3072, RSAKeyGenParameterSpec.F4);
        // generación ML DSA
        long t1 = System.nanoTime();
        KeyPair ml_dsa_kp = generator.generate(ML_DSA_ALGORITHM, ml_dsa_parameter);
        long t2 = System.nanoTime();
        double dt_ml_dsa = (t2 - t1) / 1_000_000.0;
        System.out.println("El par de llaves ML-DSA es generado exitosamente!");

        // Generación RSA
        long t3 = System.nanoTime();
        KeyPair rsa_kp = generator.generate(RSA_ALGORITHM, rsa_parameter);
        long t4 = System.nanoTime();
        double dt_rsa = (t4 - t3) / 1_000_000.0;

        // firmar el dato ML DSA
        byte[] ml_dsa_siganture = signer.sign(ML_DSA_ALGORITHM, data, ml_dsa_kp.getPrivate());
        // firmar el dato RSA
        byte[] rsa_signature = signer.sign(RSA_ALGORITHM, data, rsa_kp.getPrivate());
        // verificar la firma del dato ML DSA
        boolean ml_dsa_validity = verifier.verify(ML_DSA_ALGORITHM, data, ml_dsa_siganture, ml_dsa_kp.getPublic());
        // verificar la firma del dato RSA
        boolean rsa_validity = verifier.verify(RSA_ALGORITHM, data, rsa_signature, rsa_kp.getPublic());
        // resultados
        System.out.println("Datos a ser firmado: " + document);
        System.out.println("[ML-DSA] Firma validada: " + ml_dsa_validity);
        System.out.println("[RSA] Firma validada: " + rsa_validity);
        // benchmarking
        System.out.printf("%-30s %-18s %-18s%n", "Métrica", "ML-DSA-44", "RSA-3072");
        System.out.println("------------------------------------------------------------");
        System.out.printf("%-30s %-18.4f %-18.4f%n", "Gen llaves (ms)", dt_ml_dsa, dt_rsa);
        System.out.printf("%-30s %-18d %-18d%n", "Tam Llave privada (bytes)", ml_dsa_kp.getPrivate().getEncoded().length, rsa_kp.getPrivate().getEncoded().length);
        System.out.printf("%-30s %-18d %-18d%n", "Tam Llave pública (bytes)", ml_dsa_kp.getPublic().getEncoded().length, rsa_kp.getPublic().getEncoded().length);
        System.out.printf("%-30s %-18d %-18d%n", "Tam firma (bytes)", ml_dsa_siganture.length, rsa_signature.length);
        System.out.println("============================================================");
    }
}
