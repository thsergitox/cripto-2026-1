/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.pqc;

import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Ing. Ronald Martinez <rmartinezch@uni.edu.pe>
 */
public class ProviderConfig {
    public static void initialize(){
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Providers: " + Arrays.toString(Security.getProviders()));
    }
}
