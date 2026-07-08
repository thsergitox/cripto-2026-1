/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pe.edu.uni.fc.cc.common;

/**
 *
 * @author JUAN
 */
public class Constants {
     public static final int ALPHABET_SET_SIZE = 26;
     public static final String AES_ALGORITHM = "AES";
     public static final String RSA_ALGORITHM = "RSA";
     public static final String TRANSFORMATION_AES_CBC = "AES/CBC/PKCS5Padding";
     public static final String TRANSFORMATION_AES_GCM = "AES/GCM/NoPadding";
     public static final String TRANSFORMATION_RSA = "RSA/ECB/PKCS1Padding";
     public static final String SHA_256_ALGORITHM = "SHA-256";
     public static final String PBKDF2_WITH_HMAC_SHA_256_ALGORITHM = "PBKDF2WithHmacSHA256";
     public static final byte[] AES_GCM_ADD = "2026-I-CC".getBytes();

     public static final int AES_CBC_IV_LENGTH = 16;
     public static final int AES_GCM_IV_LENGTH = 12;
     public static final int RSA_KEY_SIZE_2048 = 2048;
     public static final int RSA_KEY_SIZE_3072 = 3072;


     public static final String ECC_ALGORITHM = "EC"; // Qué tipo de llave voy a usar (ALGORITMO PARA LA LLAVE)
     public static final String ECC_KEY_PARAM = "secp256r1";
     public static final String ECC_SIGN_ALGORITHM = "SHA256withECDSA"; // ALGORITMO PARA FIRMA
     public static final String RSA_SIGN_ALGORITHM = "SHA256WithRSA";

     public static final int TAG_LENGTH = 128;

     public static final String BC_PROVIDER = "BC";
     public static final String ML_DSA_ALGORITHM = "MLDSA";

     // ===== PKI =====
     public static final String BCFIPS_PROVIDER = "BCFIPS";
     public static final String SUNPKCS11_PROVIDER = "SunPKCS11";
     public static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
     public static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
     public static final String CA_ROOT_CONTAINER_FILENAME = "ca-root.p12";
     public static final String CA_ROOT_ALIAS = "ca-root";
     public static final String END_USER_ALIAS = "end-user";
     public static final String USER_CD_FILENAME = "user-cd.cer";
     public static final String USER_CD_FILENAME2 = "user-cd2.cer";

     // ===== TLS =====
     public static final String TLS_VERSION_1_3 = "TLSv1.3";
     public static final int TLS_PORT = 8443;
     public static final String SERVER_TLS_FILENAME = "server-tls.p12";
     public static final String CLIENT_TLS_FILENAME = "client-tls.p12";
     public static final String SERVER_TLS_ALIAS = "server-tls";
     public static final String CLIENT_TLS_ALIAS = "client-tls";
     public static final String KEY_USE_PASSWORD = "key-use-password";
}
