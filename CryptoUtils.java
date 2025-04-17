import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    public static byte[] aesEncriptar(byte[] plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext);
    }

    public static byte[] aesDesencriptar(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] calcularHMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

    public static boolean verificarHMAC(byte[] data, SecretKey key, byte[] expectedHMAC) throws Exception {
        byte[] hmac = calcularHMAC(data, key);
        return MessageDigest.isEqual(hmac, expectedHMAC);
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verificarSignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(publicKey);
        verificador.update(data);
        return verificador.verify(signatureBytes);
    }

    public static byte[] computeSHA512(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(data);
    }

    public static SecretKey[] deriveSessionKeys(byte[] digest) throws Exception {
        if (digest.length < 64) {
            throw new IllegalArgumentException("Digest must be at least 512 bits long.");
        }
        byte[] key1Bytes = Arrays.copyOfRange(digest, 0, 32);
        byte[] key2Bytes = Arrays.copyOfRange(digest, 32, 64);
        SecretKey keyEncriptada = new SecretKeySpec(key1Bytes, "AES");
        SecretKey keyHMAC = new SecretKeySpec(key2Bytes, "HmacSHA256");
        return new SecretKey[] { keyEncriptada, keyHMAC };
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static AlgorithmParameterSpec generarDHParameterSpec() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class); 
    }

    public static KeyPair generarDHKeyPair(DHParameterSpec dhSpec) throws Exception {
        // Generar un par de claves (clave pública y privada) para el algoritmo DH
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        return keyPairGen.generateKeyPair();
    }

    public static byte[] generarLlaveCompartida(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // Generar la clave compartida utilizando la clave privada y la clave pública del otro participante
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
}