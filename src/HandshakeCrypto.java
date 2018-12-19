import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    private static final String ALGORITHM_NAME = "RSA";

    public static byte[] encrypt(byte[] plainText, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error encrypting text - " + e.getMessage());
            return new byte[1];
        }
    }

    public static byte[] decrypt(byte[] cipherText, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error decrypting text - " + e.getMessage());
            return new byte[1];
        }
    }

    public static PublicKey getPublicKeyFromCertFile(String certFile) {
        X509Certificate certificate = null;
        try {
            certificate = VerifyCertificate.fetchCertificate(certFile);
        } catch (FileNotFoundException | CertificateException e) {
            System.out.println(e.getMessage());
        }
        return certificate == null ? null : certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKey(String keyFile) {
        Path path = Paths.get(keyFile);
        try {
            byte[] keyArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyArray);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME);
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error fetching private key from keyFile '" + keyFile + "': " + e.toString());
            return null;
        }
    }
}
