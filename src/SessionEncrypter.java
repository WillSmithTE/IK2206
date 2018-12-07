import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {

    static final String CIPHER_NAME = "AES/CBC/PKCS5PADDING";

    private SessionKey key;
    private Cipher cipher;
    private byte[] iv;

    public SessionEncrypter(Integer keyLength) {
        key = new SessionKey(keyLength);
        SecureRandom sr = new SecureRandom();
        try {
            iv = new byte[keyLength];
            sr.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), ivSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            System.out.println("Error generation SessionEncrypter: " + e.getMessage());
        }
    }

    String encodeKey() {
        return key.encodeKey();
    }

    String encodeIV() {
        return Base64.getEncoder().encodeToString(iv);
    }

    CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, cipher);
    }
}
