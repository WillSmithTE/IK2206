import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter {

    private Cipher cipher;

    public SessionDecrypter(String key, String iv) {
        SessionKey sessionKey = new SessionKey(key);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        try {
            cipher = Cipher.getInstance(SessionEncrypter.CIPHER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    CipherInputStream openCipherInputStream(InputStream input) {
        return new CipherInputStream(input, cipher);
    }
}
