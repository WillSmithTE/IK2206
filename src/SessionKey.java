import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static java.util.Base64.getEncoder;
import static java.util.Base64.getDecoder;

public class SessionKey {

    private static final String ALGORITHM_NAME = "AES";
    private static final int DEFAULT_KEY_LENGTH = 128;
    private SecretKey key;
    private KeyGenerator keyGenerator;

    public SessionKey(Integer keyLength) {
        try {
            keyGenerator = KeyGenerator.getInstance(ALGORITHM_NAME);
            keyGenerator.init(keyLength);
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        }

    }

    public SessionKey(String encodedKey) {
//        byte[] decodedKey = getDecoder().decode(encodedKey);
        key = new SecretKeySpec(encodedKey.getBytes(StandardCharsets.UTF_8), 0, encodedKey.length(), ALGORITHM_NAME);
    }

    public static void main(String[] args) {
        testCreateKeyFromEncodedKey();
        testIsSymmetrical();
        testKeyLength();
        testKeyRandomness();
    }

    public SecretKey getSecretKey() {
        return key;
    }

    public String encodeKey() {
        return new String(key.getEncoded());
    }

    private static void testKeyRandomness() {
        SessionKey sk1 = new SessionKey(DEFAULT_KEY_LENGTH);
        SessionKey sk2 = new SessionKey(DEFAULT_KEY_LENGTH);

        compareKeys(sk1, sk2);

    }

    private static void testIsSymmetrical() {
        final byte[] originalKey = "derp".getBytes();
        final String encodedKey = getEncoder().encodeToString(originalKey);
        SessionKey key = new SessionKey(encodedKey);

        final String afterEncodedKey = key.encodeKey();

        assert(afterEncodedKey.equals(encodedKey));



    }

    private static void testCreateKeyFromEncodedKey() {
        SessionKey key1 = new SessionKey(DEFAULT_KEY_LENGTH);
        SessionKey key2 = new SessionKey(key1.encodeKey());

        printPassOrFail(key1.getSecretKey().getEncoded().equals(key2.getSecretKey().getEncoded()), "key created from encoded key should equal key");
    }

    private static void testKeyLength() {
        final int EXPECTED_KEY_LENGTH = 16;

        SessionKey sk1 = new SessionKey(DEFAULT_KEY_LENGTH);

        checkKeyIsLength(sk1, EXPECTED_KEY_LENGTH);

        SessionKey sk2 = new SessionKey(getEncoder().encodeToString("derp".getBytes()));
        checkKeyIsLength(sk2, EXPECTED_KEY_LENGTH);
    }

    private static void compareKeys(SessionKey sk1, SessionKey sk2) {
        byte[] decoded1 = Base64.getDecoder().decode(sk1.encodeKey());
        byte[] decoded2 = Base64.getDecoder().decode(sk2.encodeKey());
        int keyLength = decoded1.length;
        int similarities = 0;

        for (int i = 0; i < keyLength; i++) {
            if (decoded1[i] == decoded2[i]) {
                similarities++;
            }
        }

        System.out.println("Keys are " + (similarities / keyLength) * 100 + "% similar!");
    }

    private static void checkKeyIsLength(SessionKey key, int test_key_length) {
        int keyLength = key.encodeKey().length();
        printPassOrFail(keyLength == test_key_length, "key length was " + keyLength + " instead of " + test_key_length);
    }

    private static void printPassOrFail(boolean isPass) {
        System.out.println(isPass ?
                "Pass" :
                "Fail");
    }


    private static void printPassOrFail(boolean isPass, String failMessage) {
        System.out.println(isPass ?
                "Pass" :
                "Fail: " + failMessage);

    }

}
