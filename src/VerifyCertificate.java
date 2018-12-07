import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifyCertificate {

    private static final String CERT_FACTORY_NAME = "X.509";

    public static void main(String[] args) {
        String filenameCA = args[0];
        String filenameUser = args[1];
        try {
            X509Certificate certCA = fetchCertificate(filenameCA);
            X509Certificate certUser = fetchCertificate(filenameUser);
            System.out.println("DN for CA: " + certCA.getSubjectDN());
            System.out.println("DN for User: " + certUser.getSubjectDN());
            PublicKey publicKeyCA = certCA.getPublicKey();
            verifyCertificate(certCA, publicKeyCA);
            verifyCertificate(certUser, publicKeyCA);
            System.out.println("Pass");
        } catch (FileNotFoundException | CertificateException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Fail: " + e.getMessage());
        }
    }

    private static X509Certificate fetchCertificate(String filename) throws FileNotFoundException, CertificateException {
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        CertificateFactory factory = CertificateFactory.getInstance(CERT_FACTORY_NAME);
        Certificate cert = factory.generateCertificate(bufferedInputStream);
        return (X509Certificate) cert;
    }

    private static void verifyCertificate(X509Certificate cert, PublicKey publicKey) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        cert.checkValidity();
        cert.verify(publicKey);
    }
}
