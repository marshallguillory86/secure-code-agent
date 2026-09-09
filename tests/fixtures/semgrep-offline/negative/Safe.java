import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public class Safe {
    void commandWithArgv(String arg) throws Exception {
        new ProcessBuilder(new String[] {"/usr/bin/git", "status", arg}).start();
    }
    MessageDigest strongHash() throws Exception { return MessageDigest.getInstance("SHA-256"); }
    Cipher strongCipher() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    SecureRandom unpredictable() { return new SecureRandom(); }
}
