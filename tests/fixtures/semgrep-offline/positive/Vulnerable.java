import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;

public class Vulnerable {
    void commandExecution(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); }
    Object unsafeDeserialization(ObjectInputStream ois) throws Exception { return ois.readObject(); }
    MessageDigest weakHash() throws Exception { return MessageDigest.getInstance("MD5"); }
    Cipher weakCipher() throws Exception { return Cipher.getInstance("AES/ECB/PKCS5Padding"); }
    Random predictable() { return new Random(); }
}
