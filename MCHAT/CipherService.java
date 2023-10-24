import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

import static java.security.MessageDigest.getInstance;

public abstract class CipherService {
    public static int VERSION = 1;     // Represents school's work phase
    public final SecureRandom secureRandomGenerator;
    public SecretKey keyCipher;
    public SecretKey keyMac;

    public Mac hmac;
    public String hmacAlgorithm;
    public Cipher cipher;
    public MessageDigest hash;

    public CipherService() {
        secureRandomGenerator = new SecureRandom();
    }


    public abstract byte[] createSecureMessage(String username, byte[] message) throws IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException;

    public abstract DataInputStream decryptSecureMessage(DataInputStream stream) throws InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException;

}