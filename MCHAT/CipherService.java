import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;

public class CipherService {
    private static int VERSION = 1;     // Represents school's work phase
    private static String FILE_PATH = "./security.conf";

    private String hmacKey;
    private String cipherKey;
    private String cipherAlgorithm;
    private String hmacAlgorithm;
    private String hashAlgorithm;


    /** Reads security.conf file to get security params */
    public void readSecurityFile() {
        try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
            String line;

            // Reads every line
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");

                // Check file validity (only has two sides, if less or more, corrupt)
                if (parts.length != 2) {
                    return;
                }

                // Assign values
                String paramName = parts[0].trim();
                String paramValue = parts[1].trim();

                switch (paramName) {
                    case "CONFIDENTIALITY":
                        cipherAlgorithm = paramValue;
                        break;
                    case "CONFIDENTIALITY-KEY":
                        cipherKey = paramValue;
                        break;
                    case "HASHFORNICKNAMES":
                        hashAlgorithm = paramValue;
                        break;
                    case "MACKEY":
                        hmacKey = paramValue;
                        break;
                    case "MACALGORITHM":
                        hmacAlgorithm = paramValue;
                        break;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Now you have the parameters stored in their respective variables
        System.out.println("CONFIDENTIALITY: " + cipherAlgorithm);
        System.out.println("CONFIDENTIALITY_KEY: " + cipherKey);
        System.out.println("HASHFORNICKNAMES: " + hashAlgorithm);
        System.out.println("MACKEY: " + hmacKey);
        System.out.println("MACALGORITHM: " + hmacAlgorithm);
    }

    // TODO convert to bytes instead of string
    public byte[] createMessage(Long magicNumber, String username, String message) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        // Params
        SecureRandom random = new SecureRandom();
        SecretKey key =  Utils.createKeyForAES(256, random);

        // Cipher
        IvParameterSpec iv =  Utils.createCtrIvForAES(1 , random);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        // Hashing
        MessageDigest hash = MessageDigest.getInstance("SHA256");
        String hashedUser = hash.digest(Utils.toByteArray(username)).toString();

        // Mac
        Mac hmac =  Mac.getInstance("HMAC-SHA256");


        // Message creation
        String controlHeader = Integer.toString(VERSION).concat(Long.toString(magicNumber)).concat(hashedUser);
        String chatMessagePayload = cipher.doFinal(Utils.toByteArray(random.toString().concat(message))).toString();
        String macProof = hmac.doFinal(Utils.toByteArray(controlHeader.concat(chatMessagePayload))).toString();

        return controlHeader.concat(chatMessagePayload).concat(macProof).getBytes();
    }
}