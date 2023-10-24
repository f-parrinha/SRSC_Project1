import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

public class CipherService {
    private static int VERSION = 1;     // Represents school's work phase
    private static String FILE_LOAD_ERROR = "ERROR WHILE LOADING SECURITY FILE";
    private static String FILE_PATH = "./security.conf";

    private String hmacKey;
    private String cipherKey;
    private String cipherAlgorithm;
    private String hmacAlgorithm;
    private String hashAlgorithm;

    public CipherService() {
        readSecurityFile();

        if (!checkFileReadCorrectly()) {
            System.out.println(FILE_LOAD_ERROR);
        }
    }



    public byte[] createSecureMessage(Long magicNumber, String username, String message) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        // Params
        SecureRandom random = new SecureRandom();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest hash = MessageDigest.getInstance("SHA256");
        Mac hmac =  Mac.getInstance("HmacSHA256");
        SecretKey keyCipher =  new SecretKeySpec(cipherKey.getBytes(), "AES");
        SecretKey keyMac = new SecretKeySpec(hmacKey.getBytes(), "HmacSHA256");
        GCMParameterSpec gcmParam = Utils.createGcmIvForAes(128, 1, random);

        // Initialization
        cipher.init(Cipher.ENCRYPT_MODE, keyCipher, gcmParam);
        hmac.init(keyMac);
        String hashedUser = Arrays.toString(hash.digest(Utils.toByteArray(username)));

        // Message creation
        String controlHeader = Integer.toString(VERSION).concat(Long.toString(magicNumber)).concat(hashedUser);
        String chatMessagePayload = Arrays.toString(cipher.doFinal(Utils.toByteArray(random.toString().concat(message))));
        String macProof = Arrays.toString(hmac.doFinal(Utils.toByteArray(controlHeader.concat(chatMessagePayload))));
        String finalMessage = controlHeader.concat(chatMessagePayload).concat(macProof);

        System.out.println("SECURE MESSAGE TEST: " + finalMessage);
        return finalMessage.getBytes();
    }


    /** Reads security.conf file to get security params */
    private void readSecurityFile() {
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
    }

    private Boolean checkFileReadCorrectly () {
        return hmacKey != null && cipherKey != null && cipherAlgorithm != null && hmacAlgorithm != null && hashAlgorithm != null;
    }

}