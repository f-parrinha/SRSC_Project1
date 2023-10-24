import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

import static java.security.MessageDigest.getInstance;

public class CipherService {
    private static int VERSION = 1;     // Represents school's work phase
    private static String FILE_LOAD_ERROR = "ERROR WHILE LOADING SECURITY FILE";
    private static String FILE_PATH = "./security.conf";

    private String hmacKey;
    private String cipherKey;
    private String cipherAlgorithm;
    private String hmacAlgorithm;
    private String hashAlgorithm;
    private final SecureRandom secureRandomGenerator;
    private final SecretKey keyCipher;
    private final SecretKey keyMac;
    private final Cipher cipher;
    private final MessageDigest hash;

    public CipherService() throws NoSuchPaddingException, NoSuchAlgorithmException {
        // Load security file
        readSecurityFile();

        if (!checkFileReadCorrectly()) {
            System.out.println(FILE_LOAD_ERROR);
        }

        secureRandomGenerator = new SecureRandom();
        keyCipher =  new SecretKeySpec(cipherKey.getBytes(), "AES");
        keyMac = new SecretKeySpec(hmacKey.getBytes(), "HmacSHA256");
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        hash = MessageDigest.getInstance("SHA256");
    }

    public byte[] createSecureMessage(Long magicNumber, String username, String message) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        // Params
        GCMParameterSpec gcmParam = createGcmIvForAes(128, 1, secureRandomGenerator);

        Mac hmac =  Mac.getInstance("HmacSHA256");

        // Initialization
        cipher.init(Cipher.ENCRYPT_MODE, keyCipher, gcmParam);
        hmac.init(keyMac);
        byte[] hashedUser = hash.digest(Utils.toByteArray(username));

        // Message creation
        System.out.println("CONTROL HEADER");
        byte[] controlHeader = concatArrays(Utils.toByteArray(Integer.toString(VERSION).concat(Long.toString(magicNumber))), hashedUser);
        System.out.println("\nMEESSAGE PAYLOAD");
        byte[] chatMessagePayload = cipher.doFinal(Utils.toByteArray(secureRandomGenerator.toString().concat(message)));
        System.out.println("\nMAC PROOF");
        byte[] macProof = hmac.doFinal(concatArrays(controlHeader, chatMessagePayload));
        return concatArrays(controlHeader, chatMessagePayload, macProof);
    }

    /**
     * Creates an IV for a cipher with AES with GCM mode
     * @param tagLen tag length
     * @param messageNumber number of message to reduce the probability of generating the same IV
     * @param random random number generator
     * @return IV for AES with GCM mode
     */
    private static GCMParameterSpec createGcmIvForAes(int tagLen, int messageNumber, SecureRandom random) {
        byte[] ivBytes = new byte[12];
        random.nextBytes(ivBytes);

        // set the message number bytes
        ivBytes[0] = (byte) (messageNumber >> 24);
        ivBytes[1] = (byte) (messageNumber >> 16);
        ivBytes[2] = (byte) (messageNumber >> 8);
        ivBytes[3] = (byte) (messageNumber >> 0);

        // set the counter bytes to 1
        for (int i = 0; i != 3; i++) {
            ivBytes[8 + i] = 0;
        }

        ivBytes[11] = 1;    // start at one
        return new GCMParameterSpec(tagLen, ivBytes);
    }

    /**
     * Concats multiple byte arrays into a single one
     * @param arrays set of byte arrays
     * @return concatenated array
     */
    public static byte[] concatArrays(byte[] ... arrays) {
        byte[] result = new byte[getConcatLength(arrays)];
        int counter = 0;

        for (byte[]array : arrays){
            System.out.println("ARRAY: " + Arrays.toString(array));
            for (byte b : array) {
                result[counter++] = b;
            }
        }
        System.out.println("RESULT: " + Arrays.toString(result));
        return result;
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

                SecurityVariablesAssigner(paramName, paramValue);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void SecurityVariablesAssigner(String paramName, String paramValue) {
        switch (paramName) {
            case "CONFIDENTIALITY" -> cipherAlgorithm = paramValue;
            case "CONFIDENTIALITY-KEY" -> cipherKey = paramValue;
            case "HASHFORNICKNAMES" -> hashAlgorithm = paramValue;
            case "MACKEY" -> hmacKey = paramValue;
            case "MACALGORITHM" -> hmacAlgorithm = paramValue;
            default -> {
                System.out.println("ERROR: Could not read the write security variable from the security file.");;
            }
        }
    }

    private static int getConcatLength(byte[] ... arrays) {
        int length = 0;

        // Get length
        for (byte[] array : arrays) {
            length += array.length;
        }

        return length;
    }

    private Boolean checkFileReadCorrectly () {
        return hmacKey != null && cipherKey != null && cipherAlgorithm != null && hmacAlgorithm != null && hashAlgorithm != null;
    }
}