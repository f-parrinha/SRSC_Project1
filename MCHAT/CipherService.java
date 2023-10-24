import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

/**
 * @author Francisco Parrinha   58360
 * @author Martin Magdalinchev  58172
 *
 * Adds the possibility to cypher and decypher using AES with GCM mode and with no padding
 *
 * NTOE: IV is sent through the encrypted payload
 */
public class CipherService {

    /** Constants */
    private static final int VERSION = 1;
    private static final String FILE_LOAD_ERROR = "ERROR WHILE LOADING SECURITY FILE";
    private static final String FILE_PATH = "./security.conf";
    private static final short NONCE_SIZE = 16;             // In bytes. In bits is 128
    private static final short TAG_SIZE = 128;              // Bits


    /** Variables */
    private final int headerLength;
    private final byte[] version;
    private final byte[] magicNumber;
    private final SecureRandom secureRandomGenerator;
    private final SecretKey keyCipher;
    private final SecretKey keyMac;
    private final Cipher cipher;
    private final MessageDigest hash;
    private final Mac hmac;
    private String hmacKey;
    private String cipherKey;
    private String cipherAlgorithm;
    private String hmacAlgorithm;
    private String hashAlgorithm;


    public CipherService(long magicNumber) throws NoSuchPaddingException, NoSuchAlgorithmException {
        // Load security file
        readSecurityFile();

        if (!checkFileReadCorrectly()) {
            System.out.println(FILE_LOAD_ERROR);
        }

        // Init variables
        this.secureRandomGenerator = new SecureRandom();
        this.keyCipher =  new SecretKeySpec(cipherKey.getBytes(), "AES");
        this.keyMac = new SecretKeySpec(hmacKey.getBytes(), "HmacSHA256");
        this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
        this.hash = MessageDigest.getInstance("SHA256");
        this.hmac =  Mac.getInstance("HmacSHA256");
        this.version = Utils.toByteArray(Integer.toString(VERSION));
        this.magicNumber = Utils.toByteArray(Long.toString(magicNumber));
        this.headerLength = hash.getDigestLength() + version.length + this.magicNumber.length;
    }

    public byte[] createSecureMessage(String username, byte[] message) throws IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        // Initialization
        byte[] nonce = new byte[NONCE_SIZE];
        secureRandomGenerator.nextBytes(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keyCipher, createGcmIvForAes(nonce));
        hmac.init(keyMac);

        // Message creation
        byte[] hashedUser = hash.digest(concatArrays(Utils.toByteArray(username), nonce));
        byte[] controlHeader = concatArrays(version, magicNumber, hashedUser);
        byte[] chatMessagePayload = concatArrays(nonce, cipher.doFinal(message));
        byte[] macProof = hmac.doFinal(concatArrays(controlHeader, chatMessagePayload));

        return concatArrays(controlHeader, chatMessagePayload, macProof);
    }

    /**
     * Decrypts a secure message from the current protocol
     * @param stream stream of data sent on the channel containing the message
     * @return input stream to read the message data
     */
    public DataInputStream decryptSecureMessage(DataInputStream stream) throws InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException {

        // Data setup and message division
        byte[] data = stream.readAllBytes();
        byte[] header_payload = Arrays.copyOfRange(data, 0, data.length - hmac.getMacLength());
        byte[] payload = Arrays.copyOfRange(header_payload, headerLength, header_payload.length);
        byte[] macProof = Arrays.copyOfRange(data, data.length - hmac.getMacLength(), data.length);
        byte[] hashProof = Arrays.copyOfRange(data, headerLength - hash.getDigestLength() , headerLength);
        byte[] nonce = Arrays.copyOfRange(payload,0, NONCE_SIZE);
        byte[] cipheredMessage = Arrays.copyOfRange(payload, NONCE_SIZE, payload.length);

        // Deciphered payload
        cipher.init(Cipher.DECRYPT_MODE, keyCipher, createGcmIvForAes(nonce));
        hmac.init(keyMac);

        byte[] deciphered = cipher.doFinal(cipheredMessage);
        byte[] message = Arrays.copyOfRange(deciphered, 0, deciphered.length);
        DataInputStream result = new DataInputStream(new ByteArrayInputStream(message));

        // Test MAC proof. Authenticity.
        if (!macProofTest(macProof, header_payload)) {
            System.out.println("SECURITY BREACH: MACs ARE NOT THE SAME. DATA HAS BEEN TEMPERED!");
            return null;
        }

        // Test replay attack
        if (!replayAttackTest(result, nonce, hashProof)) {
            System.out.println("SECURITY BREACH: USER AND NONCE ARE NOT THE SAME. POSSIBLE REPLAY ATTACK");
            return null;
        }

        return result;
    }



    /**
     * Creates an IV for a cipher with AES with GCM mode
     * @return IV for AES with GCM mode
     */
    private static GCMParameterSpec createGcmIvForAes (byte[] nonce) {
        byte[] ivBytes = Arrays.copyOf(nonce, 12);

        return new GCMParameterSpec(TAG_SIZE, ivBytes);
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
            for (byte b : array) {
                result[counter++] = b;
            }
        }

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

    private Boolean replayAttackTest(DataInputStream result, byte[] nonce, byte[] hashProof) throws IOException {
        result.skipBytes(12);

        byte[] username = Utils.toByteArray(result.readUTF());
        byte[] hashTest = hash.digest(concatArrays(username, nonce));

        result.reset();
        return checkHashMacIsValid(hashTest, hashProof);
    }

    private Boolean macProofTest(byte[] macProof, byte[] header_payload) {
        byte[] macTest= hmac.doFinal(header_payload);

        return checkHashMacIsValid(macProof, macTest);
    }

    private boolean checkHashMacIsValid(byte[] arr1, byte[] arr2) {
        return Arrays.compare(arr1, arr2) == 0;
    }

    private Boolean checkFileReadCorrectly () {
        return hmacKey != null && cipherKey != null && cipherAlgorithm != null && hmacAlgorithm != null && hashAlgorithm != null;
    }
}