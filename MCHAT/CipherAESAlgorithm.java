import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CipherAESAlgorithm extends CipherService{

    private static final short NONCE_SIZE = 16;
    public static final String AES = "AES";
    public String iv;
    private final int headerLength;
    public byte[] version;
    public byte[] magicNumber;
    private String mode;
    public CipherAESAlgorithm(String hmacKey, String cipherKey, String iv, String cipherAlgorithm,
                              String hmacAlgorithm, String hashAlgorithm, Long magicNumber) throws NoSuchPaddingException, NoSuchAlgorithmException {

        super();

        this.hmacAlgorithm = hmacAlgorithm;
        keyCipher = new SecretKeySpec(cipherKey.getBytes(), AES);
        mode = cipherAlgorithm.substring(4);
        this.iv = iv;
        this.version = Utils.toByteArray(Integer.toString(VERSION));
        this.magicNumber = Utils.toByteArray(Long.toString(magicNumber));
        keyMac = new SecretKeySpec(hmacKey.getBytes(), hmacAlgorithm);
        cipher = Cipher.getInstance(cipherAlgorithm);
        hash = MessageDigest.getInstance(hashAlgorithm);
        this.headerLength = hash.getDigestLength() + version.length + this.magicNumber.length;
        hmac =  Mac.getInstance(hmacAlgorithm);
    }

    public byte[] createSecureMessage(String username, byte[] message) throws IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException{

        // Initialization
        byte[] nonce = new byte[NONCE_SIZE];
        secureRandomGenerator.nextBytes(nonce);

        Object gcmParam = ModeService.getMode(mode, nonce, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keyCipher, (AlgorithmParameterSpec) gcmParam);
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


        Object gcmParam = ModeService.getMode(mode, nonce, iv);
        // Deciphered payload
        cipher.init(Cipher.DECRYPT_MODE, keyCipher, (AlgorithmParameterSpec) gcmParam);
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

    private Boolean macProofTest(byte[] macProof, byte[] header_payload) {
        byte[] macTest= hmac.doFinal(header_payload);

        return checkHashMacIsValid(macProof, macTest);
    }


    private Boolean replayAttackTest(DataInputStream result, byte[] nonce, byte[] hashProof) throws IOException {
        result.skipBytes(12);
        byte[] username = Utils.toByteArray(result.readUTF());
        byte[] hashTest = hash.digest(concatArrays(username, nonce));

        result.reset();
        return checkHashMacIsValid(hashTest, hashProof);
    }

    private boolean checkHashMacIsValid(byte[] arr1, byte[] arr2) {
        return Arrays.compare(arr1, arr2) == 0;
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

    private static int getConcatLength(byte[] ... arrays) {
        int length = 0;

        // Get length
        for (byte[] array : arrays) {
            length += array.length;
        }

        return length;
    }

}
