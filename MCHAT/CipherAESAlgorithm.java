import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CipherAESAlgorithm extends CipherService{

    public static final String AES = "AES";
    public String iv;
    private String mode;
    public CipherAESAlgorithm(String hmacKey, String cipherKey, String iv, String cipherAlgorithm,
                              String hmacAlgorithm, String hashAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {

        super();
        this.hmacAlgorithm = hmacAlgorithm;
        keyCipher = new SecretKeySpec(cipherKey.getBytes(), AES);
        mode = cipherAlgorithm.substring(4);
        this.iv = iv;
        keyMac = new SecretKeySpec(hmacKey.getBytes(), hmacAlgorithm);
        cipher = Cipher.getInstance(cipherAlgorithm);
        hash = MessageDigest.getInstance(hashAlgorithm);
    }


    @Override
    public byte[] createSecureMessage(long magicNumber, String username, String message) throws
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {

        // Params
        Object gcmParam = ModeService.getMode(mode, 1,secureRandomGenerator);

        Mac hmac =  Mac.getInstance(hmacAlgorithm);

        // Initialization
        cipher.init(Cipher.ENCRYPT_MODE, keyCipher, (AlgorithmParameterSpec) gcmParam);
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
