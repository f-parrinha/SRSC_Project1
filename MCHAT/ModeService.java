import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public abstract class ModeService {

    private static final short TAG_SIZE = 128;
    public static Object getMode(String mode, byte[] nonce, String iv) {
        switch(mode) {
            case "GCM/NoPadding":
                System.out.println("----------------------GCM Mode----------------");
                return createGcmIvForAes(nonce);
            case "CTR/NoPadding":
                System.out.println("----------------------CTR Mode----------------");
                return hexToIvParameterSpec(iv);
            case "CBC/PKCS5Padding":
                System.out.println("----------------------CBC Mode----------------");
                return hexToIvParameterSpec(iv);
            default:
                System.out.println();
                return null;
        }
    }

    /**
     * Creates an IV for a cipher with AES with GCM mode
     * @return IV for AES with GCM mode
     */
    private static GCMParameterSpec createGcmIvForAes (byte[] nonce) {
        byte[] ivBytes = Arrays.copyOf(nonce, 12);

        return new GCMParameterSpec(TAG_SIZE, ivBytes);
    }

    public static IvParameterSpec hexToIvParameterSpec(String hexIV) {
        try {
            // Convert the hexadecimal string to a byte array
            byte[] ivBytes = hexStringToByteArray(hexIV);

            // Create an IvParameterSpec object using the byte array
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            return ivParameterSpec;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Helper method to convert a hexadecimal string to a byte array
    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
