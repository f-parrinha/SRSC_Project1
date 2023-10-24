import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public abstract class ModeService {

    public static Object getMode(String mode, int messageNumber, SecureRandom random) {
        switch(mode) {
            case "GCM/NoPadding":
                return createGcmIvForAes(messageNumber, random);
            default:
                System.out.println();
                return null;
        }
    }
    /**
     * Creates an IV for a cipher with AES with GCM mode
     * @param messageNumber number of message to reduce the probability of generating the same IV
     * @param random random number generator
     * @return IV for AES with GCM mode
     */
    private static GCMParameterSpec createGcmIvForAes(int messageNumber, SecureRandom random) {
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
        return new GCMParameterSpec(128, ivBytes);
    }
}
