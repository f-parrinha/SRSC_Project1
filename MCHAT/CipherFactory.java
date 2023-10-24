import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class CipherFactory {
    public static String FILE_PATH = "security.conf";
    public static String FILE_LOAD_ERROR = "ERROR WHILE LOADING SECURITY FILE";
    public static final String AES = "AES";
    public static final String BLOWFISH = "Blowfish";
    public static final String RC6 = "RC6";
    public static final String RC4 = "RC4";
    public static final String CHACHA_20 = "CHACHA-20";
    private String cipherAlg;
    private String hmacKey;
    private String iv;
    private String cipherKey;
    private String cipherAlgorithm;
    private String hmacAlgorithm;
    private String hashAlgorithm;

    /**
     * Reads security.conf file to get security params
     */

    public CipherFactory() {
        readSecurityFile();

        if (!checkFileReadCorrectly())
            System.out.println(FILE_LOAD_ERROR);

        cipherAlg = cipherAlgorithm.split("/")[0];
    }

    public CipherService getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        CipherService service = null;
        switch (cipherAlg) {
            case AES:
                service = new CipherAESAlgorithm(hmacKey, cipherKey, iv, cipherAlgorithm, hmacAlgorithm, hashAlgorithm);
                break;
            case BLOWFISH:
                break;
            case RC4:
                break;
            case RC6:
                break;
            case CHACHA_20:
                break;
            default:
                break;
        }
        return service;
    }

    private void readSecurityFile() {
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
            String line;

            // Reads every line
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                System.out.println("line");
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
            System.out.println("error");
            throw new RuntimeException(e);
        }
    }

    private void SecurityVariablesAssigner(String paramName, String paramValue) {
        switch (paramName) {
            case "CONFIDENTIALITY" -> cipherAlgorithm = paramValue;
            case "CONFIDENTIALITY-KEY" -> cipherKey = paramValue;
            case "IV" -> iv = paramValue;
            case "HASHFORNICKNAMES" -> hashAlgorithm = paramValue;
            case "MACKEY" -> hmacKey = paramValue;
            case "MACALGORITHM" -> hmacAlgorithm = getHmacAlgorithm(paramValue);
            default -> {
                System.out.println("ERROR: Could not read the write security variable from the security file.");
                ;
            }
        }
    }

    private String getHmacAlgorithm(String hmac) {
        String result = "";
        switch (hmac){
            case "HMAC-SHA256":
                result = "HmacSHA256";
                break;
            case "HMAC-SHA384":
                result = "HmacSHA384";
                break;
            case "HMAC-SHA512":
                result = "HmacSHA512";
                break;
            default:
                System.out.println();
                break;
        }
        return result;
    }

    private Boolean checkFileReadCorrectly() {
        return hmacKey != null && cipherKey != null && cipherAlgorithm != null && hmacAlgorithm != null && hashAlgorithm != null;
    }
}
