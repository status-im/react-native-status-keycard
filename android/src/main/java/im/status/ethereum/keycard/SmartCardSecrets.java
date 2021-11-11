package im.status.ethereum.keycard;

import android.util.Base64;

import static android.util.Base64.NO_PADDING;
import static android.util.Base64.NO_WRAP;

import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class SmartCardSecrets {
    public static long PIN_BOUND = 999999L;
    public static long PUK_BOUND = 999999999999L;

    private String pin;
    private String puk;
    private String pairingPassword;

    public SmartCardSecrets(String pin, String puk, String pairingPassword) {
        this.pin = pin;
        this.puk = puk;
        this.pairingPassword = pairingPassword;
    }

    public static SmartCardSecrets generate(final String userPin) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pairingPassword = "KeycardDefaultPairing";
        long pinNumber = randomLong(PIN_BOUND);
        long pukNumber = randomLong(PUK_BOUND);

        String pin;
        if (userPin.isEmpty()) {
            pin = String.format("%06d", pinNumber);
        } else {
            pin = userPin;
        }

        String puk = String.format("%012d", pukNumber);

        return new SmartCardSecrets(pin, puk, pairingPassword);
    }

    public String getPin() {
        return pin;
    }

    public String getPuk() {
        return puk;
    }

    public String getPairingPassword() {
        return pairingPassword;
    }

    public static long randomLong(long bound) {
        SecureRandom random = new SecureRandom();
        return Math.abs(random.nextLong()) % bound;
    }

    public static String randomToken(int length) {
        SecureRandom random = new SecureRandom();
        char[] possibleCharacters = "abcdefghijkmnpqrstuvwxyz".toCharArray();
        char[] possibleDigits = "23456789".toCharArray();
        StringBuffer buffer = new StringBuffer(length);

        for (int i = 0; i < length; i++) {
            char[] src = (i % 2) == 0 ? possibleCharacters : possibleDigits;
            int idx = random.nextInt(src.length);
            buffer.append(src[idx]);
        }

        return buffer.toString();
    }

    public static byte[] randomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte data[] = new byte[length];
        random.nextBytes(data);

        return data;
    }
}
