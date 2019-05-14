package im.status.ethereum.keycard;

import android.support.annotation.NonNull;
import android.util.Base64;

import org.apache.commons.lang3.RandomStringUtils;

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

    @NonNull
    public static SmartCardSecrets generate(final String userPin) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pairingPassword = randomToken(16);
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
        char[] possibleCharacters = "23456789ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
        String randomStr = RandomStringUtils.random(length, 0, possibleCharacters.length-1, false, false, possibleCharacters, new SecureRandom());
        return randomStr;
    }

    public static byte[] randomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte data[] = new byte[length];
        random.nextBytes(data);

        return data;
    }
}
