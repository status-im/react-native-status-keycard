package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.res.AssetManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.support.annotation.Nullable;
import android.util.EventLog;
import android.util.Log;

import com.facebook.react.bridge.*;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import im.status.keycard.applet.RecoverableSignature;
import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.CardChannel;
import im.status.keycard.io.CardListener;
import im.status.keycard.android.NFCCardManager;
import im.status.keycard.applet.ApplicationStatus;
import im.status.keycard.applet.BIP32KeyPair;
import im.status.keycard.applet.Mnemonic;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.applet.Pairing;
import im.status.keycard.applet.ApplicationInfo;
import im.status.keycard.applet.KeyPath;

import org.spongycastle.util.encoders.Hex;

public class SmartCard extends BroadcastReceiver implements CardListener {
    private NFCCardManager cardManager;
    private Activity activity;
    private ReactContext reactContext;
    private NfcAdapter nfcAdapter;
    private CardChannel cardChannel;
    private EventEmitter eventEmitter;
    private static final String TAG = "SmartCard";
    private Boolean started = false;

    private static final String WALLET_PATH = "m/44'/60'/0'/0/0";
    private static final String WHISPER_PATH = "m/43'/60'/1581'/0'/0";
    private static final String ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";

    public SmartCard(Activity activity, ReactContext reactContext) {
        this.cardManager = new NFCCardManager();
        this.cardManager.setCardListener(this);
        this.activity = activity;
        this.reactContext = reactContext;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(activity.getBaseContext());
        this.eventEmitter = new EventEmitter(reactContext);
    }

    public String getName() {
        return "SmartCard";
    }

    public void log(String s) {
        Log.d(TAG, s);
    }

    public boolean start() {
        if (!started) {

            this.cardManager.start();
            started = true;

            if (this.nfcAdapter != null) {
                IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED);
                activity.registerReceiver(this, filter);
                nfcAdapter.enableReaderMode(activity, this.cardManager, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
                return true;
            } else {
                log("not support in this device");
                return false;
            }
        } else {
            return true;
        }
    }

    @Override
    public void onConnected(final CardChannel channel) {
        this.cardChannel = channel;
        eventEmitter.emit("keyCardOnConnected", null);
    }

    @Override
    public void onDisconnected() {
        eventEmitter.emit("keyCardOnDisconnected", null);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        final int state = intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF);
        boolean on = false;
        switch (state) {
            case NfcAdapter.STATE_ON:
                log("NFC ON");
            case NfcAdapter.STATE_OFF:
                log("NFC OFF");
            default:
                log("other");
        }
    }

    public boolean isNfcSupported() {
        return activity.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC);
    }

    public boolean isNfcEnabled() {
        if (nfcAdapter != null) {
            return nfcAdapter.isEnabled();
        } else {
            return false;
        }
    }

    public SmartCardSecrets init(final String userPin) throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        eventEmitter.emit("keycardInstallationProgress", 0.90);

        SmartCardSecrets s = SmartCardSecrets.generate(userPin);

        eventEmitter.emit("keycardInstallationProgress", 0.93);

        cmdSet.init(s.getPin(), s.getPuk(), s.getPairingPassword()).checkOK();

        eventEmitter.emit("keycardInstallationProgress", 1.0);

        return s;
    }

    public String pair(String pairingPassword) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        Log.i(TAG, "Applet selection successful");

        // First thing to do is selecting the applet on the card.
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());
        Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
        Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
        Log.i(TAG, "Application version: " + info.getAppVersionString());
        Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

        cmdSet.autoPair(pairingPassword);

        Pairing pairing = cmdSet.getPairing();

        return pairing.toBase64();
    }

    public String generateMnemonic(String pairingBase64) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        Mnemonic mnemonic = new Mnemonic(cmdSet.generateMnemonic(KeycardCommandSet.GENERATE_MNEMONIC_12_WORDS).checkOK().getData());
        mnemonic.fetchBIP39EnglishWordlist();

        return mnemonic.toMnemonicPhrase();
    }

    public void saveMnemonic(String mnemonic, String pairingBase64, String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        cmdSet.loadKey(seed);

        log("seed loaded to card");
    }

    public WritableMap getApplicationInfo(final String pairingBase64) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        Log.i(TAG, "Card initialized? " + info.isInitializedCard());

        WritableMap cardInfo = Arguments.createMap();
        cardInfo.putBoolean("initialized?", info.isInitializedCard());

        if (info.isInitializedCard()) {
            Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
            Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
            Log.i(TAG, "Application version: " + info.getAppVersionString());
            Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

            if (info.hasMasterKey()) {
                Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
            } else {
                Log.i(TAG, "The card has no master key");
            }

            Boolean isPaired = false;

            if (pairingBase64.length() > 0) {
                try {
                    Pairing pairing = new Pairing(pairingBase64);
                    cmdSet.setPairing(pairing);

                    cmdSet.autoOpenSecureChannel();
                    Log.i(TAG, "secure channel opened");
                    isPaired = true;

                    ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

                    Log.i(TAG, "PIN retry counter: " + status.getPINRetryCount());
                    Log.i(TAG, "PUK retry counter: " + status.getPUKRetryCount());

                    cardInfo.putInt("pin-retry-counter", status.getPINRetryCount());
                    cardInfo.putInt("puk-retry-counter", status.getPUKRetryCount());
                } catch (IOException | IllegalArgumentException e) {
                    Log.i(TAG, "autoOpenSecureChannel failed: " + e.getMessage());
                }
            }

            cardInfo.putBoolean("has-master-key?", info.hasMasterKey());
            cardInfo.putBoolean("paired?", isPaired);
            cardInfo.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
            cardInfo.putString("secure-channel-pub-key", Hex.toHexString(info.getSecureChannelPubKey()));
            cardInfo.putString("app-version", info.getAppVersionString());
            cardInfo.putInt("free-pairing-slots", info.getFreePairingSlots());
        }

        return cardInfo;
    }

    public void deriveKey(final String path, final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        KeyPath currentPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData());
        Log.i(TAG, "Current key path: " + currentPath);

        cmdSet.deriveKey(path).checkOK();
        Log.i(TAG, "Derived " + path);
    }

    public String exportKey(final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] key = cmdSet.exportCurrentKey(true).checkOK().getData();

        return Hex.toHexString(key);
    }

    public WritableMap getKeys(final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] tlv = cmdSet.exportKey(WALLET_PATH, true, true).checkOK().getData();
        BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlv);

        byte[] tlv2 = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlv2);

        byte[] tlv3 = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlv3);

        WritableMap data = Arguments.createMap();
        data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));

        return data;
    }

    public WritableMap generateAndLoadKey(final String mnemonic, final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        BIP32KeyPair keyPair = BIP32KeyPair.fromBinarySeed(seed);

        cmdSet.loadKey(keyPair);
        log("keypair loaded to card");

        cmdSet.deriveKey(WALLET_PATH).checkOK();
        Log.i(TAG, "Derived " + WALLET_PATH);

        byte[] tlv = cmdSet.exportCurrentKey(true).checkOK().getData();
        BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlv);

        cmdSet.deriveKey(WHISPER_PATH).checkOK();
        Log.i(TAG, "Derived " + WHISPER_PATH);

        byte[] tlv2 = cmdSet.exportCurrentKey(false).checkOK().getData();
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlv2);

        cmdSet.deriveKey(ENCRYPTION_PATH).checkOK();
        Log.i(TAG, "Derived " + ENCRYPTION_PATH);

        byte[] tlv3 = cmdSet.exportCurrentKey(false).checkOK().getData();
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlv3);

        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        WritableMap data = Arguments.createMap();
        data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));
        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));

        return data;
    }

    public void installApplet(AssetManager assets, String capPath) throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        Installer installer = new Installer(this.cardChannel, assets, capPath, eventEmitter);
        installer.start();
    }

    public SmartCardSecrets installAppletAndInitCard(final String userPin, AssetManager assets, String capPath) throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        Installer installer = new Installer(this.cardChannel, assets, capPath, eventEmitter);
        installer.start();

        return init(userPin);
    }

    public int verifyPin(final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

        return status.getPINRetryCount();
    }

    public void changePin(final String pairingBase64, final String currentPin, final String newPin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(currentPin).checkOK();
        Log.i(TAG, "pin verified");

        cmdSet.changePIN(0, newPin);
        Log.i(TAG, "pin changed");
    }

    public void unblockPin(final String pairingBase64, final String puk, final String newPin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.unblockPIN(puk, newPin).checkOK();
        Log.i(TAG, "pin unblocked");
    }

    public void unpair(final String pairingBase64, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        cmdSet.autoUnpair();
        Log.i(TAG, "card unpaired");
    }

    public void delete() throws IOException, APDUException {
        GlobalPlatformCommandSet cmdSet = new GlobalPlatformCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        cmdSet.openSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.deleteKeycardInstancesAndPackage();
        Log.i(TAG, "instance and package deleted");
    }

    public void unpairAndDelete(final String pairingBase64, final String pin) throws IOException, APDUException {
        unpair(pairingBase64, pin);
        delete();
    }

    public String sign(final String pairingBase64, final String pin, final String message) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] hash = message.getBytes();
        RecoverableSignature signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());

        Log.i(TAG, "Signed hash: " + Hex.toHexString(hash));
        Log.i(TAG, "Recovery ID: " + signature.getRecId());
        Log.i(TAG, "R: " + Hex.toHexString(signature.getR()));
        Log.i(TAG, "S: " + Hex.toHexString(signature.getS()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(signature.getR());
        out.write(signature.getS());
        out.write(signature.getRecId());

        String sig = Hex.toHexString(out.toByteArray());
        Log.i(TAG, "Signature: " + sig);

        return sig;
    }

}
