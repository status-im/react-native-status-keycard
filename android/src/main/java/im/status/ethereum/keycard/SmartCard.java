package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.support.annotation.Nullable;
import android.util.Log;
import com.facebook.react.bridge.*;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.CardChannel;
import im.status.hardwallet_lite_android.io.CardListener;
import im.status.hardwallet_lite_android.io.CardManager;
import im.status.hardwallet_lite_android.wallet.Mnemonic;
import im.status.hardwallet_lite_android.wallet.WalletAppletCommandSet;
import im.status.hardwallet_lite_android.wallet.Pairing;
import im.status.hardwallet_lite_android.wallet.RecoverableSignature;
import im.status.hardwallet_lite_android.wallet.ApplicationInfo;
import im.status.hardwallet_lite_android.wallet.ApplicationStatus;
import im.status.hardwallet_lite_android.wallet.KeyPath;
import org.spongycastle.util.encoders.Hex;

public class SmartCard extends BroadcastReceiver implements CardListener {
    private CardManager cardManager;
    private Activity activity;
    private ReactContext reactContext;
    private NfcAdapter nfcAdapter;
    private CardChannel cardChannel;
    private static final String TAG = "SmartCard";

    public SmartCard(Activity activity, ReactContext reactContext) {
        this.cardManager = new CardManager();
        this.cardManager.setCardListener(this);
        this.activity = activity;
        this.reactContext = reactContext;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(activity.getBaseContext());
    }

    public String getName() {
        return "SmartCard";
    }

    public void log(String s) {
        Log.d(TAG, s);
    }

    public boolean start() {
        this.cardManager.start();
        if (this.nfcAdapter != null) {
            IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED);
            activity.registerReceiver(this, filter);
            nfcAdapter.enableReaderMode(activity, this.cardManager, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
            return true;
        } else {
            log("not support in this device");
            return false;
        }
    }

    @Override
    public void onConnected(final CardChannel channel) {
        this.cardChannel = channel;
        sendEvent(reactContext, "keyCardOnConnected", null);
    }

    @Override
    public void onDisconnected() {
        sendEvent(reactContext, "keyCardOnDisconnected", null);
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

    private void sendEvent(ReactContext reactContext,
                           String eventName,
                           @Nullable WritableMap params) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, params);
    }

    public SmartCardSecrets init() throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        SmartCardSecrets s = SmartCardSecrets.generate();
        cmdSet.init(s.getPin(), s.getPuk(), s.getPairingPassword()).checkOK();

        return s;
    }

    public String pair(String pairingPassword) throws IOException, APDUException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        log("Pairing password: " + pairingPassword);
        Log.i(TAG, "Applet selection successful");

        // First thing to do is selecting the applet on the card.
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());
        Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
        Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
        Log.i(TAG, "Application version: " + info.getAppVersionString());
        Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

        cmdSet.autoPair(pairingPassword);

        Pairing pairing = cmdSet.getPairing();
        log("Pairing index: " + pairing.getPairingIndex());
        log("Pairing key: " + Hex.toHexString(pairing.getPairingKey()));
        log("Pairing toBase64: " + pairing.toBase64());

        return pairing.toBase64();
    }

    public void unpair(String base64) throws IOException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        Pairing pairing = new Pairing(base64);
        cmdSet.setPairing(pairing);

        cmdSet.autoUnpair();
    }

    public String generateMnemonic(String password) throws IOException, APDUException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        cmdSet.autoPair(password);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        Mnemonic mnemonic = new Mnemonic(cmdSet.generateMnemonic(WalletAppletCommandSet.GENERATE_MNEMONIC_12_WORDS).checkOK().getData());
        mnemonic.fetchBIP39EnglishWordlist();

        return mnemonic.toMnemonicPhrase();
    }

    public void saveMnemonic(String mnemonic, String password, String pin) throws  IOException, APDUException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        cmdSet.autoPair(password);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        cmdSet.loadKey(seed);

        log("seed loaded to card");
    }

    public WritableMap getApplicationInfo() throws IOException, APDUException {
        WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(this.cardChannel);
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        Log.i(TAG, "Card initialized? " + info.isInitializedCard());
        Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
        Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
        Log.i(TAG, "Application version: " + info.getAppVersionString());
        Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());
        if (info.hasMasterKey()) {
            Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
        } else {
            Log.i(TAG, "The card has no master key");
        }

        WritableMap cardInfo = Arguments.createMap();

        cardInfo.putBoolean("initialized?", info.isInitializedCard());
        cardInfo.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        cardInfo.putString("secure-channel-pub-key", Hex.toHexString(info.getSecureChannelPubKey()));
        cardInfo.putString("app-version", info.getAppVersionString());
        cardInfo.putInt("free-pairing-slots", info.getFreePairingSlots());
        cardInfo.putBoolean("has-master-key?", info.hasMasterKey());

        return cardInfo;
    }
}
