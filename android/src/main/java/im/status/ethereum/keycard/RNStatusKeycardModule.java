package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.Intent;
import android.provider.Settings;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import im.status.hardwallet_lite_android.io.APDUException;

public class RNStatusKeycardModule extends ReactContextBaseJavaModule implements LifecycleEventListener {
    private static final String TAG = "StatusKeycard";
    private SmartCard smartCard;
    private final ReactApplicationContext reactContext;

    public RNStatusKeycardModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
        reactContext.addLifecycleEventListener(this);
    }

    @Override
    public String getName() {
        return "RNStatusKeycard";
    }

    @Override
    public void onHostResume() {
        if (this.smartCard == null) {
            this.smartCard = new SmartCard(getCurrentActivity(), reactContext);
        }
    }

    @Override
    public void onHostPause() {
    }

    @Override
    public void onHostDestroy() {

    }

    @ReactMethod
    public void nfcIsSupported(final Promise promise) {
        promise.resolve(smartCard.isNfcSupported());
    }

    @ReactMethod
    public void nfcIsEnabled(final Promise promise) {
        promise.resolve(smartCard.isNfcEnabled());
    }

    @ReactMethod
    public void openNfcSettings(final Promise promise) {
        Activity currentActivity = getCurrentActivity();
        currentActivity.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
        promise.resolve(true);
    }

    @ReactMethod
    public void start(final Promise promise) {
        if (smartCard.start()) {
            promise.resolve(true);
        } else {
            promise.reject("Error", "Not supported on this device");
        }
    }

    @ReactMethod
    public void init(final Promise promise) {
        try {
            SmartCardSecrets s = smartCard.init();

            WritableMap params = Arguments.createMap();
            params.putString("pin", s.getPin());
            params.putString("puk", s.getPuk());
            params.putString("password", s.getPairingPassword());

            promise.resolve(params);
        } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void pair(final String password, final Promise promise) {
        try {
            String pairing = smartCard.pair(password);
            Log.d(TAG, "pairing done");

            promise.resolve(pairing);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void generateMnemonic(final String pairing, final Promise promise) {
        try {
            promise.resolve(smartCard.generateMnemonic(pairing));
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void generateAndLoadKey(final String mnemonic, final String pairing, final String pin, final Promise promise) {
       try {
           promise.resolve(smartCard.generateAndLoadKey(mnemonic, pairing, pin));
       } catch (IOException | APDUException e) {
           Log.d(TAG, e.getMessage());
           promise.reject(e);
       }
    }

    @ReactMethod
    public void saveMnemonic(final String mnemonic, final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.saveMnemonic(mnemonic, pairing, pin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getApplicationInfo(final Promise promise) {
        try {
            promise.resolve(smartCard.getApplicationInfo());
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void deriveKey(final String path, final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.deriveKey(path, pairing, pin);
            promise.resolve(path);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void exportKey(final String pairing, final String pin, final Promise promise) {
        try {
            promise.resolve(smartCard.exportKey(pairing, pin));
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getWhisperKey(final String pairing, final String pin, final Promise promise) {
        try {
            promise.resolve(smartCard.getWhisperKey(pairing, pin));
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void installApplet(Promise promise) {
        try {
            smartCard.installApplet(this.reactContext.getAssets(), "wallet.cap");
            promise.resolve(true);
        } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void installAppletAndInitCard(Promise promise) {
        try {
            SmartCardSecrets s = smartCard.installAppletAndInitCard(this.reactContext.getAssets(), "wallet.cap");

            WritableMap params = Arguments.createMap();
            params.putString("pin", s.getPin());
            params.putString("puk", s.getPuk());
            params.putString("password", s.getPairingPassword());

            promise.resolve(params);
        } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

}