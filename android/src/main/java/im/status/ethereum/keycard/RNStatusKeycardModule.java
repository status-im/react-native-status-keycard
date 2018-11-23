package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.Intent;
import android.provider.Settings;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
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
      Log.d("ONHOSTRESUme", " " + this.smartCard);
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
  public void nfcIsSupported(final Callback callback) {
    callback.invoke(smartCard.isNfcSupported());
  }

  @ReactMethod
  public void nfcIsEnabled(final Callback callback) {
    callback.invoke(smartCard.isNfcEnabled());
  }

  @ReactMethod
  public void openNfcSettings(final Callback callback) {
      Activity currentActivity = getCurrentActivity();
      currentActivity.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
      callback.invoke();
  }

  @ReactMethod
  public void start(Callback successCallback, Callback errorCallback) {
    if (smartCard.start()) {
       successCallback.invoke();
    } else {
       errorCallback.invoke();
    };
  }

  @ReactMethod
  public void init(final Callback successCallback, final Callback errorCallback) {
    try {
      SmartCardSecrets s = smartCard.init();

      WritableMap params = Arguments.createMap();
      params.putString("pin", s.getPin());
      params.putString("puk", s.getPuk());
      params.putString("password", s.getPairingPassword());

      successCallback.invoke(params);
    } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      Log.d(TAG, e.getMessage());
      errorCallback.invoke(e.getMessage());
    }
  }

  @ReactMethod
  public void pair(final String password, final Callback successCallback, final Callback errorCallback) {
    try {
      String pairing = smartCard.pair(password);
      Log.d(TAG, "pairing done");

      successCallback.invoke(pairing);
    } catch (IOException | APDUException e) {
      Log.d(TAG, e.getMessage());
      errorCallback.invoke(e.getMessage());
    }
  }

  @ReactMethod
  public void generateMnemonic(final String password, Callback successCallback, Callback errorCallback) {
    try {
      successCallback.invoke(smartCard.generateMnemonic(password));
    } catch (IOException | APDUException e) {
      Log.d(TAG, e.getMessage());
      errorCallback.invoke(e.getMessage());
    }
  }

  @ReactMethod
  public void saveMnemonic(final String mnemonic, final String password, String pin, Callback successCallback, Callback errorCallback) {
    try {
      smartCard.saveMnemonic(mnemonic, password, pin);
      successCallback.invoke();
    } catch (IOException | APDUException e) {
      Log.d(TAG, e.getMessage());
      errorCallback.invoke(e.getMessage());
    }
  }

  @ReactMethod
  public void getApplicationInfo(final Callback successCallback, Callback errorCallback) {
      try {
          successCallback.invoke(smartCard.getApplicationInfo());
      } catch (IOException | APDUException e) {
          Log.d(TAG, e.getMessage());
          errorCallback.invoke(e.getMessage());
      }
  }

}