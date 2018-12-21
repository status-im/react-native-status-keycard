package im.status.ethereum.keycard;

import android.os.Handler;
import android.os.Looper;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import javax.annotation.Nullable;

public class EventEmitter {
    private ReactContext reactContext;

    final Handler handler = new Handler(Looper.getMainLooper());

    public EventEmitter(ReactContext reactContext) {
       this.reactContext = reactContext;
    }

    public void emit(String eventName, @Nullable WritableMap params) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, params);
    }

    public void emit(String eventName, double progress) {
        WritableMap params = Arguments.createMap();
        params.putDouble("progress", progress);
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, params);
    }

    public void emitWithDelay(String eventName, final double progress, int delay) {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                emit("keycardInstallationProgress", progress);
            }
        }, delay);
    }

    public void removeCallbacksAndMessages() {
        handler.removeCallbacksAndMessages(null);
    }
}
