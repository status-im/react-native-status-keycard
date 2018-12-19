package im.status.ethereum.keycard;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import javax.annotation.Nullable;

public class EventEmitter {
    private ReactContext reactContext;

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
}
