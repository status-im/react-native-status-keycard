package im.status.ethereum.keycard;

import android.content.res.AssetManager;
import android.util.Log;

import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.globalplatform.LoadCallback;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.CardChannel;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Installer {
    private CardChannel plainChannel;
    private AssetManager assets;
    private String capPath;
    private EventEmitter eventEmitter;

    private GlobalPlatformCommandSet cmdSet;

    private static final String TAG = "SmartCardInstaller";

    public Installer(CardChannel channel, AssetManager assets, String capPath, EventEmitter eventEmitter) {
        this.plainChannel = channel;
        this.assets = assets;
        this.capPath = capPath;
        this.eventEmitter = eventEmitter;
    }

    public void start() throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        Log.i(TAG, "installation started...");
        long startTime = System.currentTimeMillis();

        eventEmitter.emit("keycardInstallationProgress", 0.05);

        Log.i(TAG, "select ISD...");
        cmdSet = new GlobalPlatformCommandSet(this.plainChannel);
        cmdSet.select().checkOK();


        Log.i(TAG, "opening secure channel...");
        cmdSet.openSecureChannel();


        Log.i(TAG, "deleting old version (if present)...");
        cmdSet.deleteKeycardInstancesAndPackage();

        eventEmitter.emit("keycardInstallationProgress", 0.1);

        Log.i(TAG, "loading package...");
        cmdSet.loadKeycardPackage(this.assets.open(this.capPath), new LoadCallback() {
            public void blockLoaded(int loadedBlock, int blockCount) {
                Log.i(TAG, String.format("load %d/%d...", loadedBlock, blockCount));
                eventEmitter.emit("keycardInstallationProgress", 0.1 + (0.6 * loadedBlock / blockCount));
            }
        });


        Log.i(TAG, "installing NDEF applet...");
        cmdSet.installNDEFApplet(HexUtils.hexStringToByteArray("0024d40f12616e64726f69642e636f6d3a706b67696d2e7374617475732e657468657265756d")).checkOK();

        eventEmitter.emit("keycardInstallationProgress", 0.72);

        eventEmitter.emitWithDelay("keycardInstallationProgress", 0.77, 3100);

        eventEmitter.emitWithDelay("keycardInstallationProgress", 0.82, 6200);

        eventEmitter.emitWithDelay("keycardInstallationProgress", 0.85, 8500);

        Log.i(TAG, "installing Keycard applet...");
        cmdSet.installKeycardApplet().checkOK();

        eventEmitter.removeCallbacksAndMessages();

        eventEmitter.emit("keycardInstallationProgress", 0.88);

        long duration = System.currentTimeMillis() - startTime;
        Log.i(TAG, String.format("\n\ninstallation completed in %d seconds", duration / 1000));
    }
}
