package im.status.ethereum.keycard;

import android.content.res.AssetManager;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import im.status.hardwallet_lite_android.globalplatform.Load;
import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;
import im.status.hardwallet_lite_android.globalplatform.ApplicationID;
import im.status.hardwallet_lite_android.globalplatform.GlobalPlatformCommandSet;

public class Installer {
    private CardChannel plainChannel;
    private AssetManager assets;
    private String capPath;
    private static final String TAG = "SmartCardInstaller";

    static final byte[] PACKAGE_AID = HexUtils.hexStringToByteArray("53746174757357616C6C6574");
    static final byte[] WALLET_AID = HexUtils.hexStringToByteArray("53746174757357616C6C6574417070");
    static final byte[] NDEF_APPLET_AID = HexUtils.hexStringToByteArray("53746174757357616C6C65744E4643");
    static final byte[] NDEF_INSTANCE_AID = HexUtils.hexStringToByteArray("D2760000850101");

    private GlobalPlatformCommandSet cmdSet;

    public Installer(CardChannel channel, AssetManager assets, String capPath) {
        this.plainChannel = channel;
        this.assets = assets;
        this.capPath = capPath;
    }

    public void start() throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        Log.i(TAG, "installation started...");
        long startTime = System.currentTimeMillis();

        Log.i(TAG, "auto select sdaid...");
        cmdSet = new GlobalPlatformCommandSet(this.plainChannel);
        ApplicationID sdaid = new ApplicationID(cmdSet.select().checkOK().getData());

        SecureRandom random = new SecureRandom();
        byte hostChallenge[] = new byte[8];
        random.nextBytes(hostChallenge);
        Log.i(TAG, "initialize update...");
        cmdSet.initializeUpdate(hostChallenge).checkOK();

        Log.i(TAG, "external authenticate...");
        cmdSet.externalAuthenticate(hostChallenge).checkOK();

        Log.i(TAG, "delete NDEF instance AID...");
        cmdSet.delete(NDEF_INSTANCE_AID).checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);

        Log.i(TAG, "delete wallet AID...");
        cmdSet.delete(WALLET_AID).checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);

        Log.i(TAG, "delete package AID...");
        cmdSet.delete(PACKAGE_AID).checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);

        Log.i(TAG, "install for load...");
        cmdSet.installForLoad(PACKAGE_AID, sdaid.getAID()).checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);

        InputStream in = this.assets.open(this.capPath);
        Load load = new Load(in);

        java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
        Log.i(TAG, "cap file " + s.toString().length());

        byte[] block;
        int steps = load.blocksCount();
        while((block = load.nextDataBlock()) != null) {
            int count = load.getCount() - 1;
            Log.i(TAG, String.format("load %d/%d...", count + 1, steps));
            cmdSet.load(block, count, load.hasMore()).checkOK();
        }

        Log.i(TAG, "install for install ndef...");
        byte[] params = HexUtils.hexStringToByteArray("0024d40f12616e64726f69642e636f6d3a706b67696d2e7374617475732e657468657265756d");
        cmdSet.installForInstall(PACKAGE_AID, NDEF_APPLET_AID, NDEF_INSTANCE_AID, params).checkOK();

        Log.i(TAG, "install for install wallet...");
        cmdSet.installForInstall(PACKAGE_AID, WALLET_AID, WALLET_AID, new byte[0]).checkOK();

        long duration = System.currentTimeMillis() - startTime;
        Log.i(TAG, String.format("\n\ninstallation completed in %d seconds", duration / 1000));
    }

}
