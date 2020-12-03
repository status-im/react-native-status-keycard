import Foundation
import Keycard
import os.log

enum SmartCardError: Error {
    case invalidBase64
}

class SmartCard {
    func initialize(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let puk = self.randomPUK()
      let pairingPassword = self.randomPairingPassword();
      
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      try cmdSet.initialize(pin: pin, puk: puk, pairingPassword: pairingPassword).checkOK();

      resolve(["pin": pin, "puk": puk, "password": pairingPassword])
    }

    func pair(channel: CardChannel, pairingPassword: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      let info = try ApplicationInfo(cmdSet.select().checkOK().data)
      
      logAppInfo(info)

      try cmdSet.autoPair(password: pairingPassword)

      resolve(Data(cmdSet.pairing!.bytes).base64EncodedString())
    }

    func generateMnemonic(channel: CardChannel, pairingBase64: String, words: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try securedCommandSet(channel: channel, pairingBase64: pairingBase64)

      let mnemonic = try Mnemonic(rawData: cmdSet.generateMnemonic(length: GenerateMnemonicP1.length12Words).checkOK().data)
      mnemonic.wordList = words.components(separatedBy: .newlines)

      resolve(mnemonic.toMnemonicPhrase())
    }

    func generateAndLoadKey(channel: CardChannel, mnemonic: String, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        BIP32KeyPair keyPair = BIP32KeyPair.fromBinarySeed(seed);

        cmdSet.loadKey(keyPair).checkOK();
        log("keypair loaded to card");

        byte[] tlvRoot = cmdSet.exportKey(ROOT_PATH, false, true).checkOK().getData();
        Log.i(TAG, "Derived " + ROOT_PATH);
        BIP32KeyPair rootKeyPair = BIP32KeyPair.fromTLV(tlvRoot);

        byte[] tlvWhisper = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        Log.i(TAG, "Derived " + WHISPER_PATH);
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlvWhisper);

        byte[] tlvEncryption = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        Log.i(TAG, "Derived " + ENCRYPTION_PATH);
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlvEncryption);

        byte[] tlvWallet = cmdSet.exportKey(WALLET_PATH, true, true).checkOK().getData();
        Log.i(TAG, "Derived " + WALLET_PATH);
        BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlvWallet);

        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        WritableMap data = Arguments.createMap();
        data.putString("address", Hex.toHexString(keyPair.toEthereumAddress()));
        data.putString("public-key", Hex.toHexString(keyPair.getPublicKey()));
        data.putString("wallet-root-address", Hex.toHexString(rootKeyPair.toEthereumAddress()));
        data.putString("wallet-root-public-key", Hex.toHexString(rootKeyPair.getPublicKey()));
        data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
        data.putString("wallet-public-key", Hex.toHexString(walletKeyPair.getPublicKey()));
        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));
        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        data.putString("key-uid", Hex.toHexString(info.getKeyUID()));

        return data;*/
    }    

    func saveMnemonic(channel: CardChannel, mnemonic: String, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        cmdSet.loadKey(seed);

        log("seed loaded to card");*/
    }

    func getApplicationInfo(channel: CardChannel, pairingBase64: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
       /* KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        Log.i(TAG, "Card initialized? " + info.isInitializedCard());

        WritableMap cardInfo = Arguments.createMap();
        cardInfo.putBoolean("initialized?", info.isInitializedCard());

        if (info.isInitializedCard()) {
            Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
            Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
            Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
            Log.i(TAG, "Application version: " + info.getAppVersionString());
            Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

            Boolean isPaired = false;

            if (pairingBase64.length() > 0) {
                Pairing pairing = new Pairing(pairingBase64);
                cmdSet.setPairing(pairing);

                try {
                    cmdSet.autoOpenSecureChannel();
                    Log.i(TAG, "secure channel opened");
                    isPaired = true;
                } catch(APDUException e) {
                    Log.i(TAG, "autoOpenSecureChannel failed: " + e.getMessage());
                }

                if (isPaired) {
                    ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

                    Log.i(TAG, "PIN retry counter: " + status.getPINRetryCount());
                    Log.i(TAG, "PUK retry counter: " + status.getPUKRetryCount());

                    cardInfo.putInt("pin-retry-counter", status.getPINRetryCount());
                    cardInfo.putInt("puk-retry-counter", status.getPUKRetryCount());
                }
            }

            cardInfo.putBoolean("has-master-key?", info.hasMasterKey());
            cardInfo.putBoolean("paired?", isPaired);
            cardInfo.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
            cardInfo.putString("key-uid", Hex.toHexString(info.getKeyUID()));
            cardInfo.putString("secure-channel-pub-key", Hex.toHexString(info.getSecureChannelPubKey()));
            cardInfo.putString("app-version", info.getAppVersionString());
            cardInfo.putInt("free-pairing-slots", info.getFreePairingSlots());
        }

        return cardInfo;*/
    }

    func deriveKey(channel: CardChannel, path: String, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        KeyPath currentPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData());
        Log.i(TAG, "Current key path: " + currentPath);

        if (!currentPath.toString().equals(path)) {
            cmdSet.deriveKey(path).checkOK();
            Log.i(TAG, "Derived " + path);
        }*/
    }

    func exportKey(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] key = cmdSet.exportCurrentKey(true).checkOK().getData();

        return Hex.toHexString(key);*/
    }

    func exportKeyWithPath(channel: CardChannel, pairingBase64: String, pin: String, path: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] key = BIP32KeyPair.fromTLV(cmdSet.exportKey(path, false, true).checkOK().getData()).getPublicKey();

        return Hex.toHexString(key);*/
    }

    func getKeys(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] tlvEncryption = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlvEncryption);

        byte[] tlvMaster = cmdSet.exportKey(MASTER_PATH, false, true).checkOK().getData();
        BIP32KeyPair masterPair = BIP32KeyPair.fromTLV(tlvMaster);

        byte[] tlvRoot = cmdSet.exportKey(ROOT_PATH, false, true).checkOK().getData();
        BIP32KeyPair keyPair = BIP32KeyPair.fromTLV(tlvRoot);

        byte[] tlvWhisper = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlvWhisper);

        byte[] tlvWallet = cmdSet.exportKey(WALLET_PATH, true, true).checkOK().getData();
        BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlvWallet);

        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        WritableMap data = Arguments.createMap();
        data.putString("address", Hex.toHexString(masterPair.toEthereumAddress()));
        data.putString("public-key", Hex.toHexString(masterPair.getPublicKey()));
        data.putString("wallet-root-address", Hex.toHexString(keyPair.toEthereumAddress()));
        data.putString("wallet-root-public-key", Hex.toHexString(keyPair.getPublicKey()));
        data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
        data.putString("wallet-public-key", Hex.toHexString(walletKeyPair.getPublicKey()));
        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));
        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        data.putString("key-uid", Hex.toHexString(info.getKeyUID()));

        return data;*/
    }

    func sign(channel: CardChannel, pairingBase64: String, pin: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] hash = Hex.decode(message);
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

        return sig;*/
    }

    func signWithPath(channel: CardChannel, pairingBase64: String, pin: String, path: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
       /* KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        byte[] hash = Hex.decode(message);

        RecoverableSignature signature;

        if (cmdSet.getApplicationInfo().getAppVersion() < 0x0202) {
            String actualPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData()).toString();
            if (!actualPath.equals(path)) {
                cmdSet.deriveKey(path).checkOK();
            }
            signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());
        } else {
            signature = new RecoverableSignature(hash, cmdSet.signWithPath(hash, path, false).checkOK().getData());
        }

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

        return sig;*/
    }

    func signPinless(channel: CardChannel, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = CashCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()

      let hash = hexToBytes(message)
      let res = try cmdSet.sign(data: hash).checkOK()

      /*        RecoverableSignature signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());

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
      */

      resolve(res.data.toHexString())
    }

    func verifyPin(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

        return status.getPINRetryCount();*/
    }

    func changePin(channel: CardChannel, pairingBase64: String, currentPin: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(currentPin).checkOK();
        Log.i(TAG, "pin verified");

        cmdSet.changePIN(0, newPin);
        Log.i(TAG, "pin changed");*/
    }

    func unblockPin(channel: CardChannel, pairingBase64: String, puk: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.unblockPIN(puk, newPin).checkOK();
        Log.i(TAG, "pin unblocked");*/
    }

    func unpair(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
       /* KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        cmdSet.autoUnpair();
        Log.i(TAG, "card unpaired");*/
    }

    func removeKey(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");

        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        cmdSet.removeKey();
        Log.i(TAG, "key removed");*/
    }

    func removeKeyWithUnpair(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
        /*removeKey(pairingBase64, pin);
        unpair(pairingBase64, pin);*/
    }    

    func randomPUK() -> String {
      return String(format: "%012d", Int.random(in: 0..<999999999999))
    }

    func randomPairingPassword() -> String {
      let letters = "23456789ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      return String((0..<16).map{ _ in letters.randomElement()! })      
    }

    func authenticatedCommandSet(channel: CardChannel, pairingBase64: String, pin: String) throws -> KeycardCommandSet {
      let cmdSet = try securedCommandSet(channel: channel, pairingBase64: pairingBase64)
      try cmdSet.verifyPIN(pin: pin).checkOK()
      return cmdSet;
    }

    func securedCommandSet(channel: CardChannel, pairingBase64: String) throws -> KeycardCommandSet {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try openSecureChannel(cmdSet: cmdSet, pairingBase64: pairingBase64)

      return cmdSet
    }

    func openSecureChannel(cmdSet: KeycardCommandSet, pairingBase64: String) throws -> Void {
      cmdSet.pairing = try base64ToPairing(pairingBase64)

      try cmdSet.autoOpenSecureChannel()
      os_log("secure channel opened")
    }

    func base64ToPairing(_ base64: String) throws -> Pairing {
      if let data = Data(base64Encoded: base64) {
        return Pairing(pairingData: [UInt8](data))
      } else {
        throw SmartCardError.invalidBase64
      }
    }

    func logAppInfo(_ info: ApplicationInfo) -> Void {
      os_log("Instance UID: %@", bytesToHex(info.instanceUID))
      os_log("Key UID: %@", bytesToHex(info.keyUID))
      os_log("Secure channel public key: %@", bytesToHex(info.secureChannelPubKey))
      os_log("Application version: %@", info.appVersionString)
      os_log("Free pairing slots: %d", info.freePairingSlots)
    }

    func bytesToHex(_ bytes: [UInt8]) -> String {
      return bytes.map { String(format: "%02hhx", $0) }.joined()
    }    

    func hexToBytes(_ hex: String) -> [UInt8] {
      var last = hex.first
        return hex.dropFirst().compactMap {
          guard
            let lastHexDigitValue = last?.hexDigitValue,
            let hexDigitValue = $0.hexDigitValue 
          else {
            last = $0
            return nil
          }
      defer {
        last = nil
      }
        return UInt8(lastHexDigitValue * 16 + hexDigitValue)
      }
    }
}
