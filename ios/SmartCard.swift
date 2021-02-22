import Foundation
import Keycard
import os.log

enum SmartCardError: Error {
    case invalidBase64
}

enum DerivationPath: String {
  case masterPath = "m"
  case rootPath = "m/44'/60'/0'/0"
  case walletPath = "m/44'/60'/0'/0/0"
  case whisperPath = "m/43'/60'/1581'/0'/0"
  case encryptionPath = "m/43'/60'/1581'/1'/0"
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
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let seed = Mnemonic.toBinarySeed(mnemonicPhrase: mnemonic)
      let keyPair = BIP32KeyPair(fromSeed: seed)

      try cmdSet.loadKey(keyPair: keyPair).checkOK()
      os_log("keypair loaded to card");

      let rootKeyPair = try exportKey(cmdSet: cmdSet, path: .rootPath, makeCurrent: false, publicOnly: true)
      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)
      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)
      let walletKeyPair = try exportKey(cmdSet: cmdSet, path: .walletPath, makeCurrent: false, publicOnly: true)

      let info = try ApplicationInfo(cmdSet.select().checkOK().data)

      resolve([
        "address": bytesToHex(keyPair.toEthereumAddress()),
        "public-key": bytesToHex(keyPair.publicKey),
        "wallet-root-address": bytesToHex(rootKeyPair.toEthereumAddress()),
        "wallet-root-public-key": bytesToHex(rootKeyPair.publicKey),
        "wallet-address": bytesToHex(walletKeyPair.toEthereumAddress()),
        "wallet-public-key": bytesToHex(walletKeyPair.publicKey),
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey),
        "instance-uid": bytesToHex(info.instanceUID),
        "key-uid": bytesToHex(info.keyUID)
      ])
    }

    func saveMnemonic(channel: CardChannel, mnemonic: String, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let seed = Mnemonic.toBinarySeed(mnemonicPhrase: mnemonic)
      try cmdSet.loadKey(seed: seed).checkOK()
      os_log("seed loaded to card");
      resolve(true)
    }

    func getApplicationInfo(channel: CardChannel, pairingBase64: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      let info = try ApplicationInfo(cmdSet.select().checkOK().data)

      os_log("Card initialized? %@", String(info.initializedCard))
      var cardInfo = [String: Any]()
      cardInfo["initialized?"] = info.initializedCard

      if (info.initializedCard) {
        logAppInfo(info)
        var isPaired = false

        if (!pairingBase64.isEmpty) {
          do {
            try openSecureChannel(cmdSet: cmdSet, pairingBase64: pairingBase64)
            isPaired = true
          } catch let error as CardError {
            os_log("autoOpenSecureChannel failed: %@", String(describing: error));
          } catch let error as StatusWord {
            os_log("autoOpenSecureChannel failed: %@", String(describing: error));
          }

          if (isPaired) {
            let status = try ApplicationStatus(cmdSet.getStatus(info: GetStatusP1.application.rawValue).checkOK().data);
            os_log("PIN retry counter: %d", status.pinRetryCount)
            os_log("PUK retry counter: %d", status.pukRetryCount)

            cardInfo["pin-retry-counter"] = status.pinRetryCount
            cardInfo["puk-retry-counter"] = status.pukRetryCount
          }
        }

        cardInfo["paired?"] = isPaired
      }

      cardInfo["has-master-key?"] = info.hasMasterKey
      cardInfo["instance-uid"] = bytesToHex(info.instanceUID)
      cardInfo["key-uid"] = bytesToHex(info.keyUID)
      cardInfo["secure-channel-pub-key"] = bytesToHex(info.secureChannelPubKey)
      cardInfo["app-version"] = info.appVersionString
      cardInfo["free-pairing-slots"] = info.freePairingSlots

      resolve(cardInfo)
    }

    func deriveKey(channel: CardChannel, path: String, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let currentPath = try KeyPath(data: cmdSet.getStatus(info: GetStatusP1.keyPath.rawValue).checkOK().data);
      os_log("Current key path: %@", currentPath.description)

      if (currentPath.description != path) {
        try cmdSet.deriveKey(path: path).checkOK()
        os_log("Derived %@", path)
      }

      resolve(true)
    }

    func exportKey(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let key = try cmdSet.exportCurrentKey(publicOnly: true).checkOK().data
      resolve(bytesToHex(key))
    }

    func exportKeyWithPath(channel: CardChannel, pairingBase64: String, pin: String, path: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let key = try BIP32KeyPair(fromTLV: cmdSet.exportKey(path: path, makeCurrent: false, publicOnly: true).checkOK().data).publicKey;

      resolve(bytesToHex(key))
    }

    func importKeys(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)

      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)
      let masterPair = try exportKey(cmdSet: cmdSet, path: .masterPath, makeCurrent: false, publicOnly: true)
      let rootKeyPair = try exportKey(cmdSet: cmdSet, path: .rootPath, makeCurrent: false, publicOnly: true)
      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)
      let walletKeyPair = try exportKey(cmdSet: cmdSet, path: .walletPath, makeCurrent: false, publicOnly: true)

      let info = cmdSet.info!

      resolve([
        "address": bytesToHex(masterPair.toEthereumAddress()),
        "public-key": bytesToHex(masterPair.publicKey),
        "wallet-root-address": bytesToHex(rootKeyPair.toEthereumAddress()),
        "wallet-root-public-key": bytesToHex(rootKeyPair.publicKey),
        "wallet-address": bytesToHex(walletKeyPair.toEthereumAddress()),
        "wallet-public-key": bytesToHex(walletKeyPair.publicKey),
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey),
        "instance-uid": bytesToHex(info.instanceUID),
        "key-uid": bytesToHex(info.keyUID)
      ])
    }

    func getKeys(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)

      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)
      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)

      let info = cmdSet.info!

      resolve([
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey),
        "instance-uid": bytesToHex(info.instanceUID),
        "key-uid": bytesToHex(info.keyUID)
      ])
    }

    func sign(channel: CardChannel, pairingBase64: String, pin: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let sig = try processSignature(message) { return try cmdSet.sign(hash: $0) }
      resolve(sig)
    }

    func signWithPath(channel: CardChannel, pairingBase64: String, pin: String, path: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let sig = try processSignature(message) {
        if (cmdSet.info!.appVersion < 0x0202) {
          let currentPath = try KeyPath(data: cmdSet.getStatus(info: GetStatusP1.keyPath.rawValue).checkOK().data);

          if (currentPath.description != path) {
            try cmdSet.deriveKey(path: path).checkOK()
          }

          return try cmdSet.sign(hash: $0)
        } else {
          return try cmdSet.sign(hash: $0, path: path, makeCurrent: false)
        }
      }

      resolve(sig)
    }

    func signPinless(channel: CardChannel, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = CashCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()

      let sig = try processSignature(message) { return try cmdSet.sign(data: $0) }
      resolve(sig)
    }

    func verifyPin(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      let status = try ApplicationStatus(cmdSet.getStatus(info: GetStatusP1.application.rawValue).checkOK().data);
      resolve(status.pinRetryCount)
    }

    func changePin(channel: CardChannel, pairingBase64: String, currentPin: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: currentPin)
      try cmdSet.changePIN(pin: newPin).checkOK()
      os_log("pin changed")
      resolve(true)
    }

    func unblockPin(channel: CardChannel, pairingBase64: String, puk: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try securedCommandSet(channel: channel, pairingBase64: pairingBase64)
      try cmdSet.unblockPIN(puk: puk, newPIN: newPin).checkAuthOK()
      os_log("pin unblocked")
      resolve(true)
    }

    func unpair(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)

      try cmdSet.autoUnpair()
      os_log("card unpaired")

      resolve(true)
    }

    func removeKey(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      try cmdSet.removeKey().checkOK()
      os_log("key removed")

      resolve(true)
    }

    func removeKeyWithUnpair(channel: CardChannel, pairingBase64: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pairingBase64: pairingBase64, pin: pin)
      try cmdSet.removeKey().checkOK()
      os_log("key removed")

      try cmdSet.autoUnpair()
      os_log("card unpaired")

      resolve(true)
    }

    func randomPUK() -> String {
      return String(format: "%012ld", Int64.random(in: 0..<999999999999))
    }

    func randomPairingPassword() -> String {
      let digits = "23456789"
      let letters = "abcdefghijkmnopqrstuvwxyz"
      return String((0..<5).map{ i in ((i % 2) == 0) ? letters.randomElement()! : digits.randomElement()! })
    }

    func exportKey(cmdSet: KeycardCommandSet, path: DerivationPath, makeCurrent: Bool, publicOnly: Bool) throws -> BIP32KeyPair {
      let tlvRoot = try cmdSet.exportKey(path: path.rawValue, makeCurrent: makeCurrent, publicOnly: publicOnly).checkOK().data
      os_log("Derived %@", path.rawValue)
      return try BIP32KeyPair(fromTLV: tlvRoot)
    }

    func authenticatedCommandSet(channel: CardChannel, pairingBase64: String, pin: String) throws -> KeycardCommandSet {
      let cmdSet = try securedCommandSet(channel: channel, pairingBase64: pairingBase64)
      try cmdSet.verifyPIN(pin: pin).checkAuthOK()
      os_log("pin verified")

      return cmdSet;
    }

    func securedCommandSet(channel: CardChannel, pairingBase64: String) throws -> KeycardCommandSet {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      try openSecureChannel(cmdSet: cmdSet, pairingBase64: pairingBase64)

      return cmdSet
    }

    func openSecureChannel(cmdSet: KeycardCommandSet, pairingBase64: String) throws -> Void {
      cmdSet.pairing = try base64ToPairing(pairingBase64)

      try cmdSet.autoOpenSecureChannel()
      os_log("secure channel opened")
    }

    func processSignature(_ message: String, sign: ([UInt8]) throws -> APDUResponse) throws -> String {
      let hash = hexToBytes(message)
      let signature = try RecoverableSignature(hash: hash, data: sign(hash).checkOK().data)
      logSignature(hash, signature)
      return formatSignature(signature)
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

    func logSignature(_ hash: [UInt8], _ signature: RecoverableSignature) -> Void {
      os_log("Signed hash: %@", bytesToHex(hash))
      os_log("Recovery ID: %d", signature.recId)
      os_log("R: %@", bytesToHex(signature.r))
      os_log("S: %@", bytesToHex(signature.s))
    }

    func formatSignature(_ signature: RecoverableSignature) -> String {
      var out = Data(signature.r)
      out.append(contentsOf: signature.s)
      out.append(contentsOf: [signature.recId])
      let sig = dataToHex(out)

      os_log("Signature: %@", sig)
      return sig
    }

    func dataToHex(_ data: Data) -> String {
      return data.map { String(format: "%02hhx", $0) }.joined()
    }

    func bytesToHex(_ bytes: [UInt8]) -> String {
      return bytes.map { String(format: "%02hhx", $0) }.joined()
    }

    func hexToBytes(_ hex: String) -> [UInt8] {
      let h = hex.starts(with: "0x") ? String(hex.dropFirst(2)) : hex

      var last = h.first
        return h.dropFirst().compactMap {
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
