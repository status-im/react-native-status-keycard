import Foundation
import Keycard
import UIKit

@objc(StatusKeycard)
class StatusKeycard: RCTEventEmitter {
    let smartCard = SmartCard()
    var cardChannel: CardChannel? = nil

    @available(iOS 13.0, *)
    private(set) lazy var keycardController: KeycardController? = nil

    @objc
    func nfcIsSupported(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        resolve(KeycardController.isAvailable)
      } else {
        resolve(false)
      }
    }

    @objc
    func nfcIsEnabled(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      // On iOS NFC is always enabled (if available)
      nfcIsSupported(resolve, reject: reject)
    }

    @objc
    func openNfcSettings(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      // NFC cannot be enabled/disabled
      reject("E_KEYCARD", "Unsupported on iOS", nil)
    }

    @objc
    func `init`(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.initialize(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func pair(_ pairingPassword: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.pair(channel: channel, pairingPassword: pairingPassword, resolve: resolve, reject: reject) }
    }

    @objc
    func generateMnemonic(_ pairing: String, words: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.generateMnemonic(channel: channel, pairingBase64: pairing, words: words, resolve: resolve, reject: reject) }
    }

    @objc
    func generateAndLoadKey(_ mnemonic: String, pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.generateAndLoadKey(channel: channel, mnemonic: mnemonic, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func saveMnemonic(_ mnemonic: String, pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.saveMnemonic(channel: channel, mnemonic: mnemonic, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func getApplicationInfo(_ pairingBase64: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.getApplicationInfo(channel: channel, pairingBase64: pairingBase64, resolve: resolve, reject: reject) }
    }

    @objc
    func deriveKey(_ path: String, pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.deriveKey(channel: channel, path: path, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func exportKey(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.exportKey(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func exportKeyWithPath(_ pairing: String, pin: String, path: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.exportKeyWithPath(channel: channel, pairingBase64: pairing, pin: pin, path: path, resolve: resolve, reject: reject) }
    }

    @objc
    func getKeys(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.getKeys(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func sign(_ pairing: String, pin: String, hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.sign(channel: channel, pairingBase64: pairing, pin: pin, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func signWithPath(_ pairing: String, pin: String, path: String, hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.signWithPath(channel: channel, pairingBase64: pairing, pin: pin, path: path, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func signPinless(_ hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.signPinless(channel: channel, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func installApplet(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func installAppletAndInitCard(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func verifyPin(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.verifyPin(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func changePin(_ pairing: String, currentPin: String, newPin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.changePin(channel: channel, pairingBase64: pairing, currentPin: currentPin, newPin: newPin, resolve: resolve, reject: reject) }
    }

    @objc
    func unblockPin(_ pairing: String, puk: String, newPin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.unblockPin(channel: channel, pairingBase64: pairing, puk: puk, newPin: newPin, resolve: resolve, reject: reject) }
    }

    @objc
    func unpair(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.unpair(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func delete(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func removeKey(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.removeKey(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func removeKeyWithUnpair(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.removeKeyWithUnpair(channel: channel, pairingBase64: pairing, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func unpairAndDelete(_ pairing: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func startNFC(_ prompt: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        if (keycardController == nil) {
          self.keycardController = KeycardController(onConnect: { [unowned self] channel in
            self.cardChannel = channel
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            self.sendEvent(withName: "keyCardOnConnected", body: nil)
            self.keycardController?.setAlert("Connected. Don't move your card.")
          }, onFailure: { [unowned self] _ in
            self.cardChannel = nil
            self.sendEvent(withName: "keyCardOnDisconnected", body: nil)
          })
          keycardController?.start(alertMessage: prompt.isEmpty ? "Hold your iPhone near a Status Keycard." : prompt)
          resolve(true)
        } else {
          reject("E_KEYCARD", "already started", nil)
        }
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    @objc
    func stopNFC(_ err: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        if (err.isEmpty) {
          self.keycardController?.stop(alertMessage: "Success")
        } else {
          self.keycardController?.stop(errorMessage: err)
        }
        self.cardChannel = nil
        self.keycardController = nil
        resolve(true)
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    @objc
    func setNFCMessage(_ message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        self.keycardController?.setAlert(message)
        resolve(true)
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    override static func requiresMainQueueSetup() -> Bool {
      return true
    }

    override func supportedEvents() -> [String]! {
      return ["keyCardOnConnected", "keyCardOnDisconnected", "keyCardOnNFCEnabled", "keyCardOnNFCDisabled"]
    }

    func keycardInvokation(_ reject: @escaping RCTPromiseRejectBlock, body: @escaping (CardChannel) throws -> Void) {
      if self.cardChannel != nil {
        DispatchQueue.global().async { [unowned self] in
          do {
            try body(self.cardChannel!)
          } catch {
            var errMsg = ""

            if type(of: error) is NSError.Type {
              let nsError = error as NSError
              errMsg = "\(nsError.domain):\(nsError.code)"
              if nsError.code == 100 && nsError.domain == "NFCError" {
                self.sendEvent(withName: "keyCardOnDisconnected", body: nil)
              }
            } else {
              errMsg = "\(error)"
            }
            reject("E_KEYCARD", errMsg, error)
          }
        }
      } else {
        reject("E_KEYCARD", "not connected", nil)
      }
    }
}
