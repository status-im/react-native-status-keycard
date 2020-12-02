import Foundation
import Keycard

@objc(StatusKeycard)
class StatusKeycard: NSObject {
    @available(iOS 13.0, *)
    private(set) lazy var smartCard: SmartCard? = nil

    override init() {
      super.init()

      if #available(iOS 13.0, *) {
        self.smartCard = SmartCard()
      }    
    }

    @objc
    func nfcIsSupported(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        resolve(smartCard?.nfcIsSupported())
      } else {
        resolve(false)
      }
    }

    @objc
    func nfcIsEnabled(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
      // On iOS NFC is always enabled (if available)
      nfcIsSupported(resolve, rejecter: reject)
    }    

    @objc
    func openNfcSettings(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
      // NFC cannot be enabled/disabled
      reject("E_KEYCARD", "Unsupported on iOS", nil)
    }

    @objc
    func `init`(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in if #available(iOS 13.0, *) { try self.smartCard?.initCard(channel: channel, pin: pin, resolve: resolve, reject: reject) } }
    }

    @objc
    func signPinless(_ hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in if #available(iOS 13.0, *) { try self.smartCard?.signPinless(channel: channel, hash: hash, resolve: resolve, reject: reject)} }
    }
    
    @objc
    static func requiresMainQueueSetup() -> Bool {
      return true
    }

    func keycardInvokation(_ reject: @escaping RCTPromiseRejectBlock, body: @escaping (CardChannel) throws -> Void) {
      if #available(iOS 13.0, *) {
        DispatchQueue.main.async {
          var keycardController: KeycardController? = nil;
          keycardController = KeycardController(onConnect: { channel in
            do {
              try body(channel)
              keycardController?.stop(alertMessage: "Success")
            } catch {
              reject("E_KEYCARD", "error", error)
              keycardController?.stop(errorMessage: "Read error. Please try again.")
            }      
          }, onFailure: { error in
            reject("E_KEYCARD", "disconnected", error)
          })

          keycardController?.start(alertMessage: "Hold your iPhone near a Status Keycard.")
        }
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }      
    }
}
