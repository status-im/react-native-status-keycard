import Foundation
import Keycard

@objc(StatusKeycard)
class StatusKeycard: NSObject {

    @available(iOS 13.0, *)
    private(set) lazy var keycardController: KeycardController? = nil

    @objc(multiply:withB:withResolver:withRejecter:)
    func multiply(a: Float, b: Float, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        resolve(a*b)
    }

    @objc
    func select() {
      if #available(iOS 13.0, *) {
        keycardController = KeycardController(onConnect: { [unowned self] channel in
            do {
            let cmdSet = KeycardCommandSet(cardChannel: channel)
            let info = try ApplicationInfo(cmdSet.select().checkOK().data)
            print(info)
            self.keycardController?.stop(alertMessage: "Success")
            } catch {
            print("Error: \(error)")
            self.keycardController?.stop(errorMessage: "Read error. Please try again.")
            }
            self.keycardController = nil
            }, onFailure: { [unowned self] error in
            print("Disconnected: \(error)")
            self.keycardController = nil
            })
        keycardController?.start(alertMessage: "Hold your iPhone near a Status Keycard.")
      } else {
        print("Unavailable")
      }
    }

    @objc
    func hasKeycardSDK(_ resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        resolve(true)
      } else {
        resolve(false)
      }
    }

    @objc
    func hasNFC(_ resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        resolve(KeycardController.isAvailable)
      } else {
        resolve(false)
      }
    }

    @objc
    static func requiresMainQueueSetup() -> Bool {
      return true
    }
}
