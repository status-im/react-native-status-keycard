import Foundation
import Keycard

@objc(StatusKeycard)
class StatusKeycard: NSObject {

    @available(iOS 13.0, *)
    private(set) lazy var keycardController: KeycardController? = nil

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
    func openNfcSettings(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        reject("E_KEYCARD", "Unsupported on iOS", nil)
    }

    @objc
    func signPinless(_ hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
        if #available(iOS 13.0, *) {
            DispatchQueue.main.async {
                self.keycardController = KeycardController(onConnect: { [unowned self] channel in
                    do {
                        let cmdSet = CashCommandSet(cardChannel: channel)
                        let info = try CashApplicationInfo(cmdSet.select().checkOK().data)
                        print("SELECT")
                        print(info)
                        
                        let message = self.hexToBytes(hash)
                        let res = try cmdSet.sign(data: message).checkOK()
                        print("SELECT")
                        print(res)
                        
                        self.keycardController?.stop(alertMessage: "SELECT: Success")
                        print("DONE!")
                        resolve(res.data.toHexString())
                    } catch {
                        reject("E_KEYCARD", "error", nil)
                        print("Error: \(error)")
                        self.keycardController?.stop(errorMessage: "Read error. Please try again.")
                    }
                        self.keycardController = nil
                    }, onFailure: { [unowned self] error in
                        reject("E_KEYCARD", "disconnected", nil)
                        print("Disconnected: \(error)")
                        self.keycardController = nil
                    })
                self.keycardController?.start(alertMessage: "Hold your iPhone near a Status Keycard.")
            }
        } else {
            print("Unavailable")
            reject("E_KEYCARD", "unavailable", nil)
        }
    }
    
    

    @objc
    func nfcIsSupported(_ resolve: RCTPromiseResolveBlock, rejecter _: RCTPromiseRejectBlock) -> Void {
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
    
    func hexToBytes(_ hex: String) -> [UInt8] {
        var last = hex.first
        return hex.dropFirst().compactMap {
            guard
                    let lastHexDigitValue = last?.hexDigitValue,
                    let hexDigitValue = $0.hexDigitValue else {
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
