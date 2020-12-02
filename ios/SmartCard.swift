import Foundation
import Keycard

@available(iOS 13.0, *)
class SmartCard {
    func nfcIsSupported() -> Bool {
      return KeycardController.isAvailable
    } 

    func initCard(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      //let cmdSet = KeycardCommandSet(cardChannel: channel)
      //cmdSet.select().checkOK()
      //SmartCardSecrets s = SmartCardSecrets.generate(userPin);
      //cmdSet.init(s.getPin(), s.getPuk(), s.getPairingPassword()).checkOK();
    } 

    func signPinless(channel: CardChannel, hash: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = CashCommandSet(cardChannel: channel)
      let info = try CashApplicationInfo(cmdSet.select().checkOK().data)      
      let message = self.hexToBytes(hash)
      let res = try cmdSet.sign(data: message).checkOK()
      
      resolve(res.data.toHexString())
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
