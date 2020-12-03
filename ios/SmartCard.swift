import Foundation
import Keycard

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
      try cmdSet.select().checkOK()    
      try cmdSet.autoPair(password: pairingPassword);

      resolve(Data(cmdSet.pairing!.bytes).base64EncodedString());
    }    

    func signPinless(channel: CardChannel, hash: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = CashCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()

      let message = self.hexToBytes(hash)
      let res = try cmdSet.sign(data: message).checkOK()
      
      resolve(res.data.toHexString())
    }

    func randomPUK() -> String {
      return String(format: "%012d", Int.random(in: 0..<999999999999))
    }

    func randomPairingPassword() -> String {
      let letters = "23456789ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      return String((0..<16).map{ _ in letters.randomElement()! })      
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
