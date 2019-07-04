import CoreNFC

@objc(RNStatusKeycard)
class RNStatusKeycard: NSObject {
    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    @objc
    func nfcIsSupported(
        _ resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock) -> Void {
        if #available(iOS 9.0, *) {
            resolve(true)
        } else {
            resolve(false)
        }

    }
    
    @objc
    func nfcIsEnabled(
        _ resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock) -> Void {
        if NFCNDEFReaderSession.readingAvailable {
            resolve(true)
        } else {
            resolve(false)
        }

    }
    
}
