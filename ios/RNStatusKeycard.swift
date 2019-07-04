
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
        resolve(true)
    }
    
    @objc
    func nfcIsEnabled(
        _ resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock) -> Void {
        resolve(true)
    }
    
}
