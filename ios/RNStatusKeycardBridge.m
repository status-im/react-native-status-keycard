#import <React/RCTBridgeModule.h>

// - (dispatch_queue_t)methodQueue
// {
//     return dispatch_queue_create("im.status.KeycardQueue", DISPATCH_QUEUE_SERIAL);
// }

@interface RCT_EXTERN_MODULE(RNStatusKeycard, NSObject)

RCT_EXTERN_METHOD(nfcIsEnabled: (RCTPromiseResolveBlock)resolve
                  rejecter: (__unused RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(nfcIsSupported: (RCTPromiseResolveBlock)resolve
                  rejecter: (__unused RCTPromiseRejectBlock)reject)

@end
