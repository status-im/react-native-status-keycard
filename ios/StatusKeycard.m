#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_REMAP_MODULE(RNStatusKeycard, StatusKeycard, NSObject)

RCT_EXTERN_METHOD(nfcIsSupported:(RCTPromiseResolveBlock)resolve rejecter: (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(openNfcSettings:(RCTPromiseResolveBlock)resolve rejecter: (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(signPinless:(NSString *)hash resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)


@end
