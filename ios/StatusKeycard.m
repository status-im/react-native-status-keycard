#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(StatusKeycard, NSObject)

RCT_EXTERN_METHOD(multiply:(float)a withB:(float)b
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(hasKeycardSDK:(RCTPromiseResolveBlock)resolve rejecter: (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(hasNFC:(RCTPromiseResolveBlock)resolve rejecter: (RCTPromiseRejectBlock)reject)

@end
