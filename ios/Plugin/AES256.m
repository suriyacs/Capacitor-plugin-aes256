#import <Foundation/Foundation.h>
#import <Capacitor/Capacitor.h>

// Define the plugin using the CAP_PLUGIN Macro, and
// each method the plugin supports using the CAP_PLUGIN_METHOD macro.
CAP_PLUGIN(AES256, "AES256",
           CAP_PLUGIN_METHOD(encrypt, CAPPluginReturnPromise);
           CAP_PLUGIN_METHOD(decrypt, CAPPluginReturnPromise);
           CAP_PLUGIN_METHOD(generateSecureKey, CAPPluginReturnPromise);
           CAP_PLUGIN_METHOD(generateSecureIv, CAPPluginReturnPromise);
)
