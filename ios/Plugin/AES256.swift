import Foundation
import Capacitor
import CommonCrypto;


/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitor.ionicframework.com/docs/plugins/ios
 */
@objc(AES256)
public class AES256: CAPPlugin {

    private static let SECURE_KEY_LENGTH = 16;
    private static let SECURE_IV_LENGTH = 8;
    private static let PBKDF2_ITERATION_COUNT = 1001;
    private static let aes256Queue = DispatchQueue(label: "AESQUEUE", qos: DispatchQoS.background, attributes: .concurrent)
    
    @objc func echo(_ call: CAPPluginCall) {
        let value = call.getString("value") ?? ""
        call.success([
            "value": value
        ])
    }

    // Encrypts the plain text using aes256 encryption alogrithm
    @objc(encrypt:) func encrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs: "Error occurred while performing Encryption"
            )
            let secureKey = call.getString("secureKey")
            let iv = call.getString("iv")
            let value = call.getString("value")
            let encrypted = AES256CBC.encryptString(value, password: secureKey, iv: iv)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
            call.success([
                "response": pluginResult
            ])
        }
    }

    // Decrypts the aes256 encoded string into plain text
    @objc(decrypt:) func decrypt(_ command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            var pluginResult = CDVPluginResult(
              status: CDVCommandStatus_ERROR,
              messageAs: "Error occurred while performing Decryption"
            )
            let secureKey = call.getString("secureKey")
            let iv = call.getString("iv")
            let value = call.getString("value")
            let decrypted = AES256CBC.decryptString(value, password: secureKey, iv: iv)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: decrypted)
            call.success([
                "response": pluginResult
            ])
        }
    }

    // Generates the secure key from the given password
    @objc(generateSecureKey:) func generateSecureKey(_ call: CAPPluginCall) {
      AES256.aes256Queue.async {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while generating secure key"
        )
        let password = call.getString("password")
        let secureKey:String? = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_KEY_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT)
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: secureKey)
        call.success([
            "response": pluginResult
        ])
      }
    }

    // Generates the IV from the given password
    @objc(generateSecureIV:) func generateSecureIV(_ call: CAPPluginCall) {
      AES256.aes256Queue.async {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: "Error occurred while generating secure IV"
        )
        let password = call.getString("password");
        let secureIV:String? = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_IV_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT)
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: secureIV)
        call.success([
            "response": pluginResult
        ])
      }
    }
}
