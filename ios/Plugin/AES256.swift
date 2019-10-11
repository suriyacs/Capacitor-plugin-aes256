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
        call.resolve([
            "value": value
        ])
    }

    // Encrypts the plain text using aes256 encryption alogrithm
    @objc func encrypt(_ call: CAPPluginCall) {
        let secureKey = call.getString("secureKey") ?? "";
        let iv = call.getString("iv") ?? "";
        let value = call.getString("value") ?? "";
        let encrypted = AES256CBC.encryptString(value, password: secureKey, iv: iv) ?? "";
        call.resolve([
            "response": encrypted
        ])
    }

    // Decrypts the aes256 encoded string into plain text
    @objc func decrypt(_ call: CAPPluginCall) {
        let secureKey = call.getString("secureKey") ?? "";
        let iv = call.getString("iv") ?? "";
        let value = call.getString("value") ?? "";
        let decrypted = AES256CBC.decryptString(value, password: secureKey, iv: iv) ?? "";
        call.resolve([
            "response": decrypted
        ])
        
    }

    // Generates the secure key from the given password
    @objc func generateSecureKey(_ call: CAPPluginCall) {
        let password = call.getString("password") ?? "";
        let secureKey = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_KEY_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT) ?? "";
        call.resolve([
            "response": secureKey
        ])
    }

    // Generates the IV from the given password
    @objc func generateSecureIv(_ call: CAPPluginCall) {
        let password = call.getString("password") ?? "";
        let secureIV = PBKDF2.pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password:password, salt:AES256CBC.generateSalt(), keyByteCount:AES256.SECURE_IV_LENGTH, rounds:AES256.PBKDF2_ITERATION_COUNT) ?? "";
        call.resolve([
            "response": secureIV
        ])
    }
}
