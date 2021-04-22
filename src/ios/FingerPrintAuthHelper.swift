/*
 * Copyright (c) 2019 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import Foundation
import LocalAuthentication

public typealias AuthenticationCallback = (FingerprintPluginError?) -> Void

public class FingerPrintAuthHelper {
    private static let FINGER_PRINT_HELPER = "FingerPrintAuthHelper"
    private static let KEYCHAIN_PASS_KEY = "KEYCHAIN_PASS_KEY"
    private static let KEYSTORE_APP_ALIAS = "Trinity"
    private static let TAG = "FingerPrintAuthHelper"

    private let did: String

    // TODO remove did and dAppID
    init(did: String, dAppID: String) {
        self.did = did
    }

    public enum BiometryState {
        case available, locked, notAvailable
    }

    /**
     * Current state of the biometric sensors
     */
    public var biometryState: BiometryState {
        let authContext = LAContext()
        var error: NSError?

        let biometryAvailable = authContext.canEvaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {
            return .locked
        }

        return biometryAvailable ? .available : .notAvailable
    }

    /**
     * Creates a keychain entry accessible only after a biometry check
     */
    func createBioProtectedEntry(key: String, data: Data) -> OSStatus {
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecAttrAccessControl as String: getBioSecAccessControl(),
            kSecValueData as String   : data ] as CFDictionary

        return SecItemAdd(query as CFDictionary, nil)
    }

    /**
     * Saves a password to keychain, for a given password key.
     * Password keys are user defined keys, simply used to be able to store multiple passwords for a same dApp.
     */
    private func savePassword(passwordKey: String, password: String) {
        // Sandbox dApps by storing passwords using the dApp package id as prefix.
        let data = password.data(using: .utf8)!
        _ = createBioProtectedEntry(key: getPasswordKeychainStorageKey(passwordKey: passwordKey), data: data)
    }

    private func getPasswordKeychainStorageKey(passwordKey: String) -> String {
        return FingerPrintAuthHelper.KEYCHAIN_PASS_KEY + did + passwordKey
    }

    private func getBioSecAccessControl() -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?

        if #available(iOS 11.3, *) {
            access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .biometryCurrentSet,
                                                     &error)
        } else {
            access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .touchIDCurrentSet,
                                                     &error)
        }
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }

    /**
     * Reads a saved password entry from keychain, configuring the biometry protection requirement
     * (can't read without biometry auth completed)
     */
    func loadBioProtected(key: String, context: LAContext? = nil, prompt: String? = nil) -> Data? {
        var query: [String: Any] = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecAttrAccessControl as String: getBioSecAccessControl(),
            kSecMatchLimit as String  : kSecMatchLimitOne ]

        if let context = context {
            query[kSecUseAuthenticationContext as String] = context

            // Prevent system UI from automatically requesting Touch ID/Face ID authentication
            // just in case someone passes here an LAContext instance without
            // a prior evaluateAccessControl call
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }

        if let prompt = prompt {
            query[kSecUseOperationPrompt as String] = prompt
        }

        var dataTypeRef: AnyObject? = nil

        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == noErr {
            return (dataTypeRef! as! Data)
        } else {
            if #available(iOS 11.3, *) {
                NSLog(FingerPrintAuthHelper.TAG, "Failed to load biometric password with error: \(SecCopyErrorMessageString(status, nil) as String?)")
            }
            return nil
        }
    }

    private func getSavedPassword(passwordKey: String, context: LAContext) -> String? {
        if let data = loadBioProtected(key: getPasswordKeychainStorageKey(passwordKey: passwordKey), context: context) {
            return String(data: data, encoding: .utf8)
        }

        return nil
    }

    private func checkBiometryState(_ completion: @escaping (Bool)->Void) {
        let bioState = self.biometryState
        guard bioState != .notAvailable else {
            // Can't read entry, biometry not available
            DispatchQueue.main.async {
                completion(false)
            }
            return
        }
        if bioState == .locked {
            // To unlock biometric authentication iOS requires user to enter a valid passcode
            let authContext = LAContext()
            authContext.evaluatePolicy(LAPolicy.deviceOwnerAuthentication, localizedReason: "Access sample keychain entry", reply: { (success, error) in

                DispatchQueue.main.async {
                    if success {
                        completion(true)
                    } else {
                        // Can't read entry, check error for details
                        completion(false)
                    }
                }
            })
        } else {
            DispatchQueue.main.async {
                completion(true)
            }
        }
    }

    private func laErrorToFingerprintPluginError(_ laError: LAError) -> FingerprintPluginError {
        switch laError {
        case LAError.authenticationFailed:
            return .BIOMETRIC_AUTHENTICATION_FAILED
        case LAError.userCancel:
            return .BIOMETRIC_DISMISSED
        case LAError.userFallback:
            return .BIOMETRIC_AUTHENTICATION_FAILED
        case LAError.biometryNotAvailable:
            return .BIOMETRIC_HARDWARE_NOT_SUPPORTED
        case LAError.biometryNotEnrolled:
            return .BIOMETRIC_NOT_ENROLLED
        case LAError.biometryLockout:
            return .BIOMETRIC_LOCKED_OUT
        default:
            return .BIOMETRIC_AUTHENTICATION_FAILED
        }
    }

    private func _authenticate(_ completion: @escaping (FingerprintPluginError?, LAContext)->Void) {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Authenticate") { (success, evaluateError) in
            DispatchQueue.main.async {
                if success {
                    completion(nil, context)
                } else {
                    completion(self.laErrorToFingerprintPluginError(evaluateError as! LAError), context)
                }
            }
        }
    }

    func authenticateAndSavePassword(passwordKey: String, password: String, callback: @escaping (FingerprintPluginError?)->Void) {

        _authenticate { err, context in
            guard err == nil else {
                callback(err)
                return
            }

            // Biometry auth was completed and successful
            self.savePassword(passwordKey: passwordKey, password: password)

            callback(nil)
        }
    }

    func authenticateAndGetPassword(passwordKey: String, callback: @escaping (String?, FingerprintPluginError?)->Void) {

        _authenticate { err, context in
            guard err == nil else {
                callback(nil, err)
                return
            }

            // Biometry auth was completed and successful
            callback(self.getSavedPassword(passwordKey: passwordKey, context: context), nil)
        }
    }

    func authenticate(callback: @escaping (FingerprintPluginError?)->Void) {
        _authenticate { err, context in
            guard err == nil else {
                callback(err)
                return
            }

            // Biometry auth was completed and successful
            callback(nil)
        }
    }
}
