
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

@objc(FingerprintPlugin)
class FingerprintPlugin : CDVPlugin {
    internal static let TAG = "FingerprintPlugin"

    internal let keyCode        = "code"
    internal let keyMessage     = "message"
    internal let keyException   = "exception"

    internal let errCodeInvalidArg                 = 10001
    internal let errCodeActionNotFound             = 10014
    internal let errCodeUnspecified                = 10015
    internal let errCodeException                  = 20001

    // Model

    // Methods

    private func success(_ command: CDVInvokedUrlCommand) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK);

        self.commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func success(_ command: CDVInvokedUrlCommand, retAsString: String) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK,
                                     messageAs: retAsString);

        self.commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func error(_ command: CDVInvokedUrlCommand, retAsString: String) {
        self.error(command, code: errCodeUnspecified, msg: retAsString)
    }

    private func error(_ command: CDVInvokedUrlCommand, code: Int, msg: String) {
       let errJson : NSMutableDictionary = [:]
       errJson.setValue(code, forKey: keyCode)
       errJson.setValue(msg, forKey: keyMessage)

       self.log(message: "(" + command.methodName + ") - " + errJson.description)

       let result = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: (errJson as! [AnyHashable : Any]))
       self.commandDelegate.send(result, callbackId: command.callbackId)
   }

    private func error(_ command: CDVInvokedUrlCommand, _ e: FingerprintPluginError?) {
        self.error(command, code: e?.rawValue ?? -1, msg: "")
    }

    private func exception(_ e: Error, _ command: CDVInvokedUrlCommand) {
        let msg = "(" + command.methodName + ") - " + e.localizedDescription

        NSLog(msg)

        self.error(command, code: errCodeException, msg: msg)
    }

    private func log(message: String) {
        NSLog(FingerprintPlugin.TAG+": "+message)
    }

    private func sendWrongParametersCount(_ command: CDVInvokedUrlCommand, expected: Int) {
        self.error(command, code: errCodeInvalidArg, msg: "Wrong number of parameters passed. Expected \(expected).")
            return
    }

    @objc func isBiometricAuthenticationMethodAvailable(_ command: CDVInvokedUrlCommand) {
        guard command.arguments.count == 0 else {
            self.sendWrongParametersCount(command, expected: 0)
            return
        }

        let error = checkCanAuthenticate()
        if (error != nil) {
            success(command ,retAsString: "false")
        } else {
            success(command ,retAsString: "true")
        }
    }

    @objc func authenticateAndSavePassword(_ command: CDVInvokedUrlCommand) {
        guard command.arguments.count == 2 else {
            self.sendWrongParametersCount(command, expected: 2)
            return
        }

        let passwordKey = command.arguments[0] as! String
        let password = command.arguments[1] as! String

        let canAuthenticate = checkCanAuthenticate()
        if (canAuthenticate != nil) {
            error(command, canAuthenticate)
            return
        }

        let activeAuthHelper = FingerPrintAuthHelper(did: "")
        activeAuthHelper.authenticateAndSavePassword(passwordKey: passwordKey, password: password) {
            err in

            if let err = err {
                self.error(command, err)
            }
            else {
                self.success(command)
            }
        }
    }

    @objc func authenticateAndGetPassword(_ command: CDVInvokedUrlCommand) {
        guard command.arguments.count == 1 else {
            self.sendWrongParametersCount(command, expected: 1)
            return
        }

        let passwordKey = command.arguments[0] as! String

        let canAuthenticate = checkCanAuthenticate()
        if (canAuthenticate != nil) {
            error(command, canAuthenticate)
            return
        }

        let activeAuthHelper = FingerPrintAuthHelper(did: "")
        activeAuthHelper.authenticateAndGetPassword(passwordKey: passwordKey) {
            password, err in

            if let err = err {
                self.error(command, err)
            }
            else {
                if let password = password {
                    self.success(command, retAsString: password)
                }
                else {
                    self.error(command, FingerprintPluginError.NO_PASSWORD_INFO)
                }
            }
        }
    }

    @objc func authenticate(_ command: CDVInvokedUrlCommand) {
        guard command.arguments.count == 0 else {
            self.sendWrongParametersCount(command, expected: 0)
            return
        }

        let canAuthenticate = checkCanAuthenticate()
        if (canAuthenticate != nil) {
            error(command, canAuthenticate)
            return
        }

        let activeAuthHelper = FingerPrintAuthHelper(did: "")
        activeAuthHelper.authenticate() {
            err in

            if let err = err {
                self.error(command, err)
            }
            else {
                self.success(command)
            }
        }
    }

    private func checkCanAuthenticate() -> FingerprintPluginError? {
        let context = LAContext()
        var error: NSError?

        let evaluation = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if evaluation {
            return nil
        }
        else {
            //TODO if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {

            return .BIOMETRIC_HARDWARE_NOT_SUPPORTED
        }
    }
}

public enum FingerprintPluginError: Int {
    public typealias RawValue = Int

    // Biometric errors
    case BIOMETRIC_AUTHENTICATION_FAILED = -102
    case BIOMETRIC_HARDWARE_NOT_SUPPORTED = -104
    case BIOMETRIC_NOT_ENROLLED = -106
    case BIOMETRIC_DISMISSED = -108
    case BIOMETRIC_PIN_OR_PATTERN_DISMISSED = -109
    case BIOMETRIC_SCREEN_GUARD_UNSECURED = -110
    case BIOMETRIC_LOCKED_OUT = -111
    case BIOMETRIC_LOCKED_OUT_PERMANENT = -112

    // Generic errors
    case INVALID_PARAMETERS_COUNT = -2
    case NO_PASSWORD_INFO = -3
}
