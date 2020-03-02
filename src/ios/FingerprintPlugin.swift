
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

@objc(Fingerprint)
class FingerprintPlugin : TrinityPlugin {
    internal static let TAG = "FingerprintPlugin"
    
    internal let keyCode        = "code"
    internal let keyMessage     = "message"
    internal let keyException   = "exception"
    
    internal let errCodeParseJsonInAction          = 10000
    internal let errCodeInvalidArg                 = 10001
    internal let errCodeNullPointer                = 10002
    internal let errCodeDidStoreUninitialized      = 10003
    internal let errCodeInvalidDidDocment          = 10004
    internal let errCodeInvalidDid                 = 10005
    internal let errCodeInvalidPublicKey           = 10006
    internal let errCodeInvalidCredential          = 10007
    internal let errCodeLoadDid                    = 10008
    internal let errCodePublishDid                 = 10009
    internal let errCodeUpdateDid                  = 10010
    internal let errCodeLoadCredential             = 10011
    internal let errCodeDeleteCredential           = 10012
    internal let errCodeVerify                     = 10013
    internal let errCodeActionNotFound             = 10014
    internal let errCodeUnspecified                = 10015
    internal let errCodeDidException               = 20000
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
    
    private func success(_ command: CDVInvokedUrlCommand, retAsDict: NSDictionary) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK,
                                     messageAs: (retAsDict as! [AnyHashable : Any]));

        self.commandDelegate.send(result, callbackId: command.callbackId)
    }
    
    /** Dirty way to convert booleans to strings but we are following the original implementation mechanism for now. */
    private func success(_ command: CDVInvokedUrlCommand, retAsFakeBool: Bool) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: (retAsFakeBool ? "true" : "false"));

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
    
    private func exception(_ e: Error, _ command: CDVInvokedUrlCommand) {
        let msg = "(" + command.methodName + ") - " + e.localizedDescription
        
        NSLog(msg)
        
        self.error(command, code: errCodeException, msg: msg)
    }

    private func log(message: String) {
        NSLog(DIDPlugin.TAG+": "+message)
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
        
        //let pres = command.arguments[0] as! String
        
        let error = checkCanAuthenticate()
        if (error != nil) {
            success(command ,retAsString: "false")
        } else {
            success(command ,retAsString: "true")
        }
        
        /*do {
            let presentation = try VerifiablePresentation.fromJson(pres.description);

            let r = NSMutableDictionary()
            r.setValue(try presentation.isValid(), forKey: "isvalid");
            self.success(command, retAsDict: r)
        } catch {
            self.exception(error, command)
        }*/
    }
    
    @objc func authenticateAndSavePassword(_ command: CDVInvokedUrlCommand) {
        guard command.arguments.count == 2 else {
            self.sendWrongParametersCount(command, expected: 2)
            return
        }
        
        /*
        int idx = 0;
        let passwordKey = command.arguments[0] as! String
        let password = command.arguments[1] as! String
        
        let error = checkCanAuthenticate()
        if (error != nil) {
            error
            return;
        }

        CancellationSignal cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                System.out.println("CANCELLED");
            }
        });

        cordova.getActivity().runOnUiThread(() -> {
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getActivity(), getActiveDAppID());
            activeAuthHelper.init();
            activeAuthHelper.authenticateAndSavePassword(passwordKey, password, cancellationSignal, new FingerPrintAuthHelper.SimpleAuthenticationCallback() {
                @Override
                public void onSuccess() {
                    sendSuccess(null);
                }

                @Override
                public void onFailure(String message) {
                    sendError(-1, message);
                }

                @Override
                public void onHelp(int helpCode, String helpString) {
                    displayNotImplemented("ON HELP - "+helpString);
                }
            });
        });
        PluginResult pluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        pluginResult.setKeepCallback(true);
        this.mCallbackContext.sendPluginResult(pluginResult);*/
    }
    
    private func checkCanAuthenticate() -> FingerprintPluginError? {
        return nil
    }
}

private enum FingerprintPluginError: Int {
    typealias RawValue = Int
    
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
}
