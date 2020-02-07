package org.elastos.trinity.plugins.fingerprint;

import android.annotation.TargetApi;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.util.Log;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.elastos.trinity.runtime.TrinityPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static android.content.Context.FINGERPRINT_SERVICE;

public class Fingerprint extends TrinityPlugin {
    private static final String TAG = "FingerprintPlugin";
    private CallbackContext mCallbackContext = null;

    private static FingerPrintAuthHelper activeAuthHelper = null;

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "Init Fingerprint");
    }

    public boolean execute(final String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        this.mCallbackContext = callbackContext;
        Log.v(TAG, "Fingerprint action: " + action);

        switch (action) {
            case "isAvailable":
                executeIsAvailable();
                return true;
            case "authenticateAndSavePassword":
                Intent i = new Intent();
                executeAuthenticateAndSavePassword(args);
                return true;
            case "authenticateAndGetPassword":
                executeAuthenticateAndGetPassword(args);
                return true;
            case "authenticate":
                executeAuthenticate(args);
                return true;
            default:
                return false;
        }
    }

    private void executeIsAvailable() {
        PluginError error = canAuthenticate();
        if (error != null) {
            sendError(error);
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P){
            sendSuccess("biometric");
        } else {
            sendSuccess("finger");
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void executeAuthenticateAndSavePassword(JSONArray args) throws JSONException {
        PluginError error = canAuthenticate();
        if (error != null) {
            sendError(error);
            return;
        }

        int idx = 0;
        String passwordKey = args.getString(idx++);
        String password = args.getString(idx++);

        if (args.length() != idx) {
            sendError(PluginError.INVALID_PARAMETERS_COUNT);
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
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getContext(), getActiveDAppID());
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
        this.mCallbackContext.sendPluginResult(pluginResult);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void executeAuthenticateAndGetPassword(JSONArray args) throws JSONException {
        PluginError error = canAuthenticate();
        if (error != null) {
            sendError(error);
            return;
        }

        int idx = 0;
        String passwordKey = args.getString(idx++);

        if (args.length() != idx) {
            sendError(PluginError.INVALID_PARAMETERS_COUNT);
            return;
        }

        cordova.getActivity().runOnUiThread(() -> {
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getContext(), getActiveDAppID());
            activeAuthHelper.init();
            activeAuthHelper.authenticateAndGetPassword(passwordKey, new CancellationSignal(), new FingerPrintAuthHelper.GetPasswordAuthenticationCallback() {
                @Override
                public void onSuccess(String password) {
                    // User authenticated and the previously saved password was decrypted
                    sendSuccess(password);
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
        this.mCallbackContext.sendPluginResult(pluginResult);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void executeAuthenticate(JSONArray args) {
        PluginError error = canAuthenticate();
        if (error != null) {
            sendError(error);
            return;
        }
        cordova.getActivity().runOnUiThread(() -> {
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getContext(), getActiveDAppID());
            activeAuthHelper.init();
            activeAuthHelper.authenticate(new CancellationSignal(), new FingerPrintAuthHelper.SimpleAuthenticationCallback() {
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
        this.mCallbackContext.sendPluginResult(pluginResult);
    }

    private PluginError canAuthenticate() {
        // TODO: re-enable code for API 29+ after we increase our target API version.
        /*if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return cordova.getContext().getSystemService(android.hardware.biometrics.BiometricManager.class).canAuthenticate(mBiometricManager);
        } else {*/
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
        }

        FingerprintManager fingerprintManager = fingerprintManager = (FingerprintManager) cordova.getContext().getSystemService(FINGERPRINT_SERVICE);
        if (fingerprintManager == null)
            return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
        else if (!fingerprintManager.isHardwareDetected()) {
            return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
            return PluginError.BIOMETRIC_NOT_ENROLLED;
        }
        //}

        return null;
    }

    private void sendError(int code, String message) {
        JSONObject resultJson = new JSONObject();
        try {
            resultJson.put("code", code);
            resultJson.put("message", message);

            PluginResult result = new PluginResult(PluginResult.Status.ERROR, resultJson);
            result.setKeepCallback(true);
            cordova.getActivity().runOnUiThread(() -> {
                    Fingerprint.this.mCallbackContext.sendPluginResult(result);
            });
        } catch (JSONException e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    private void sendError(PluginError error) {
        sendError(error.getValue(), error.getMessage());
    }

    private void sendSuccess(String message) {
        cordova.getActivity().runOnUiThread(() -> {
            if (message != null)
                this.mCallbackContext.success(message);
            else
                this.mCallbackContext.success();
        });
    }

    /**
     * Reference to a static global auth helper used by the authentication activity for convenience.
     */
    static FingerPrintAuthHelper getActiveAuthHelper() {
        return activeAuthHelper;
    }

    private void displayNotImplemented(String message) {
        Log.d(TAG, "NOT YET IMPLEMENTED - "+message);
    }

    /**
     * App package ID of the currently active DApp calling this plugin.
     */
    private String getActiveDAppID() {
        return appId;
    }
}
