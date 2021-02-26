package org.elastos.trinity.plugins.fingerprint;

import android.annotation.TargetApi;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.util.Log;

import androidx.biometric.BiometricManager;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static android.content.Context.FINGERPRINT_SERVICE;

public class FingerprintPlugin extends CordovaPlugin {
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
            case "isBiometricAuthenticationMethodAvailable":
                executeIsBiometricAuthenticationMethodAvailable();
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

    private void executeIsBiometricAuthenticationMethodAvailable() {
        PluginError error = checkCanAuthenticate();
        if (error != null) {
            sendSuccess("false");
        } else {
            sendSuccess("true");
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void executeAuthenticateAndSavePassword(JSONArray args) throws JSONException {
        PluginError error = checkCanAuthenticate();
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
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getActivity(), "", getActiveDAppID());
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
        PluginError error = checkCanAuthenticate();
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
            // TODO remove did
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getActivity(), "", getActiveDAppID());
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
        PluginError error = checkCanAuthenticate();
        if (error != null) {
            sendError(error);
            return;
        }
        cordova.getActivity().runOnUiThread(() -> {
            // TODO remove did
            activeAuthHelper = new FingerPrintAuthHelper(cordova.getActivity(), "", getActiveDAppID());
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

    private PluginError checkCanAuthenticate() {
        BiometricManager biometricManager = BiometricManager.from(cordova.getContext().getApplicationContext());
        switch (biometricManager.canAuthenticate()) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d(TAG, "App can authenticate using biometrics.");
                return null;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e(TAG, "No biometric features available on this device.");
                return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.e(TAG, "Biometric features are currently unavailable.");
                return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                Log.e(TAG, "The user hasn't associated any biometric credentials with their account.");
                return PluginError.BIOMETRIC_NOT_ENROLLED;
            default:
                return PluginError.BIOMETRIC_HARDWARE_NOT_SUPPORTED;
        }
    }

    private void sendError(int code, String message) {
        JSONObject resultJson = new JSONObject();
        try {
            resultJson.put("code", code);
            resultJson.put("message", message);

            PluginResult result = new PluginResult(PluginResult.Status.ERROR, resultJson);
            result.setKeepCallback(true);
            cordova.getActivity().runOnUiThread(() -> {
                    FingerprintPlugin.this.mCallbackContext.sendPluginResult(result);
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
        // TODO remove this
        return "";
    }
}
