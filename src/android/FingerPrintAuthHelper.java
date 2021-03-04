package org.elastos.essentials.plugins.fingerprint;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;

import android.os.Bundle;
import android.os.CancellationSignal;
import android.util.Log;
import org.apache.cordova.CordovaPlugin;

import static android.content.Context.KEYGUARD_SERVICE;

/**
 * Initially from https://riptutorial.com/android/example/29719/how-to-use-android-fingerprint-api-to-save-user-passwords
 * then largely reworked and adjusted for Elastos Essentials.
 */
public class FingerPrintAuthHelper {
    private static final String FINGER_PRINT_HELPER = "FingerPrintAuthHelper";
    private static final String TAG = "FingerPrintAuthHelper";

    private static final int REQUEST_CODE_BIOMETRIC = 1;
    private PromptInfo.Builder mPromptInfoBuilder;

    private final Activity activity;
    private final CordovaPlugin cordovaPlugin;
    private final String did; // Signed in DID string
    AuthenticationCallback listener;

    private String lastError;

    public interface AuthenticationCallback {
        void onFailure(String message);
        void onSuccess(String password);
    }

    public FingerPrintAuthHelper(CordovaPlugin cordovaPlugin, String did) {
        this.cordovaPlugin = cordovaPlugin;
        this.activity = cordovaPlugin.cordova.getActivity();
        this.did = did;
    }

    public String getLastError() {
        return lastError;
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean init() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            setError("This Android version does not support fingerprint authentication");
            return false;
        }

        KeyguardManager keyguardManager = (KeyguardManager) activity.getSystemService(KEYGUARD_SERVICE);
        if (!keyguardManager.isKeyguardSecure()) {
            setError("User hasn't enabled Lock Screen");
            return false;
        }

        if (!hasPermission()) {
            setError("User hasn't granted permission to use Fingerprint");
            return false;
        }

        mPromptInfoBuilder = new PromptInfo.Builder();
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean hasPermission() {
        return ActivityCompat.checkSelfPermission(activity, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void startActivityToAuthenticate() {
        Intent intent = new Intent(this.activity.getApplicationContext(), BiometricActivity.class);
        intent.putExtras(mPromptInfoBuilder.build().getBundle());
        this.cordovaPlugin.cordova.startActivityForResult(this.cordovaPlugin, intent, REQUEST_CODE_BIOMETRIC);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticateAndSavePassword(@NonNull String passwordKey, @NonNull String password, AuthenticationCallback callback) {
        mPromptInfoBuilder.setType(BiometricActivityType.REGISTER_SECRET);
        mPromptInfoBuilder.setPassword(password);
        mPromptInfoBuilder.setPasswordKey(passwordKey);
        listener = callback;

        startActivityToAuthenticate();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticateAndGetPassword(@NonNull String passwordKey, AuthenticationCallback callback) {
        mPromptInfoBuilder.setType(BiometricActivityType.LOAD_SECRET);
        mPromptInfoBuilder.setPasswordKey(passwordKey);
        listener = callback;

        startActivityToAuthenticate();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticate(AuthenticationCallback callback) {
        mPromptInfoBuilder.setType(BiometricActivityType.JUST_AUTHENTICATE);
        listener = callback;
        startActivityToAuthenticate();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void setActivityResult(int requestCode, int resultCode, Intent intent) {
        if (resultCode != Activity.RESULT_OK) {
            sendError(intent);
            return;
        }
        sendSuccessWithIntent(intent);
    }

    private void sendSuccessWithIntent(Intent intent) {
        if (intent != null && intent.getExtras() != null) {
            listener.onSuccess(intent.getExtras().getString(PromptInfo.SECRET_EXTRA));
        } else {
            listener.onSuccess("biometric_success");
        }
    }

    private void sendError(Intent intent) {
        if (intent != null) {
            Bundle extras = intent.getExtras();
            listener.onFailure(extras.getString("message"));
        } else {
            listener.onFailure("Authentication failed");
        }
    }

    private void setError(String error) {
        lastError = error;
        Log.w(FINGER_PRINT_HELPER, lastError);
    }
}