package org.elastos.trinity.plugins.fingerprint;

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

@TargetApi(Build.VERSION_CODES.M)
public class AuthenticateActivity extends AppCompatActivity {
    private static final String TAG = "AuthenticateActivity";
    FingerPrintAuthHelper globalAuthHelper;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setTitle(null);
        int layout = getResources().getIdentifier("biometric_activity", "layout", getPackageName());
        setContentView(layout);

        if (savedInstanceState != null) {
            return;
        }

        globalAuthHelper = Fingerprint.getActiveAuthHelper();

        FingerprintManager fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        FingerprintManager.CryptoObject crypto = new FingerprintManager.CryptoObject(globalAuthHelper.getActivityInfoHolder().cipher);
        fingerprintManager.authenticate(crypto, globalAuthHelper.getActivityInfoHolder().cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                Log.d(TAG, "Authentication error");

                // Authentication failed permanently - exit the activity
                finish();

                globalAuthHelper.getActivityInfoHolder().listener.onAuthenticationError(errorCode, errString);
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                Log.d(TAG, "Authentication help");
                globalAuthHelper.getActivityInfoHolder().listener.onAuthenticationHelp(helpCode, helpString);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                Log.d(TAG, "Authentication succeeded");

                // Authentication completed - exit the activity
                finish();

                globalAuthHelper.getActivityInfoHolder().listener.onAuthenticationSucceeded(result);
            }

            @Override
            public void onAuthenticationFailed() {
                Log.d(TAG, "Authentication failed");
                globalAuthHelper.getActivityInfoHolder().listener.onAuthenticationFailed();
            }
        }, null);
    }

    @Override
    public void onBackPressed() {
        Log.d(TAG, "Back key pressed - cancelling fingerprint authentication");

        globalAuthHelper.getActivityInfoHolder().cancellationSignal.cancel();

        super.onBackPressed();
    }
}