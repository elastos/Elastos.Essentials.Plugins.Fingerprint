package org.elastos.trinity.plugins.fingerprint;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricPrompt;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;

/**
 * Initially from https://riptutorial.com/android/example/29719/how-to-use-android-fingerprint-api-to-save-user-passwords
 * then largely reworked and adjusted for trinity.
 */
public class FingerPrintAuthHelper {
    private static final String FINGER_PRINT_HELPER = "FingerPrintAuthHelper";
    private static final String ENCRYPTED_PASS_SHARED_PREF_KEY = "ENCRYPTED_PASS_SHARED_PREF_KEY";
    private static final String LAST_USED_IV_SHARED_PREF_KEY = "LAST_USED_IV_SHARED_PREFS_KEY";
    private static final String KEYSTORE_APP_ALIAS = "Trinity";
    private static final String TAG = "FingerPrintAuthHelper";

    private final Activity activity;
    private final String did; // Signed in DID string
    private KeyStore keyStore;
    private AuthenticateActivityInfoHolder activityInfoHolder;

    private String lastError;

    class AuthenticateActivityInfoHolder {
        String passwordKey;
        String password;
        CancellationSignal cancellationSignal;
        FingerPrintAuthenticationListener listener;
        Cipher cipher;
    }

    private interface AuthenticationCallbackBase {
        void onFailure(String message);
        void onHelp(int helpCode, String helpString);
    }

    public interface SimpleAuthenticationCallback extends AuthenticationCallbackBase {
        void onSuccess();
    }

    public interface GetPasswordAuthenticationCallback extends AuthenticationCallbackBase {
        void onSuccess(String password);
    }

    // TODO remove did
    public FingerPrintAuthHelper(Activity activity, String did, String dAppID) {
        this.activity = activity;
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
        FingerprintManager fingerprintManager = (FingerprintManager) activity.getSystemService(FINGERPRINT_SERVICE);

        if (!keyguardManager.isKeyguardSecure()) {
            setError("User hasn't enabled Lock Screen");
            return false;
        }

        if (!hasPermission()) {
            setError("User hasn't granted permission to use Fingerprint");
            return false;
        }

        if (!initKeyStore()) {
            return false;
        }

        return true;
    }

    AuthenticateActivityInfoHolder getActivityInfoHolder() {
        return activityInfoHolder;
    }

    @Nullable
    @RequiresApi(api = Build.VERSION_CODES.M)
    private Cipher createCipher(int mode, String passwordKey) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" +
                KeyProperties.BLOCK_MODE_CBC + "/" +
                KeyProperties.ENCRYPTION_PADDING_PKCS7);

        Key key = keyStore.getKey(KEYSTORE_APP_ALIAS, null);
        if (key == null) {
            return null;
        }
        if(mode == Cipher.ENCRYPT_MODE || mode == Cipher.UNWRAP_MODE) {
            cipher.init(mode, key);
        } else {
            byte[] lastIv = getLastIv(passwordKey);
            if (lastIv != null)
                cipher.init(mode, key, new IvParameterSpec(lastIv));
            else
                return null;
        }
        return cipher;
    }

    @NonNull
    @RequiresApi(api = Build.VERSION_CODES.M)
    private KeyGenParameterSpec createKeyGenParameterSpec() {
        return new KeyGenParameterSpec.Builder(KEYSTORE_APP_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean initKeyStore() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyStore.load(null);

            // Generate a permanent keypair in case we don't have one yet
            if (!keyStore.containsAlias(KEYSTORE_APP_ALIAS)) {
                Log.d(TAG, "No alias found in keystore, creating a new keypair");
                KeyGenParameterSpec keyGeneratorSpec = createKeyGenParameterSpec();
                keyGenerator.init(keyGeneratorSpec);
                keyGenerator.generateKey();
            }
        } catch (Throwable t) {
            setError("Failed init of keyStore & keyGenerator: " + t.getMessage());
            return false;
        }
        return true;
    }

    private String getPasswordSharedPrefsKey(String passwordKey) {
        return ENCRYPTED_PASS_SHARED_PREF_KEY + passwordKey;
    }

    private String getSavedEncryptedPassword(String passwordKey) {
        SharedPreferences sharedPreferences = getSharedPreferences();
        if (sharedPreferences != null) {
            return sharedPreferences.getString(getPasswordSharedPrefsKey(passwordKey), null);
        }
        return null;
    }

    /**
     * Saves an encrypted password to shared memory, for a given password key.
     * Password keys are user defined keys, simply used to be able to store multiple passwords for a same dApp.
     */
    private void saveEncryptedPassword(String passwordKey, String encryptedPassword) {
        // Sandbox dApps by storing passwords using the dApp package as prefix.
        SharedPreferences.Editor edit = getSharedPreferences().edit();
        edit.putString(getPasswordSharedPrefsKey(passwordKey), encryptedPassword);
        edit.apply();
    }

    private String getIvSharedPrefsKey(String passwordKey) {
        return LAST_USED_IV_SHARED_PREF_KEY + passwordKey;
    }

    private byte[] getLastIv(String passwordKey) {
        SharedPreferences sharedPreferences = getSharedPreferences();
        if (sharedPreferences != null) {
            String ivString = sharedPreferences.getString(getIvSharedPrefsKey(passwordKey), null);

            if (ivString != null) {
                return decodeBytes(ivString);
            }
        }
        return null;
    }

    private void saveIv(String passwordKey, byte[] iv) {
        SharedPreferences.Editor edit = getSharedPreferences().edit();
        String string = encodeBytes(iv);
        edit.putString(getIvSharedPrefsKey(passwordKey), string);
        edit.apply();
    }

    private SharedPreferences getSharedPreferences() {
        // TODO replace did with context?
        return activity.getSharedPreferences(FINGER_PRINT_HELPER+"_"+did, 0);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean hasPermission() {
        return ActivityCompat.checkSelfPermission(activity, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void authenticate(int mode) {
        try {
            if (hasPermission()) {
                Cipher cipher = createCipher(mode, activityInfoHolder.passwordKey);
                if (cipher == null) {
                    activityInfoHolder.listener.getCallback().onFailure("Unable to create cipher");
                }
                else {
                    activityInfoHolder.cipher = cipher;

                    Executor executor = ContextCompat.getMainExecutor(activity);
                    BiometricPrompt biometricPrompt = new BiometricPrompt((FragmentActivity) activity,
                            executor, new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                            super.onAuthenticationError(errorCode, errString);

                            activityInfoHolder.listener.onAuthenticationError(errorCode, errString);
                        }

                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            super.onAuthenticationSucceeded(result);
                            activityInfoHolder.listener.onAuthenticationSucceeded(result);
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            super.onAuthenticationFailed();
                            activityInfoHolder.listener.onAuthenticationFailed();
                        }
                    });

                    BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Authentication required")
                            .setSubtitle("Please use your biometric authentication")
                            .setNegativeButtonText("Cancel")
                            .setConfirmationRequired(false)
                            .build();

                    biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
                }
            } else {
                activityInfoHolder.listener.getCallback().onFailure("User hasn't granted permission to use Fingerprint");
            }
        } catch (Throwable t) {
            activityInfoHolder.listener.getCallback().onFailure("An error occurred: " + t.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticateAndSavePassword(@NonNull String passwordKey, @NonNull String password, CancellationSignal cancellationSignal, SimpleAuthenticationCallback callback) {
        activityInfoHolder = new AuthenticateActivityInfoHolder();
        activityInfoHolder.passwordKey = passwordKey;
        activityInfoHolder.password = password;
        activityInfoHolder.cancellationSignal = cancellationSignal;
        activityInfoHolder.listener = new FingerPrintEncryptPasswordListener(callback, passwordKey, password);

        authenticate(Cipher.ENCRYPT_MODE);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticateAndGetPassword(@NonNull String passwordKey, CancellationSignal cancellationSignal, GetPasswordAuthenticationCallback callback) {
        activityInfoHolder = new AuthenticateActivityInfoHolder();
        activityInfoHolder.passwordKey = passwordKey;
        activityInfoHolder.cancellationSignal = cancellationSignal;
        activityInfoHolder.listener = new FingerPrintDecryptPasswordListener(callback, passwordKey);

        authenticate(Cipher.DECRYPT_MODE);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticate(CancellationSignal cancellationSignal, SimpleAuthenticationCallback callback) {
        activityInfoHolder = new AuthenticateActivityInfoHolder();
        activityInfoHolder.cancellationSignal = cancellationSignal;
        activityInfoHolder.listener = new FingerPrintSimpleAuthenticationListener(callback);

        authenticate(Cipher.ENCRYPT_MODE); // Use encrypt mode (even if we won't encrypt anything) to not have to generate and provide a cipher IV (needed for decoding operations)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean encryptAndSavePassword(Cipher cipher, String passwordKey, String password) {
        Log.d(TAG, "Encrypting and saving password");

        try {
            if(password.isEmpty()) {
                setError("Password is empty");
                return false;
            }

            if (cipher == null) {
                setError("Could not create cipher");
                return false;
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            byte[] bytes = password.getBytes(Charset.defaultCharset());
            cipherOutputStream.write(bytes);
            cipherOutputStream.flush();
            cipherOutputStream.close();
            saveEncryptedPassword(passwordKey, encodeBytes(outputStream.toByteArray()));
        } catch (Throwable t) {
            setError("Encryption failed " + t.getMessage());
            return false;
        }

        return true;
    }

    private byte[] decodeBytes(String s) {
        final int len = s.length();

        // "111" is not a valid hex encoding.
        if( len%2 != 0 )
            throw new IllegalArgumentException("hexBinary needs to be even-length: "+s);

        byte[] out = new byte[len/2];

        for( int i=0; i<len; i+=2 ) {
            int h = hexToBin(s.charAt(i  ));
            int l = hexToBin(s.charAt(i+1));
            if( h==-1 || l==-1 )
                throw new IllegalArgumentException("contains illegal character for hexBinary: "+s);

            out[i/2] = (byte)(h*16+l);
        }

        return out;
    }

    private static int hexToBin( char ch ) {
        if( '0'<=ch && ch<='9' )    return ch-'0';
        if( 'A'<=ch && ch<='F' )    return ch-'A'+10;
        if( 'a'<=ch && ch<='f' )    return ch-'a'+10;
        return -1;
    }

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    private String encodeBytes(byte[] data) {
        StringBuilder r = new StringBuilder(data.length*2);
        for ( byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    private String decryptPassword(Cipher cipher, String savedEncryptedPassword) throws IOException {
        String retVal = null;

        if (savedEncryptedPassword != null) {
            byte[] decodedPassword = decodeBytes(savedEncryptedPassword);
            CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(decodedPassword), cipher);

            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }
            cipherInputStream.close();

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < values.size(); i++) {
                bytes[i] = values.get(i);  // .byteValue()
            }

            retVal = new String(bytes, Charset.defaultCharset());
        }
        return retVal;
    }

    private void setError(String error) {
        lastError = error;
        Log.w(FINGER_PRINT_HELPER, lastError);
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected abstract class FingerPrintAuthenticationListener extends FingerprintManager.AuthenticationCallback {
        FingerPrintAuthenticationListener() {
        }

        public void onAuthenticationError(int errorCode, CharSequence errString) {
            getCallback().onFailure("Authentication error [" + errorCode + "] " + errString);
        }

        /**
         * Called when a recoverable error has been encountered during authentication. The help
         * string is provided to give the user guidance for what went wrong, such as
         * "Sensor dirty, please clean it."
         *
         * @param helpCode An integer identifying the error message
         * @param helpString A human-readable string that can be shown in UI
         */
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            getCallback().onHelp(helpCode, helpString.toString());
        }

        /**
         * Called when a fingerprint is recognized.
         *
         * @param result An object containing authentication-related data
         */
        public abstract void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result);

        /**
         * Called when a fingerprint is valid but not recognized.
         */
        public void onAuthenticationFailed() {
            getCallback().onFailure("Authentication failed");
        }

        public abstract AuthenticationCallbackBase getCallback();
    }

    /**
     * Authentication listener that also encrypts a given password.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private class FingerPrintEncryptPasswordListener extends FingerPrintAuthenticationListener {
        private SimpleAuthenticationCallback callback;
        private final String passwordKey;
        private final String password;

        FingerPrintEncryptPasswordListener(SimpleAuthenticationCallback callback, String passwordKey, String password) {
            this.callback = callback;
            this.passwordKey = passwordKey;
            this.password = password;
        }

        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            try {
                if (encryptAndSavePassword(cipher, passwordKey, password)) {
                    // On success only, save the cipher information to be able to decrypt later on.
                    byte[] iv = cipher.getIV();
                    saveIv(passwordKey, iv);

                    callback.onSuccess();
                } else {
                    callback.onFailure("Encryption failed");
                }

            } catch (Exception e) {
                callback.onFailure("Encryption failed " + e.getMessage());
            }
        }

        @Override
        public AuthenticationCallbackBase getCallback() {
            return callback;
        }
    }

    /**
     * Authentication listener for authentications that require decrypting a previously encrypted password.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    protected class FingerPrintDecryptPasswordListener extends FingerPrintAuthenticationListener {
        private GetPasswordAuthenticationCallback callback;
        private final String passwordKey;

        FingerPrintDecryptPasswordListener(@NonNull GetPasswordAuthenticationCallback callback, String passwordKey) {
            this.callback = callback;
            this.passwordKey = passwordKey;
        }

        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            try {
                String encryptedPassword = getSavedEncryptedPassword(passwordKey);
                if (encryptedPassword == null) {
                    callback.onFailure("No stored password found");
                }
                else {
                    String savedPass = decryptPassword(cipher, encryptedPassword);
                    if (savedPass != null) {
                        callback.onSuccess(savedPass);
                    } else {
                        callback.onFailure("Failed deciphering");
                    }
                }

            } catch (Exception e) {
                callback.onFailure("Deciphering failed " + e.getMessage());
            }
        }

        @Override
        public AuthenticationCallbackBase getCallback() {
            return callback;
        }
    }

    /**
     * Authentication listener for authentications without any password management (just to make sure that
     * the phone owner is in front of his phone).
     */
    @RequiresApi(Build.VERSION_CODES.M)
    protected class FingerPrintSimpleAuthenticationListener extends FingerPrintAuthenticationListener {
        private SimpleAuthenticationCallback callback;

        FingerPrintSimpleAuthenticationListener(@NonNull SimpleAuthenticationCallback callback) {
            this.callback = callback;
        }

        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            callback.onSuccess();
        }

        @Override
        public AuthenticationCallbackBase getCallback() {
            return callback;
        }
    }
}