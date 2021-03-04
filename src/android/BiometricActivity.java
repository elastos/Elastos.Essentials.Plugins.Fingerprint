package org.elastos.essentials.plugins.fingerprint;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

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

public class BiometricActivity extends AppCompatActivity {

    private static final String FINGER_PRINT_HELPER = "FingerPrintAuthHelper";
    private static final String ENCRYPTED_PASS_SHARED_PREF_KEY = "ENCRYPTED_PASS_SHARED_PREF_KEY";
    private static final String LAST_USED_IV_SHARED_PREF_KEY = "LAST_USED_IV_SHARED_PREFS_KEY";
    private static final String KEYSTORE_APP_ALIAS = "Trinity";
    private static final String TAG = "FingerPrintAuthHelper";

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 2;
    private PromptInfo mPromptInfo;
    private BiometricPrompt mBiometricPrompt;

    private String did; // Signed in DID string
    private KeyStore keyStore;
    private AuthenticateActivityInfoHolder activityInfoHolder;

    private String lastError;

    class AuthenticateActivityInfoHolder {
        String passwordKey;
        String password;
        Cipher cipher;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(null);
        int layout = getResources()
                .getIdentifier("biometric_activity", "layout", getPackageName());
        setContentView(layout);

        if (savedInstanceState != null) {
            return;
        }

        if (!initKeyStore()) {
            return;
        }

        mPromptInfo = new PromptInfo.Builder(getIntent().getExtras()).build();

        final Handler handler = new Handler(Looper.getMainLooper());
        Executor executor = handler::post;
        mBiometricPrompt = new BiometricPrompt(this, executor, mAuthenticationCallback);
        try {
            authenticate();
        } catch (Exception e) {
            finishWithError(PluginError.BIOMETRIC_UNKNOWN_ERROR, e.getMessage());
        }
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
        return this.getSharedPreferences(FINGER_PRINT_HELPER+"_"+did, 0);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void authenticate(int mode) {
        try {
            Cipher cipher = createCipher(mode, activityInfoHolder.passwordKey);
            if (cipher == null) {
                Log.e(TAG, "Unable to create cipher");
//                activityInfoHolder.listener.getCallback().onFailure("Unable to create cipher");
            }
            else {
                activityInfoHolder.cipher = cipher;

                final Handler handler = new Handler(Looper.getMainLooper());
                Executor executor = handler::post;
                mBiometricPrompt = new BiometricPrompt(this,
                        executor, mAuthenticationCallback);

                BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Authentication required")
                        .setSubtitle("Please use your biometric authentication")
                        .setNegativeButtonText("Cancel")
                        .setConfirmationRequired(false)
                        .build();

                mBiometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
            }
        } catch (Throwable t) {
//            activityInfoHolder.listener.getCallback().onFailure("An error occurred: " + t.getMessage());
            Log.e(TAG, "An error occurred: " + t.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void authenticate() throws CryptoException {
        activityInfoHolder = new AuthenticateActivityInfoHolder();
        switch (mPromptInfo.getType()) {
          case JUST_AUTHENTICATE:
              authenticate(Cipher.ENCRYPT_MODE); // Use encrypt mode (even if we won't encrypt anything) to not have to generate and provide a cipher IV (needed for decoding operations)
            return;
          case REGISTER_SECRET:
              activityInfoHolder.passwordKey = mPromptInfo.getPasswordKey();
              activityInfoHolder.password = mPromptInfo.getPassword();
              authenticate(Cipher.ENCRYPT_MODE);
            return;
          case LOAD_SECRET:
              activityInfoHolder.passwordKey = mPromptInfo.getPasswordKey();
              authenticate(Cipher.DECRYPT_MODE);
            return;
        }
        throw new CryptoException(PluginError.BIOMETRIC_ARGS_PARSING_FAILED);
    }

    private BiometricPrompt.AuthenticationCallback mAuthenticationCallback =
            new BiometricPrompt.AuthenticationCallback() {

                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    onError(errorCode, errString);
                }

                @RequiresApi(api = Build.VERSION_CODES.M)
                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    try {
                        finishWithSuccess(result.getCryptoObject());
                    } catch (CryptoException e) {
                        finishWithError(e);
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    onError(PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getValue(), PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getMessage());
                }
            };


    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    private void showAuthenticationScreen() {
        KeyguardManager keyguardManager = ContextCompat
                .getSystemService(this, KeyguardManager.class);
        if (keyguardManager == null
                || android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        if (keyguardManager.isKeyguardSecure()) {
            Intent intent = keyguardManager
                    .createConfirmDeviceCredentialIntent("Authentication required", "");
            this.startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            // Show a message that the user hasn't set up a lock screen.
            finishWithError(PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED);
        }
    }

    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode == Activity.RESULT_OK) {
                finishWithSuccess();
            } else {
                finishWithError(PluginError.BIOMETRIC_PIN_OR_PATTERN_DISMISSED);
            }
        }
    }

    private void onError(int errorCode, @NonNull CharSequence errString) {
        switch (errorCode)
        {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_CANCELED:
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                return;
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                // TODO: remove after fix https://issuetracker.google.com/issues/142740104
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.P) {
                    showAuthenticationScreen();
                    return;
                }
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                break;
            case BiometricPrompt.ERROR_LOCKOUT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT.getValue(), errString.toString());
                break;
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT_PERMANENT.getValue(), errString.toString());
                break;
            default:
                finishWithError(errorCode, errString.toString());
        }
    }

    private void finishWithSuccess() {
        setResult(RESULT_OK);
        finish();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void finishWithSuccess(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        Intent intent = null;
        Cipher cipher = cryptoObject.getCipher();
        switch (mPromptInfo.getType()) {
          case REGISTER_SECRET:
              try {
                  if (encryptAndSavePassword(cipher, activityInfoHolder.passwordKey, activityInfoHolder.password)) {
                      // On success only, save the cipher information to be able to decrypt later on.
                      byte[] iv = cipher.getIV();
                      saveIv(activityInfoHolder.passwordKey, iv);

//                      callback.onSuccess();
                  } else {
//                      callback.onFailure("Encryption failed");
                  }

              } catch (Exception e) {
//                  callback.onFailure("Encryption failed " + e.getMessage());
              }
            break;
          case LOAD_SECRET:
              try {
                  String encryptedPassword = getSavedEncryptedPassword(activityInfoHolder.passwordKey);
                  if (encryptedPassword == null) {
//                      callback.onFailure("No stored password found");
                  }
                  else {
                      String savedPass = decryptPassword(cipher, encryptedPassword);
                      if (savedPass != null) {
                        intent = new Intent();
                        intent.putExtra(PromptInfo.SECRET_EXTRA, savedPass);
//                          callback.onSuccess(savedPass);
                      } else {
//                          callback.onFailure("Failed deciphering");
                      }
                  }

              } catch (Exception e) {
//                  callback.onFailure("Deciphering failed " + e.getMessage());
              }
            break;
        }
        if (intent == null) {
            setResult(RESULT_OK);
        } else {
            setResult(RESULT_OK, intent);
        }
        finish();
    }

    private void finishWithError(CryptoException e) {
        finishWithError(e.getError().getValue(), e.getMessage());
    }

    private void finishWithError(PluginError error) {
        finishWithError(error.getValue(), error.getMessage());
    }

    private void finishWithError(PluginError error, String message) {
        finishWithError(error.getValue(), message);
    }

    private void finishWithError(int code, String message) {
        Intent data = new Intent();
        data.putExtra("code", code);
        data.putExtra("message", message);
        setResult(RESULT_CANCELED, data);
        finish();
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
}
