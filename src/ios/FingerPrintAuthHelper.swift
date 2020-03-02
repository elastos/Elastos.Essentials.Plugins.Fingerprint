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

protocol AuthenticationCallbackBase {
    func onFailure(message: String)
    func onHelp(helpCode: Int, helpString: String)
}

protocol SimpleAuthenticationCallback : AuthenticationCallbackBase {
    func onSuccess()
}

protocol GetPasswordAuthenticationCallback : AuthenticationCallbackBase {
    func onSuccess(password: String)
}

public class FingerPrintAuthHelper {
    private static let FINGER_PRINT_HELPER = "FingerPrintAuthHelper"
    private static let ENCRYPTED_PASS_SHARED_PREF_KEY = "ENCRYPTED_PASS_SHARED_PREF_KEY"
    private static let LAST_USED_IV_SHARED_PREF_KEY = "LAST_USED_IV_SHARED_PREFS_KEY"
    private static let KEYSTORE_APP_ALIAS = "Trinity"
    private static let TAG = "FingerPrintAuthHelper"

    private let viewController: UIViewController
    private let dAppID: String // Package id of the Trinity DApp calling us
    //private KeyStore keyStore;
    private var activityInfoHolder: AuthenticateActivityInfoHolder?

    class AuthenticateActivityInfoHolder {
        var passwordKey: String?
        var password: String?
        //var listener: FingerPrintAuthenticationListener?
        //var cipher: Cipher
    }
    
    init(viewController: UIViewController, dAppID: String) {
        self.viewController = viewController
        self.dAppID = dAppID

        /*KeyguardManager keyguardManager = (KeyguardManager) activity.getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager) activity.getSystemService(FINGERPRINT_SERVICE);

        if (!keyguardManager.isKeyguardSecure()) {
            setError("User hasn't enabled Lock Screen");
            return false;
        }

        if (!hasPermission()) {
            setError("User hasn't granted permission to use Fingerprint");
            return false;
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            setError("User hasn't registered any fingerprints");
            return false;
        }

        if (!initKeyStore()) {
            return false;
        }
        return false;*/
    }

    func getActivityInfoHolder() -> AuthenticateActivityInfoHolder {
        return activityInfoHolder!
    }

   /* private Cipher createCipher(int mode, String passwordKey) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException {
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
            cipher.init(mode, key, new IvParameterSpec(lastIv));
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
        return ENCRYPTED_PASS_SHARED_PREF_KEY + dAppID + passwordKey;
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
        return LAST_USED_IV_SHARED_PREF_KEY + dAppID + passwordKey;
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
        return activity.getSharedPreferences(FINGER_PRINT_HELPER+"_"+dAppID, 0);
    }
*/
    private func authenticate(mode: Int) {
        do {
           /* Cipher cipher = createCipher(mode, activityInfoHolder.passwordKey);
            if (cipher == null) {
                activityInfoHolder.listener.getCallback().onFailure("Unable to create cipher");
            }
            else {
                activityInfoHolder.cipher = cipher;
*/
                let context = LAContext()
                context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                  localizedReason: "To Do") { (success, evaluateError) in
                    // 4
                    if success {
                      DispatchQueue.main.async {
                        // User authenticated successfully, take appropriate action
                        //completion()
                        //activityInfoHolder.listener.onAuthenticationSucceeded(result);
                      }
                    } else {
                      // TODO: deal with LAError cases
                        
                        var message: String = ""
                        switch evaluateError {
                        // 3
                        case LAError.authenticationFailed?:
                          message = "There was a problem verifying your identity."
                        case LAError.userCancel?:
                          message = "You pressed cancel."
                        case LAError.userFallback?:
                          message = "You pressed password."
                        case LAError.biometryNotAvailable?:
                          message = "Face ID/Touch ID is not available."
                        case LAError.biometryNotEnrolled?:
                          message = "Face ID/Touch ID is not set up."
                        case LAError.biometryLockout?:
                          message = "Face ID/Touch ID is locked."
                        default:
                          message = "Face ID/Touch ID may not be configured"
                        }
                        
                        //activityInfoHolder.listener.onAuthenticationError(errorCode, errString);
                        //activityInfoHolder.listener.onAuthenticationFailed();
                    }
                }
            
                //biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
           // }
        } catch {
           // activityInfoHolder.listener.getCallback().onFailure("An error occurred: \(error)")
        }
    }

    func authenticateAndSavePassword(passwordKey: String, password: String, callback: SimpleAuthenticationCallback) {
        activityInfoHolder = AuthenticateActivityInfoHolder()
        activityInfoHolder!.passwordKey = passwordKey
        activityInfoHolder!.password = password
        //activityInfoHolder!.listener = FingerPrintEncryptPasswordListener(callback, passwordKey, password)

        //authenticate(Cipher.ENCRYPT_MODE);
    }

    func authenticateAndGetPassword(passwordKey: String, callback: GetPasswordAuthenticationCallback) {
        activityInfoHolder = AuthenticateActivityInfoHolder()
        activityInfoHolder!.passwordKey = passwordKey
        //activityInfoHolder!.listener = FingerPrintDecryptPasswordListener(callback, passwordKey);

        //authenticate(Cipher.DECRYPT_MODE);
    }

    func authenticate(callback: SimpleAuthenticationCallback) {
        activityInfoHolder = AuthenticateActivityInfoHolder()
        //activityInfoHolder!.listener = new FingerPrintSimpleAuthenticationListener(callback);

        //authenticate(Cipher.ENCRYPT_MODE); // Use encrypt mode (even if we won't encrypt anything) to not have to generate and provide a cipher IV (needed for decoding operations)
    }

    /*private boolean encryptAndSavePassword(Cipher cipher, String passwordKey, String password) {
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

    class FingerPrintAuthenticationListener : FingerprintManager.AuthenticationCallback {
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
    private class FingerPrintEncryptPasswordListener : FingerPrintAuthenticationListener {
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
    }*/
}
