package org.elastos.essentials.plugins.fingerprint;

import android.os.Bundle;

class PromptInfo {
    private static final String PASSWORDKEY = "passwordkey";
    private static final String SECRET = "secret";
    private static final String BIOMETRIC_ACTIVITY_TYPE = "biometricActivityType";

    static final String SECRET_EXTRA = "secret";

    private Bundle bundle = new Bundle();

    Bundle getBundle() {
        return bundle;
    }

    String getPasswordKey() {
        return bundle.getString(PASSWORDKEY);
    }

    String getPassword() {
        return bundle.getString(SECRET);
    }


    BiometricActivityType getType() {
        return BiometricActivityType.fromValue(bundle.getInt(BIOMETRIC_ACTIVITY_TYPE));
    }

    public static final class Builder {
        private static final String TAG = "PromptInfo.Builder";
        private Bundle bundle;
        private String passwordkey = null;
        private String secret = null;
        private BiometricActivityType type = null;

        Builder() {
        }

        Builder(Bundle bundle) {
            this.bundle = bundle;
        }

        public PromptInfo build() {
            PromptInfo promptInfo = new PromptInfo();

            if (this.bundle != null) {
                promptInfo.bundle = bundle;
                return promptInfo;
            }

            Bundle bundle = new Bundle();

            bundle.putString(PASSWORDKEY, this.passwordkey);
            bundle.putString(SECRET, this.secret);
            bundle.putInt(BIOMETRIC_ACTIVITY_TYPE, this.type.getValue());
            promptInfo.bundle = bundle;

            return promptInfo;
        }

        public void setPasswordKey(String passwordkey) {
            this.passwordkey = passwordkey;
        }
        public void setPassword(String password) {
            this.secret = password;
        }
        public void setType(BiometricActivityType type) {
            this.type = type;
        }
    }
}
