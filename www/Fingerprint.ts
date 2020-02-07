
var exec = cordova.exec;

class FingerprintManagerImpl implements FingerprintPlugin.FingerprintManager {
  authenticateAndSavePassword(passwordKey: string, password: string): Promise<void> {
    return new Promise((resolve, reject)=>{
      exec(()=>{
        resolve();
      },
      (err)=>{
        reject(err);
      },
      "Fingerprint", "authenticate", [passwordKey, password]);
    });
  }  
  
  authenticateAndGetPassword(passwordKey: string): Promise<string> {
    return new Promise((resolve, reject)=>{
      exec((clearPassword: string)=>{
        resolve(clearPassword);
      },
      (err)=>{
        reject(err);
      },
      "Fingerprint", "authenticateAndGetPassword", [passwordKey]);
    });
  }

  authenticate(): Promise<void> {
    return new Promise((resolve, reject)=>{
      exec(()=>{
        resolve();
      },
      (err)=>{
        reject(err);
      },
      "Fingerprint", "authenticate", []);
    });
  }

  isAvailable(): Promise<FingerprintPlugin.BiometricType> {
    return new Promise((resolve, reject)=>{
      exec((biometricType: FingerprintPlugin.BiometricType)=>{
        resolve(biometricType);
      },
      (err)=>{
        reject(err);
      },
      "Fingerprint", "isAvailable", []);
    });
  }
}

export = new FingerprintManagerImpl();