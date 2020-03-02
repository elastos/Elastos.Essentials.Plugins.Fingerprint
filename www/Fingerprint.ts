
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
      "Fingerprint", "authenticateAndSavePassword", [passwordKey, password]);
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

  isBiometricAuthenticationMethodAvailable(): Promise<boolean> {
    return new Promise((resolve, reject)=>{
      exec((isAvailable: string)=>{
        resolve((isAvailable=="true"?true:false));
      },
      (err)=>{
        reject(err);
      },
      "Fingerprint", "isBiometricAuthenticationMethodAvailable", []);
    });
  }
}

export = new FingerprintManagerImpl();