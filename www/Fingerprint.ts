
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
      "FingerprintPlugin", "authenticateAndSavePassword", [passwordKey, password]);
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
      "FingerprintPlugin", "authenticateAndGetPassword", [passwordKey]);
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
      "FingerprintPlugin", "authenticate", []);
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
      "FingerprintPlugin", "isBiometricAuthenticationMethodAvailable", []);
    });
  }
}

export = new FingerprintManagerImpl();