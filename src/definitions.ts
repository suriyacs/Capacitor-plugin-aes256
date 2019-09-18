// @ts-ignore
declare module "@capacitor/core" {
  interface PluginRegistry {
    AES256: AES256Plugin;
  }
}

export interface AES256Plugin {
  encrypt(options: { secureKey: string, iv: string, value: string }): Promise<{response: string}>;
  decrypt(options: { secureKey: string, iv: string, value: string }): Promise<{response: string}>;
  generateSecureKey(options: { password: string }): Promise<{response: string}>;
  generateSecureIv(options: {password: string}): Promise<{response: string}>;
}

