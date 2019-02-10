import forge = require('node-forge');

/**
* Class for encrypting and decrypting payloads.
* @class
* @private
* @param options
* @param options.key localKey of cipher
* @param options.version protocol version
* @example
* const cipher = new TuyaCipher({key: 'xxxxxxxxxxxxxxxx', version: 3.1})
*/
class TuyaCipher {
  private version: number;
  private cipher: any;
  private decipher: any;

  constructor(options: { key: string, version: number }) {
    // Check arguments
    if (typeof options.key !== 'string') {
      throw TypeError('Wrong key type.');
    }

    if (typeof options.version !== 'number') {
      throw TypeError('Wrong version type.');
    }

    this.cipher = forge.cipher.createCipher('AES-ECB', options.key);
    this.decipher = forge.cipher.createDecipher('AES-ECB', options.key);
    this.version = options.version;
  }

  /**
  * Encrypts data.
  * @param options
  * @param options.data data to encrypt
  * @param [options.base64=true] `true` to return result in Base64
  * @example
  * TuyaCipher.encrypt({data: 'hello world'})
  * @returns returns Buffer unless options.base64 is true
  */
  encrypt(options: { data: string, base64: boolean}) : Buffer | string {
    // Check arguments
    if (typeof options.data !== 'string') {
      throw TypeError('Wrong data type.')
    }

    this.cipher.start({iv: ''});
    this.cipher.update(forge.util.createBuffer(options.data, 'utf8'));
    this.cipher.finish();

    if (options.base64 !== false) {
      return forge.util.encode64(this.cipher.output.data);
    }

    return this.cipher.output;
  }

  /**
  * Decrypts data.
  * @param data to decrypt
  * @returns
  * returns object if data is JSON, else returns string
  */
  decrypt(data: string) : {} & string {
    // Check arguments
    if (typeof data !== 'string') {
      throw TypeError('Wrong data type.');
    }

    if (data.indexOf(this.version.toString()) !== -1) {
      // Data has version number and is encoded in base64

      // Remove prefix of version number and MD5 hash
      data = data.slice(19);

      // Decode data
      data = forge.util.decode64(data);
    }

    // Turn data into Buffer
    let filteredData = forge.util.createBuffer(data);

    this.decipher.start({iv: ''});
    this.decipher.update(filteredData);
    this.decipher.finish();

    const result = this.decipher.output.data;

    // Try to parse data as JSON,
    // otherwise return as string.
    try {
      return JSON.parse(result);
    } catch (error) {
      return result;
    }
  }

  /**
  * Calculates a MD5 hash.
  * @param data to hash
  * @returns last 8 characters of hash of data
  */
  md5(data: string): string {
    // Check arguments
    if (typeof data !== 'string') {
      throw new TypeError('Wrong data type.');
    }

    const md5hash = forge.md.md5.create().update(data).digest().toHex();
    return md5hash.toString().toLowerCase().substr(8, 16);
  }
}

export = TuyaCipher;
