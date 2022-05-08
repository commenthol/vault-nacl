export class Vault {
    /**
     * @param {string} password
     * @param {object} opts
     * @param {string} [opts.digest='sha256']
     * @param {number} [opts.iterations=310000]
     * @param {BufferEncoding} [opts.inputEncoding='utf8']
     * @param {BufferEncoding} [opts.outputEncoding='base64']
     */
    constructor(password: string, opts?: {
        digest?: string | undefined;
        iterations?: number | undefined;
        inputEncoding?: BufferEncoding | undefined;
        outputEncoding?: BufferEncoding | undefined;
    });
    iterations: number;
    digest: string;
    inputEncoding: BufferEncoding;
    outputEncoding: BufferEncoding;
    clear(): void;
    _derivedKeySync({ salt, iterations, digest }: {
        salt: any;
        iterations: any;
        digest: any;
    }): {
        nonce: Buffer;
        key: Buffer;
    };
    _joinV1({ salt, digest, iterations, box }: {
        salt: any;
        digest: any;
        iterations: any;
        box: any;
    }): Buffer;
    _sliceV1(buf: any): {
        salt: any;
        digest: string;
        iterations: any;
        box: any;
        version: any;
    };
    _enc({ salt, digest, iterations, msgBuffer, nonce, key }: {
        salt: any;
        digest: any;
        iterations: any;
        msgBuffer: any;
        nonce: any;
        key: any;
    }): string;
    _dec({ box, nonce, key }: {
        box: any;
        nonce: any;
        key: any;
    }): string;
    encryptSync(message: any): string;
    decryptSync(message: any): string;
    _derivedKey({ salt, iterations, digest }: {
        salt: any;
        iterations: any;
        digest: any;
    }): Promise<{
        nonce: Buffer;
        key: Buffer;
    }>;
    encrypt(message: any): Promise<string>;
    decrypt(message: any): Promise<string>;
}
