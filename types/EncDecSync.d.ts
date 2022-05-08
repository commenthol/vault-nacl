export class EncDecSync {
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
    _vault: Vault;
    _keys: any[];
    _doSplit: boolean;
    _hasVaults: boolean;
    clear(): void;
    /**
     * @param {any} values
     * @return {any}
     */
    decrypt(values: any): any;
    /**
     * @param {any} values
     * @return {any}
     */
    encrypt(values: any): any;
    /**
     * @param {string} str
     * @return {string}
     */
    encryptString(str: string, { doSplit }?: {
        doSplit?: boolean | undefined;
    }): string;
    /**
     * @param {any} values
     * @param {Vault|String} [newVault] - new password/vault for re-encryption
     * @return {any}
     */
    rekey(values: any, newVault?: string | Vault | undefined): any;
    /**
     * @param {any} values
     * @return {boolean}
     */
    check(values: any): boolean;
    /**
     * @private
     * @param {any} obj
     * @param {object} [param1]
     * @param {boolean} [param1.isCheckMode]
     * @param {boolean} [param1.isEncMode]
     * @param {Vault} [param1.newVault]
     * @param {any} [param1.visited]
     * @returns {any}
     */
    private _traverse;
    /**
     * @private
     * @param {string} str
     * @param {object} [param1 ]
     * @param {Vault} [param1.newVault]
     * @returns {string}
     */
    private _replaceEncMode;
    _replace(str: any): any;
}
import { Vault } from "./Vault";
