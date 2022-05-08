export class EncDec {
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
     * @return {Promise<any>}
     */
    decrypt(values: any): Promise<any>;
    /**
     * @param {any} values
     * @return {Promise<any>}
     */
    encrypt(values: any): Promise<any>;
    /**
     * @param {string} str
     * @return {Promise<string>}
     */
    encryptString(str: string, { doSplit }?: {
        doSplit?: boolean | undefined;
    }): Promise<string>;
    /**
     * @param {any} values
     * @param {Vault|String} [newVault] - new password/vault for re-encryption
     * @return {Promise<any>}
     */
    rekey(values: any, newVault?: string | Vault | undefined): Promise<any>;
    /**
     * @param {any} values
     * @return {Promise<boolean>}
     */
    check(values: any): Promise<boolean>;
    /**
     * @private
     * @param {any} obj
     * @param {object} [param1]
     * @param {boolean} [param1.isCheckMode]
     * @param {boolean} [param1.isEncMode]
     * @param {Vault} [param1.newVault]
     * @param {any} [param1.visited]
     * @returns {Promise<any>}
     */
    private _traverse;
    /**
     * @private
     * @param {string} str
     * @param {object} [param1 ]
     * @param {Vault} [param1.newVault]
     * @returns {Promise<string>}
     */
    private _replaceEncMode;
    _replace(str: any): Promise<string>;
}
import { Vault } from "./Vault";
