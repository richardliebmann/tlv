import { TLV } from "./tlv";

export class TLVUtils {

    /**
     * Returns the byte length of the given tag.
     * 
     * @param {number} tag
     * @return {number}
     */
    static getTagLength(tag: number) {
        var lenTag = 4;

        while (lenTag > 1) {
            var tmpTag = tag >>> ((lenTag - 1) * 8);

            if ((tmpTag & 0xFF) != 0x00) {
                break;
            }

            lenTag--;
        }

        return lenTag;
    }

    /**
     * Returns the byte length of the given value.
     * Value can be either a Buffer or an array of TLVs.
     * 
     * @param {object} value
     * @param {boolean} constructed
     * @return {number}
     */
    static getValueLength(value: Buffer | Array<TLV>, constructed: boolean) {
        var lenValue = 0;

        if (constructed) {
            for (var i = 0; i < value.length; i++) {
                if (value instanceof Buffer || typeof value[i] === "number") {
                    lenValue = lenValue + 1;
                }
                else {
                    lenValue = lenValue + value[i].byteLength;
                }
            }
        } else {
            lenValue = value.length;
        }

        return lenValue;
    }

    /**
     * Returns the number of bytes needed to encode the given length.
     * If the length is indefinite, this value takes in account the bytes needed to encode the EOC tag.
     * 
     * @param {number} lenValue
     * @param {boolean} indefiniteLength
     * @return {number}
     */
    static getLengthOfLength(lenValue: number, indefiniteLength: boolean) {
        var lenOfLen;

        if (indefiniteLength) {
            lenOfLen = 3;
        } else if (lenValue > 0x00FFFFFF) {
            lenOfLen = 5;
        } else if (lenValue > 0x0000FFFF) {
            lenOfLen = 4;
        } else if (lenValue > 0x000000FF) {
            lenOfLen = 3;
        } else if (lenValue > 0x0000007F) {
            lenOfLen = 2;
        } else {
            lenOfLen = 1;
        }

        return lenOfLen
    }

    /**
     * Encodes the given numeric value in the given Buffer, using the specified number of bytes.
     * 
     * @param {Buffer} buf
     * @param {number} value
     * @param {number} len
     */
    static encodeNumber(buf: Buffer, value: number, len: number) {
        var index = 0;

        while (len > 0) {
            var tmpValue = value >>> ((len - 1) * 8);
            buf[index++] = tmpValue & 0xFF;
            len--;
        }
    }

}