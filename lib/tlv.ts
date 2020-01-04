import { TLVUtils } from "./tlv-utils"

export class TLV {
    get tag() { return this._tag }
    get value() { return this._value }
    get constructed() { return this._value instanceof Array }
    get indefiniteLength() { return this._indefiniteLength === undefined ? false : this._indefiniteLength }
    get originalLength() { return this._originalLength }
    get byteLength() { return this.getByteLength() }

    /**
     * Creates a TLV object. 
     * The originalLength parameter only makes sense for values parsed from a buffer.
     *
     * @param {number} tag 
     * @param {object} value
     * @param {number}
     */
    constructor(private _tag: number, private _value: any, private _indefiniteLength?: boolean, private _originalLength?: number) {
    }

    /**
     * Calculates and returns the byte length of the encoded TLV.
     * This value can be used to allocate a buffer able to contain the encoded TLV.
     *
     * @return {number}
     */
    getByteLength() {
        var lenValue = TLVUtils.getValueLength(this.value, this.constructed);
        return TLVUtils.getTagLength(this.tag) + TLVUtils.getLengthOfLength(lenValue, this.indefiniteLength) + lenValue;
    }
    /**
     * Returns the 1st child TLV of this object with the given tag. 
     * If there is no child with the given tag, returns null.
     *
     * @param {number} tagToSearch
     * @return {TLV}
     */
    getFirstChild(tagToSearch: number) {
        for (var i = 0; i < this.value.length; i++) {
            if (this.value[i].tag == tagToSearch) {
                return this.value[i];
            }
        }

        return null;
    }

    /**
     * Returns an Array of children TLV of this object with the given tag. 
     * If there is no child with the given tag, returns an empty Array.
     *
     * @param {number} tagToSearch
     * @return {Array}
     */
    getChildren(tagToSearch: number) {
        var result = [];
        for (var i = 0; i < this.value.length; i++) {
            if (this.value[i].tag == tagToSearch) {
                result.push(this.value[i]);
            }
        }

        return result;
    }
    /**
     * Encodes this TLV in the given Buffer object. If no Buffer object is given
     * a new one is created. The given or created buffer is returned for convenience.
     *
     * @param  {Buffer} buf
     * @return {Buffer}
     */
    encode(buf: Buffer = null) {
        var tagLength = TLVUtils.getTagLength(this.tag);
        var valueLength = TLVUtils.getValueLength(this.value, this.constructed);
        var lenOfLen = TLVUtils.getLengthOfLength(valueLength, this.indefiniteLength);

        if (!buf) {
            buf = new Buffer(tagLength + valueLength + lenOfLen);
        }

        var index = 0;

        TLVUtils.encodeNumber(buf, this.tag, tagLength);
        index += tagLength;

        if (this.indefiniteLength) {
            buf[index++] = 0x80;
        } else if (lenOfLen == 1) {
            buf[index++] = valueLength;
        } else {
            lenOfLen--;
            buf[index++] = 0x80 | lenOfLen;
            TLVUtils.encodeNumber(buf.slice(index), valueLength, lenOfLen);
            index += lenOfLen;
        }

        if (this.constructed) {
            for (var i = 0; i < this.value.length; i++) {
                this.value[i].encode(buf.slice(index));
                index = index + this.value[i].byteLength;
            }

            if (this.indefiniteLength) {
                buf[index++] = 0x00;
                buf[index++] = 0x00;
            }
        } else {
            this.value.copy(buf, index);
        }

        return buf;
    }
    /**
     * Returns a value of this TLV object, represented as an unsigned big endian.
     * The value can not be larger than 4 bytes.
     * 
     * @return {number}
     */
    getUIntValue() {
        var index = 0;
        var intValue = 0;
        var len = this.value.length;
        var msb = 0;

        if (len > 4) {
            throw new RangeError("The length of the value cannot be more than 4 bytes in this implementation");
        }

        if (len == 4) {
            msb = this.value[index++] * 0x1000000;
            len--;
        }

        while (len > 0) {
            intValue = intValue | this.value[index++];

            if (len > 1) {
                intValue = intValue << 8;
            }

            len--;
        }

        return msb + intValue;
    }
    /**
     * Returns a value of this TLV object, represented as an signed big endian.
     * The value can not be larger than 4 bytes.
     * 
     * @return {number}
     */
    getIntValue() {
        var index = 0;
        var intValue = 0;
        var len = this.value.length;
        var signMask = 0x80 << ((len - 1) * 8);
        var signExt = 0xFFFFFFFF << (len * 8);

        if (len > 4) {
            throw new RangeError("The length of the value cannot be more than 4 bytes in this implementation");
        }

        while (len > 0) {
            intValue = intValue | this.value[index++];

            if (len > 1) {
                intValue = intValue << 8;
            }

            len--;
        }

        if ((intValue & signMask) == signMask) {
            intValue = intValue | signExt;
        }

        return intValue;
    }
    /**
     * Encodes the given numeric value in the value Buffer of this object.
     * 
     * @param {number} intValue
     */
    setIntValue(intValue: number) {
        TLVUtils.encodeNumber(this.value, intValue, this.value.length);
    }

    toString() {
        if(this.value && Array.isArray(this.value) && this.value.length > 0 && this.value[0] instanceof TLV) {
            var s = "TLV 0x" + this.tag.toString(16);

            this.value.forEach(tlv => {
                var toks =  (tlv + "").split("\n");

                toks.forEach(j => {
                    s += "\n\t" + j
                })
            })

            return s;
        }
        else {
            return "TLV 0x" + this.tag.toString(16) + " [" + (Array.isArray(this.value) ? this.value.map(c => "0x" + (c).toString(16)).join(" ") : this.value) + "]";
        }
    }
}
