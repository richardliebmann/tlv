import { TLV } from "./tlv";

export class TLVParser {

    /**
     * Parses (recursively) all the TLVs in the buffer and returns them in an array. 
     * The buffer is expected to only contain valid TLV values.
     * 
     * @param {Buffer} buf
     * @return {Array}
     */
    parseAll(buf: Buffer | number[], stopOnEOC = false) {
        var tlvs = [];

        for (var i = 0; i < buf.length; i += tlvs[tlvs.length - 1].originalLength) {
            var tlv = this.parse(buf.slice(i));

            if (stopOnEOC && tlv.tag == 0x00 && tlv.originalLength == 2) {
                break;
            }

            tlvs.push(tlv);
        }

        return tlvs;
    }

    /**
     * Parses (recursively) the first TLV in the buffer and returns it. 
     * Any data after the first TLV is ignored. 
     * The originalLength parameter of the returned object tells how many bytes from the buffer are part of the TLV.
     * The value of the TLV contains a copy of the data from the input buffer. Modifying the input buffer afterwards
     * does not affect the returned TLV object.
     * 
     * @param {Buffer} buf
     * @return {TLV}
     */
    parse(buf: Buffer | number[], index = 0): TLV {
        var tag = this.parseTag(buf);
        index += tag.length;

        var len = 0;
        var value;

        if (buf[index] == 0x80) {
            index++;

            if (!tag.constructed) {
                throw new Error("Only constructed TLV can have indefinite length");
            }

            value = this.parseAll(buf.slice(index), true);
            for (var i = 0; i < value.length; i++) {
                index += value[i].originalLength;
            }

            return new TLV(tag.tag, value, true, index + 2);
        } else if ((buf[index] & 0x80) == 0x80) {
            var lenOfLen = buf[index++] & 0x7F;

            if (lenOfLen > 4) {
                throw new RangeError("The length of the value cannot be represented on more than 4 bytes in this implementation");
            }

            while (lenOfLen > 0) {
                len = len | buf[index++];

                if (lenOfLen > 1) {
                    len = len << 8;
                }

                lenOfLen--;
            }
        } else {
            len = buf[index++];
        }

        value = buf.slice(index, len + index);
        index += len;

        if (tag.constructed) {
            value = this.parseAll(value);
        } else {
            if(Array.isArray(value)) {
                value = value.slice();
            }
            else {
                var tmpBuffer = value;
                value = new Buffer(tmpBuffer.length);
                tmpBuffer.copy(value);
            }
        }

        return new TLV(tag.tag, value, false, index);
    }

    isConstructed(tag: number) {
        return (tag & 0x20) == 0x20;
    }

    /**
     * Parses the first bytes of the given Buffer as a TLV tag. The tag is returned as an object
     * containing the tag, its length in bytes and whether it is constructed or not.
     * 
     * @param {Buffer} buf
     * @return {object}
     */
    parseTag(buf: Buffer | number[]) {
        var index = 0;
        var tag = buf[index++];
        var constructed = this.isConstructed(tag);

        if ((tag & 0x1F) == 0x1F) {
            do {
                tag = tag << 8;
                tag = tag | buf[index++];
            } while ((tag & 0x80) == 0x80);

            if (index > 4) {
                throw new RangeError("The length of the tag cannot be more than 4 bytes in this implementation");
            }
        }
        return { tag: tag, length: index, constructed: constructed };
    }

    /**
     * Parses the entire Buffer as a sequence of TLV tags. 
     * The tags are returned in an array, containing their numeric values.
     * 
     * @param {Buffer} buf
     * @return {Array}
     */
    parseAllTags(buf: Buffer) {
        var result = [];
        var element;

        while (buf.length > 0) {
            element = this.parseTag(buf);
            buf = buf.slice(element.length);
            result.push(element.tag);
        }

        return result;
    }
}