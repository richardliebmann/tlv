import { TLV } from "./tlv";
import { TLVUtils } from "./tlv-utils";

export class TLVEncoder {

    /**
     * Encodes an array of tags in a new Buffer. 
     * 
     * @param {Array} tags
     * @return {Buffer}
     */
    static encodeTags(tags: number[]) {
        var bufLength = 0;
        var tagLengths = []

        for (var i = 0; i < tags.length; i++) {
            var tagLength = TLVUtils.getTagLength(tags[i]);
            tagLengths.push(tagLength);
            bufLength += tagLength;
        }

        var buf = new Buffer(bufLength);
        var slicedBuf = buf;

        for (var i = 0; i < tags.length; i++) {
            TLVUtils.encodeNumber(slicedBuf, tags[i], tagLengths[i]);
            slicedBuf = slicedBuf.slice(tagLengths[i]);
        }

        return buf;
    }

}