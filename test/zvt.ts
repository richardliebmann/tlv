import { TLVParser } from "../lib/tlv-parser";
import { TLV } from "../lib/tlv";
import { TLVUtils } from "../lib/tlv-utils";
import { TLVEncoder } from "../lib/tlv-encoder";
const chai = require('chai');

chai.should();
    
const expect = chai.expect;

class ZVTTLVParser extends TLVParser {
    isConstructed(tag: number) {
        return super.isConstructed(tag) || tag == 0x06;
    }
}

describe('ZVT', function () {
    describe('#parse', function () {
        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 1 byte.', function () {
            var buf = Buffer.from([0x06, 0x0c, 0x26, 0x04, 0x0a, 0x02, 0x06, 0xd3, 0x1f, 0x73, 0x03, 0x00, 0x00, 0x00]);
            var parser = new ZVTTLVParser();
            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x06);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(14);
            expect(res.value).to.deep.equal([
                new TLV(0x26, [
                    new TLV(0x0A, Buffer.from([0x06, 0xD3]), false, 4)
                ], false, 6),
                new TLV(0x1F73, Buffer.from([0x00, 0x00, 0x00]), false, 6)
            ])
        });
    });
});