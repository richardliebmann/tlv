import { TLVParser } from "../lib/tlv-parser";
import { TLV } from "../lib/tlv";
import { TLVUtils } from "../lib/tlv-utils";
import { TLVEncoder } from "../lib/tlv-encoder";
const chai = require('chai');

chai.should();
var parser = new TLVParser();
    
const expect = chai.expect;
describe('TLV', function () {
    describe('#parse', function () {
        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 1 byte.', function () {
            var buf = Buffer.from([0x80, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]);
            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x80);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(6);
            expect(res.value).to.deep.equal(Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]));
            buf[2] = 0xAA;
            expect(res.value).to.deep.equal(Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length 0x00', function () {
            var res = parser.parse(Buffer.from([0x80, 0x00]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x80);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(2);
            expect(res.value).to.deep.equal(Buffer.from([]));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length 0x7F', function () {
            var buf = new Buffer(129);
            buf[0] = 0x80;
            buf[1] = 0x7F

            for (var i = 2; i < buf.length; i++) {
                buf[i] = i;
            }

            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x80);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(buf.length);
            expect(res.value).to.deep.equal(buf.slice(2, buf.length));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 2 bytes', function () {
            var buf = new Buffer(131);
            buf[0] = 0xC4;
            buf[1] = 0x81;
            buf[2] = 0x80;

            for (var i = 3; i < buf.length; i++) {
                buf[i] = i;
            }

            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0xC4);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(buf.length);
            expect(res.value).to.deep.equal(buf.slice(3, buf.length));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 3 bytes and spurious data at end', function () {
            var buf = new Buffer(0x109);
            buf[0] = 0x80;
            buf[1] = 0x82;
            buf[2] = 0x01;
            buf[3] = 0x00;

            for (var i = 4; i < buf.length; i++) {
                buf[i] = i;
            }

            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x80);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal((buf.length - 5));
            expect(res.value).to.deep.equal(buf.slice(4, (buf.length - 5)));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 4 bytes and spurious data at end', function () {
            var buf = new Buffer(0x1000A);
            buf[0] = 0x12;
            buf[1] = 0x83;
            buf[2] = 0x01;
            buf[3] = 0x00;
            buf[4] = 0x00;

            for (var i = 5; i < buf.length; i++) {
                buf[i] = i;
            }

            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x12);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(buf.length - 5);
            expect(res.value).to.deep.equal(buf.slice(5, (buf.length - 5)));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 1 byte and length on 5 bytes and spurious data at end', function () {
            var buf = new Buffer(0x100000B);
            buf[0] = 0x80;
            buf[1] = 0x84;
            buf[2] = 0x01;
            buf[3] = 0x00;
            buf[4] = 0x00;
            buf[5] = 0x00;
            buf[6] = 0xFF;
            buf[buf.length - 1] = 0xFF;

            var res = parser.parse(buf);

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x80);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(buf.length - 5);
            expect(res.value).to.deep.equal(buf.slice(6, (buf.length - 5)));
        });

        it('should throw an exception when provided a buffer with primitive tag on 1 byte and length on 6 bytes', function () {
            var buf = new Buffer(0x1000007);
            buf[0] = 0x80;
            buf[1] = 0x85;
            buf[2] = 0x01;
            buf[3] = 0x00;
            buf[4] = 0x00;
            buf[5] = 0x00;
            buf[6] = 0x00;

            expect(parser.parse(buf)).to.throw();
        });

        it('should return a TLV object when provided a buffer with constructed tag on 1 byte and length on 1 byte.', function () {
            var res = parser.parse(Buffer.from([0xE1, 0x08, 0x80, 0x02, 0xBA, 0xBE, 0x82, 0x02, 0xBB, 0xBC]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0xE1);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(10);
            expect(res.value).to.deep.equal([
                new TLV(0x80, Buffer.from([0xBA, 0xBE]), false, 4),
                new TLV(0x82, Buffer.from([0xBB, 0xBC]), false, 4)
            ]);
        });

        it('should return a TLV object when provided a buffer with constructed tag on 1 byte and zero length.', function () {
            var res = parser.parse(Buffer.from([0xE1, 0x00]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0xE1);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(2);
            expect(res.value).to.deep.equal([]);
        });

        it('should return a TLV object when provided a buffer with constructed tlvs with 2 levels of nesting', function () {
            var res = parser.parse(Buffer.from([0xE1, 0x0C, 0xA0, 0x04, 0x82, 0x02, 0xCA, 0xFE, 0x00, 0x00, 0x83, 0x02, 0xBB, 0xBC]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0xE1);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(14);
            expect(res.value).to.deep.equal([
                new TLV(0xA0, [new TLV(0x82, Buffer.from([0xCA, 0xFE]), false, 4)], false, 6),
                new TLV(0x00, new Buffer(0), false, 2),
                new TLV(0x83, Buffer.from([0xBB, 0xBC]), false, 4)
            ]);
        });

        it('should return a TLV object when provided a buffer with primitive tag on 2 bytes and length on 2 bytes.', function () {
            var res = parser.parse(Buffer.from([0x9F, 0x70, 0x81, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]));

           expect(res).to.be.an.instanceof(TLV);
           expect(res.tag).to.equal(0x9F70);
           expect(res.constructed).to.equal(false);
           expect(res.indefiniteLength).to.equal(false);
           expect(res.originalLength).to.equal(8);
           expect(res.value).to.deep.equal(Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 3 bytes and length on 2 bytes.', function () {
            var res = parser.parse(Buffer.from([0x9F, 0x85, 0x22, 0x81, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x9F8522);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(9);
            expect(res.value).to.deep.equal(Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should return a TLV object when provided a buffer with primitive tag on 4 bytes and length on 2 bytes.', function () {
            var res = parser.parse(Buffer.from([0x1F, 0x85, 0xA2, 0x01, 0x81, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0x1F85A201);
            expect(res.constructed).to.equal(false);
            expect(res.indefiniteLength).to.equal(false);
            expect(res.originalLength).to.equal(10);
            expect(res.value).to.deep.equal(Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should throw an exception when provided a buffer with primitive tag on 5 bytes.', function () {
            var buf = Buffer.from([0x1F, 0x85, 0xA2, 0x81, 0x01, 0x00]);

            expect(parser.parse(buf)).to.throw(RangeError);
        });

        it('should return a TLV object when provided a buffer with constructed tag and indefinite length and spurious data after the end.', function () {
            var res = parser.parse(Buffer.from([0xE1, 0x80, 0x81, 0x02, 0x00, 0x00, 0x82, 0x02, 0xBB, 0xBC, 0x00, 0x00, 0xAA, 0xFF]));

            expect(res).to.be.an.instanceof(TLV);
            expect(res.tag).to.equal(0xE1);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(true);
            expect(res.originalLength).to.equal(12);
            expect(res.value).to.deep.equal([
                new TLV(0x81, Buffer.from([0x00, 0x00]), false, 4),
                new TLV(0x82, Buffer.from([0xBB, 0xBC]), false, 4)
            ]);
        });

        it('should return a TLV object when provided a buffer with constructed tag and indefinite length.', function () {
            var buf = Buffer.from([0xe1, 0x80, 0xa0, 0x03, 0x81, 0x01, 0x03, 0x00, 0x00]);
            var res = parser.parse(buf);

            expect(res.tag).to.equal(0xe1);
            expect(res.constructed).to.equal(true);
            expect(res.indefiniteLength).to.equal(true);
            expect(res.originalLength).to.equal(9);
        });

        it('should throw an exception when provided a buffer with primitive tag and indefinite length.', function () {
            var buf = Buffer.from([0xC0, 0x80, 0x81, 0x01, 0x00, 0x00, 0x00]);

            expect(parser.parse(buf)).to.throw(Error);
        });
    });

    describe('#byteLength', function () {
        it('should return the length of an encoded TLV object with primitive tag on 1 byte and length 7F', function () {
            var buf = new Buffer(0x7F);
            for (var i = 0; i < buf.length; i++) {
                buf[i] = i;
            }

            var tlv = new TLV(0xC2, buf);
            expect(tlv.byteLength).to.equal(129);
        });

        it('should return the length of an encoded TLV object with primitive tag on 2 bytes and length 0', function () {
            var buf = new Buffer(0);

            var tlv = new TLV(0x9FC2, buf);
            expect(tlv.byteLength).to.equal(3);
        });

        it('should return the length of an encoded TLV object with primitive tag on 3 bytes and length on 3 bytes', function () {
            var buf = new Buffer(0x100);

            var tlv = new TLV(0x9FC2C2, buf);
            expect(tlv.byteLength).to.equal(0x106);
        });

        it('should return the length of an encoded TLV object with primitive tag on 4 bytes and length on 2 bytes', function () {
            var buf = new Buffer(0x80);

            var tlv = new TLV(0x9FC2C222, buf);
            expect(tlv.byteLength).to.equal(0x86);
        });

        it('should return the length of an encoded TLV object with constructed tag', function () {
            var buf = new Buffer(0x80);

            var tlvChild1 = new TLV(0x9F70, buf);
            var tlvChild2 = new TLV(0x82, new Buffer(1));
            var tlv = new TLV(0x3F12, [tlvChild1, tlvChild2]);

            expect(tlv.byteLength).to.equal(0x8B);
        });

        it('should return the length of an encoded TLV object with constructed tag and indefinite length', function () {
            var buf = new Buffer(0x80);

            var tlvChild1 = new TLV(0x9F70, buf, true);
            var tlvChild2 = new TLV(0x82, new Buffer(1));
            var tlv = new TLV(0x3F12, [tlvChild1, tlvChild2]);

            expect(tlv.byteLength).to.equal(0x8C);
        });
    });

    describe('#encode', function () {
        it('should encode the TLV object in the given Buffer. The TLV is primitive with tag on 1 byte and length on 1 byte', function () {
            var outputBuf = new Buffer(6);
            var buf = Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]);
            var tlv = new TLV(0x80, buf);
            var returnedBuf = tlv.encode(outputBuf);
            expect(returnedBuf).to.equal(outputBuf);
            expect(returnedBuf).to.deep.equal(Buffer.from([0x80, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is primitive with tag on 1 byte and length on 1 byte', function () {
            var tlvHeader = Buffer.from([0x80, 0x7F]);
            var buf = new Buffer(0x7F);
            var tlv = new TLV(0x80, buf);
            expect(tlv.encode()).to.deep.equal(Buffer.concat([tlvHeader, buf]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is constructed with tag on 1 byte and length on 1 byte', function () {
            var buf = Buffer.from([0xBA, 0xBE]);
            var tlv = new TLV(0xA0, [new TLV(0xCA, buf)]);
            expect(tlv.encode()).to.deep.equal(Buffer.from([0xA0, 0x04, 0xCA, 0x02, 0xBA, 0xBE]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is primitive with tag on 2 bytes and length on 1 byte', function () {
            var buf = Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]);
            var tlv = new TLV(0x9F70, buf);
            expect(tlv.encode()).to.deep.equal(Buffer.from([0x9F, 0x70, 0x04, 0xCA, 0xFE, 0xBA, 0xBE]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is primitive with tag on 3 bytes and length on 2 bytes', function () {
            var tlvHeader = Buffer.from([0x9F, 0x81, 0x20, 0x81, 0x80]);
            var buf = new Buffer(0x80);
            var tlv = new TLV(0x9F8120, buf);
            expect(tlv.encode()).to.deep.equal(Buffer.concat([tlvHeader, buf]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is primitive with tag on 1 byte and length on 3 bytes', function () {
            var tlvHeader = Buffer.from([0xC0, 0x82, 0x01, 0x00]);
            var buf = new Buffer(0x100);
            var tlv = new TLV(0xC0, buf);
            expect(tlv.encode()).to.deep.equal(Buffer.concat([tlvHeader, buf]));
        });

        it('should return a Buffer containing the encoded TLV object. The TLV is constructed with tag on 1 byte and indefinite length', function () {
            var buf = Buffer.from([0xBA, 0xBE]);
            var tlv = new TLV(0xA0, [new TLV(0xCA, buf)], true);
            expect(tlv.encode()).to.deep.equal(Buffer.from([0xA0, 0x80, 0xCA, 0x02, 0xBA, 0xBE, 0x00, 0x00]));
        });
    });

    describe('#getFirstChild', function () {
        it('should return the first child with the given tag', function () {
            var parentTlv = new TLV(0xE1, [
                new TLV(0x80, Buffer.from([0xfa, 0xfb])),
                new TLV(0x81, Buffer.from([0xaa, 0xab])),
                new TLV(0x82, Buffer.from([0xda, 0xdb])),
                new TLV(0x81, Buffer.from([0xff, 0xff])),
                new TLV(0x83, Buffer.from([0xdf, 0xaf])),
            ]);

            var child = parentTlv.getFirstChild(0x80);
            expect(child.tag).to.equal(0x80);
            expect(child.value).to.deep.equal(Buffer.from([0xfa, 0xfb]));

            child = parentTlv.getFirstChild(0x81);
            expect(child.tag).to.equal(0x81);
            expect(child.value).to.deep.equal(Buffer.from([0xaa, 0xab]));

            child = parentTlv.getFirstChild(0x82);
            expect(child.tag).to.equal(0x82);
            expect(child.value).to.deep.equal(Buffer.from([0xda, 0xdb]));

            child = parentTlv.getFirstChild(0x83);
            expect(child.tag).to.equal(0x83);
            expect(child.value).to.deep.equal(Buffer.from([0xdf, 0xaf]));
        });

        it('should return null if no child with the given tag is found', function () {
            var parentTlv = new TLV(0xE1, [
                new TLV(0x80, Buffer.from([0xfa, 0xfb])),
                new TLV(0x81, Buffer.from([0xaa, 0xab])),
                new TLV(0x82, Buffer.from([0xda, 0xdb])),
                new TLV(0x81, Buffer.from([0xff, 0xff])),
                new TLV(0x83, Buffer.from([0xdf, 0xaf])),
            ]);

            expect(parentTlv.getFirstChild(0x84)).to.be.null;
        });
    });

    describe('#getChildren', function () {
        it('should return all children with the given tag', function () {
            var parentTlv = new TLV(0xE1, [
                new TLV(0x80, Buffer.from([0xfa, 0xfb])),
                new TLV(0x81, Buffer.from([0xaa, 0xab])),
                new TLV(0x81, Buffer.from([0xa1, 0xa2])),
                new TLV(0x82, Buffer.from([0xda, 0xdb])),
                new TLV(0x81, Buffer.from([0xff, 0xff])),
                new TLV(0x83, Buffer.from([0xdf, 0xaf])),
            ]);

            var children = parentTlv.getChildren(0x80);
            expect(children).to.deep.equal([parentTlv.value[0]]);

            children = parentTlv.getChildren(0x81);
            expect(children).to.deep.equal([parentTlv.value[1], parentTlv.value[2], parentTlv.value[4]]);

            children = parentTlv.getChildren(0x82);
            expect(children).to.deep.equal([parentTlv.value[3]]);

            children = parentTlv.getChildren(0x83);
            expect(children).to.deep.equal([parentTlv.value[5]]);
        });

        it('should return an empty array if no children with the given tag are found', function () {
            var parentTlv = new TLV(0xE1, [
                new TLV(0x80, Buffer.from([0xfa, 0xfb])),
                new TLV(0x81, Buffer.from([0xaa, 0xab])),
                new TLV(0x81, Buffer.from([0xa1, 0xa2])),
                new TLV(0x82, Buffer.from([0xda, 0xdb])),
                new TLV(0x81, Buffer.from([0xff, 0xff])),
                new TLV(0x83, Buffer.from([0xdf, 0xaf])),
            ]);

            expect(parentTlv.getChildren(0x84)).to.deep.equal([]);
        });
    });

    describe('#parseTag', function () {
        it('should parse a tag and returns it as an object with tag, length and constructed properties', function () {
            var buf = Buffer.from([0x9f, 0x70]);
            var tag = parser.parseTag(buf);
            expect(tag.tag).to.equal(0x9f70);
            expect(tag.length).to.equal(2);
            expect(tag.constructed).to.equal(false);
        });
    });

    describe('#parseAllTags', function () {
        it('should parse the entire buffer as TLV tags and returns an array of integers with the tags', function () {
            var buf = Buffer.from([0x9f, 0x70, 0x80, 0xA0, 0x9f, 0x80, 0x7f, 0x81]);
            var tag = parser.parseAllTags(buf);

            expect(tag[0]).to.equal(0x9f70);
            expect(tag[1]).to.equal(0x80);
            expect(tag[2]).to.equal(0xA0);
            expect(tag[3]).to.equal(0x9f807f);
            expect(tag[4]).to.equal(0x81);
        });
    });

    describe('#encodeTags', function () {
        it('should return a new buffer containing the encoded form the given array of tags', function () {
            var tags = [0x9f70, 0x80, 0xA0, 0x9f807f];
            var buf = TLVEncoder.encodeTags(tags);
            expect(buf).to.deep.equal(Buffer.from([0x9f, 0x70, 0x80, 0xA0, 0x9f, 0x80, 0x7f]));
        });
    }); 

    describe('#getUIntValue', function () {
        it('should return an unsigned big endian integer from a 1 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff]));
            expect(intTlv.getUIntValue()).to.equal(255);
        });

        it('should return an unsigned big endian integer from a 2 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff]));
            expect(intTlv.getUIntValue()).to.equal(65535);
        });

        it('should return an unsigned big endian integer from a 3 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff, 0xff]));
            expect(intTlv.getUIntValue()).to.equal(16777215);
        });

        it('should return an unsigned big endian integer from a 4 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff, 0xff, 0xff]));
            expect(intTlv.getUIntValue()).to.equal(4294967295);

            intTlv = new TLV(0x80, Buffer.from([0xde, 0xad, 0xbe, 0xef]));
            expect(intTlv.getUIntValue()).to.equal(3735928559);
        });
    });

    describe('#getIntValue', function () {
        it('should return an signed big endian integer from a 1 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff]));
            expect(intTlv.getIntValue()).to.equal(-1);

            intTlv = new TLV(0x80, Buffer.from([0x7f]));
            expect(intTlv.getIntValue()).to.equal(127);
        });

        it('should return an signed big endian integer from a 2 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff]));
            expect(intTlv.getIntValue()).to.equal(-1);

            intTlv = new TLV(0x80, Buffer.from([0x7f, 0xff]));
            expect(intTlv.getIntValue()).to.equal(32767);
        });

        it('should return an signed big endian integer from a 3 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff, 0xff]));
            expect(intTlv.getIntValue()).to.equal(-1);

            intTlv = new TLV(0x80, Buffer.from([0x7f, 0xff, 0xff]));
            expect(intTlv.getIntValue()).to.equal(8388607);
        });

        it('should return an signed big endian integer from a 4 byte buffer', function () {
            var intTlv = new TLV(0x80, Buffer.from([0xff, 0xff, 0xff, 0xff]));
            expect(intTlv.getIntValue()).to.equal(-1);

            intTlv = new TLV(0x80, Buffer.from([0x5e, 0xad, 0xbe, 0xef]));
            expect(intTlv.getIntValue()).to.equal(1588444911);
        });
    });

    describe('#setIntValue', function () {
        it('should write a big endian integer in a 1 byte buffer', function () {
            var intTlv = new TLV(0x80, new Buffer(1));
            intTlv.setIntValue(255);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff]));

            intTlv.setIntValue(-1);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff]));

            intTlv.setIntValue(127);
            expect(intTlv.value).to.deep.equal(Buffer.from([0x7f]));
        });

        it('should write a big endian integer in a 2 byte buffer', function () {
            var intTlv = new TLV(0x80, new Buffer(2));
            intTlv.setIntValue(65535);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff]));

            intTlv.setIntValue(-1);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff]));

            intTlv.setIntValue(32767);
            expect(intTlv.value).to.deep.equal(Buffer.from([0x7f, 0xff]));
        });

        it('should write a big endian integer in a 3 byte buffer', function () {
            var intTlv = new TLV(0x80, new Buffer(3));
            intTlv.setIntValue(16777215);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff, 0xff]));

            intTlv.setIntValue(-1);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff, 0xff]));

            intTlv.setIntValue(8388607);
            expect(intTlv.value).to.deep.equal(Buffer.from([0x7f, 0xff, 0xff]));
        });

        it('should write a big endian integer in a 4 byte buffer', function () {
            var intTlv = new TLV(0x80, new Buffer(4));
            intTlv.setIntValue(4294967295);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff, 0xff, 0xff]));

            intTlv.setIntValue(-1);
            expect(intTlv.value).to.deep.equal(Buffer.from([0xff, 0xff, 0xff, 0xff]));

            intTlv.setIntValue(2147483647);
            expect(intTlv.value).to.deep.equal(Buffer.from([0x7f, 0xff, 0xff, 0xff]));
        });
    });
});