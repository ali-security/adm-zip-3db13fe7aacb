"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Same shape as craftBomb, but the oversized uncompressed size is smuggled in
// through the zip64 "extended information" extra field: the classic 32 bit size
// fields carry the 0xFFFFFFFF placeholder and the real (attacker chosen) size is
// picked up while the central directory extra field is parsed.
function craftZip64ExtraBomb(declaredSize, content) {
    const name = Buffer.from("a");
    const crc = 0;
    const placeholder = 0xffffffff;
    // header id 0x0001, 8 bytes of payload: 64 bit uncompressed size
    const zip64Extra = Buffer.concat([u16(0x0001), u16(8), u32(declaredSize), u32(0)]);
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(45),
        u16(0),
        u16(0) /* STORED */,
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(placeholder),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(45),
        u16(45),
        u16(0),
        u16(0) /* STORED */,
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(placeholder),
        u16(name.length),
        u16(zip64Extra.length),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name,
        zip64Extra
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

const rssMB = () => process.memoryUsage().rss / (1024 * 1024);

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the advisory's 0xFFFFFFFF declared size through readFile()", () => {
        // the published proof of concept sets CENLEN/LOCLEN to 0xFFFFFFFF (~4 GB)
        const zip = new Zip(craftBomb(0xffffffff, 0 /* STORED */, Buffer.from("A")));
        const before = rssMB();
        expect(() => zip.readFile("a")).to.throw(/CRC32/);
        expect(rssMB() - before, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate a size declared through the zip64 extra field", () => {
        // 0x7ff00000 stays under Buffer.kMaxLength on every supported node, so the
        // unpatched code really did commit ~2 GB here instead of failing fast
        const zip = new Zip(craftZip64ExtraBomb(0x7ff00000, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        expect(entry.header.size, "size must come from the zip64 extra field").to.equal(0x7ff00000);
        const before = rssMB();
        expect(() => entry.getData()).to.throw(/CRC32/);
        expect(rssMB() - before, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size on the async read path", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        let reported = null;
        const before = rssMB();
        expect(() =>
            entry.getDataAsync(function (data, err) {
                reported = err;
            })
        ).to.throw(/CRC32/);
        expect(String(reported)).to.match(/CRC32/);
        expect(rssMB() - before, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size while zip.test() validates the archive", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = rssMB();
        expect(zip.test()).to.equal(false);
        expect(rssMB() - before, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});
