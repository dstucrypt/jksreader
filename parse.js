function reader(buf, pos) {
    return {buf: buf, pos: pos || 0}
}

function U32(inst) {
    var ret = inst.buf.readUInt32BE(inst.pos);
    inst.pos += 4;
    return ret;
}
function U16(inst) {
    var ret = inst.buf.readUInt16BE(inst.pos);
    inst.pos += 2;
    return ret;
}
function BIN(inst, len) {
    var ret = inst.buf.slice(inst.pos, inst.pos + len);
    inst.pos += len;
    return ret;
}
function STR(inst, len) {
    return BIN(inst, len).toString();
}

function readCert(_jks) {
    var type = STR(_jks, U16(_jks));
    var data = BIN(_jks, U32(_jks));
    return {type: type, data: data};
}

function readKey(_jks) {
    var name = STR(_jks, U16(_jks));
    U32(_jks); // skip timestamp high
    U32(_jks); // skip timestamp low
    var key_data = BIN(_jks, U32(_jks)).slice(0x18); // drop header

    var chain = U32(_jks);
    var certs = [];
    for (var j=0; j<chain; j++) {
        var cert = readCert(_jks);
        if (cert.type === 'X.509') {
            certs.push(cert.data);
        }
    }
    return {key: key_data, certs: certs, name: name};
}


var MAGIC_JKS = 0xfeedfeed;
function parse(jks) {
    var _jks = reader(jks);
    var magic = U32(_jks);
    if (magic !== MAGIC_JKS) {
        return null;
    }
    var version = U32(_jks);
    if (version !== 2) {
        return null;
    }
    var entries = U32(_jks);
    var material = [];
    for(var i=0; i<entries; i++) {
        var tag = U32(_jks);
        if (tag === 1) {
            material.push(readKey(_jks));
        }
        if (tag === 2) {
            material.push(readCert(_jks));
        }
    }
    return {
        format: 'jks',
        material: material,
    };
}

module.exports = parse;
