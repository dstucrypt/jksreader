var sha1 = require('js-sha1');

function encode_utf16(str) {
    var buf = new Buffer(str.length * 2);
    for(var i=0;i<str.length;i++) {
        var code = str.charCodeAt(i);
        buf[i*2] = (code & 0xFF00) >> 8;
        buf[(i*2)+1] = code & 0xFF;
    }
    return buf;
}

function decode(buf, password) {
  var pw = encode_utf16(password);
  var iv = buf.slice(0, 20);
  var data = buf.slice(20, buf.length - 20);
  var check = buf.slice(buf.length - 20);

  var open = new Buffer(data.length);
  var pos = 0;

  var cur = iv;

  while (pos < data.length) {
      var hash = sha1.create();
      hash.update(pw);
      hash.update(cur);
      cur = hash.digest();

      var i;
      for(i=0; i<cur.length; i++) {
          open[pos] = data[pos] ^ cur[i];
          pos++;
      }
  }

  var toCheck = sha1.create();
  toCheck.update(pw);
  toCheck.update(open);
  var digest = toCheck.digest();

  var match = 0;
  for(var i=0; i<check.length; i++) {
      match = (digest[i] ^ check[i]) || match;
  }

  return (match===0) ? open : null;

}

module.exports = decode;
