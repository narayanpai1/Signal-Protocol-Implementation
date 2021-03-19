function ab2str(buf) {
  return Buffer.from(String.fromCharCode.apply(null, new Uint16Array(buf)),'utf8').toString('base64');
}
function str2ab(str) {
  str = Buffer.from(str,'base64').toString('utf8')
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

module.exports = {
    ab2str,str2ab
}