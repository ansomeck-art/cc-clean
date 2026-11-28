/* Private JavaScriptCore entry point; no network, filesystem or logging APIs. */
var RegionGuardFilter = (function () {
  function bytes(value) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var output = [], bits = 0, buffer = 0;
    for (var i = 0; i < value.length; i++) {
      var n = alphabet.indexOf(value.charAt(i));
      if (n < 0) break;
      buffer = (buffer << 6) | n; bits += 6;
      if (bits >= 8) { bits -= 8; output.push((buffer >> bits) & 255); }
    }
    return new Uint8Array(output);
  }
  return {
    endpoint: function (url, method) { return !!rgPolicy.endpoint(url, method); },
    inspectJSON: function (serialized) {
      var request = JSON.parse(serialized);
      request.body = bytes(request.bodyBase64 || '');
      delete request.bodyBase64;
      return JSON.stringify(rgPolicy.inspect(request, rgCompression));
    }
  };
})();
