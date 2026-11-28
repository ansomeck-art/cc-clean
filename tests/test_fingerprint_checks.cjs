const assert = require("node:assert/strict");
const { buildFingerprintCheck } = require("../static/fingerprint-checks.js");

function inspect(canvasHashes, audioHashes) {
  const result = buildFingerprintCheck({ canvasHashes, audioHashes });
  assert.equal(result.status, "INFO", "hash samples alone cannot establish a security failure");
  assert.equal(result.severity, "low");
  return result;
}
assert.match(inspect(["a", "a"], ["b", "b"]).observed, /两次一致/);
const audioChanges = inspect(["a", "a"], ["b", "c"]);
assert.match(audioChanges.observed, /Audio=b \/ c（两次不同）/);
assert.match(audioChanges.detail, /不能确定原因/);
assert.match(inspect(["a", "c"], ["b", "b"]).observed, /Canvas=a \/ c（两次不同）/);
assert.match(inspect(["a", "c"], ["b", "d"]).detail, /内置防指纹保护/);
assert.match(inspect(["a", "a"], ["", ""]).observed, /Audio=.*采样未完成/);
assert.match(inspect(["a", "a"], ["b", ""]).observed, /Audio=b \/ 不可用（采样未完成）/);
assert.match(inspect([], []).detail, /不可用不算稳定/);
assert.match(inspect(null, undefined).observed, /采样未完成/);
console.log("8 fingerprint evidence regression cases passed");
