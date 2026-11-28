const assert = require("node:assert/strict");
const { buildUsRegionCheck, selectDefaultVoice } = require("../static/locale-checks.js");

const us = { targetCode: "US", navLang: "en-US", acceptLang: "en-US,en;q=0.9",
  intlLocales: { Date: "en-US", Number: "en-US", Collator: "en-US", RelativeTime: "en-US" } };
assert.equal(buildUsRegionCheck(us).status, "PASS");
assert.equal(buildUsRegionCheck({ ...us, navLang: "en-SG" }).status, "WARN");
assert.equal(buildUsRegionCheck({ ...us, acceptLang: "en-GB,en-US;q=0.9" }).status, "WARN");
assert.equal(buildUsRegionCheck({ ...us, intlLocales: { ...us.intlLocales, Date: "en-SG" } }).status, "WARN");
assert.equal(buildUsRegionCheck({ ...us, acceptLang: "" }).status, "WARN");
assert.equal(buildUsRegionCheck({ ...us, intlLocales: {} }).status, "WARN");
assert.equal(buildUsRegionCheck({ ...us, targetCode: "SG", navLang: "en-SG" }), null);
const unmarked = [{ name: "Majed", lang: "ar-001", default: false }, { name: "Samantha", lang: "en-US", default: false }];
assert.equal(selectDefaultVoice(unmarked), null);
assert.equal(selectDefaultVoice([...unmarked, { name: "Alex", lang: "en-US", default: true }]).name, "Alex");
assert.equal(selectDefaultVoice([]), null);
console.log("10 locale/default-voice regression cases passed");
