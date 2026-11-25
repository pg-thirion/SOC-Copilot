import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
test("UI control IDs are present and unique",()=>{const html=readFileSync(new URL("../public/index.html",import.meta.url),"utf8"),js=readFileSync(new URL("../public/app.js",import.meta.url),"utf8");const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(new Set(ids).size,ids.length);for(const m of js.matchAll(/\$\("([^"]+)"\)/g))assert.ok(ids.includes(m[1]),"Missing control: "+m[1]);assert.ok(!js.includes(".innerHTML"));});
