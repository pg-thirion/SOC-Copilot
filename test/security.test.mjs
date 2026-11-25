import {test} from "node:test";
import assert from "node:assert/strict";
import {hashPassword,verifyPassword,makeCrypto,loadUsers} from "../security.mjs";
test("scrypt hashes are salted and verified",async()=>{const p="a strong demo password";const a=await hashPassword(p),b=await hashPassword(p);assert.notEqual(a,b);assert.equal(await verifyPassword(p,a),true);assert.equal(await verifyPassword("wrong",a),false);assert.equal(await verifyPassword(p,undefined),false);});
test("authenticated encryption binds metadata",()=>{const c=makeCrypto("ab".repeat(32)),value=c.seal({secret:"telemetry"},"case1");assert.notEqual(value,c.seal({secret:"telemetry"},"case1"));assert.deepEqual(c.open(value,"case1"),{secret:"telemetry"});assert.throws(()=>c.open(value,"case2"));assert.throws(()=>makeCrypto("bad"));});
test("user configuration rejects missing supervisors",()=>assert.throws(()=>loadUsers("[]")));
