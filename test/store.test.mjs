import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,rmSync,readFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {DatabaseSync} from "node:sqlite";
import {makeCrypto} from "../security.mjs";
import {openStore} from "../store.mjs";
test("persistent encrypted cases, ownership, revisions and audit integrity",()=>{
  const dir=mkdtempSync(join(tmpdir(),"soc-store-")),path=join(dir,"test.db"),crypto=makeCrypto("ab".repeat(32));
  const alice={username:"alice",role:"analyst"},bob={username:"bob",role:"analyst"},supervisor={username:"supervisor",role:"supervisor"};
  let s;
  try{
    s=openStore(path,crypto);
    const c=s.create(alice,{severity:"high",classification:"credential attack",events:[{detail:"SENSITIVE_TEST_TELEMETRY"}]});
    assert.equal(s.list(alice).items.length,1);assert.equal(s.list(bob).items.length,0);assert.equal(s.get(c.id,bob),null);assert.equal(s.review(c.id,bob,1,{}).status,404);
    assert.equal(s.get(c.id,supervisor).id,c.id);
    assert.equal(s.review(c.id,alice,1,{disposition:"Escalated",notes:"reviewed"}).status,200);
    assert.equal(s.review(c.id,alice,1,{disposition:"False positive",notes:"stale"}).status,409);
    assert.equal(s.verifyAudit().valid,true);
    s.close();s=null;assert.equal(readFileSync(path).includes("SENSITIVE_TEST_TELEMETRY"),false);
    assert.throws(()=>openStore(path,makeCrypto("cd".repeat(32))),/does not match/);
    s=openStore(path,crypto);assert.equal(s.get(c.id,alice).review.disposition,"Escalated");s.close();s=null;
    const tamper=new DatabaseSync(path);tamper.exec("UPDATE audit SET action='changed' WHERE seq=1");tamper.close();
    s=openStore(path,crypto);assert.equal(s.verifyAudit().valid,false);
  }finally{if(s)s.close();rmSync(dir,{recursive:true,force:true});}
});
