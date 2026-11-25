import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawn} from "node:child_process";
import {createServer} from "node:net";
import {once} from "node:events";
import {hashPassword} from "../security.mjs";
test("HTTP sessions, CSRF, case ownership, supervisor access and logout",{timeout:30000},async()=>{
  const dir=await mkdtemp(join(tmpdir(),"soc-http-"));let child;
  try{
    const probe=createServer();probe.listen(0,"127.0.0.1");await once(probe,"listening");const port=probe.address().port;await new Promise(r=>probe.close(r));
    const origin="http://127.0.0.1:"+port,password="demo password for integration";
    const hash=await hashPassword(password),users=join(dir,"users.json");
    await writeFile(users,JSON.stringify([{username:"alice",role:"analyst",passwordHash:hash},{username:"bob",role:"analyst",passwordHash:hash},{username:"supervisor",role:"supervisor",passwordHash:hash}]));
    child=spawn(process.execPath,["server.mjs"],{env:{...process.env,PORT:String(port),SOC_ORIGIN:origin,SOC_USERS_FILE:users,SOC_DB_PATH:join(dir,"soc.db"),SOC_DATA_KEY:"ab".repeat(32),OLLAMA_MODEL:""},stdio:["ignore","pipe","pipe"]});
    let stderr="";child.stderr.on("data",x=>stderr+=x);
    for(let i=0;i<100;i++){try{if((await fetch(origin+"/healthz")).ok)break;}catch{}if(child.exitCode!==null||i===99)throw Error("Server did not start: "+stderr);await new Promise(r=>setTimeout(r,100));}
    const call=(path,{method="GET",cookie="",body,requestOrigin=origin}={})=>fetch(origin+path,{method,headers:{...(cookie?{Cookie:cookie}:{}),...(method!=="GET"?{Origin:requestOrigin,"Content-Type":"application/json"}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
    const login=async username=>{const r=await call("/api/login",{method:"POST",body:{username,password}});assert.equal(r.status,200);const c=r.headers.get("set-cookie");assert.match(c,/HttpOnly/);assert.match(c,/SameSite=Strict/);return c.split(";")[0];};
    assert.equal((await call("/api/cases")).status,401);
    assert.equal((await call("/api/login",{method:"POST",requestOrigin:"https://evil.example",body:{username:"alice",password}})).status,403);
    const alice=await login("alice"),bob=await login("bob"),supervisor=await login("supervisor");
    const created=await call("/api/investigate",{method:"POST",cookie:alice,body:{events:[{type:"malware_detection",detail:"demo"}]}});assert.equal(created.status,201);const c=await created.json();
    const route="/api/cases/"+c.id;
    assert.equal((await call(route,{cookie:bob})).status,404);
    assert.equal((await call(route,{cookie:supervisor})).status,200);
    assert.equal((await call("/api/audit",{cookie:alice})).status,403);
    assert.equal((await call("/api/audit",{cookie:supervisor})).status,200);
    const review={revision:1,disposition:"Escalated",notes:"verified"};
    assert.equal((await call(route,{method:"PATCH",cookie:bob,body:review})).status,404);
    assert.equal((await call(route,{method:"PATCH",cookie:alice,body:review})).status,200);
    assert.equal((await call(route,{method:"PATCH",cookie:alice,body:review})).status,409);
    assert.equal((await call("/api/logout",{method:"POST",cookie:alice})).status,200);
    assert.equal((await call("/api/cases",{cookie:alice})).status,401);
  }finally{if(child&&child.exitCode===null){child.kill("SIGTERM");await once(child,"exit");}await rm(dir,{recursive:true,force:true});}
});
