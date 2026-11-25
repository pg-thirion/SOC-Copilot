import assert from "node:assert/strict";
import {chromium} from "playwright";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawn} from "node:child_process";
import {once} from "node:events";
import {createServer} from "node:net";
import {hashPassword} from "../security.mjs";
const dir=await mkdtemp(join(tmpdir(),"soc-browser-"));
let browser,child;
try{
  const probe=createServer();probe.listen(0,"127.0.0.1");await once(probe,"listening");const port=probe.address().port;await new Promise(r=>probe.close(r));
  const origin="http://127.0.0.1:"+port,password="browser testing password";
  const passwordHash=await hashPassword(password),users=join(dir,"users.json");
  await writeFile(users,JSON.stringify([{username:"analyst",role:"analyst",passwordHash},{username:"supervisor",role:"supervisor",passwordHash}]));
  child=spawn(process.execPath,["server.mjs"],{env:{...process.env,PORT:String(port),SOC_ORIGIN:origin,SOC_USERS_FILE:users,SOC_DB_PATH:join(dir,"soc.db"),SOC_DATA_KEY:"ab".repeat(32),OLLAMA_MODEL:""},stdio:"inherit"});
  for(let i=0;i<100;i++){try{if((await fetch(origin+"/healthz")).ok)break;}catch{}if(i===99||child.exitCode!==null)throw Error("Server failed to start");await new Promise(r=>setTimeout(r,100));}
  browser=await chromium.launch({headless:true});
  const page=await browser.newPage({viewport:{width:1440,height:900},acceptDownloads:true});const errors=[];page.on("pageerror",e=>errors.push(e.message));
  const waitText=async(selector,text)=>page.waitForFunction(([s,t])=>document.querySelector(s)?.textContent.includes(t),[selector,text]);
  const login=async username=>{await page.locator("#username").fill(username);await page.locator("#password").fill(password);await page.locator("#login-form button").click();await page.locator("#workspace").waitFor({state:"visible"});await waitText("#identity",username);await page.waitForFunction(()=>document.querySelectorAll("#sample option").length===8);};
  await page.goto(origin);await login("analyst");
  await page.locator("#sample").selectOption({label:"Password spraying"});await page.locator("#run").click();await waitText("#classification","Possible password spraying");await waitText("#case-id","Revision 1");
  await page.locator("#timeline-query").fill("employee1");await waitText("#timeline-count","1 of 6");await page.locator("#timeline-query").clear();
  await page.locator("#integrity").click();await waitText("#integrity-result","Fingerprint verified");
  await page.locator("#case-title").fill("Browser investigation");await page.locator("#case-priority").selectOption("P1");await page.locator("#case-status").selectOption("Awaiting approval");await page.locator("#case-tags").fill("identity, urgent");await page.locator("#tasks input").first().check();await page.locator("#save-workflow").click();await waitText("#workflow-status","Saved revision 2");
  await page.locator("#disposition").selectOption("Escalated");await page.locator("#notes").fill("Browser test completed.");await page.locator("#save").click();await waitText("#save-status","Saved revision 3");
  await page.locator("#filter-tag").fill("identity");await page.locator("#filter-tag").press("Tab");await waitText("#cases","Browser investigation");
  const [download]=await Promise.all([page.waitForEvent("download"),page.locator("#summary-export").click()]);assert.match(download.suggestedFilename(),/^soc-summary-/);
  const [full]=await Promise.all([page.waitForEvent("download"),page.locator("#export").click()]);assert.equal(full.suggestedFilename(),"soc-investigation.json");
  await page.locator("#logout").click();await page.locator("#login").waitFor({state:"visible"});assert.equal(await page.locator("#notes").inputValue(),"");
  await login("supervisor");await waitText("#cases","Browser investigation");await page.locator("#cases button").filter({hasText:"Browser investigation"}).click();await waitText("#case-id","Revision 3");
  await page.locator("#case-status").selectOption("Closed");await page.locator("#save-workflow").click();await waitText("#workflow-status","Saved revision 4");
  await page.locator("#audit").click();await waitText("#audit-status","Integrity check passed");
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),true,"Mobile horizontal overflow");
  assert.deepEqual(errors,[]);
  console.log("Chromium workflow passed: login, investigation, evidence, checklist, workflow, review, filtering, exports, logout, supervisor closure, audit and mobile layout.");
}finally{if(browser)await browser.close();if(child&&child.exitCode===null){child.kill("SIGTERM");await once(child,"exit");}await rm(dir,{recursive:true,force:true});}
