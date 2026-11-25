const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;};
let examples=[],report=null,current=null,offset=0,auditBefore=null,epoch=0;
let account=null;
async function init(){
  try{
    const data=await api("/api/examples"); $("sample").replaceChildren(node("option","Choose a scenario")); $("sample").firstChild.value="";examples=data.examples;
    for(const [i,e] of examples.entries()){const option=node("option",e.name);option.value=i;$("sample").append(option);}
    $("ai").disabled=!data.aiAvailable;
    $("model-status").textContent=data.aiAvailable?"Model configured. Only rule summaries and evidence IDs are sent.":"Offline rules active. Configure OLLAMA_MODEL to enable local AI.";
  }catch(e){$("model-status").textContent=e.message;}
}
$("sample").addEventListener("change",()=>{const i=$("sample").value;if(i!=="")$("events").value=JSON.stringify(examples[Number(i)].events,null,2);});
$("file").addEventListener("change",async()=>{const f=$("file").files[0];if(!f)return;if(f.size>256000){$("error").textContent="File exceeds 256 KB.";return;}try{$("events").value=await f.text();$("sample").value="";$("error").textContent="";}catch{$("error").textContent="Could not read file.";}});
function render(r){
  $("severity").textContent=r.severity.toUpperCase();$("severity").className=r.severity;
  $("count").textContent=r.findings.length;$("total").textContent=r.events.length;
  $("classification").textContent=r.classification;
  $("findings").replaceChildren();
  if(!r.findings.length)$("findings").append(node("p","No supported pattern matched. Review the evidence manually.","muted"));
  for(const f of r.findings){
    const card=node("div","","finding");card.append(node("h3",f.category+" · "+f.severity.toUpperCase(),f.severity),node("p",f.summary),node("p","Evidence: "+f.evidence.join(", ")+(f.mitre?" | Possible ATT&CK: "+f.mitre:""),"muted"),node("strong","Recommended verification and response"));
    const list=node("ul","");for(const a of f.actions)list.append(node("li",a));card.append(list);$("findings").append(card);
  }
  $("timeline").replaceChildren();$("timeline-empty").hidden=true;
  for(const e of [...r.events].sort((a,b)=>(Date.parse(a.timestamp)||0)-(Date.parse(b.timestamp)||0))){
    const tr=node("tr","");for(const value of [e.id,e.timestamp,e.type,[e.user,e.host].filter(Boolean).join(" / "),e.ip,e.outcome,e.detail])tr.append(node("td",value||"—"));$("timeline").append(tr);
  }
  $("ai-output").textContent=r.ai.text;$("limitations").replaceChildren(...r.limitations.map(x=>node("li",x)));
  $("disposition").value="Pending review";$("notes").value="";$("export").disabled=false;
}
$("run").addEventListener("click",async()=>{
  $("error").textContent="";$("run").disabled=true;$("export").disabled=true;
  try{
    const events=JSON.parse($("events").value);
    const generation=epoch; const c=await api("/api/investigate",{method:"POST",body:JSON.stringify({events,ai:$("ai").checked})}); if(generation!==epoch)return; showCase(c); await loadCases();
  }catch(e){$("error").textContent=e.message+" Previous results, if shown, have not changed.";$("export").disabled=!report;}
  finally{$("run").disabled=false;}
});
$("export").addEventListener("click",()=>{
  if(!report)return;
  const exported={...report,caseId:current.id,revision:current.revision,owner:current.owner,review:{...current.review,exportedAt:new Date().toISOString()}};
  const url=URL.createObjectURL(new Blob([JSON.stringify(exported,null,2)],{type:"application/json"}));
  const a=document.createElement("a");a.href=url;a.download="soc-investigation.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});

async function api(path,options={}){
  const r=await fetch(path,{...options,headers:{"Content-Type":"application/json",...options.headers},cache:"no-store"});
  const data=await r.json();
  if(r.status===401&&path!=="/api/login"){signedOut();throw Error("Session expired. Sign in again.");}
  if(!r.ok)throw Error(data.error||"Request failed.");
  return data;
}
function signedOut(){
  epoch++;account=null;current=null;report=null;examples=[];offset=0;auditBefore=null;
  $("workspace").hidden=true;$("login").hidden=false;$("logout").hidden=true;$("identity").textContent="AUTHENTICATION REQUIRED";
  for(const id of ["events","notes","password","error","save-status","case-id","audit-status"]) {const e=$(id);if("value" in e)e.value="";else e.textContent="";}
  $("file").value="";$("sample").replaceChildren(node("option","Choose a scenario"));$("sample").firstChild.value="";
  $("severity").textContent="Pending";$("severity").className="";$("count").textContent="0";$("total").textContent="0";$("classification").textContent="Awaiting intake";
  for(const id of ["findings","timeline","cases","audit-items"])$(id).replaceChildren();
  $("timeline-empty").hidden=false;$("ai-output").textContent="No investigation yet.";$("export").disabled=true;$("save").disabled=true;$("ai").checked=false;
  $("audit-panel").hidden=true;$("more-audit").hidden=true;$("more-cases").hidden=true;
}
async function signedIn(user){
  account=user;epoch++;$("workspace").hidden=false;$("login").hidden=true;$("logout").hidden=false;
  $("identity").textContent=user.username+" / "+user.role;$("audit-panel").hidden=user.role!=="supervisor";
  await init();await loadCases();
}
$("login-form").addEventListener("submit",async e=>{
  e.preventDefault();const button=e.currentTarget.querySelector("button");button.disabled=true;$("login-error").textContent="";
  try{const user=await api("/api/login",{method:"POST",body:JSON.stringify({username:$("username").value,password:$("password").value})});await signedIn(user);}
  catch(e){$("login-error").textContent=e.message;}finally{$("password").value="";button.disabled=false;}
});
$("logout").addEventListener("click",async()=>{try{await api("/api/logout",{method:"POST"});signedOut();}catch(e){$("error").textContent=e.message;}});
function showCase(c){
  current=c;report=c.report;render(c.report);
  $("case-id").textContent="Case "+c.id+" | Revision "+c.revision+" | Owner "+c.owner;
  $("disposition").value=c.review.disposition;$("notes").value=c.review.notes;$("save").disabled=false;$("save-status").textContent="Saved revision "+c.revision;
}
async function loadCases(append=false){
  const generation=epoch;
  if(!append)offset=0;
  try{
    const data=await api("/api/cases?offset="+offset);if(generation!==epoch)return;
    if(!append)$("cases").replaceChildren();
    if(!data.items.length&&!append)$("cases").append(node("p","No saved cases.","muted"));
    for(const c of data.items){
      const button=node("button",c.classification+" / "+c.severity.toUpperCase(),c.severity);button.append(node("small",c.disposition+" · "+c.owner+" · "+c.updated));
      button.addEventListener("click",async()=>{const g=epoch;try{const item=await api("/api/cases/"+c.id);if(g===epoch)showCase(item);}catch(e){$("error").textContent=e.message;}});$("cases").append(button);
    }
    offset=data.nextOffset;$("more-cases").hidden=offset===null;
  }catch(e){$("error").textContent=e.message;}
}
$("refresh").addEventListener("click",()=>loadCases());
$("more-cases").addEventListener("click",()=>loadCases(true));
$("save").addEventListener("click",async()=>{
  if(!current)return;const id=current.id,generation=epoch;$("save").disabled=true;
  try{
    const c=await api("/api/cases/"+id,{method:"PATCH",body:JSON.stringify({revision:current.revision,disposition:$("disposition").value,notes:$("notes").value})});
    if(generation!==epoch)return;if(current?.id===id)showCase(c);await loadCases();
  }catch(e){$("save-status").textContent=e.message;}finally{if(current)$("save").disabled=false;}
});
for(const id of ["notes","disposition"])$(id).addEventListener("input",()=>{$("save-status").textContent="Unsaved changes. Save before exporting.";$("export").disabled=true;});
async function loadAudit(append=false){
  const generation=epoch;
  try{const data=await api("/api/audit"+(append&&auditBefore?"?before="+auditBefore:""));if(generation!==epoch)return;
    $("audit-status").textContent=(data.valid?"Integrity check passed":"Integrity check FAILED")+" · "+data.checked+" records";
    if(!append)$("audit-items").replaceChildren();
    for(const item of data.items)$("audit-items").append(node("p",item.at+" | "+item.actor+" | "+item.action+" | "+item.target));
    auditBefore=data.items.at(-1)?.seq||null;$("more-audit").hidden=data.items.length<100;
  }catch(e){$("audit-status").textContent=e.message;}
}
$("audit").addEventListener("click",()=>loadAudit());
$("more-audit").addEventListener("click",()=>loadAudit(true));
api("/api/session").then(signedIn).catch(()=>signedOut());
