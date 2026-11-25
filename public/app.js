const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;};
let examples=[],report=null,current=null,offset=0,auditBefore=null,epoch=0;
let account=null;
async function init(){
  const generation=epoch;
  try{
    const data=await api("/api/examples");if(generation!==epoch)return; $("sample").replaceChildren(node("option","Choose a scenario")); $("sample").firstChild.value="";examples=data.examples;
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
  renderTimeline(r);renderEvidence(r);
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
  const exported={...report,caseId:current.id,revision:current.revision,owner:current.owner,workflow:current.workflow,review:{...current.review,exportedAt:new Date().toISOString()}};
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
  for(const id of ["findings","timeline","cases","audit-items","tasks","workflow-history","evidence-info"])$(id).replaceChildren();
  $("timeline-empty").hidden=false;$("ai-output").textContent="No investigation yet.";$("export").disabled=true;$("save").disabled=true;$("ai").checked=false;
  $("audit-panel").hidden=true;$("more-audit").hidden=true;$("more-cases").hidden=true;for(const id of ["query","filter-tag","timeline-query","case-title","case-tags"])$(id).value="";for(const id of ["queue-metrics","case-due","workflow-status","integrity-result","timeline-count"])$(id).textContent="";for(const id of ["save-workflow","summary-export","integrity"])$(id).disabled=true;
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
  $("disposition").value=c.review.disposition;$("notes").value=c.review.notes;$("save").disabled=false;$("save-status").textContent="Saved revision "+c.revision;renderWorkflow(c);
}
async function loadCases(append=false){
  const generation=epoch;
  if(!append)offset=0;
  try{
    const params=new URLSearchParams({offset:String(offset),q:$("query").value,status:$("filter-status").value,severity:$("filter-severity").value,priority:$("filter-priority").value,tag:$("filter-tag").value.trim(),overdue:String($("filter-overdue").checked)});const data=await api("/api/cases?"+params);if(generation!==epoch)return;
    if(!append)$("cases").replaceChildren();
    if(!data.items.length&&!append)$("cases").append(node("p","No saved cases.","muted"));
    for(const c of data.items){
      const button=node("button",c.title+" / "+c.severity.toUpperCase(),c.severity);button.append(node("small",c.priority+" · "+c.status+" · "+(c.overdue?"OVERDUE · ":"")+c.owner+" · "+c.updated));
      button.addEventListener("click",async()=>{const g=epoch;try{const item=await api("/api/cases/"+c.id);if(g===epoch)showCase(item);}catch(e){$("error").textContent=e.message;}});$("cases").append(button);
    }
    offset=data.nextOffset;$("more-cases").hidden=offset===null;if(data.truncated)$("cases").append(node("p","Search limited to latest 5,000 cases.","muted"));if(!append)await loadMetrics();
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
function renderTimeline(r){
  const q=$("timeline-query").value.toLowerCase();$("timeline").replaceChildren();
  const rows=[...r.events].filter(e=>Object.values(e).some(v=>String(v).toLowerCase().includes(q))).sort((a,b)=>(Date.parse(a.timestamp)||0)-(Date.parse(b.timestamp)||0));
  for(const e of rows){const tr=node("tr","");for(const v of [e.id,e.timestamp,e.type,[e.user,e.host].filter(Boolean).join(" / "),e.ip,e.outcome,e.detail])tr.append(node("td",v||"—"));$("timeline").append(tr);}
  $("timeline-count").textContent=rows.length+" of "+r.events.length+" events";
}
$("timeline-query").addEventListener("input",()=>{if(report)renderTimeline(report);});
function renderEvidence(r){
  const root=$("evidence-info");root.replaceChildren();const info=r.evidenceInfo;
  $("integrity").disabled=!info;$("integrity-result").textContent="";
  if(!info){root.textContent="Legacy case: evidence fingerprints unavailable.";return;}
  root.append(node("p","Unique events: "+info.quality.uniqueEvents+" | Duplicates: "+info.duplicates+" | Missing timestamps: "+info.quality.missingTimestamps+" | Invalid IPs: "+info.quality.invalidSourceIPs),
    node("p","Rule coverage: "+info.coverage.matched+"/"+info.coverage.total+" events; "+info.coverage.unmatched+" unmatched."),
    node("p","Time range: "+(info.timeRange.first||"Unknown")+" to "+(info.timeRange.last||"Unknown")),
    node("p","ATT&CK techniques: "+(info.techniques.join(", ")||"None")),
    node("p","Event types: "+info.eventCounts.map(x=>x.type+" ("+x.count+")").join(", ")),
    node("p","SHA-256 fingerprint: "+info.fingerprint));
  for(const [kind,items] of Object.entries(info.indicators)){const detail=node("details","");detail.append(node("summary",kind+" ("+items.length+")"));for(const item of items)detail.append(node("p",item.value+" | "+item.evidence.join(", ")));root.append(detail);}
}
function renderWorkflow(c){
  const w=c.workflow;$("case-title").value=w.title;$("case-status").value=w.status;$("case-priority").value=w.priority;$("case-tags").value=w.tags.join(", ");
  $("case-due").textContent="Response target: "+w.dueAt+(w.status!=="Closed"&&Date.parse(w.dueAt)<Date.now()?" | OVERDUE":"");
  $("tasks").replaceChildren();for(const task of c.report.evidenceInfo?.checklist||[]){const label=node("label","","check"),check=document.createElement("input");check.type="checkbox";check.value=task.id;check.checked=w.completed.includes(task.id);label.append(check,document.createTextNode(task.label));$("tasks").append(label);}
  $("workflow-history").replaceChildren(...w.history.map(h=>node("p",h.at+" | "+h.actor+" | "+h.changed.join(", ")+" | "+h.status)));
  $("save-workflow").disabled=false;$("summary-export").disabled=false;$("workflow-status").textContent="Saved revision "+c.revision;
}
async function loadMetrics(){const g=epoch;try{const m=await api("/api/metrics");if(g===epoch)$("queue-metrics").textContent=(m.truncated?"Latest 5,000: ":"")+m.total+" cases · "+m.open+" open · "+m.high+" high · "+m.overdue+" overdue";}catch(e){$("error").textContent=e.message;}}
for(const id of ["filter-status","filter-severity","filter-priority","filter-overdue"])$(id).addEventListener("change",()=>loadCases());
for(const id of ["query","filter-tag"])$(id).addEventListener("change",()=>loadCases());
$("save-workflow").addEventListener("click",async()=>{
  if(!current)return;const id=current.id,g=epoch;$("save-workflow").disabled=true;
  const workflow={title:$("case-title").value,status:$("case-status").value,priority:$("case-priority").value,tags:$("case-tags").value.split(",").map(x=>x.trim()).filter(Boolean),completed:[...$("tasks").querySelectorAll("input:checked")].map(e=>e.value)};
  try{const c=await api("/api/cases/"+id+"/workflow",{method:"PATCH",body:JSON.stringify({revision:current.revision,workflow})});if(g!==epoch)return;if(current?.id===id){current=c;renderWorkflow(c);$("case-id").textContent="Case "+c.id+" | Revision "+c.revision+" | Owner "+c.owner;}await loadCases();}
  catch(e){$("workflow-status").textContent=e.message;}finally{if(current)$("save-workflow").disabled=false;}
});
$("integrity").addEventListener("click",async()=>{if(!current)return;const id=current.id,g=epoch;try{const result=await api("/api/cases/"+id+"/integrity");if(g===epoch&&current?.id===id)$("integrity-result").textContent=result.available?(result.valid?"Fingerprint verified":"Integrity mismatch"):"Legacy case: unavailable";}catch(e){$("integrity-result").textContent=e.message;}});
$("summary-export").addEventListener("click",async()=>{if(!current)return;const id=current.id,g=epoch;try{const summary=await api("/api/cases/"+id+"/summary");if(g!==epoch||current?.id!==id)return;const url=URL.createObjectURL(new Blob([JSON.stringify(summary,null,2)],{type:"application/json"})),a=document.createElement("a");a.href=url;a.download="soc-summary-"+id+".json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){$("workflow-status").textContent=e.message;}});
api("/api/session").then(signedIn).catch(()=>signedOut());
