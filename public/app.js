const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el;};
let examples=[],report=null;
async function init(){
  try{
    const response=await fetch("/api/examples");if(!response.ok)throw Error("Unable to load scenarios.");
    const data=await response.json();examples=data.examples;
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
    const response=await fetch("/api/investigate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({events,ai:$("ai").checked})});
    const r=await response.json();if(!response.ok)throw Error(r.error||"Investigation failed.");
    report=r;render(r);
  }catch(e){$("error").textContent=e.message+" Previous results, if shown, have not changed.";$("export").disabled=!report;}
  finally{$("run").disabled=false;}
});
$("export").addEventListener("click",()=>{
  if(!report)return;
  const exported={...report,review:{disposition:$("disposition").value,notes:$("notes").value,exportedAt:new Date().toISOString()}};
  const url=URL.createObjectURL(new Blob([JSON.stringify(exported,null,2)],{type:"application/json"}));
  const a=document.createElement("a");a.href=url;a.download="soc-investigation.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
init();
