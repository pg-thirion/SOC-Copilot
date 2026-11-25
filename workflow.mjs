export const statuses=["Open","Investigating","Awaiting approval","Closed"];
export const priorities=["P1","P2","P3","P4"];
const hours={P1:4,P2:24,P3:72,P4:168};
const transitions={Open:["Open","Investigating","Awaiting approval"],Investigating:["Open","Investigating","Awaiting approval"],"Awaiting approval":["Investigating","Awaiting approval","Closed"],Closed:["Closed","Investigating"]};
const trim=(v,max,label)=>{if(typeof v!=="string"||v.length>max)throw Error("Invalid "+label+".");return v.trim();};
export function defaultWorkflow(report,created){
  const priority=({high:"P2",medium:"P3",low:"P4"})[report.severity]||"P4";
  return {title:report.classification,status:"Open",priority,tags:[],completed:[],dueAt:new Date(Date.parse(created)+hours[priority]*3600000).toISOString(),history:[]};
}
export function updateWorkflow(current,patch,user,now=new Date().toISOString()){
  const before=current.workflow||defaultWorkflow(current.report,current.created);
  if(!patch||typeof patch!=="object"||Array.isArray(patch))throw Error("Invalid workflow.");
  if(Object.keys(patch).some(k=>!["title","status","priority","tags","completed"].includes(k)))throw Error("Unknown workflow field.");
  const next={...before};
  if("title" in patch){next.title=trim(patch.title,120,"title");if(!next.title)throw Error("Title is required.");}
  if("priority" in patch){if(!priorities.includes(patch.priority))throw Error("Invalid priority.");next.priority=patch.priority;}
  if("status" in patch){if(!transitions[before.status].includes(patch.status))throw Error("Invalid status transition.");if(patch.status!==before.status&&(patch.status==="Closed"||before.status==="Closed")&&user.role!=="supervisor")throw Error("Supervisor approval required.");if(patch.status==="Closed"&&current.review.disposition==="Pending review")throw Error("Record a disposition before closing.");next.status=patch.status;}
  if("tags" in patch){if(!Array.isArray(patch.tags)||patch.tags.length>10)throw Error("Invalid tags.");next.tags=[...new Set(patch.tags.map(t=>trim(t,32,"tag").toLowerCase()).filter(Boolean))];}
  if("completed" in patch){const allowed=new Set((current.report.evidenceInfo?.checklist||[]).map(t=>t.id));if(!Array.isArray(patch.completed)||patch.completed.length>200||patch.completed.some(t=>!allowed.has(t)))throw Error("Invalid task IDs.");next.completed=[...new Set(patch.completed)];}
  if(next.priority!==before.priority)next.dueAt=new Date(Date.parse(current.created)+hours[next.priority]*3600000).toISOString();
  const changed=["title","status","priority","tags","completed"].filter(k=>JSON.stringify(before[k])!==JSON.stringify(next[k]));
  if(changed.length)next.history=[...before.history,{at:now,actor:user.username,changed,status:next.status,priority:next.priority}].slice(-100);
  return next;
}
export function summarize(c,now=Date.now()){
  const w=c.workflow||defaultWorkflow(c.report,c.created);
  return {id:c.id,owner:c.owner,updated:c.updated,revision:c.revision,severity:c.report.severity,classification:c.report.classification,disposition:c.review.disposition,title:w.title,status:w.status,priority:w.priority,tags:w.tags,dueAt:w.dueAt,overdue:w.status!=="Closed"&&Date.parse(w.dueAt)<now};
}
export function filterCases(items,filters={}){
  const q=(filters.q||"").toLowerCase();
  return items.filter(c=>(!filters.status||c.status===filters.status)&&(!filters.severity||c.severity===filters.severity)&&(!filters.priority||c.priority===filters.priority)&&(!filters.tag||c.tags.includes(filters.tag.toLowerCase()))&&(!filters.overdue||c.overdue)&&(!q||[c.id,c.title,c.classification,c.owner,...c.tags].some(v=>v.toLowerCase().includes(q))));
}
export function caseMetrics(items){
  const result={total:items.length,open:0,closed:0,overdue:0,high:0,byStatus:Object.fromEntries(statuses.map(s=>[s,0])),byPriority:Object.fromEntries(priorities.map(p=>[p,0]))};
  for(const c of items){result.byStatus[c.status]++;result.byPriority[c.priority]++;if(c.status==="Closed")result.closed++;else result.open++;if(c.overdue)result.overdue++;if(c.severity==="high")result.high++;}
  return result;
}
export function executiveReport(c){
  const w=c.workflow||defaultWorkflow(c.report,c.created);
  return {caseId:c.id,revision:c.revision,title:w.title,status:w.status,priority:w.priority,severity:c.report.severity,classification:c.report.classification,disposition:c.review.disposition,created:c.created,updated:c.updated,dueAt:w.dueAt,findings:c.report.findings.map(({category,severity,summary,evidence,mitre})=>({category,severity,summary,evidence,mitre})),eventCount:c.report.events.length,limitations:c.report.limitations,notice:"Executive summary omits raw evidence, identities, free-text notes and AI commentary. Titles are analyst-supplied and may contain sensitive information."};
}
