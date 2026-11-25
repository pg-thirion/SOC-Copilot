import {createHash} from "node:crypto";
import {isIP} from "node:net";
const sha=value=>createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const eventKey=e=>JSON.stringify([e.timestamp,e.type,e.user,e.host,e.ip,e.outcome,e.detail]);
export const uniqueEvents=events=>[...new Map(events.map(e=>[eventKey(e),e])).values()];
const catalog=[
 ["mfa_fatigue_alert","high","Possible MFA fatigue","Repeated MFA prompts were reported.","T1621","Verify MFA approvals and sign-in records."],
 ["suspicious_powershell","medium","Suspicious scripting","Endpoint telemetry flagged PowerShell activity.","T1059.001","Inspect the script provenance and endpoint telemetry."],
 ["persistence_alert","high","Possible persistence","Telemetry reported a possible persistence mechanism.","","Validate the reported configuration against a known-good baseline."],
 ["ransomware_alert","high","Possible ransomware","Endpoint telemetry flagged possible ransomware activity.","T1486","Verify file activity and invoke the approved incident response playbook if confirmed."],
 ["cloud_policy_change","medium","Cloud policy change","Cloud telemetry reported a policy change.","","Compare cloud audit events with approved change requests."],
 ["suspicious_dns","medium","Suspicious DNS","Network telemetry flagged DNS activity.","","Validate resolver logs, destination reputation and business justification."],
 ["lateral_movement_alert","high","Possible lateral movement","Telemetry flagged possible lateral movement.","","Review source and destination authentication and endpoint records."],
 ["web_attack_alert","medium","Possible web attack","Web security telemetry reported suspicious requests.","","Review request context, WAF records and application logs."]
];
export function advancedFindings(events){
  const results=[];
  for(const [type,severity,category,summary,mitre,step] of catalog){
    const matched=events.filter(e=>e.type===type);
    if(matched.length)results.push({category,severity,summary,mitre,evidence:matched.map(e=>e.id),actions:[step,"Preserve relevant evidence and document analyst verification.","Escalate confirmed incidents through the approved response process."]});
  }
  function correlate(groupBy, distinctBy, category, summary, mitre){
    const groups=new Map();
    for(const e of uniqueEvents(events)){
      if(e.type!=="authentication"||e.outcome!=="failure"||!e.timestamp||!e[groupBy]||!e[distinctBy])continue;
      const k=e[groupBy];if(!groups.has(k))groups.set(k,[]);groups.get(k).push(e);
    }
    for(const group of groups.values()){
      group.sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp));
      for(let i=0;i<group.length;i++){
        const window=group.slice(i).filter(e=>Date.parse(e.timestamp)-Date.parse(group[i].timestamp)<=600000);
        if(new Set(window.map(e=>e[distinctBy])).size>=5){
          results.push({category,severity:"medium",summary,mitre,evidence:window.map(e=>e.id),actions:["Verify identity and source telemetry.","Check expected authentication patterns and MFA records.","Escalate suspicious activity for analyst review."]});break;
        }
      }
    }
  }
  correlate("ip","user","Possible password spraying","One source recorded failures for at least five distinct users within ten minutes.","T1110.003");
  correlate("user","ip","Distributed authentication failures","One identity recorded failures from at least five distinct sources within ten minutes.","T1110");
  return results;
}
export function describeEvidence(events,findings){
  const unique=uniqueEvents(events),duplicates=events.length-unique.length;
  const types=[...new Set(events.map(e=>e.type))].sort();
  const covered=new Set(findings.flatMap(f=>f.evidence));
  const indicators={users:[],hosts:[],ips:[],hashes:[],domains:[]};
  const seen=Object.fromEntries(Object.keys(indicators).map(k=>[k,new Map()]));
  const add=(k,value,id)=>{if(!value)return;let entry=seen[k].get(value);if(!entry){entry={value,evidence:[]};seen[k].set(value,entry);}if(!entry.evidence.includes(id))entry.evidence.push(id);};
  for(const e of events){
    add("users",e.user,e.id);add("hosts",e.host,e.id);if(isIP(e.ip))add("ips",e.ip,e.id);
    for(const match of e.detail.matchAll(/\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b/g))add("hashes",match[0].toLowerCase(),e.id);
    for(const match of e.detail.matchAll(/https?:\/\/([a-z0-9.-]+)(?=[:/?#\s]|$)/gi))if(match[1].includes(".")&&!isIP(match[1]))add("domains",match[1].toLowerCase(),e.id);
  }
  for(const k of Object.keys(indicators))indicators[k]=[...seen[k].values()].slice(0,500);
  const times=events.filter(e=>e.timestamp).map(e=>Date.parse(e.timestamp)).sort((a,b)=>a-b);
  const eventCounts=types.map(type=>({type,count:events.filter(e=>e.type===type).length}));
  return {fingerprint:sha(events),eventDigests:events.map(e=>({id:e.id,sha256:sha(e)})),duplicates,
    quality:{missingTimestamps:events.filter(e=>!e.timestamp).length,invalidSourceIPs:events.filter(e=>e.ip&&!isIP(e.ip)).length,uniqueEvents:unique.length},
    indicators,eventCounts,coverage:{matched:covered.size,total:events.length,unmatched:events.length-covered.size},
    timeRange:{first:times.length?new Date(times[0]).toISOString():null,last:times.length?new Date(times.at(-1)).toISOString():null},
    techniques:[...new Set(findings.map(f=>f.mitre).filter(Boolean))].sort(),
    checklist:[...new Set(findings.flatMap(f=>f.actions))].map((label,i)=>({id:"T"+(i+1),label}))};
}
export function verifyEvidence(report){
  return Boolean(report.evidenceInfo&&report.evidenceInfo.fingerprint===sha(report.events)&&JSON.stringify(report.evidenceInfo.eventDigests)===JSON.stringify(report.events.map(e=>({id:e.id,sha256:sha(e)}))));
}
