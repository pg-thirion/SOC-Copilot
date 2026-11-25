// Deterministic, evidence-linked triage. No automated response actions.
export function analyze(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 500) throw Error("Provide 1 to 500 events.");
  const events=input.map((e,i)=>{
    if (!e || typeof e!=="object" || Array.isArray(e)) throw Error("Each event must be an object.");
    const clean={id:"E"+(i+1)};
    for (const key of ["timestamp","type","user","host","ip","outcome","detail"]) {
      const v=e[key]??"";
      if(typeof v!=="string" || v.length>2000) throw Error("Invalid event field: "+key);
      clean[key]=v.trim();
    }
    if(!clean.type) throw Error("Every event requires a type.");
    if(clean.timestamp && !Number.isFinite(Date.parse(clean.timestamp))) throw Error("Invalid timestamp.");
    clean.type=clean.type.toLowerCase();
    clean.outcome=clean.outcome.toLowerCase();
    return clean;
  });
  const findings=[];
  function add(category,severity,summary,ids,mitre,actions) {
    findings.push({category,severity,summary,evidence:ids,mitre,actions});
  }
  const byIdentity=new Map();
  for(const e of events.filter(e=>e.type==="authentication" && e.user && e.ip)) {
    const key=JSON.stringify([e.user,e.ip]);
    if(!byIdentity.has(key)) byIdentity.set(key,[]);
    byIdentity.get(key).push(e);
  }
  for(const group of byIdentity.values()){
    const timed=group.filter(e=>e.timestamp).sort((a,b)=>Date.parse(a.timestamp)-Date.parse(b.timestamp));
    let left=0, fails=0, best=[], success=null;
    for(let right=0;right<timed.length;right++){
      const e=timed[right];
      while(left<right && Date.parse(e.timestamp)-Date.parse(timed[left].timestamp)>600000){
        if(timed[left].outcome==="failure") fails--;
        left++;
      }
      if(e.outcome==="failure") fails++;
      const window=timed.slice(left,right+1).filter(x=>x.outcome==="failure");
      if(window.length>best.length) best=window;
      if(e.outcome==="success" && fails>=5){success=e;best=window;break;}
    }
    if(best.length>=5) add("Credential attack",success?"high":"medium",success?"At least five failed logins followed by a successful login for the same user and source within ten minutes.":"At least five failed logins for the same user and source within ten minutes.",[...best.map(e=>e.id),...(success?[success.id]:[])],"T1110",["Verify login ownership and MFA activity.","Review related sessions and identity logs.","If compromise is confirmed, revoke sessions and rotate credentials with approval."]);
  }
  const rules=[
    ["malware_detection","high","Malware detection","Endpoint telemetry reported a malware detection.","",["Validate the detection and collect endpoint evidence.","Review related process and file activity.","If confirmed, request endpoint isolation and quarantine."]],
    ["privilege_change","medium","Privilege change","A privilege change was recorded.","T1098",["Verify the change against approved change records.","Review the initiating identity and assigned permissions.","Revoke unauthorised access only after approval."]],
    ["phishing_report","medium","Suspected phishing","A phishing report was submitted.","T1566",["Inspect message headers and URLs in an approved sandbox.","Search for related recipients and delivery events.","Request quarantine if the message is confirmed malicious."]],
    ["data_transfer_alert","high","Possible data exfiltration","A data transfer alert was reported.","",["Verify destination, volume and business justification.","Preserve network and data access logs.","Escalate confirmed unauthorised transfers to incident response."]],
    ["defence_tamper","high","Possible defence impairment","Security-control tampering was reported.","T1562",["Check endpoint protection and audit logs.","Confirm whether an approved maintenance task occurred.","Request restoration of security controls if necessary."]]
  ];
  for(const [type,severity,category,summary,mitre,actions] of rules){
    const matched=events.filter(e=>e.type===type);
    if(matched.length) add(category,severity,summary,matched.map(e=>e.id),mitre,actions);
  }
  const rank={high:3,medium:2,low:1};
  findings.sort((a,b)=>rank[b.severity]-rank[a.severity]);
  return {severity:findings[0]?.severity??"unclassified",classification:findings[0]?.category??"Insufficient evidence",findings,events,limitations:["Rule matches are hypotheses, not confirmed incidents.","ATT&CK mappings are indicative and require analyst validation.","No matching rule does not establish that an event is benign.","This engine evaluates supplied telemetry only. It does not query live systems."]};
}
export const examples = [
  {
    "name": "Credential attack",
    "events": [
      {
        "timestamp": "2026-11-25T08:00:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:01:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:02:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:03:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:04:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:05:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "failure",
        "detail": "Invalid credentials"
      },
      {
        "timestamp": "2026-11-25T08:07:00Z",
        "type": "authentication",
        "user": "analyst@example.test",
        "host": "idp-01",
        "ip": "192.0.2.44",
        "outcome": "success",
        "detail": "Session established"
      }
    ]
  },
  {
    "name": "Endpoint detection",
    "events": [
      {
        "timestamp": "2026-11-25T09:10:00Z",
        "type": "malware_detection",
        "host": "WS-042",
        "user": "user@example.test",
        "detail": "Synthetic EDR alert: suspicious file quarantined",
        "outcome": "detected"
      },
      {
        "timestamp": "2026-11-25T09:11:00Z",
        "type": "defence_tamper",
        "host": "WS-042",
        "detail": "Endpoint protection setting changed"
      }
    ]
  },
  {
    "name": "Phishing report",
    "events": [
      {
        "timestamp": "2026-11-25T10:15:00Z",
        "type": "phishing_report",
        "user": "employee@example.test",
        "detail": "Synthetic report of an unexpected password reset message"
      }
    ]
  },
  {
    "name": "Unclassified activity",
    "events": [
      {
        "timestamp": "2026-11-25T11:00:00Z",
        "type": "authentication",
        "user": "staff@example.test",
        "ip": "192.0.2.80",
        "outcome": "success",
        "detail": "Successful sign-in"
      }
    ]
  }
];
