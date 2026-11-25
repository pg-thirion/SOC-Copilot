import {DatabaseSync} from "node:sqlite";
import {randomUUID} from "node:crypto";
export function openStore(path,crypto){
  const db=new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA trusted_schema=OFF;");
  const version=db.prepare("PRAGMA user_version").get().user_version;
  if(version>1)throw Error("Unsupported database schema.");
  db.exec("BEGIN IMMEDIATE");
  try{
    db.exec("CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, owner TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, revision INTEGER NOT NULL, payload TEXT NOT NULL); CREATE INDEX IF NOT EXISTS cases_owner_updated ON cases(owner,updated DESC); CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, prev TEXT NOT NULL, mac TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, username TEXT NOT NULL, version TEXT NOT NULL, expires INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires); CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); PRAGMA user_version=1;");
    const verifier=crypto.mac("database key verification");
    const saved=db.prepare("SELECT value FROM meta WHERE key='keycheck'").get();
    if(saved&&saved.value!==verifier)throw Error("Database encryption key does not match.");
    if(!saved)db.prepare("INSERT INTO meta VALUES('keycheck',?)").run(verifier);
    db.exec("COMMIT");
  }catch(e){db.exec("ROLLBACK");db.close();throw e;}
  function tx(fn){db.exec("BEGIN IMMEDIATE");try{const r=fn();db.exec("COMMIT");return r;}catch(e){db.exec("ROLLBACK");throw e;}}
  function append(actor,action,target){
    const tail=db.prepare("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1").get();
    const seq=(tail?.seq||0)+1, at=new Date().toISOString(),prev=tail?.mac||"genesis";
    const mac=crypto.mac(JSON.stringify([seq,at,actor,action,target,prev]));
    db.prepare("INSERT INTO audit VALUES(?,?,?,?,?,?,?)").run(seq,at,actor,action,target,prev,mac);
  }
  function allowed(row,user){return row&&(row.owner===user.username||user.role==="supervisor");}
  function unpack(row){return {id:row.id,owner:row.owner,created:row.created,updated:row.updated,revision:row.revision,...crypto.open(row.payload,JSON.stringify([row.id,row.owner,row.created,row.updated,row.revision]))};}
  function seal(row,value){return crypto.seal(value,JSON.stringify([row.id,row.owner,row.created,row.updated,row.revision]));}
  function verifyAudit(){
    let seq=0,prev="genesis";
    for(const row of db.prepare("SELECT * FROM audit ORDER BY seq").iterate()){
      const mac=crypto.mac(JSON.stringify([row.seq,row.at,row.actor,row.action,row.target,row.prev]));
      if(row.seq!==++seq||row.prev!==prev||row.mac!==mac)return {valid:false,checked:seq-1};
      prev=row.mac;
    }
    return {valid:true,checked:seq,head:prev};
  }
  return {
    close:()=>db.close(),
    ping:()=>db.prepare("SELECT 1 AS ok").get().ok===1,
    audit:(actor,action,target="")=>tx(()=>append(actor,action,target)),
    verifyAudit,
    auditPage(before=Number.MAX_SAFE_INTEGER){return db.prepare("SELECT * FROM audit WHERE seq<? ORDER BY seq DESC LIMIT 100").all(before);},
    session(token,username,version,expires){tx(()=>{db.prepare("DELETE FROM sessions WHERE expires<=?").run(Date.now());db.prepare("INSERT INTO sessions VALUES(?,?,?,?)").run(token,username,version,expires);append(username,"login","");});},
    getSession(token){return db.prepare("SELECT * FROM sessions WHERE token=? AND expires>?").get(token,Date.now());},
    logout(token,actor){tx(()=>{db.prepare("DELETE FROM sessions WHERE token=?").run(token);append(actor,"logout","");});},
    create(user,report){return tx(()=>{const now=new Date().toISOString(),row={id:randomUUID(),owner:user.username,created:now,updated:now,revision:1};
      const value={report,review:{disposition:"Pending review",notes:""}};
      db.prepare("INSERT INTO cases VALUES(?,?,?,?,?,?)").run(row.id,row.owner,row.created,row.updated,row.revision,seal(row,value));append(user.username,"case.created",row.id);return {...row,...value};});},
    list(user,offset=0){
      const rows=user.role==="supervisor"?db.prepare("SELECT * FROM cases ORDER BY updated DESC,id LIMIT 51 OFFSET ?").all(offset):db.prepare("SELECT * FROM cases WHERE owner=? ORDER BY updated DESC,id LIMIT 51 OFFSET ?").all(user.username,offset);
      return {items:rows.slice(0,50).map(row=>{const c=unpack(row);return {id:c.id,owner:c.owner,updated:c.updated,revision:c.revision,severity:c.report.severity,classification:c.report.classification,disposition:c.review.disposition};}),nextOffset:rows.length>50?offset+50:null};
    },
    get(id,user){return tx(()=>{const row=db.prepare("SELECT * FROM cases WHERE id=?").get(id);if(!allowed(row,user))return null;const value=unpack(row);append(user.username,"case.viewed",id);return value;});},
    review(id,user,revision,review){return tx(()=>{const row=db.prepare("SELECT * FROM cases WHERE id=?").get(id);if(!allowed(row,user))return {status:404};if(row.revision!==revision)return {status:409};
      const current=unpack(row),next={...row,revision:row.revision+1,updated:new Date().toISOString()};
      db.prepare("UPDATE cases SET updated=?,revision=?,payload=? WHERE id=?").run(next.updated,next.revision,seal(next,{report:current.report,review}),id);
      append(user.username,"case.reviewed",id);return {status:200,value:{id,owner:row.owner,created:row.created,updated:next.updated,revision:next.revision,report:current.report,review}};});}
  };
}
