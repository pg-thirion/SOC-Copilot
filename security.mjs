import {randomBytes,createHash,createHmac,createCipheriv,createDecipheriv,scrypt,timingSafeEqual} from "node:crypto";
import {promisify} from "node:util";
const derive=promisify(scrypt);
const params={N:32768,r:8,p:1,maxmem:64*1024*1024};
export const hashToken=t=>createHash("sha256").update(t).digest("hex");
export const newToken=()=>randomBytes(32).toString("hex");
export async function hashPassword(password){
  if(typeof password!=="string"||password.length<14||password.length>256)throw Error("Password must be 14 to 256 characters.");
  const salt=randomBytes(16);
  return salt.toString("hex")+":"+(await derive(password,salt,64,params)).toString("hex");
}
const format=/^[a-f0-9]{32}:[a-f0-9]{128}$/;
const dummy="0".repeat(32)+":"+"0".repeat(128);
export async function verifyPassword(password,encoded){
  if(typeof password!=="string"||password.length>256)return false;
  const valid=typeof encoded==="string"&&format.test(encoded);
  const [salt,hash]=(valid?encoded:dummy).split(":");
  const candidate=await derive(password,Buffer.from(salt,"hex"),64,params);
  return timingSafeEqual(candidate,Buffer.from(hash,"hex"))&&valid;
}
export function loadUsers(raw){
  const rows=JSON.parse(raw||"[]");
  if(!Array.isArray(rows)||!rows.length||rows.length>100)throw Error("Configure 1 to 100 users in SOC_USERS_FILE.");
  const users=new Map();
  for(const u of rows){
    if(!u||typeof u.username!=="string"||!/^[a-z0-9_.-]{3,64}$/.test(u.username)||!format.test(u.passwordHash||"")||!["analyst","supervisor"].includes(u.role)||users.has(u.username))throw Error("Invalid user configuration.");
    users.set(u.username,{username:u.username,role:u.role,passwordHash:u.passwordHash});
  }
  if(![...users.values()].some(u=>u.role==="supervisor"))throw Error("At least one supervisor is required.");
  return users;
}
export function makeCrypto(hex){
  if(typeof hex!=="string"||!/^[a-fA-F0-9]{64}$/.test(hex))throw Error("SOC_DATA_KEY must be 32 random bytes encoded as hex.");
  const root=Buffer.from(hex,"hex");
  const key=purpose=>createHmac("sha256",root).update("soc-copilot-v1:"+purpose).digest();
  const enc=key("case encryption"),audit=key("audit integrity"),sessions=key("session configuration");
  return {
    seal(value,aad){const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",enc,iv);cipher.setAAD(Buffer.from(aad));const data=Buffer.concat([cipher.update(JSON.stringify(value),"utf8"),cipher.final()]);return [iv,cipher.getAuthTag(),data].map(x=>x.toString("base64")).join(".");},
    open(value,aad){const [iv,tag,data]=value.split(".").map(x=>Buffer.from(x,"base64"));const cipher=createDecipheriv("aes-256-gcm",enc,iv);cipher.setAAD(Buffer.from(aad));cipher.setAuthTag(tag);return JSON.parse(Buffer.concat([cipher.update(data),cipher.final()]).toString("utf8"));},
    mac(value){return createHmac("sha256",audit).update(value).digest("hex");},
    userVersion(user){return createHmac("sha256",sessions).update(JSON.stringify([user.username,user.role,user.passwordHash])).digest("hex");}
  };
}
