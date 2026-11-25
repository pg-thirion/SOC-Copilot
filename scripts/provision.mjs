import {createInterface} from "node:readline/promises";
import {Writable} from "node:stream";
import {mkdir,readFile,writeFile,chmod,rename} from "node:fs/promises";
import {dirname,resolve} from "node:path";
import {randomBytes} from "node:crypto";
import {hashPassword} from "../security.mjs";
process.umask(0o077);
const [username,role="analyst"]=process.argv.slice(2);
if(!/^[a-z0-9_.-]{3,64}$/.test(username||"")||!["analyst","supervisor"].includes(role))throw Error("Usage: npm run provision -- username supervisor|analyst");
const file=resolve(process.env.SOC_USERS_FILE||"./secrets/users.json");
await mkdir(dirname(file),{recursive:true,mode:0o700});
let rows=[];try{rows=JSON.parse(await readFile(file,"utf8"));}catch(e){if(e.code!=="ENOENT")throw e;}
if(!Array.isArray(rows))throw Error("Invalid users file.");
if(rows.length>=100&&!rows.some(u=>u.username===username))throw Error("User limit reached.");
if(!process.stdin.isTTY)throw Error("Interactive terminal required.");
const sink=new Writable({write(chunk,encoding,cb){cb();}});
const rl=createInterface({input:process.stdin,output:sink,terminal:true});
let password,confirmation;
try{process.stdout.write("Password (hidden, minimum 14 characters): ");password=await rl.question("");process.stdout.write("\nConfirm password: ");confirmation=await rl.question("");}finally{rl.close();process.stdout.write("\n");}
if(password!==confirmation)throw Error("Passwords do not match.");
const passwordHash=await hashPassword(password);
rows=rows.filter(u=>u.username!==username);rows.push({username,role,passwordHash});
if(!rows.some(u=>u.role==="supervisor"))throw Error("At least one supervisor is required.");
const tmp=file+"."+randomBytes(8).toString("hex")+".tmp";
await writeFile(tmp,JSON.stringify(rows,null,2)+"\n",{flag:"wx",mode:0o600});await rename(tmp,file);await chmod(file,0o600);
console.log("User provisioned. Restart the service to apply changes.");
