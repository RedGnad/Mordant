#!/usr/bin/env node
/**
 * M-05 dry run, Monad side. Read-only.
 *
 * Estimates the creation gas for every PROTOCOL DOUBLE contract against Monad testnet. No key, no
 * signature, no broadcast. Placeholder constructor arguments only satisfy code-length checks; the
 * real deployment passes the addresses produced by the preceding step.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { encodeDeployData } from "viem";
const ROOT="/Users/red.g/CascadeProjects/Master/Mordant";
const RPC=process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const CALLER="0x000000000000000000000000000000000000d341";
let id=0;
async function rpc(method,params){
  const r=await fetch(RPC,{method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:++id,method,params}),signal:AbortSignal.timeout(30000)});
  const j=await r.json(); if(j.error) throw new Error(j.error.message); return j.result;
}
const art=(f,n)=>{const p=JSON.parse(readFileSync(join(ROOT,"contracts","out",f,n+".json"),"utf8"));
  return {abi:p.abi,bytecode:p.bytecode.object,runtime:(p.deployedBytecode.object.length-2)/2};};
const PLAN=[
 ["MockEligibility","MockEligibility.sol","MockEligibility",[]],
 ["settlement double (MockERC20)","MockERC20.sol","MockERC20",["Mordant Demo Settlement (double)","dSETTLE",6]],
 ["CVA double (MockERC20)","MockERC20.sol","MockERC20",["Mordant Demo Invoice A-Token (double)","dINV",6]],
 ["MockCvaAdapter","MockCvaAdapter.sol","MockCvaAdapter",["0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
 ["MordantFactory","MordantFactory.sol","MordantFactory",[CALLER,"0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
];
const chainId=Number(BigInt(await rpc("eth_chainId",[])));
if(chainId!==10143){console.error("wrong chain",chainId);process.exit(3);}
const head=BigInt(await rpc("eth_blockNumber",[]));
const blockTag="0x"+(head-20n).toString(16);
const block=await rpc("eth_getBlockByNumber",[blockTag,false]);
const gasPrice=BigInt(await rpc("eth_gasPrice",[]));
console.log("chainId",chainId,"| block",(head-20n).toString(),"| hash",block.hash);
console.log("gasPrice",gasPrice.toString(),"wei =",(Number(gasPrice)/1e9).toFixed(3),"gwei\n");
let total=0n;
const rows=[];
for(const [label,file,name,args] of PLAN){
  const a=art(file,name);
  let data;
  try{ data=encodeDeployData({abi:a.abi,bytecode:a.bytecode,args}); }
  catch(e){ rows.push([label,"-","-","encode failed: "+e.message.slice(0,60)]); continue; }
  const initBytes=(data.length-2)/2;
  try{
    const gas=BigInt(await rpc("eth_estimateGas",[{from:CALLER,data},blockTag]));
    total+=gas;
    rows.push([label,initBytes,a.runtime,gas.toString()]);
  }catch(e){ rows.push([label,initBytes,a.runtime,"ESTIMATE FAILED: "+e.message.slice(0,70)]); }
}
for(const r of rows) console.log("  "+String(r[0]).padEnd(32)+" init "+String(r[1]).padStart(6)+" B  runtime "+String(r[2]).padStart(6)+" B  gas "+r[3]);
console.log("\n  deployments subtotal gas:",total.toString());
console.log("  at current gasPrice     :",(total*gasPrice).toString(),"wei =",(Number(total*gasPrice)/1e18).toFixed(4),"MON");
