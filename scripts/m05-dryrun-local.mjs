#!/usr/bin/env node
/**
 * M-05 dry run, local side. Measures gas for the configuration and journey transactions that cannot
 * be estimated remotely because they need deployed contracts.
 *
 * Requires a local Anvil on port 8547:
 *   anvil --port 8547 --code-size-limit 131072 --silent
 *
 * Local measurement, not a Monad observation. Nothing is broadcast to Monad.
 */
import { readFileSync } from "node:fs"; import { join } from "node:path";
import { createPublicClient, createWalletClient, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts"; import { anvil } from "viem/chains";
const ROOT="/Users/red.g/CascadeProjects/Master/Mordant", RPC="http://127.0.0.1:8547";
const A=(f,n)=>{const p=JSON.parse(readFileSync(join(ROOT,"contracts","out",f,n+".json"),"utf8"));return{abi:p.abi,bytecode:p.bytecode.object};};
const K=["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80","0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d","0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a","0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6","0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a","0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba","0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"];
const [dep,buyer,orig,fA,fB,hA,hB]=K.map(privateKeyToAccount);
const t=http(RPC), pc=createPublicClient({chain:anvil,transport:t});
const w=a=>createWalletClient({account:a,chain:anvil,transport:t});
const rows=[];
async function dep_(acct,art,args,label){const h=await w(acct).deployContract({...art,args});const r=await pc.waitForTransactionReceipt({hash:h});rows.push([label,r.gasUsed]);return r.contractAddress;}
async function tx(acct,address,abi,fn,args,label){const h=await w(acct).writeContract({address,abi,functionName:fn,args});const r=await pc.waitForTransactionReceipt({hash:h});rows.push([label,r.gasUsed]);return r;}
const EL=A("MockEligibility.sol","MockEligibility"),E20=A("MockERC20.sol","MockERC20"),AD=A("MockCvaAdapter.sol","MockCvaAdapter"),FA=A("MordantFactory.sol","MordantFactory");
const el=await dep_(dep,EL,[],"deploy MockEligibility");
const st=await dep_(dep,E20,["Mordant Demo Settlement (double)","dSETTLE",6],"deploy settlement double");
const cva=await dep_(dep,E20,["Mordant Demo Invoice A-Token (double)","dINV",6],"deploy CVA double");
const ad=await dep_(dep,AD,[cva],"deploy MockCvaAdapter");
const fac=await dep_(dep,FA,[dep.address,el],"deploy MordantFactory");
for(const [a,r,l] of [[buyer.address,1,"buyer"],[orig.address,2,"originator"],[fA.address,3,"facilityA"],[fB.address,3,"facilityB"],[hA.address,4,"holderA"],[hB.address,4,"holderB"]])
  await tx(dep,el,EL.abi,"setEligible",[a,r,true],`setEligible ${l}`);
await tx(dep,fac,FA.abi,"setFacility",[fA.address,true],"setFacility A");
await tx(dep,fac,FA.abi,"setFacility",[fB.address,true],"setFacility B");
await tx(dep,fac,FA.abi,"setCvaAdapter",[ad,true],"setCvaAdapter");
await tx(dep,fac,FA.abi,"setSettlementToken",[st,true],"setSettlementToken");
const blk=await pc.getBlock();
const rc=await tx(buyer,fac,FA.abi,"createInvoiceVault",[{cvaAdapter:ad,settlementToken:st,invoiceRoot:"0x"+"a1".repeat(32),currency:"0x"+Buffer.from("USD").toString("hex").padEnd(64,"0"),buyer:buyer.address,originatorTreasury:orig.address,initialOriginatorSigner:orig.address,initialUnits:100000000n,advanceAmount:100000000n,faceValue:110000000n,bondBps:1000,protectionEnd:blk.timestamp+2592000n,revealPeriod:3600n,curePeriod:3600n}],"createInvoiceVault");
const vault=parseEventLogs({abi:FA.abi,eventName:"InvoiceVaultCreated",logs:rc.logs})[0].args.vault;
await tx(dep,el,EL.abi,"setIdentityValid",[vault,true],"setIdentityValid(vault)");
await tx(dep,cva,E20.abi,"mint",[dep.address,100000000n],"mint CVA supply");
await tx(dep,cva,E20.abi,"approve",[ad,100000000n],"approve adapter");
await tx(dep,ad,AD.abi,"creditVault",[vault,100000000n],"creditVault");
await tx(dep,st,E20.abi,"mint",[hA.address,100000000n],"mint settlement to funder");
await tx(dep,st,E20.abi,"mint",[buyer.address,110000000n],"mint settlement to buyer");
let tot=0n; for(const [l,g] of rows){tot+=g;console.log("  "+l.padEnd(30)+String(g).padStart(9));}
console.log("\n  TOTAL gas (deploy + config):",tot.toString());
console.log("  vault:",vault);

// ---- phase 3: the journey itself ----
const V=A("MordantInvoiceVault.sol","MordantInvoiceVault");
const j=[];
async function jtx(acct,address,abi,fn,args,label){const h=await w(acct).writeContract({address,abi,functionName:fn,args});const r=await pc.waitForTransactionReceipt({hash:h});j.push([label,r.gasUsed]);return r;}
const dom={name:"Mordant",version:"1",chainId:31337,verifyingContract:vault};
const types={Pledge:[{name:"invoiceRoot",type:"bytes32"},{name:"originatorSigner",type:"address"},{name:"facility",type:"address"},{name:"obligationId",type:"bytes32"},{name:"amount",type:"uint256"},{name:"currency",type:"bytes32"},{name:"activeFrom",type:"uint64"},{name:"activeUntil",type:"uint64"},{name:"nonce",type:"uint256"},{name:"deadline",type:"uint64"},{name:"exclusive",type:"bool"}]};
const now=(await pc.getBlock()).timestamp;
const mk=(fac,n)=>({invoiceRoot:"0x"+"a1".repeat(32),originatorSigner:orig.address,facility:fac,obligationId:"0x"+n.toString(16).padStart(64,"0"),amount:110000000n,currency:"0x"+Buffer.from("USD").toString("hex").padEnd(64,"0"),activeFrom:now-1n,activeUntil:blk.timestamp+2592001n,nonce:BigInt(n),deadline:now+172800n,exclusive:true});
const p1=mk(fA.address,1); const s1=await w(orig).signTypedData({account:orig,domain:dom,types,primaryType:"Pledge",message:p1});
await jtx(hA,st,E20.abi,"approve",[vault,100000000n],"approve funding");
await jtx(fA,vault,V.abi,"activate",[p1,s1,hA.address,[hA.address],[100000000n]],"activate 90/10");
await jtx(hA,vault,V.abi,"transfer",[hB.address,40000000n],"transfer 40 units");
const p2=mk(fB.address,2); const s2=await w(orig).signTypedData({account:orig,domain:dom,types,primaryType:"Pledge",message:p2});
const dig=await pc.readContract({address:vault,abi:V.abi,functionName:"hashPledge",args:[p2]});
const salt="0x"+"5a".repeat(32);
const cmt=await pc.readContract({address:vault,abi:V.abi,functionName:"conflictCommitment",args:[dig,(await import("viem")).keccak256(s2),fB.address,salt]});
await jtx(fB,vault,V.abi,"commitConflict",[cmt],"commitConflict");
await jtx(fB,vault,V.abi,"revealConflict",[p2,s2,salt],"revealConflict");
await fetch(RPC,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify([{jsonrpc:"2.0",id:1,method:"evm_increaseTime",params:[3700]},{jsonrpc:"2.0",id:2,method:"evm_mine",params:[]}])});
await jtx(fB,vault,V.abi,"finalizeConflict",[],"finalizeConflict");
await jtx(hA,vault,V.abi,"claimBond",[],"claimBond A");
await jtx(hB,vault,V.abi,"claimBond",[],"claimBond B");
await jtx(buyer,st,E20.abi,"approve",[vault,110000000n],"approve redemption");
await jtx(buyer,vault,V.abi,"fundRedemption",[110000000n],"fundRedemption");
await jtx(hA,vault,V.abi,"redeem",[60000000n],"redeem A");
await jtx(hB,vault,V.abi,"redeem",[40000000n],"redeem B");
let jt=0n; console.log("\n  --- phase 3, journey ---");
for(const [l,g] of j){jt+=g;console.log("  "+l.padEnd(30)+String(g).padStart(9));}
console.log("\n  journey gas:",jt.toString());
console.log("  GRAND TOTAL:",(tot+jt).toString());
