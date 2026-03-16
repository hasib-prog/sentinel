import { useState, useEffect } from "react";

function fakeHash(s,l){const c="0123456789abcdef";let h="";for(let i=0;i<l;i++)h+=c[(s.charCodeAt(i%s.length)*(i+1)*31+17)%16];return h}
function tc(l){return{safe:"var(--safe)",low:"var(--low)",susp:"var(--yellow)",suspicious:"var(--yellow)",malicious:"var(--red)",mal:"var(--red)"}[l]||"var(--t3)"}
function fmt(ts){if(!ts)return"—";const d=new Date(ts);return d.toLocaleDateString("en-US",{month:"short",day:"numeric"})+" "+d.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit",hour12:false})}
function badgeCls(l){return{safe:"badge-safe",low:"badge-low",suspicious:"badge-suspicious",susp:"badge-suspicious",malicious:"badge-malicious",mal:"badge-malicious"}[l]||"badge-safe"}

const DEMO=[
  {fileName:"setup_crack.exe",threatScore:92,threatLevel:"malicious",threatLabel:"Malicious",verdict:"Malware detected",timestamp:new Date(Date.now()-7200000).toISOString(),fileInfo:{sha256:fakeHash("a",64)},scanId:"SCAN-DEMO1",confidence:88},
  {fileName:"report_Q4.docx",threatScore:8,threatLevel:"safe",threatLabel:"Clean",verdict:"No threats",timestamp:new Date(Date.now()-14400000).toISOString(),fileInfo:{sha256:fakeHash("b",64)},scanId:"SCAN-DEMO2",confidence:94},
  {fileName:"update_service.dll",threatScore:67,threatLevel:"suspicious",threatLabel:"Suspicious",verdict:"Suspicious patterns",timestamp:new Date(Date.now()-21600000).toISOString(),fileInfo:{sha256:fakeHash("c",64)},scanId:"SCAN-DEMO3",confidence:72},
  {fileName:"invoice_dec.pdf",threatScore:3,threatLevel:"safe",threatLabel:"Clean",verdict:"No threats",timestamp:new Date(Date.now()-28800000).toISOString(),fileInfo:{sha256:fakeHash("d",64)},scanId:"SCAN-DEMO4",confidence:97},
  {fileName:"game_trainer.exe",threatScore:88,threatLevel:"malicious",threatLabel:"Malicious",verdict:"Malware detected",timestamp:new Date(Date.now()-36000000).toISOString(),fileInfo:{sha256:fakeHash("e",64)},scanId:"SCAN-DEMO5",confidence:85},
];

export default function HistoryPage({ navigate, onSelectScan }) {
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState("newest");

  useEffect(()=>{
    const stored=JSON.parse(localStorage.getItem("sentinel_history")||"[]");
    setHistory(stored.length>0?stored:DEMO);
  },[]);

  const clearHistory=()=>{localStorage.removeItem("sentinel_history");setHistory(DEMO)};

  const mal=history.filter(s=>s.threatLevel==="malicious"||s.threatLevel==="mal").length;
  const susp=history.filter(s=>s.threatLevel==="suspicious"||s.threatLevel==="susp").length;
  const safe=history.filter(s=>s.threatLevel==="safe"||s.threatLevel==="low").length;
  const avg=history.length>0?Math.round(history.reduce((a,s)=>a+s.threatScore,0)/history.length):0;

  const filtered=history
    .filter(s=>filter==="all"||(filter==="safe"&&(s.threatLevel==="safe"||s.threatLevel==="low"))||s.threatLevel===filter||s.threatLevel==={mal:"malicious",susp:"suspicious"}[filter])
    .sort((a,b)=>sort==="newest"?new Date(b.timestamp)-new Date(a.timestamp):sort==="oldest"?new Date(a.timestamp)-new Date(b.timestamp):sort==="highest"?b.threatScore-a.threatScore:a.threatScore-b.threatScore);

  return (
    <div style={{padding:"40px 0 80px"}}>
      <div className="container">
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"24px",flexWrap:"wrap",gap:"12px"}}>
          <div>
            <div className="section-label">Analytics Dashboard</div>
            <h1 style={{fontSize:"30px",fontWeight:800,color:"var(--t1)",letterSpacing:".04em",marginBottom:"5px"}}>Scan History</h1>
            <p style={{color:"var(--t3)",fontSize:"13px"}}>{history.length} analyses stored</p>
          </div>
          <div style={{display:"flex",gap:"8px"}}>
            <button className="btn btn-primary" onClick={()=>navigate("scan")}>+ New Scan</button>
            <button className="btn btn-ghost" onClick={clearHistory}>Clear All</button>
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:"12px",marginBottom:"20px"}}>
          {[[history.length,"Total Scans","var(--blue)","📊"],[mal,"Malicious","var(--red)","⚠"],[susp,"Suspicious","var(--yellow)","⚡"],[safe,"Clean","var(--safe)","✓"],[avg,"Avg Score","var(--cyan)","🎯"]].map(([v,l,c,i],idx)=>(
            <div key={idx} className="card" style={{display:"flex",flexDirection:"column",alignItems:"center",gap:"4px",padding:"16px 10px",textAlign:"center"}}>
              <div style={{fontSize:"18px"}}>{i}</div>
              <div style={{fontFamily:"var(--font-mono)",fontSize:"24px",fontWeight:800,color:c,lineHeight:1}}>{v}</div>
              <div style={{fontSize:"10px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".08em"}}>{l}</div>
            </div>
          ))}
        </div>

        <div className="card" style={{marginBottom:"16px"}}>
          <div className="section-label">Threat Distribution</div>
          <div style={{display:"flex",height:"24px",borderRadius:"5px",overflow:"hidden",gap:"2px",margin:"10px 0"}}>
            {mal>0&&<div style={{flex:mal,background:"var(--red)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"10px",fontWeight:700,color:"rgba(0,0,0,.7)",borderRadius:"4px",minWidth:"24px"}}>{mal}</div>}
            {susp>0&&<div style={{flex:susp,background:"var(--yellow)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"10px",fontWeight:700,color:"rgba(0,0,0,.7)",borderRadius:"4px",minWidth:"24px"}}>{susp}</div>}
            {safe>0&&<div style={{flex:safe,background:"var(--safe)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"10px",fontWeight:700,color:"rgba(0,0,0,.7)",borderRadius:"4px",minWidth:"24px"}}>{safe}</div>}
          </div>
          <div style={{display:"flex",gap:"16px",fontSize:"11px",color:"var(--t3)"}}>
            {[["var(--red)","Malicious",mal],["var(--yellow)","Suspicious",susp],["var(--safe)","Safe",safe]].map(([c,l,v],i)=>(
              <span key={i}><span style={{width:"7px",height:"7px",borderRadius:"50%",background:c,display:"inline-block",marginRight:"5px"}}/>{l} ({v})</span>
            ))}
          </div>
        </div>

        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"14px",flexWrap:"wrap",gap:"10px"}}>
          <div style={{display:"flex",gap:"5px",flexWrap:"wrap"}}>
            {[["all","All"],["malicious","Malicious"],["suspicious","Suspicious"],["safe","Safe"],["low","Low Risk"]].map(([f,l])=>(
              <button key={f} onClick={()=>setFilter(f)} style={{padding:"5px 12px",background:filter===f?"rgba(20,140,255,.12)":"none",border:`1px solid ${filter===f?"rgba(20,140,255,.35)":"var(--b0)"}`,borderRadius:"5px",color:filter===f?"var(--blue)":"var(--t3)",fontSize:"11px",fontFamily:"var(--font-display)",cursor:"pointer",transition:"all .2s"}}>{l}</button>
            ))}
          </div>
          <select value={sort} onChange={e=>setSort(e.target.value)} style={{background:"var(--bg5)",border:"1px solid var(--b0)",borderRadius:"5px",color:"var(--t2)",fontSize:"11px",fontFamily:"var(--font-display)",padding:"5px 9px",cursor:"pointer",outline:"none"}}>
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="highest">Highest Threat</option>
            <option value="lowest">Lowest Threat</option>
          </select>
        </div>

        {filtered.length>0 ? (
          <div className="card" style={{padding:0}}>
            <div style={{display:"grid",gridTemplateColumns:"1.8fr 1.2fr 1.2fr 100px 90px 90px",gap:"12px",padding:"10px 16px",fontSize:"10px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".07em",borderBottom:"1px solid var(--b0)"}}>
              <span>File</span><span>Hash</span><span>Score</span><span>Level</span><span>Date</span><span/>
            </div>
            {filtered.map((s,i)=>(
              <div key={i} onClick={()=>onSelectScan(s.scanId,s)} style={{display:"grid",gridTemplateColumns:"1.8fr 1.2fr 1.2fr 100px 90px 90px",gap:"12px",padding:"10px 16px",alignItems:"center",borderBottom:"1px solid rgba(255,255,255,.025)",cursor:"pointer",transition:"background .15s"}} onMouseEnter={e=>e.currentTarget.style.background="var(--bg5)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                <div><div style={{fontSize:"12px",fontWeight:600,color:"var(--t1)"}}>{s.fileName}</div><div style={{fontSize:"9px",color:"var(--t4)",fontFamily:"var(--font-mono)",marginTop:"2px"}}>{s.scanId}</div></div>
                <div style={{fontSize:"10px",color:"var(--t4)",fontFamily:"var(--font-mono)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{(s.fileInfo?.sha256||"").slice(0,20)}...</div>
                <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
                  <div style={{flex:1,height:"3px",background:"rgba(255,255,255,.05)",borderRadius:"2px",overflow:"hidden"}}><div style={{height:"100%",borderRadius:"2px",background:tc(s.threatLevel),width:`${s.threatScore}%`}}/></div>
                  <span style={{fontFamily:"var(--font-mono)",fontSize:"13px",fontWeight:700,color:tc(s.threatLevel),width:"24px",textAlign:"right"}}>{s.threatScore}</span>
                </div>
                <div><span className={`badge ${badgeCls(s.threatLevel)}`} style={{fontSize:"9px"}}>{s.threatLabel}</span></div>
                <div style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--t3)"}}>{fmt(s.timestamp)}</div>
                <div><button className="btn btn-ghost" style={{padding:"4px 10px",fontSize:"10px"}} onClick={e=>{e.stopPropagation();onSelectScan(s.scanId,s)}}>View</button></div>
              </div>
            ))}
          </div>
        ) : (
          <div className="card" style={{display:"flex",flexDirection:"column",alignItems:"center",gap:"10px",padding:"52px",textAlign:"center"}}>
            <div style={{fontSize:"36px"}}>📂</div>
            <div style={{fontSize:"18px",fontWeight:700,color:"var(--t1)"}}>No scans</div>
            <div style={{fontSize:"13px",color:"var(--t3)"}}>Run your first analysis to see results here.</div>
            <button className="btn btn-primary" style={{marginTop:"8px"}} onClick={()=>navigate("scan")}>Start Scanning</button>
          </div>
        )}
      </div>
    </div>
  );
}
