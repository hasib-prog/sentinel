import { useState, useEffect } from "react";

const SEV_COLORS={critical:"#ff3344",high:"#ff8800",medium:"#ffcc00",low:"#148cff"};

export default function ReportPage({ scanData, navigate }) {
  const [tab, setTab] = useState("overview");
  const [anim, setAnim] = useState(false);
  useEffect(()=>{setTimeout(()=>setAnim(true),100);},[scanData]);

  if(!scanData) return <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"60vh",color:"var(--t3)"}}>No scan data. <button onClick={()=>navigate("scan")} style={{color:"var(--blue)",background:"none",border:"none",cursor:"pointer",marginLeft:"8px"}}>Run a scan</button></div>;

  const {threatScore,threatLevel,threatLabel,verdict,malwareFamily,confidence,fileInfo,staticAnalysis,yaraMatches,behaviors,avResults,aiClassification,scanMetadata,fileName}=scanData;
  const tc={safe:"var(--safe)",low:"var(--low)",susp:"var(--yellow)",suspicious:"var(--yellow)",malicious:"var(--red)",mal:"var(--red)"}[threatLevel]||"var(--t2)";
  const badgeCls={safe:"badge-safe",low:"badge-low",suspicious:"badge-suspicious",susp:"badge-suspicious",malicious:"badge-malicious",mal:"badge-malicious"}[threatLevel]||"badge-safe";
  const detCount=avResults?.filter(r=>r.detected).length||0;
  const totCount=avResults?.length||0;
  const fmt=b=>b<1024?b+" B":b<1048576?(b/1024).toFixed(1)+" KB":(b/1048576).toFixed(2)+" MB";
  const exportReport=()=>{const blob=new Blob([JSON.stringify(scanData,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`sentinel-${scanData.scanId}.json`;a.click()};

  const TABS=[{id:"overview",l:"Overview"},{id:"static",l:"Static Analysis"},{id:"ai",l:"AI Classification"},{id:"yara",l:`YARA (${yaraMatches?.length||0})`},{id:"behaviors",l:`Behaviors (${behaviors?.length||0})`},{id:"av",l:`AV Results (${detCount}/${totCount})`}];

  return (
    <div style={{padding:"32px 0 80px"}}>
      <div className="container">
        <div style={{display:"flex",alignItems:"center",gap:"7px",marginBottom:"20px",fontSize:"12px",color:"var(--t4)"}}>
          {[["home","Home"],["scan","Scan"]].map(([p,l])=><span key={p}><button onClick={()=>navigate(p)} style={{background:"none",border:"none",color:"var(--t3)",fontSize:"12px",cursor:"pointer",fontFamily:"var(--font-display)"}}>{l}</button> / </span>)}
          <span style={{color:"var(--t2)"}}>Report</span>
        </div>

        <div className="card" style={{marginBottom:"20px",borderColor:threatLevel==="malicious"||threatLevel==="mal"?"rgba(255,51,68,.3)":threatLevel==="suspicious"||threatLevel==="susp"?"rgba(255,204,0,.25)":"rgba(0,255,136,.2)"}}>
          <div style={{marginBottom:"12px"}}>
            <div style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--t4)",marginBottom:"5px"}}>{scanMetadata?.scanId||scanData.scanId} • {new Date(scanData.timestamp||Date.now()).toLocaleString()}</div>
            <div style={{fontSize:"22px",fontWeight:800,color:"var(--t1)",letterSpacing:".02em",wordBreak:"break-all",marginBottom:"6px"}}>{fileInfo?.name||fileName}</div>
            <div style={{display:"flex",gap:"10px",flexWrap:"wrap",fontSize:"12px",color:"var(--t3)"}}>
              <span className="mono">{fmt(fileInfo?.size||0)}</span>
              <span style={{opacity:.3}}>•</span><span>{fileInfo?.type||"Unknown"}</span>
              <span style={{opacity:.3}}>•</span><span className="mono">Sentinel v3.1.0</span>
            </div>
            <div style={{fontFamily:"var(--font-mono)",fontSize:"10px",padding:"6px 12px",background:"var(--bg5)",border:"1px solid var(--b0)",borderRadius:"6px",marginTop:"8px",display:"flex",gap:"10px",overflow:"hidden"}}>
              <span style={{color:"var(--t4)",fontSize:"9px",letterSpacing:".1em",textTransform:"uppercase",alignSelf:"center",flexShrink:0}}>SHA256</span>
              <span style={{color:"var(--t2)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{fileInfo?.sha256}</span>
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:"20px",padding:"16px",background:"var(--bg5)",border:"1px solid var(--b0)",borderRadius:"10px",marginBottom:"14px"}}>
            <svg width="140" height="140" viewBox="0 0 140 140" style={{flexShrink:0}}>
              <circle cx="70" cy="70" r="56" fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="9"/>
              <circle cx="70" cy="70" r="56" fill="none" stroke={tc} strokeWidth="9" strokeLinecap="round"
                strokeDasharray={`${2*Math.PI*56}`} strokeDashoffset={anim?`${2*Math.PI*56*(1-threatScore/100)}`:`${2*Math.PI*56}`}
                transform="rotate(-90 70 70)" style={{transition:"stroke-dashoffset 1.5s ease",filter:`drop-shadow(0 0 7px ${tc})`}}/>
              <text x="70" y="64" textAnchor="middle" fill={tc} fontSize="32" fontWeight="800" fontFamily="monospace">{threatScore}</text>
              <text x="70" y="82" textAnchor="middle" fill="rgba(255,255,255,.35)" fontSize="9" fontFamily="sans-serif" letterSpacing="2">THREAT SCORE</text>
            </svg>
            <div>
              <span className={`badge ${badgeCls}`} style={{marginBottom:"8px",display:"inline-flex"}}>{threatLabel}</span>
              <div style={{fontSize:"13px",color:"var(--t2)",marginTop:"4px",marginBottom:"8px"}}>{verdict}</div>
              {malwareFamily && <div style={{display:"flex",gap:"8px",alignItems:"center",marginBottom:"8px"}}><span style={{fontSize:"9px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".1em"}}>Family</span><span style={{fontFamily:"var(--font-mono)",fontSize:"12px",color:"var(--red)"}}>{malwareFamily}</span></div>}
              <div style={{display:"flex",alignItems:"center",gap:"8px",marginBottom:"8px"}}>
                <span style={{fontSize:"11px",color:"var(--t3)"}}>AI Confidence</span>
                <div style={{width:"90px",height:"4px",background:"rgba(255,255,255,.06)",borderRadius:"2px",overflow:"hidden"}}><div style={{height:"100%",borderRadius:"2px",background:tc,width:`${confidence}%`}}/></div>
                <span style={{fontFamily:"var(--font-mono)",fontSize:"11px",color:"var(--t2)"}}>{confidence}%</span>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
                <span style={{fontFamily:"var(--font-mono)",fontSize:"16px",fontWeight:700,color:detCount>0?tc:"var(--safe)"}}>{detCount}/{totCount}</span>
                <span style={{fontSize:"11px",color:"var(--t3)"}}>AV engines detected</span>
              </div>
            </div>
          </div>
          <div style={{display:"flex",gap:"8px",flexWrap:"wrap"}}>
            <button className="btn btn-ghost" onClick={()=>navigate("scan")}>New Scan</button>
            <button className="btn btn-ghost" onClick={exportReport}>Export JSON</button>
            <button className="btn btn-ghost" onClick={()=>navigate("history")}>History</button>
          </div>
        </div>

        <div style={{display:"flex",gap:"1px",marginBottom:"20px",borderBottom:"1px solid var(--b0)",overflowX:"auto"}}>
          {TABS.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"9px 16px",background:"none",border:"none",color:tab===t.id?"var(--cyan)":"var(--t3)",fontFamily:"var(--font-display)",fontSize:"12px",fontWeight:500,cursor:"pointer",whiteSpace:"nowrap",borderBottom:tab===t.id?"2px solid var(--cyan)":"2px solid transparent",marginBottom:"-1px",transition:"all .2s"}}>{t.l}</button>)}
        </div>

        <div className="animate-fade-in" key={tab}>
          {tab==="overview" && (
            <div style={{display:"grid",gridTemplateColumns:"1fr 300px",gap:"16px"}}>
              <div className="card">
                <div className="section-label">File Information</div>
                {[["Filename",fileInfo?.name],["Size",fmt(fileInfo?.size||0)],["Type",fileInfo?.type],["SHA-256",fileInfo?.sha256],["MD5",fileInfo?.md5],["SHA-1",fileInfo?.sha1],["Entropy",`${staticAnalysis?.entropy} — ${staticAnalysis?.entropyRating}`],["Packed",staticAnalysis?.isPacked?"Yes ⚠":"No"]].map(([k,v],i)=>(
                  <div key={i} style={{display:"flex",gap:"14px",padding:"8px 0",borderBottom:"1px solid var(--b0)"}}>
                    <span style={{fontSize:"11px",color:"var(--t3)",width:"90px",flexShrink:0,textTransform:"uppercase",letterSpacing:".06em"}}>{k}</span>
                    <span style={{fontSize:"11px",color:"var(--t1)",flex:1,wordBreak:"break-all",fontFamily:"var(--font-mono)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:k==="Filename"||k==="Type"?"normal":"nowrap"}}>{v}</span>
                  </div>
                ))}
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:"14px"}}>
                <div className="card">
                  <div className="section-label">Scan Stats</div>
                  {[["⏱",`${scanMetadata?.scanDuration}s`,"Duration"],["📋",scanMetadata?.yaraRulesChecked,"YARA Rules"],["⚡",yaraMatches?.length||0,"YARA Matches",(yaraMatches?.length||0)>0],["🔧",staticAnalysis?.foundApis?.length||0,"Suspicious APIs",(staticAnalysis?.foundApis?.length||0)>0],["⚙",staticAnalysis?.sectionCount||0,"PE Sections"],["🌐",behaviors?.length||0,"Behaviors",( behaviors?.length||0)>0]].map(([ico,v,l,alert],i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:"8px",padding:"6px 8px",borderRadius:"5px",background:alert?"rgba(255,204,0,.04)":"transparent"}}>
                      <span style={{fontSize:"13px",width:"18px",textAlign:"center"}}>{ico}</span>
                      <span style={{flex:1,fontSize:"11px",color:"var(--t3)"}}>{l}</span>
                      <span style={{fontSize:"13px",fontWeight:700,color:alert?"var(--yellow)":"var(--t1)",fontFamily:"var(--font-mono)"}}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {tab==="static" && (
            <div style={{display:"flex",flexDirection:"column",gap:"14px"}}>
              <div className="card">
                <div className="section-label">Suspicious API Imports ({staticAnalysis?.foundApis?.length||0})</div>
                {staticAnalysis?.foundApis?.length>0 ? <div style={{display:"flex",flexWrap:"wrap",gap:"8px",marginTop:"10px"}}>{staticAnalysis.foundApis.map((a,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:"8px",padding:"6px 12px",background:"rgba(255,204,0,.06)",border:"1px solid rgba(255,204,0,.2)",borderRadius:"7px"}}><span style={{fontSize:"12px",fontFamily:"var(--font-mono)",color:"var(--t1)"}}>{a}</span><span className="badge badge-suspicious" style={{fontSize:"9px"}}>suspicious</span></div>)}</div> : <div style={{textAlign:"center",color:"var(--t3)",fontSize:"12px",padding:"20px"}}>No suspicious API imports found</div>}
              </div>
              <div className="card">
                <div className="section-label">PE Sections ({staticAnalysis?.sectionCount})</div>
                <div style={{overflowX:"auto",marginTop:"10px"}}>
                  <div style={{display:"grid",gridTemplateColumns:"70px 90px 90px 60px 1fr",gap:"12px",padding:"7px 4px",fontSize:"10px",color:"var(--t3)",borderBottom:"1px solid var(--b0)",textTransform:"uppercase",letterSpacing:".06em"}}>
                    <span>Name</span><span>Virt Size</span><span>Raw Size</span><span>Entropy</span><span>Chars</span>
                  </div>
                  {(staticAnalysis?.sections||[]).map((s,i)=>(
                    <div key={i} style={{display:"grid",gridTemplateColumns:"70px 90px 90px 60px 1fr",gap:"12px",padding:"7px 4px",fontSize:"10px",color:"var(--t2)",borderBottom:"1px solid rgba(255,255,255,.02)",fontFamily:"var(--font-mono)"}}>
                      <span>{s.name}</span><span>{s.virtualSize?.toString(16).padStart(8,"0")}</span><span>{s.rawSize?.toString(16).padStart(8,"0")}</span>
                      <span style={{color:s.entropy>7?"var(--red)":s.entropy>6?"var(--yellow)":"var(--safe)"}}>{s.entropy}</span>
                      <span style={{fontSize:"9px",color:"var(--t3)"}}>{s.characteristics}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {tab==="ai" && (
            <div style={{display:"flex",flexDirection:"column",gap:"14px"}}>
              <div className="card">
                <div className="section-label">Machine Learning Model</div>
                <div style={{fontSize:"15px",fontWeight:700,color:"var(--t1)"}}>{aiClassification?.model}</div>
                <div style={{fontFamily:"var(--font-mono)",fontSize:"11px",color:"var(--t3)",marginTop:"3px"}}>v{aiClassification?.version}</div>
                <div style={{display:"flex",gap:"24px",marginTop:"14px",paddingTop:"14px",borderTop:"1px solid var(--b0)"}}>
                  <div><div style={{fontSize:"10px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".08em",marginBottom:"5px"}}>Malware Probability</div><div style={{fontFamily:"var(--font-mono)",fontSize:"26px",fontWeight:800,color:tc}}>{((aiClassification?.malwareProbability||0)*100).toFixed(1)}%</div></div>
                  <div><div style={{fontSize:"10px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".08em",marginBottom:"5px"}}>Risk Score</div><div style={{fontFamily:"var(--font-mono)",fontSize:"26px",fontWeight:800,color:tc}}>{aiClassification?.riskScore}/100</div></div>
                  <div><div style={{fontSize:"10px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".08em",marginBottom:"5px"}}>Classification</div><div style={{marginTop:"5px"}}><span className={`badge ${badgeCls}`}>{threatLabel}</span></div></div>
                </div>
              </div>
              <div className="card">
                <div className="section-label">Feature Importance</div>
                {(aiClassification?.featureImportance||aiClassification?.feature_importance||[]).map((f,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"10px"}}>
                    <span style={{fontSize:"11px",color:"var(--t2)",width:"150px",flexShrink:0,fontFamily:"var(--font-mono)",textTransform:"capitalize"}}>{(f.f||f.feature||"").replace(/_/g," ")}</span>
                    <div style={{flex:1,height:"5px",background:"rgba(255,255,255,.05)",borderRadius:"3px",overflow:"hidden"}}><div style={{height:"100%",borderRadius:"3px",background:`hsl(${210-i*20},75%,58%)`,width:`${(f.i||f.importance||0)*100}%`,transition:"width 1s ease"}}/></div>
                    <span style={{fontFamily:"var(--font-mono)",fontSize:"11px",color:"var(--t3)",width:"30px",textAlign:"right"}}>{((f.i||f.importance||0)*100).toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {tab==="yara" && (
            <div>
              <div className="card" style={{marginBottom:"14px"}}><div className="section-label">YARA Scanning</div><p style={{fontSize:"13px",color:"var(--t2)",marginTop:"6px"}}>Scanned against <strong>{scanMetadata?.yaraRulesChecked}</strong> rules. Found <strong style={{color:(yaraMatches?.length||0)>0?"var(--yellow)":"var(--safe)"}}>{yaraMatches?.length||0}</strong> matches.</p></div>
              {yaraMatches?.length>0 ? yaraMatches.map((r,i)=>{const sc=SEV_COLORS[r.severity]||"var(--blue)";return(<div key={i} className="card" style={{marginBottom:"10px"}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"5px"}}><span style={{fontFamily:"var(--font-mono)",fontSize:"11px",color:"var(--t3)"}}>{r.id}</span><span className="badge" style={{color:sc,background:sc+"18",border:`1px solid ${sc}30`}}>{r.severity}</span></div><div style={{fontSize:"13px",fontWeight:600,color:"var(--t1)"}}>{r.name}</div></div>)}) : <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:"10px",padding:"40px",textAlign:"center",color:"var(--t3)"}}><span style={{color:"var(--safe)",fontSize:"22px"}}>✓</span>No YARA matches found</div>}
            </div>
          )}
          {tab==="behaviors" && (
            <div>
              {behaviors?.length>0 ? behaviors.map((b,i)=>{const bc=SEV_COLORS[b.severity]||"var(--blue)";return(<div key={i} className="card" style={{marginBottom:"10px"}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"6px"}}><div style={{display:"flex",alignItems:"center",gap:"8px"}}><div style={{width:"9px",height:"9px",borderRadius:"50%",background:bc,boxShadow:`0 0 7px ${bc}`,flexShrink:0}}/><div style={{fontSize:"14px",fontWeight:700,color:"var(--t1)"}}>{b.label}</div></div><span className="badge" style={{color:bc,background:bc+"18",border:`1px solid ${bc}30`}}>{b.severity}</span></div><div style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--t4)",marginBottom:"6px"}}>{b.id}</div><div style={{fontSize:"12px",color:"var(--t3)"}}>{b.detail}</div></div>)}) : <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:"10px",padding:"40px",textAlign:"center",color:"var(--t3)"}}><span style={{color:"var(--safe)",fontSize:"22px"}}>✓</span>No suspicious behaviors detected</div>}
            </div>
          )}
          {tab==="av" && (
            <div>
              <div className="card" style={{marginBottom:"16px"}}>
                <div style={{display:"flex",alignItems:"center",gap:"16px"}}>
                  <div><div style={{fontFamily:"var(--font-mono)",fontSize:"32px",fontWeight:800,color:detCount>0?tc:"var(--safe)"}}>{detCount}/{totCount}</div><div style={{fontSize:"11px",color:"var(--t3)",marginTop:"3px"}}>engines detected</div></div>
                  <div style={{flex:1,height:"6px",background:"rgba(255,255,255,.06)",borderRadius:"3px",overflow:"hidden"}}><div style={{height:"100%",borderRadius:"3px",background:detCount>0?tc:"var(--safe)",width:`${(detCount/totCount*100).toFixed(0)}%`,transition:"width 1s ease"}}/></div>
                  <div style={{fontFamily:"var(--font-mono)",fontSize:"14px",color:"var(--t2)"}}>{(detCount/totCount*100).toFixed(0)}%</div>
                </div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(190px,1fr))",gap:"10px"}}>
                {avResults?.map((av,i)=>(
                  <div key={i} className="card" style={{padding:"12px 14px",borderColor:av.detected?"rgba(255,51,68,.25)":undefined,background:av.detected?"rgba(255,51,68,.04)":undefined}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"4px"}}>
                      <span style={{fontSize:"12px",fontWeight:600,color:"var(--t1)"}}>{av.engine}</span>
                      <span style={{fontSize:"10px",color:av.detected?"var(--red)":"var(--safe)"}}>{av.detected?"⚠ Detected":"✓ Clean"}</span>
                    </div>
                    {av.detected && <div style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--yellow)",marginTop:"3px"}}>{av.result}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
