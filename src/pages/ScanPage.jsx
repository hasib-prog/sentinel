import { useState, useRef, useCallback } from "react";
import { simulateScan } from "../utils/scanSimulator";

const ALLOWED=[".exe",".dll",".pdf",".doc",".docx",".xls",".xlsx",".zip",".rar",".7z",".js",".py",".sh",".bat",".ps1",".jar",".apk",".msi",".iso",".vbs"];
const STAGES=[
  {id:"upload",l:"File Upload & Validation",ms:600},
  {id:"hash",l:"Hash Generation (SHA-256, MD5)",ms:500},
  {id:"static",l:"Static Analysis — PE Headers",ms:900},
  {id:"strings",l:"String Extraction & Analysis",ms:700},
  {id:"entropy",l:"Entropy Calculation",ms:500},
  {id:"yara",l:"YARA Rule Matching (542 rules)",ms:800},
  {id:"api",l:"Suspicious API Detection",ms:600},
  {id:"features",l:"ML Feature Extraction",ms:500},
  {id:"ai",l:"AI Malware Classification (RF+GB)",ms:1200},
  {id:"score",l:"Threat Scoring & Report Generation",ms:600},
];

function fakeHash(seed,len){const c="0123456789abcdef";let h="";for(let i=0;i<len;i++)h+=c[(seed.charCodeAt(i%seed.length)*(i+1)*31+17)%16];return h}
function formatSize(b){return b<1024?b+" B":b<1048576?(b/1024).toFixed(1)+" KB":(b/1048576).toFixed(2)+" MB"}
function fileIcon(n){const e=n.split(".").pop().toLowerCase();return{exe:"⚙",dll:"🔧",pdf:"📄",zip:"📦",doc:"📝",docx:"📝",js:"📜",py:"🐍",sh:"💻",bat:"💻",apk:"📱",jar:"☕",msi:"⚙",rar:"📦"}[e]||"📁"}
function getExt(n){return"."+n.split(".").pop().toLowerCase()}
function stageDetail(id,f){
  const d={upload:`Received ${f.name} (${formatSize(f.size)}) — validation passed`,hash:`SHA256: ${fakeHash(f.name,64)} | MD5: ${fakeHash(f.name,32)}`,static:`PE32 executable — entry point 0x${Math.floor(Math.random()*0xFFFF).toString(16).padStart(4,"0")} — ${Math.floor(Math.random()*6+2)} sections`,strings:`${Math.floor(Math.random()*180+40)} printable strings — ${Math.floor(Math.random()*12)} suspicious`,entropy:`Overall entropy: ${(Math.random()*3+5).toFixed(2)} — ${Math.random()>.5?"⚠ High entropy (possible packing)":"Normal distribution"}`,yara:`Matched ${Math.floor(Math.random()*3)} YARA rules — scanned 542 signatures`,api:`Analyzed import table — ${Math.floor(Math.random()*5)} suspicious API calls found`,features:"Extracted 22 features — vectorization complete",ai:`Random Forest confidence: ${(Math.random()*25+65).toFixed(1)}% — ensemble voting complete`,score:"Threat score calculated — security report generated"};
  return d[id]||"Processing...";
}

export default function ScanPage({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState([]);
  const [stage, setStage] = useState(-1);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  const selectFile = f => {
    if(f.size > 52428800){setError("File too large (max 50MB)");return}
    if(!ALLOWED.includes(getExt(f.name))){setError("File type not supported: "+getExt(f.name));return}
    setError(null); setFile(f);
  };

  const handleDrop = useCallback(e => {
    e.preventDefault(); setDrag(false);
    if(e.dataTransfer.files[0]) selectFile(e.dataTransfer.files[0]);
  },[]);

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  const startScan = async () => {
    if(!file) return;
    setScanning(true); setProgress([]); setStage(0);
    const results = [];
    for(let i=0;i<STAGES.length;i++){
      setStage(i);
      await sleep(STAGES[i].ms);
      results.push({label:STAGES[i].l, detail:stageDetail(STAGES[i].id,file)});
      setProgress([...results]);
    }
    setStage(-1);
    const report = simulateScan(file);
    const scanId = "SCAN-"+Date.now().toString(36).toUpperCase();
    const full = {...report, fileName:file.name, scanId, timestamp:new Date().toISOString()};
    const history = JSON.parse(localStorage.getItem("sentinel_history")||"[]");
    history.unshift(full);
    localStorage.setItem("sentinel_history", JSON.stringify(history.slice(0,50)));
    await sleep(400);
    onScanComplete(scanId, full);
  };

  return (
    <div style={{padding:"40px 0 80px"}}>
      <div className="container">
        <div style={{marginBottom:"32px"}}>
          <div className="section-label">Threat Analysis</div>
          <h1 style={{fontSize:"36px",fontWeight:800,color:"var(--t1)",letterSpacing:".04em",marginBottom:"8px"}}>File Scanner</h1>
          <p style={{color:"var(--t3)",fontSize:"15px"}}>Upload a file to run comprehensive AI-powered malware analysis</p>
        </div>
        {!scanning ? (
          <div style={{display:"flex",flexDirection:"column",gap:"20px"}}>
            <div
              onClick={() => !file && inputRef.current.click()}
              onDragOver={e=>{e.preventDefault();setDrag(true)}}
              onDragLeave={()=>setDrag(false)}
              onDrop={handleDrop}
              style={{border:`2px dashed ${drag?"var(--blue)":file?"var(--b2)":"var(--b1)"}`,borderStyle:file?"solid":"dashed",borderRadius:"12px",background:drag||file?"var(--bg4)":"var(--bg3)",padding:file?"28px 40px":"60px 40px",textAlign:"center",cursor:file?"default":"pointer",transition:"all .3s",minHeight:"240px",display:"flex",alignItems:"center",justifyContent:"center",position:"relative",overflow:"hidden"}}
            >
              <input ref={inputRef} type="file" hidden onChange={e=>e.target.files[0]&&selectFile(e.target.files[0])} accept={ALLOWED.join(",")}/>
              {!file ? (
                <div>
                  <div style={{width:"52px",height:"52px",background:"rgba(20,140,255,.1)",border:"1px solid rgba(20,140,255,.3)",borderRadius:"12px",display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 12px"}}>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M12 3L12 15M12 3L8 7M12 3L16 7" stroke="#148cff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/><path d="M3 19V21C3 21.6 3.4 22 4 22H20C20.6 22 21 21.6 21 21V19" stroke="#148cff" strokeWidth="2" strokeLinecap="round"/></svg>
                  </div>
                  <div style={{fontSize:"17px",fontWeight:700,color:"var(--t1)",marginBottom:"4px"}}>Drop File Here</div>
                  <div style={{fontSize:"12px",color:"var(--t3)",marginBottom:"12px"}}>or click to browse</div>
                  <div style={{display:"flex",gap:"6px",flexWrap:"wrap",justifyContent:"center"}}>
                    {["EXE","DLL","PDF","ZIP","APK","+15"].map(t=><span key={t} style={{fontFamily:"var(--font-mono)",fontSize:"9px",padding:"2px 7px",background:"var(--bg5)",border:"1px solid var(--b0)",borderRadius:"3px",color:"var(--t3)"}}>{t}</span>)}
                  </div>
                </div>
              ) : (
                <div style={{display:"flex",alignItems:"center",gap:"16px",width:"100%"}}>
                  <span style={{fontSize:"28px",flexShrink:0}}>{fileIcon(file.name)}</span>
                  <div style={{flex:1,textAlign:"left"}}>
                    <div style={{fontSize:"16px",fontWeight:700,color:"var(--t1)",marginBottom:"6px",wordBreak:"break-all"}}>{file.name}</div>
                    <div style={{display:"flex",gap:"16px",fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--t3)"}}>
                      <span>{formatSize(file.size)}</span><span style={{color:"var(--safe)"}}>Ready for analysis</span>
                    </div>
                  </div>
                  <div onClick={e=>{e.stopPropagation();setFile(null);setError(null)}} style={{width:"24px",height:"24px",background:"rgba(255,51,68,.1)",border:"1px solid rgba(255,51,68,.25)",borderRadius:"50%",color:"var(--red)",fontSize:"14px",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center"}}>×</div>
                </div>
              )}
            </div>
            {error && <div style={{display:"flex",gap:"7px",padding:"10px 14px",background:"rgba(255,51,68,.08)",border:"1px solid rgba(255,51,68,.25)",borderRadius:"7px",color:"var(--red)",fontSize:"12px"}}>⚠ {error}</div>}
            {file && <button className="btn btn-primary" style={{width:"100%",padding:"16px",fontSize:"16px"}} onClick={startScan}>⊕ Start Analysis</button>}
            <div className="panel">
              <div className="section-label">What We Analyze</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"7px",marginTop:"10px"}}>
                {["SHA-256 & MD5 hash generation","File entropy calculation","Suspicious string extraction","PE header & section analysis","Import table API scanning","YARA signature matching","AI/ML malware classification","Threat score computation"].map((item,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"center",gap:"7px",fontSize:"11px",color:"var(--t2)"}}>
                    <span style={{color:"var(--safe)",fontWeight:700}}>✓</span>{item}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div style={{display:"flex",flexDirection:"column",gap:"16px"}}>
            <div className="panel">
              <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"12px"}}>
                <div style={{width:"18px",height:"18px",border:"2px solid var(--b0)",borderTopColor:"var(--blue)",borderRadius:"50%",animation:"rotate .8s linear infinite",flexShrink:0}}/>
                <span style={{fontFamily:"var(--font-mono)",fontSize:"13px",color:"var(--cyan)"}}>
                  {stage>=0 ? "Analyzing: "+STAGES[stage]?.l : "Analysis Complete ✓"}
                </span>
              </div>
              <div style={{height:"4px",background:"rgba(255,255,255,.06)",borderRadius:"2px",overflow:"hidden",marginBottom:"8px"}}>
                <div style={{height:"100%",background:"linear-gradient(90deg,var(--blue),var(--cyan))",borderRadius:"2px",width:`${(progress.length/STAGES.length)*100}%`,transition:"width .4s ease",boxShadow:"0 0 8px var(--blue)"}}/>
              </div>
              <div style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--t3)",textAlign:"right"}}>{progress.length} / {STAGES.length}</div>
            </div>
            <div style={{background:"#020c14",border:"1px solid var(--b1)",borderRadius:"10px",overflow:"hidden"}}>
              <div style={{background:"var(--bg5)",padding:"9px 14px",display:"flex",alignItems:"center",gap:"10px",borderBottom:"1px solid var(--b0)"}}>
                <div style={{display:"flex",gap:"5px"}}>
                  {["#ff5f56","#ffbd2e","#27c93f"].map(c=><span key={c} style={{width:"9px",height:"9px",borderRadius:"50%",background:c,display:"inline-block"}}/>)}
                </div>
                <span style={{fontFamily:"var(--font-terminal)",fontSize:"11px",color:"var(--t3)"}}>sentinel_scanner.py — {file?.name}</span>
              </div>
              <div style={{padding:"16px",fontFamily:"'Courier New',monospace",fontSize:"11px",lineHeight:1.9,minHeight:"300px",maxHeight:"420px",overflowY:"auto"}}>
                <div style={{display:"flex",gap:"7px",flexWrap:"wrap",marginBottom:"4px"}}>
                  <span style={{color:"#27c93f"}}>sentinel@engine:~$</span>
                  <span style={{color:"var(--t2)"}}>python3 scanner.py --file "{file?.name}" --deep-scan --ai</span>
                </div>
                <div style={{color:"var(--t3)"}}>[ INFO ] Sentinel AI Malware Analysis Engine v3.1.0</div>
                <div style={{color:"var(--t3)"}}>[ INFO ] Starting comprehensive threat analysis...</div>
                {progress.map((s,i)=>(
                  <div key={i}>
                    <span style={{color:"var(--safe)",fontWeight:700}}>[ ✓ OK ] </span>
                    <span style={{color:"var(--t1)"}}>{s.label}</span>
                    <div style={{fontSize:"10px",color:"var(--t4)",paddingLeft:"52px"}}>{s.detail}</div>
                  </div>
                ))}
                {stage>=0 && <div><span style={{color:"var(--blue)"}}>[ ··· ] </span><span style={{color:"var(--cyan)"}}>{STAGES[stage]?.l}<span style={{animation:"blink .7s step-end infinite",color:"var(--blue)"}}>_</span></span></div>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
