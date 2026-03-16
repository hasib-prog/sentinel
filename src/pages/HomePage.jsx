import { useEffect, useState } from "react";

const FEED=[
  {n:"document_Q4.exe",s:87,l:"malicious",h:"a7f3d2e1b9c4"},
  {n:"setup_v2.msi",s:12,l:"safe",h:"2b8c4a1d3e7f"},
  {n:"update_patch.dll",s:63,l:"suspicious",h:"9e1f4b7c2a8d"},
  {n:"invoice_dec.pdf",s:4,l:"safe",h:"5d3a9c7e2b1f"},
  {n:"crack_software.zip",s:96,l:"malicious",h:"c2e6f1a9b4d8"},
];
const THREATS=[
  {n:"Trojan",p:34,c:"#ff3344"},{n:"Ransomware",p:21,c:"#ff8800"},
  {n:"Spyware",p:18,c:"#ffcc00"},{n:"Worm",p:15,c:"#b044ff"},{n:"Adware",p:12,c:"#148cff"}
];

export default function HomePage({ navigate }) {
  const [anim, setAnim] = useState(false);
  useEffect(() => { setTimeout(() => setAnim(true), 100); }, []);

  const tc = l => ({malicious:"var(--red)",suspicious:"var(--yellow)",safe:"var(--safe)",low:"var(--low)"}[l]||"var(--t3)");

  return (
    <div style={{paddingBottom:"80px"}}>
      <section style={{position:"relative",padding:"80px 0 60px",overflow:"hidden",borderBottom:"1px solid var(--b0)",marginBottom:"32px"}}>
        <div style={{position:"absolute",inset:0,pointerEvents:"none"}}>
          <div style={{position:"absolute",width:"500px",height:"500px",background:"radial-gradient(circle,rgba(20,140,255,.08),transparent)",top:"-200px",right:"-100px",borderRadius:"50%"}}/>
          <div style={{position:"absolute",width:"350px",height:"350px",background:"radial-gradient(circle,rgba(176,68,255,.06),transparent)",bottom:"-150px",left:"-80px",borderRadius:"50%"}}/>
        </div>
        <div className="container" style={{position:"relative",zIndex:1}}>
          <div style={{opacity:anim?1:0,transform:anim?"translateY(0)":"translateY(30px)",transition:"all .8s ease",maxWidth:"780px"}}>
            <div style={{display:"inline-flex",alignItems:"center",gap:"8px",padding:"5px 14px",background:"rgba(20,140,255,.1)",border:"1px solid rgba(20,140,255,.25)",borderRadius:"100px",fontSize:"12px",color:"var(--cyan)",marginBottom:"24px"}}>
              <span style={{width:"6px",height:"6px",borderRadius:"50%",background:"var(--cyan)",boxShadow:"0 0 8px var(--cyan)",display:"inline-block",animation:"pulse-blue 2s infinite"}}/>
              AI-Powered Threat Intelligence
            </div>
            <h1 style={{fontSize:"clamp(36px,5vw,58px)",fontWeight:900,lineHeight:1.0,marginBottom:"20px",letterSpacing:"-.01em"}}>
              <span style={{display:"block",letterSpacing:".06em",color:"var(--t1)"}}>ADVANCED MALWARE</span>
              <span style={{display:"block",letterSpacing:".06em",color:"var(--t2)",marginTop:"4px"}}>ANALYSIS <span style={{color:"var(--blue)",textShadow:"0 0 30px rgba(20,140,255,.5)"}}>ENGINE</span></span>
            </h1>
            <p style={{fontSize:"16px",color:"var(--t3)",lineHeight:1.7,marginBottom:"32px",maxWidth:"560px"}}>Military-grade static analysis combined with machine learning classification. Upload any file for instant threat assessment.</p>
            <div style={{display:"flex",gap:"12px",marginBottom:"48px"}}>
              <button className="btn btn-primary" style={{fontSize:"15px",padding:"13px 28px"}} onClick={() => navigate("scan")}>⊕ Scan a File</button>
              <button className="btn btn-ghost" onClick={() => navigate("history")}>View History</button>
            </div>
            <div style={{display:"flex",gap:"40px",paddingTop:"32px",borderTop:"1px solid var(--b0)"}}>
              {[["2,847,293","Files Scanned"],["43,821","Threats Detected"],["99.7%","Detection Rate"],["2.3s","Avg Scan Time"]].map(([v,l],i) => (
                <div key={i}><div style={{fontFamily:"var(--font-mono)",fontSize:"22px",fontWeight:700,color:"var(--t1)"}}>{v}</div><div style={{fontSize:"11px",color:"var(--t3)",textTransform:"uppercase",letterSpacing:".1em",marginTop:"4px"}}>{l}</div></div>
              ))}
            </div>
          </div>
        </div>
      </section>
      <div className="container">
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"20px",marginBottom:"20px"}}>
          <div className="card" style={{gridColumn:"1/-1"}}>
            <div className="section-label">Analysis Pipeline</div>
            <div style={{display:"flex",alignItems:"center",overflowX:"auto",gap:0,paddingBottom:"4px"}}>
              {[["⬆","Upload","File ingestion"],["#","Hash","SHA-256 gen"],["⚙","Static","Entropy+PE"],["Y","YARA","542 rules"],["🤖","AI Model","RF+GB ensemble"],["📊","Report","Threat score"]].map(([ico,lbl,sub],i,arr) => (
                <div key={i} style={{display:"flex",alignItems:"center",flexShrink:0}}>
                  <div style={{width:"38px",height:"38px",background:"var(--bg5)",border:"1px solid var(--b1)",borderRadius:"8px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"13px",color:"var(--blue)",fontFamily:"var(--font-mono)",fontWeight:700}}>{ico}</div>
                  <div style={{background:"var(--bg5)",border:"1px solid var(--b0)",borderLeft:"none",borderRadius:"0 7px 7px 0",padding:"6px 12px 6px 8px"}}>
                    <div style={{fontSize:"11px",fontWeight:700,color:"var(--t1)"}}>{lbl}</div>
                    <div style={{fontSize:"9px",color:"var(--t3)",marginTop:"1px"}}>{sub}</div>
                  </div>
                  {i<arr.length-1 && <div style={{fontSize:"12px",color:"var(--b2)",padding:"0 8px",fontWeight:700}}>→</div>}
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <div className="section-label">Threat Intelligence</div>
            <div style={{fontSize:"14px",fontWeight:700,color:"var(--t1)",marginBottom:"14px"}}>Malware Distribution</div>
            {THREATS.map((t,i) => (
              <div key={i} style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"10px"}}>
                <span style={{fontSize:"11px",fontWeight:600,color:"var(--t2)",width:"70px",flexShrink:0}}>{t.n}</span>
                <div style={{flex:1,height:"5px",background:"rgba(255,255,255,.04)",borderRadius:"3px",overflow:"hidden"}}>
                  <div style={{height:"100%",borderRadius:"3px",background:t.c,width:anim?`${t.p}%`:"0%",transition:`width 1s ease ${.3+i*.1}s`}}/>
                </div>
                <span style={{fontFamily:"var(--font-mono)",fontSize:"11px",color:"var(--t3)",width:"28px",textAlign:"right"}}>{t.p}%</span>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="section-label">Live Feed</div>
            <div style={{fontSize:"14px",fontWeight:700,color:"var(--t1)",marginBottom:"14px"}}>Recent Analyses</div>
            {FEED.map((f,i) => (
              <div key={i} style={{display:"flex",alignItems:"center",gap:"10px",padding:"8px 12px",background:"var(--bg5)",border:"1px solid var(--b0)",borderRadius:"7px",marginBottom:"6px",cursor:"pointer"}} onClick={() => navigate("scan")}>
                <div style={{width:"26px",height:"26px",borderRadius:"5px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"11px",background:`${tc(f.l)}20`,border:`1px solid ${tc(f.l)}40`,color:tc(f.l),flexShrink:0}}>
                  {f.l==="malicious"?"⚠":f.l==="suspicious"?"⚡":"✓"}
                </div>
                <div style={{flex:1,overflow:"hidden"}}>
                  <div style={{fontSize:"12px",fontWeight:600,color:"var(--t1)"}}>{f.n}</div>
                  <div style={{fontSize:"9px",color:"var(--t4)",fontFamily:"var(--font-mono)",marginTop:"1px"}}>{f.h}...</div>
                </div>
                <div style={{textAlign:"right"}}>
                  <div style={{fontFamily:"var(--font-mono)",fontSize:"15px",fontWeight:700,color:tc(f.l)}}>{f.s}</div>
                  <div style={{fontSize:"9px",color:"var(--t4)"}}>{[3,7,12,19,28][i]}m ago</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"14px"}}>
          {[["🔬","Static Analysis","Deep file inspection: entropy, PE headers, section analysis, API imports."],["🧠","AI Detection","Random Forest + Gradient Boosting ensemble trained on millions of samples."],["⚡","YARA Rules","542 curated rules for signature-based detection of known malware families."],["📋","PDF Reports","Professional security reports with IOCs, behaviors, and remediation steps."]].map(([ico,title,desc],i) => (
            <div key={i} className="card">
              <div style={{fontSize:"20px",marginBottom:"10px"}}>{ico}</div>
              <div style={{fontSize:"13px",fontWeight:700,color:"var(--t1)",marginBottom:"6px"}}>{title}</div>
              <div style={{fontSize:"11px",color:"var(--t3)",lineHeight:1.6}}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
