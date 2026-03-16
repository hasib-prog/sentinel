import { useState, useEffect } from "react";

export default function Navbar({ currentPage, navigate }) {
  const [time, setTime] = useState(new Date());
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    const s = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", s);
    return () => { clearInterval(t); window.removeEventListener("scroll", s); };
  }, []);

  const fmt = d => d.toLocaleTimeString("en-US", { hour12: false });

  return (
    <nav style={{
      position:"fixed",top:0,left:0,right:0,zIndex:1000,height:"64px",
      background: scrolled ? "rgba(3,5,8,.96)" : "rgba(3,5,8,.85)",
      backdropFilter:"blur(20px)",borderBottom:"1px solid rgba(20,140,255,.08)",
      transition:"all .3s"
    }}>
      <div style={{maxWidth:"1280px",margin:"0 auto",padding:"0 24px",height:"100%",display:"flex",alignItems:"center",gap:"32px"}}>
        <div onClick={() => navigate("home")} style={{display:"flex",alignItems:"center",gap:"12px",cursor:"pointer",flexShrink:0}}>
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
            <polygon points="14,2 26,8 26,20 14,26 2,20 2,8" stroke="#148cff" strokeWidth="1.5" fill="rgba(20,140,255,.08)"/>
            <polygon points="14,6 22,11 22,18 14,22 6,18 6,11" stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,.06)"/>
            <circle cx="14" cy="14" r="3" fill="#148cff"/>
          </svg>
          <div>
            <div style={{fontSize:"18px",fontWeight:800,letterSpacing:".18em",background:"linear-gradient(90deg,#fff,#00d4ff)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>SENTINEL</div>
            <div style={{fontSize:"9px",color:"var(--t3)",letterSpacing:".12em",textTransform:"uppercase"}}>AI Threat Platform</div>
          </div>
        </div>
        <div style={{display:"flex",gap:"4px",flex:1}}>
          {[["home","Home"],["scan","New Scan"],["history","History"]].map(([id,label]) => (
            <button key={id} onClick={() => navigate(id)} style={{
              background: id==="scan" ? "rgba(20,140,255,.12)" : "none",
              border: id==="scan" ? "1px solid rgba(20,140,255,.3)" : "none",
              color: currentPage===id ? "var(--cyan)" : id==="scan" ? "var(--blue)" : "var(--t3)",
              fontFamily:"var(--font-display)",fontSize:"13px",fontWeight:600,
              padding:"6px 14px",borderRadius:"6px",cursor:"pointer",
              letterSpacing:".06em",textTransform:"uppercase",transition:"all .2s"
            }}>{label}</button>
          ))}
        </div>
        <div style={{display:"flex",alignItems:"center",gap:"12px",flexShrink:0}}>
          <div style={{width:"7px",height:"7px",borderRadius:"50%",background:"var(--safe)",boxShadow:"0 0 8px var(--safe)",animation:"pulse-blue 2s infinite"}}/>
          <span style={{fontFamily:"var(--font-mono)",fontSize:"10px",color:"var(--safe)",letterSpacing:".1em"}}>ONLINE</span>
          <span style={{fontFamily:"var(--font-terminal)",fontSize:"13px",color:"var(--t2)"}}>{fmt(time)}</span>
        </div>
      </div>
      <div style={{position:"absolute",bottom:0,left:0,right:0,height:"1px",background:"linear-gradient(90deg,transparent,rgba(20,140,255,.4),transparent)"}}/>
    </nav>
  );
}
