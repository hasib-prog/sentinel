/**
 * Sentinel AI Scan Simulator
 * Simulates the complete malware analysis pipeline
 * In production this calls the FastAPI backend
 */

const SUSPICIOUS_APIS = [
  "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
  "WinExec", "ShellExecute", "CreateProcess", "LoadLibrary",
  "GetProcAddress", "NtCreateThread", "ZwCreateProcess",
  "InternetOpenUrl", "InternetConnect", "HttpSendRequest",
  "RegCreateKeyEx", "RegSetValueEx", "DeleteFile",
  "FindFirstFile", "GetTempPath", "CryptEncrypt",
];

const YARA_RULES = [
  { id: "TR_GENERIC_PACKER", name: "Generic Packer Detection", severity: "medium" },
  { id: "MAL_DOWNLOADER_V3", name: "Downloader Malware Family", severity: "high" },
  { id: "SUSP_CRYPTO_ROUTINE", name: "Suspicious Crypto Routine", severity: "medium" },
  { id: "RANSOM_LOCKBIT_2", name: "LockBit 2.0 Indicator", severity: "critical" },
  { id: "TR_AGENT_OBFUSCATED", name: "Obfuscated Agent Trojan", severity: "high" },
  { id: "HEUR_ANTIVM_001", name: "Anti-VM Detection Routine", severity: "medium" },
  { id: "SUSP_STRING_REGISTRY", name: "Registry Persistence Strings", severity: "low" },
  { id: "MAL_EMOTET_C2", name: "Emotet C2 Pattern", severity: "critical" },
];

const MALWARE_FAMILIES = [
  "Trojan.GenericKD", "Ransom.WannaCry", "Trojan.Downloader",
  "Backdoor.RAT", "Worm.Conficker", "Spyware.Keylogger",
  "Adware.GenericFB", "Rootkit.Hidden", "Trojan.Dropper",
  "Ransomware.LockBit"
];

const BEHAVIORS = [
  { id: "PROCESS_INJECTION", label: "Process Injection", severity: "critical", detail: "Attempts to inject code into running processes" },
  { id: "PERSISTENCE", label: "Registry Persistence", severity: "high", detail: "Creates autorun registry keys for persistence" },
  { id: "NETWORK_COMM", label: "Network Communication", severity: "medium", detail: "Initiates outbound connections to external hosts" },
  { id: "FILE_ENCRYPTION", label: "File Encryption", severity: "critical", detail: "Encrypts files matching target extensions" },
  { id: "ANTI_DEBUG", label: "Anti-Debug Techniques", severity: "medium", detail: "Implements debugger detection and evasion" },
  { id: "PRIV_ESCALATION", label: "Privilege Escalation", severity: "high", detail: "Attempts to elevate to SYSTEM privileges" },
  { id: "KEYLOGGING", label: "Keystroke Capture", severity: "high", detail: "Hooks keyboard input for credential theft" },
  { id: "SCREEN_CAPTURE", label: "Screen Capture", severity: "medium", detail: "Captures screenshots at intervals" },
  { id: "SANDBOX_EVASION", label: "Sandbox Evasion", severity: "medium", detail: "Detects virtual environments and analysis tools" },
  { id: "DATA_EXFIL", label: "Data Exfiltration", severity: "critical", detail: "Sends collected data to remote servers" },
];

/**
 * Deterministic hash-based seed from file name
 * Ensures same file always gets same score
 */
function hashSeed(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

/**
 * Seeded pseudo-random number generator
 */
function seededRand(seed) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) & 0xffffffff;
    return (s >>> 0) / 0xffffffff;
  };
}

/**
 * Main scan simulation function
 * Generates a realistic, deterministic analysis report
 */
export function simulateScan(file) {
  const seed = hashSeed(file.name + file.size);
  const rand = seededRand(seed);

  // ─── Feature Extraction (ML inputs) ───
  const entropy = 4.5 + rand() * 3.5; // 4.5 to 8.0
  const fileSize = file.size;
  const suspiciousStringCount = Math.floor(rand() * 25);
  const suspiciousApiCount = Math.floor(rand() * 8);
  const sectionCount = Math.floor(rand() * 6) + 2;
  const importCount = Math.floor(rand() * 100) + 20;
  const yaraMatchCount = Math.floor(rand() * 4);

  // Pick suspicious APIs found
  const foundApis = [];
  for (let i = 0; i < suspiciousApiCount; i++) {
    const api = SUSPICIOUS_APIS[Math.floor(rand() * SUSPICIOUS_APIS.length)];
    if (!foundApis.includes(api)) foundApis.push(api);
  }

  // Pick YARA matches
  const yaraMatches = [];
  const shuffledYara = [...YARA_RULES].sort(() => rand() - 0.5);
  for (let i = 0; i < yaraMatchCount; i++) {
    yaraMatches.push(shuffledYara[i]);
  }

  // ─── AI Classification (simulated Random Forest) ───
  // Weighted feature scoring mimicking ML model
  let mlScore = 0;
  mlScore += (entropy - 4.5) / 3.5 * 30;           // entropy weight: 30%
  mlScore += (suspiciousApiCount / 8) * 25;          // API weight: 25%
  mlScore += (suspiciousStringCount / 25) * 20;      // strings weight: 20%
  mlScore += (yaraMatchCount / 4) * 15;              // YARA weight: 15%
  mlScore += (fileSize > 1024 * 1024 ? 5 : 0);       // size bonus: 5%
  mlScore += rand() * 10;                            // variance: 5-10%

  const threatScore = Math.min(Math.round(mlScore), 100);

  // ─── Threat Classification ───
  let threatLevel, threatLabel, verdict;
  if (threatScore <= 20) {
    threatLevel = "safe"; threatLabel = "Clean"; verdict = "No threats detected";
  } else if (threatScore <= 50) {
    threatLevel = "low"; threatLabel = "Low Risk"; verdict = "Potentially unwanted";
  } else if (threatScore <= 80) {
    threatLevel = "suspicious"; threatLabel = "Suspicious"; verdict = "Suspicious patterns detected";
  } else {
    threatLevel = "malicious"; threatLabel = "Malicious"; verdict = "Malware detected";
  }

  // ─── Detected Behaviors ───
  const detectedBehaviors = [];
  if (threatScore > 20) {
    const numBehaviors = Math.floor(threatScore / 20);
    const shuffled = [...BEHAVIORS].sort(() => rand() - 0.5);
    for (let i = 0; i < numBehaviors && i < shuffled.length; i++) {
      detectedBehaviors.push(shuffled[i]);
    }
  }

  // ─── Malware Family (only if malicious/suspicious) ───
  const malwareFamily = threatScore > 50
    ? MALWARE_FAMILIES[Math.floor(rand() * MALWARE_FAMILIES.length)]
    : null;

  // ─── Hashes ───
  const sha256 = generateHash(file.name + file.size + "sha256", 64);
  const md5 = generateHash(file.name + file.size + "md5", 32);
  const sha1 = generateHash(file.name + file.size + "sha1", 40);

  // ─── PE Sections (for executables) ───
  const sections = generatePeSections(rand, sectionCount);

  // ─── Network Indicators ───
  const networkIndicators = threatScore > 50 ? generateNetworkIndicators(rand) : [];

  // ─── AV Engine Results (simulated multi-engine) ───
  const avResults = generateAvResults(rand, threatScore);

  // ─── Suspicious Strings ───
  const suspiciousStrings = generateSuspiciousStrings(rand, suspiciousStringCount);

  return {
    threatScore,
    threatLevel,
    threatLabel,
    verdict,
    malwareFamily,
    confidence: Math.round(60 + rand() * 35),
    fileInfo: {
      name: file.name,
      size: file.size,
      type: file.type || detectFileType(file.name),
      extension: file.name.split(".").pop().toLowerCase(),
      sha256,
      md5,
      sha1,
    },
    staticAnalysis: {
      entropy: parseFloat(entropy.toFixed(4)),
      entropyRating: entropy > 7.0 ? "High (possible packing/encryption)" : entropy > 5.5 ? "Medium" : "Normal",
      sections,
      importCount,
      sectionCount,
      suspiciousStringCount,
      suspiciousStrings,
      foundApis,
      isPacked: entropy > 7.0,
      hasOverlay: rand() > 0.7,
      fileType: detectFileType(file.name),
    },
    yaraMatches,
    behaviors: detectedBehaviors,
    networkIndicators,
    avResults,
    aiClassification: {
      model: "Random Forest + Gradient Boosting Ensemble",
      version: "3.1.0",
      malwareProbability: parseFloat((threatScore / 100).toFixed(4)),
      threatLevel,
      riskScore: threatScore,
      features: {
        entropy: parseFloat(entropy.toFixed(4)),
        suspicious_strings: suspiciousStringCount,
        suspicious_apis: suspiciousApiCount,
        yara_matches: yaraMatchCount,
        file_size_kb: parseFloat((file.size / 1024).toFixed(2)),
        section_count: sectionCount,
        import_count: importCount,
      },
      topFeatureImportances: [
        { feature: "entropy", importance: 0.28 },
        { feature: "suspicious_apis", importance: 0.22 },
        { feature: "yara_matches", importance: 0.18 },
        { feature: "suspicious_strings", importance: 0.16 },
        { feature: "section_count", importance: 0.10 },
        { feature: "import_count", importance: 0.06 },
      ],
    },
    scanMetadata: {
      scanId: `SCAN-${Date.now().toString(36).toUpperCase()}`,
      engine: "Sentinel v3.1.0",
      timestamp: new Date().toISOString(),
      scanDuration: parseFloat((2 + rand() * 3).toFixed(2)),
      yaraRulesChecked: 542,
      avEnginesTotal: avResults.length,
      avEnginesDetected: avResults.filter(r => r.detected).length,
    },
  };
}

function generateHash(seed, len) {
  const chars = "0123456789abcdef";
  let h = "";
  for (let i = 0; i < len; i++) {
    h += chars[(seed.charCodeAt(i % seed.length) * (i + 1) * 31 + 17) % 16];
  }
  return h;
}

function generatePeSections(rand, count) {
  const names = [".text", ".data", ".rsrc", ".rdata", ".bss", ".reloc", ".idata", ".edata"];
  return names.slice(0, count).map(name => ({
    name,
    virtualSize: Math.floor(rand() * 0x10000 + 0x1000),
    rawSize: Math.floor(rand() * 0x10000 + 0x1000),
    entropy: parseFloat((rand() * 4 + 4).toFixed(2)),
    characteristics: name === ".text" ? "CODE, EXECUTE, READ" : "INITIALIZED_DATA, READ, WRITE",
  }));
}

function generateNetworkIndicators(rand) {
  const ips = ["185.220.101.47", "94.102.61.10", "45.142.212.100", "104.21.14.22", "198.199.80.45"];
  const domains = ["update-service.co", "cdn-static-js.com", "telemetry-api.net"];
  const result = [];
  if (rand() > 0.5) result.push({ type: "IP", value: ips[Math.floor(rand() * ips.length)], threat: "C2 Server" });
  if (rand() > 0.6) result.push({ type: "Domain", value: domains[Math.floor(rand() * domains.length)], threat: "C2 Communication" });
  return result;
}

function generateAvResults(rand, threatScore) {
  const engines = [
    "Sentinel AV", "MalwareBytes", "Kaspersky", "ESET NOD32",
    "Bitdefender", "Avast", "McAfee", "Windows Defender",
    "Sophos", "F-Secure", "Trend Micro", "Norton"
  ];
  return engines.map(engine => {
    const detected = rand() < (threatScore / 100) * 0.8;
    return {
      engine,
      detected,
      result: detected ? `Trojan.GenericKD.${Math.floor(rand() * 90000 + 10000)}` : "Clean",
    };
  });
}

function generateSuspiciousStrings(rand, count) {
  const pool = [
    "cmd.exe /c", "powershell -enc", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "http://", "ftp://", ".onion", "base64", "eval(", "exec(",
    "GetWindowsDirectory", "GetSystemDirectory", "IsDebuggerPresent",
    "WScript.Shell", "CONOUT$", "\\\\127.0.0.1\\",
  ];
  const result = [];
  for (let i = 0; i < count; i++) {
    const str = pool[Math.floor(rand() * pool.length)];
    if (!result.find(s => s.value === str)) {
      result.push({
        value: str,
        offset: `0x${Math.floor(rand() * 0xFFFF).toString(16).padStart(4, "0")}`,
        type: "ASCII",
      });
    }
  }
  return result;
}

function detectFileType(filename) {
  const ext = filename.split(".").pop().toLowerCase();
  const types = {
    exe: "PE32 Executable", dll: "PE32 Dynamic Link Library",
    pdf: "PDF Document", zip: "ZIP Archive",
    doc: "Microsoft Word", docx: "Microsoft Word (OOXML)",
    xls: "Microsoft Excel", xlsx: "Microsoft Excel (OOXML)",
    js: "JavaScript", py: "Python Script",
    sh: "Shell Script", bat: "Batch Script",
    apk: "Android Package", jar: "Java Archive",
    msi: "Windows Installer", iso: "Disk Image",
  };
  return types[ext] || "Unknown Binary";
}
