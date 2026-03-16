import { useState } from "react";
import HomePage from "./pages/HomePage";
import ScanPage from "./pages/ScanPage";
import ReportPage from "./pages/ReportPage";
import HistoryPage from "./pages/HistoryPage";
import Navbar from "./components/Navbar";

export default function App() {
  const [currentPage, setCurrentPage] = useState("home");
  const [scanData, setScanData] = useState(null);

  const navigate = (page, data = null) => {
    setCurrentPage(page);
    if (data) setScanData(data);
  };

  const handleScanComplete = (id, data) => {
    setScanData(data);
    setCurrentPage("report");
  };

  return (
    <div className="app-shell">
      <Navbar currentPage={currentPage} navigate={navigate} />
      <main className="main-content">
        {currentPage === "home" && <HomePage navigate={navigate} />}
        {currentPage === "scan" && <ScanPage onScanComplete={handleScanComplete} navigate={navigate} />}
        {currentPage === "report" && <ReportPage scanData={scanData} navigate={navigate} />}
        {currentPage === "history" && <HistoryPage navigate={navigate} onSelectScan={(id, data) => handleScanComplete(id, data)} />}
      </main>
    </div>
  );
}
