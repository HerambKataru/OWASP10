import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import Reconnaissance from './pages/Reconnaissance';
import HttpAnalyzer from './pages/HttpAnalyzer';
import SqliScanner from './pages/SqliScanner';
import XssScanner from './pages/XssScanner';
import IdorScanner from './pages/IdorScanner';
import AuthScanner from './pages/AuthScanner';
import UploadScanner from './pages/UploadScanner';
import HeadersScanner from './pages/HeadersScanner';
import ExposureScanner from './pages/ExposureScanner';
import StaticAnalysis from './pages/StaticAnalysis';
import ThreatIntel from './pages/ThreatIntel';
import CveIntelligence from './pages/CveIntelligence';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import { scanService } from './services/api';

function MainAppLayout() {
  const [scans, setScans] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);

  const fetchScans = () => {
    scanService.getScans()
      .then((res) => {
        setScans(res.data);
        if (res.data.length > 0) {
          if (!currentScan) {
            setCurrentScan(res.data[0]);
          } else {
            const updated = res.data.find(s => s.id === currentScan.id);
            if (updated) setCurrentScan(updated);
          }
        }
      })
      .catch(() => console.log('Waiting for backend server at localhost:8000...'));
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 4000);
    return () => clearInterval(interval);
  }, [currentScan?.id]);

  const handleScanCreated = (newScan) => {
    setScans(prev => [newScan, ...prev]);
    setCurrentScan(newScan);
  };

  return (
    <div className="flex min-h-screen bg-[#080C14] text-slate-100 selection:bg-cyan-500 selection:text-black">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header
          currentScan={currentScan}
          scans={scans}
          onSelectScan={(s) => setCurrentScan(s)}
        />

        <main className="flex-1 overflow-y-auto pb-12">
          <Routes>
            <Route path="/" element={<Dashboard currentScan={currentScan} />} />
            <Route path="/new-scan" element={<NewScan onScanCreated={handleScanCreated} />} />
            <Route path="/recon" element={<Reconnaissance currentScan={currentScan} />} />
            <Route path="/http-analyzer" element={<HttpAnalyzer currentScan={currentScan} />} />
            <Route path="/scanners/sqli" element={<SqliScanner currentScan={currentScan} />} />
            <Route path="/scanners/xss" element={<XssScanner currentScan={currentScan} />} />
            <Route path="/scanners/idor" element={<IdorScanner currentScan={currentScan} />} />
            <Route path="/scanners/auth" element={<AuthScanner currentScan={currentScan} />} />
            <Route path="/scanners/upload" element={<UploadScanner currentScan={currentScan} />} />
            <Route path="/scanners/headers" element={<HeadersScanner currentScan={currentScan} />} />
            <Route path="/scanners/exposure" element={<ExposureScanner currentScan={currentScan} />} />
            <Route path="/static-analysis" element={<StaticAnalysis currentScan={currentScan} />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/cve-intelligence" element={<CveIntelligence currentScan={currentScan} />} />
            <Route path="/reports" element={<Reports currentScan={currentScan} scans={scans} />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <MainAppLayout />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}
