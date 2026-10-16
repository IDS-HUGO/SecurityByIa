import React, { useState, useEffect, useCallback, useRef } from 'react';
import api from './api/client';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import ScanCard from './components/ScanCard';
import ProgressPanel from './components/ProgressPanel';
import OverviewTab from './components/OverviewTab';
import FindingsTab from './components/FindingsTab';
import BenchmarkTab from './components/BenchmarkTab';
import ReportTab from './components/ReportTab';
import ProxyTab from './components/ProxyTab';

export default function App() {
  const [activeTab, setActiveTab] = useState(() => {
    const hash = window.location.hash.replace('#', '');
    return ['overview', 'findings', 'benchmark', 'report', 'proxy'].includes(hash) ? hash : 'overview';
  });

  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  // Benchmark state
  const [benchmarkStatus, setBenchmarkStatus] = useState(null);
  const [isBenchRunning, setIsBenchRunning] = useState(false);
  const [isBenchLoading, setIsBenchLoading] = useState(false);
  const [benchError, setBenchError] = useState(null);

  const scanPollRef = useRef(null);
  const benchPollRef = useRef(null);

  // Sync activeTab with window.location.hash
  const handleTabChange = useCallback((tab) => {
    setActiveTab(tab);
    window.location.hash = tab;
  }, []);

  // Fetch recent analyses
  const loadRecentAnalyses = useCallback(async () => {
    try {
      const data = await api.listAnalyses();
      setRecentAnalyses(data || []);
    } catch (err) {
      console.warn('Error loading recent analyses:', err);
    }
  }, []);

  // Fetch benchmark status
  const loadBenchmarkStatus = useCallback(async () => {
    setIsBenchLoading(true);
    setBenchError(null);
    try {
      const data = await api.getBenchmarkStatus();
      setBenchmarkStatus(data);
      setIsBenchRunning(Boolean(data && data.is_running));
    } catch (err) {
      console.warn('Error loading benchmark status:', err);
      setBenchError(err.message || 'Error al cargar el estado del benchmark');
    } finally {
      setIsBenchLoading(false);
    }
  }, []);

  // Start a new scan
  const handleStartScan = async (repoUrl, enableAiTriage = false) => {
    setIsScanning(true);
    try {
      const queued = await api.startAnalysis(repoUrl, enableAiTriage);
      const analysisId = queued.analysis_id;
      setCurrentAnalysis({
        ...queued,
        repository: { url: repoUrl },
      });

      // Poll analysis status
      if (scanPollRef.current) clearInterval(scanPollRef.current);
      scanPollRef.current = setInterval(async () => {
        try {
          const detail = await api.getAnalysis(analysisId);
          setCurrentAnalysis(detail);
          if (detail.status === 'completed' || detail.status === 'error' || detail.status === 'failed') {
            clearInterval(scanPollRef.current);
            setIsScanning(false);
            loadRecentAnalyses();
            if (detail.status === 'completed') {
              handleTabChange('findings');
            }
          }
        } catch (pollErr) {
          console.error('Polling error:', pollErr);
          clearInterval(scanPollRef.current);
          setIsScanning(false);
        }
      }, 1500);
    } catch (err) {
      setIsScanning(false);
      setCurrentAnalysis({
        status: 'error',
        stage: 'error',
        message: 'No fue posible iniciar el análisis',
        error: err.message || 'Error de red o servidor no disponible.',
      });
    }
  };

  // Human Triage Decision Handler
  const handleTriageDecision = async (findingId, { decision, reason, author }) => {
    if (!currentAnalysis?.analysis_id) return null;
    const result = await api.triageFinding(currentAnalysis.analysis_id, findingId, { decision, reason, author });
    if (result?.finding) {
      setCurrentAnalysis((prev) => {
        if (!prev) return prev;
        const updatedFindings = (prev.findings || []).map((f) =>
          f.id === findingId ? result.finding : f
        );
        return { ...prev, findings: updatedFindings };
      });
    }
    return result;
  };

  // Remediation Fixer & Review Handlers (F6)
  const handleProposeFix = async (findingId) => {
    if (!currentAnalysis?.analysis_id) return null;
    const result = await api.proposeFix(currentAnalysis.analysis_id, findingId);
    if (result?.finding) {
      setCurrentAnalysis((prev) => {
        if (!prev) return prev;
        const updatedFindings = (prev.findings || []).map((f) =>
          f.id === findingId ? result.finding : f
        );
        return { ...prev, findings: updatedFindings };
      });
    }
    return result;
  };

  const handleReviewRemediation = async (findingId, { decision, reason, author }) => {
    if (!currentAnalysis?.analysis_id) return null;
    const result = await api.reviewRemediation(currentAnalysis.analysis_id, findingId, { decision, reason, author });
    if (result?.finding) {
      setCurrentAnalysis((prev) => {
        if (!prev) return prev;
        const updatedFindings = (prev.findings || []).map((f) =>
          f.id === findingId ? result.finding : f
        );
        return { ...prev, findings: updatedFindings };
      });
    }
    return result;
  };

  // Load a specific analysis from history
  const handleLoadAnalysis = async (analysisId) => {
    try {
      const detail = await api.getAnalysis(analysisId);
      setCurrentAnalysis(detail);
      handleTabChange('findings');
    } catch (err) {
      console.error('Error loading analysis:', err);
    }
  };

  // Trigger a benchmark run
  const handleRunBenchmark = async ({ feature, saveAsBaseline }) => {
    setIsBenchRunning(true);
    setBenchError(null);
    try {
      await api.runBenchmark({ feature, saveAsBaseline });

      // Poll benchmark status
      if (benchPollRef.current) clearInterval(benchPollRef.current);
      benchPollRef.current = setInterval(async () => {
        try {
          const data = await api.getBenchmarkStatus();
          setBenchmarkStatus(data);
          if (!data.is_running) {
            clearInterval(benchPollRef.current);
            setIsBenchRunning(false);
          }
        } catch (pollErr) {
          console.error('Benchmark poll error:', pollErr);
          clearInterval(benchPollRef.current);
          setIsBenchRunning(false);
        }
      }, 2000);
    } catch (err) {
      setIsBenchRunning(false);
      setBenchError(err.message || 'Error al iniciar la corrida de benchmark');
    }
  };

  // Global refresh button
  const handleRefresh = useCallback(() => {
    loadRecentAnalyses();
    loadBenchmarkStatus();
    if (currentAnalysis && currentAnalysis.analysis_id) {
      api.getAnalysis(currentAnalysis.analysis_id).then(setCurrentAnalysis).catch(() => {});
    }
  }, [loadRecentAnalyses, loadBenchmarkStatus, currentAnalysis]);

  // Initial load
  useEffect(() => {
    loadRecentAnalyses();
    loadBenchmarkStatus();
    return () => {
      if (scanPollRef.current) clearInterval(scanPollRef.current);
      if (benchPollRef.current) clearInterval(benchPollRef.current);
    };
  }, [loadRecentAnalyses, loadBenchmarkStatus]);

  const findings = currentAnalysis?.findings || [];

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar
        activeTab={activeTab}
        onTabChange={handleTabChange}
        findingsCount={findings.length}
      />

      <main className="main" style={{ flex: 1, padding: '1.5rem 2rem', maxWidth: '1400px', margin: '0 auto' }}>
        <Topbar
          activeTab={activeTab}
          onRefresh={handleRefresh}
        />

        {/* Global Scan Card (available on overview and findings tabs) */}
        {(activeTab === 'overview' || activeTab === 'findings') && (
          <>
            <ScanCard
              onStartScan={handleStartScan}
              isScanning={isScanning}
            />

            <ProgressPanel
              analysis={currentAnalysis}
            />
          </>
        )}

        {/* Tab content */}
        {activeTab === 'overview' && (
          <OverviewTab
            currentAnalysis={currentAnalysis}
            recentAnalyses={recentAnalyses}
            onLoadAnalysis={handleLoadAnalysis}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsTab
            findings={findings}
            analysisId={currentAnalysis?.analysis_id}
            onTriageDecision={handleTriageDecision}
            onProposeFix={handleProposeFix}
            onReviewRemediation={handleReviewRemediation}
          />
        )}

        {activeTab === 'benchmark' && (
          <BenchmarkTab
            benchmarkStatus={benchmarkStatus}
            onRunBenchmark={handleRunBenchmark}
            isRunning={isBenchRunning}
            isLoading={isBenchLoading}
            error={benchError}
          />
        )}

        {activeTab === 'report' && (
          <ReportTab
            currentAnalysis={currentAnalysis}
          />
        )}

        {activeTab === 'proxy' && (
          <ProxyTab />
        )}
      </main>
    </div>
  );
}
