'use client';

import { useCallback, useRef, useState } from 'react';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel from '@/components/BehavioralAnalysisPanel';
import ThreatReportPanel from '@/components/ThreatReportPanel';
import SandboxSimulation from '@/components/SandboxSimulation';

const STAGE_DURATIONS = [800, 1500, 2500, 1000, 2000, 800];

export default function Home() {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(6).fill(false));
  const [reportVisible, setReportVisible] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const startAnalysis = useCallback(() => {
    if (analysisRunning) return;
    setAnalysisRunning(true);
    setReportVisible(false);
    setCurrentStage(-1);
    setStageDone(Array(6).fill(false));

    let idx = 0;

    function nextStage() {
      if (idx >= 6) return;

      // Mark previous stage as done
      if (idx > 0) {
        setStageDone(prev => {
          const next = [...prev];
          next[idx - 1] = true;
          return next;
        });
      }

      setCurrentStage(idx);

      if (idx === 5) {
        // Final stage — show report then complete
        setTimeout(() => {
          setStageDone(prev => { const n = [...prev]; n[5] = true; return n; });
          setReportVisible(true);
          setAnalysisRunning(false);
          setCurrentStage(-1);
        }, STAGE_DURATIONS[5]);
        return;
      }

      idx++;
      timerRef.current = setTimeout(nextStage, STAGE_DURATIONS[idx - 1]);
    }

    nextStage();
  }, [analysisRunning]);

  return (
    <>
      <Header />
      <div className="main-grid">
        <FileIntakePanel
          fileInfo={fileInfo}
          onFileLoaded={setFileInfo}
          onAnalyze={startAnalysis}
          analysisRunning={analysisRunning}
        />
        <BehavioralAnalysisPanel
          currentStage={currentStage}
          stageDone={stageDone}
        />
        <ThreatReportPanel visible={reportVisible} />
        <SandboxSimulation />
      </div>
    </>
  );
}
