import React, { useState } from 'react';
import { Shield, Download, BookOpen, Database, RefreshCw, CheckCircle2, Menu, X } from 'lucide-react';
import { downloadPythonProjectZip } from '../utils/pythonProjectExport';

interface HeaderProps {
  onLoadDemo: () => void | Promise<void>;
  onOpenGuide: () => void;
  datasetName: string;
  totalFlows: number;
  isSyntheticData: boolean;
  isMobileMenuOpen: boolean;
  onToggleMobileMenu: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onLoadDemo,
  onOpenGuide,
  datasetName,
  totalFlows,
  isSyntheticData,
  isMobileMenuOpen,
  onToggleMobileMenu,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [justLoaded, setJustLoaded] = useState(false);

  const handleLoadClick = async () => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      await Promise.resolve(onLoadDemo());
      setJustLoaded(true);
      setTimeout(() => setJustLoaded(false), 2500);
    } catch (err) {
      console.error('Error loading demo dataset:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <header className="flex items-center justify-between gap-3 sm:gap-6 px-4 sm:px-6 py-3.5 bg-slate-950 border-b border-slate-800/80 sticky top-0 z-40">
      {/* Zone 1: Mobile Menu Toggle + Brand Wordmark */}
      <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
        <button
          type="button"
          onClick={onToggleMobileMenu}
          className="md:hidden p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 transition-colors cursor-pointer"
          aria-label={isMobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
          aria-expanded={isMobileMenuOpen}
        >
          {isMobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
        </button>

        <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <Shield className="w-4 h-4" />
        </div>
        <span className="text-base font-bold tracking-tight text-slate-100 font-sans">
          NETGUARD AI
        </span>
      </div>

      {/* Zone 2: Navigation Links (Desktop) */}
      <nav className="hidden lg:flex items-center gap-6 text-xs font-medium text-slate-400 min-w-0">
        <button
          onClick={onOpenGuide}
          className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <BookOpen className="w-3.5 h-3.5" />
          <span>SOC Workflow Guide</span>
        </button>

        <button
          onClick={() => downloadPythonProjectZip()}
          className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Download Python Streamlit Project (.zip)</span>
        </button>

        <div className="flex items-center gap-2 text-slate-500 whitespace-nowrap min-w-0">
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border ${
              isSyntheticData
                ? 'bg-amber-950/60 text-amber-300 border-amber-500/30'
                : 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
            }`}
          >
            {isSyntheticData ? 'SYNTHETIC' : 'UPLOADED CSV'}
          </span>
          <span className="text-slate-300 font-mono truncate max-w-[200px]" title={datasetName}>
            {datasetName}
          </span>
          <span className="text-slate-600">·</span>
          <span>Flows: </span>
          <span className="text-cyan-400 font-mono tabular-nums">{totalFlows.toLocaleString()}</span>
        </div>
      </nav>

      {/* Zone 3: 1 Primary Action */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        <button
          onClick={handleLoadClick}
          disabled={isLoading}
          aria-label="Load Demo Dataset"
          className={`px-3 sm:px-3.5 py-1.5 text-xs font-semibold rounded transition-all duration-200 whitespace-nowrap shrink-0 flex items-center gap-1.5 shadow-sm active:scale-95 cursor-pointer disabled:opacity-80 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 ${
            justLoaded
              ? 'bg-emerald-400 hover:bg-emerald-300 text-slate-950 shadow-emerald-950/50'
              : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-cyan-950/50'
          }`}
        >
          {isLoading ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-950" />
          ) : justLoaded ? (
            <CheckCircle2 className="w-3.5 h-3.5 text-slate-950" />
          ) : (
            <Database className="w-3.5 h-3.5" />
          )}
          <span className="font-semibold tracking-wide hidden sm:inline">
            {isLoading
              ? 'Loading Dataset...'
              : justLoaded
              ? 'Demo Dataset Loaded!'
              : 'Load Demo Dataset'}
          </span>
          <span className="font-semibold tracking-wide sm:hidden">
            {isLoading ? 'Loading...' : justLoaded ? 'Loaded!' : 'Demo Data'}
          </span>
        </button>
      </div>
    </header>
  );
};
