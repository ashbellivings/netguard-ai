import React from 'react';
import {
  LayoutDashboard,
  FileSpreadsheet,
  Cpu,
  BarChart3,
  Bot,
  Scale,
  Bell,
  SearchCode,
  Globe2,
  FileText,
  Network,
  Code2,
  BookOpen,
  Download,
  X,
} from 'lucide-react';
import { downloadPythonProjectZip } from '../utils/pythonProjectExport';

export type NavTab =
  | 'overview'
  | 'data_management'
  | 'preprocessing'
  | 'eda'
  | 'detection'
  | 'evaluation'
  | 'alerts'
  | 'incidents'
  | 'threat_intel'
  | 'reports'
  | 'integrations'
  | 'python_export';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  alertCount: number;
  criticalAlertCount: number;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenGuide: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  alertCount,
  criticalAlertCount,
  isMobileOpen,
  onCloseMobile,
  onOpenGuide,
}) => {
  const navItems = [
    { id: 'overview' as NavTab, label: 'Security Overview', icon: LayoutDashboard },
    { id: 'data_management' as NavTab, label: 'Traffic Data Management', icon: FileSpreadsheet },
    { id: 'preprocessing' as NavTab, label: 'Data Preprocessing', icon: Cpu },
    { id: 'eda' as NavTab, label: 'Exploratory Analysis', icon: BarChart3 },
    { id: 'detection' as NavTab, label: 'AI Intrusion Detection', icon: Bot },
    { id: 'evaluation' as NavTab, label: 'Model Evaluation', icon: Scale },
    {
      id: 'alerts' as NavTab,
      label: 'Security Alerts',
      icon: Bell,
      badge: alertCount > 0 ? alertCount : undefined,
      badgeColor: criticalAlertCount > 0 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-slate-800 text-slate-300'
    },
    { id: 'incidents' as NavTab, label: 'Incident Workspace', icon: SearchCode },
    { id: 'threat_intel' as NavTab, label: 'Threat Intelligence', icon: Globe2 },
    { id: 'reports' as NavTab, label: 'Security Reports', icon: FileText },
    { id: 'integrations' as NavTab, label: 'Packet & Log Tools', icon: Network },
    { id: 'python_export' as NavTab, label: 'Python Project & Code', icon: Code2 },
  ];

  const handleSelect = (tab: NavTab) => {
    onSelectTab(tab);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-950/75 backdrop-blur-xs md:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed md:static inset-y-0 left-0 z-50 w-64 bg-slate-950 border-r border-slate-850 flex flex-col shrink-0 md:min-h-[calc(100vh-53px)] select-none transform transition-transform duration-200 ease-out ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div className="p-4 border-b border-slate-900/80 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold tracking-wider text-slate-500 uppercase mb-1">
              SOC Navigation
            </div>
            <div className="text-xs text-slate-400">
              Junior Security Analyst Console
            </div>
          </div>
          <button
            type="button"
            onClick={onCloseMobile}
            className="md:hidden p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-900"
            aria-label="Close navigation drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 p-2.5 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleSelect(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors text-left cursor-pointer ${
                  isActive
                    ? 'bg-slate-800/90 text-cyan-400 shadow-sm border border-cyan-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}

          {/* Mobile / Tablet Quick Utilities (visible when Header nav links collapse on < lg) */}
          <div className="lg:hidden pt-3 mt-3 border-t border-slate-900/80 space-y-1">
            <button
              type="button"
              onClick={() => {
                onCloseMobile();
                onOpenGuide();
              }}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium text-slate-400 hover:text-cyan-400 hover:bg-slate-900/60 transition-colors text-left cursor-pointer"
            >
              <BookOpen className="w-4 h-4 shrink-0 text-slate-500" />
              <span>SOC Workflow Guide</span>
            </button>
            <button
              type="button"
              onClick={() => {
                onCloseMobile();
                downloadPythonProjectZip();
              }}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium text-slate-400 hover:text-cyan-400 hover:bg-slate-900/60 transition-colors text-left cursor-pointer"
            >
              <Download className="w-4 h-4 shrink-0 text-slate-500" />
              <span>Download Python Project (.zip)</span>
            </button>
          </div>
        </nav>

        <div className="p-3.5 border-t border-slate-900/80 text-[11px] text-slate-500 font-mono">
          <div className="text-slate-400 font-medium">B.Sc. CS Capstone 2026</div>
          <div>Engine: Browser ML + Rules</div>
        </div>
      </aside>
    </>
  );
};
