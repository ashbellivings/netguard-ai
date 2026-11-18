import React, { useState } from 'react';
import { Network, Terminal, FileCode, CheckCircle2, Copy, Check } from 'lucide-react';

export const ToolsIntegrationView: React.FC = () => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const tsharkCmd = `tshark -r capture.pcap -T fields -E header=y -E separator=, \\
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \\
  -e ip.proto -e frame.len > netguard_export.csv`;

  const zeekCmd = `cat conn.log | zeek-cut ts id.orig_h id.resp_h id.orig_p id.resp_p proto duration orig_pkts orig_bytes > netguard_conn.tsv`;

  const suricataPythonScript = `import json
import csv

# Converts Suricata eve.json alerts to NETGUARD AI schema
with open("eve.json", "r") as f_in, open("suricata_netguard.csv", "w", newline="") as f_out:
    writer = csv.writer(f_out)
    writer.writerow(["Timestamp", "Source_IP", "Destination_IP", "Source_Port", "Destination_Port", "Protocol", "Flow_Duration", "Packet_Count", "Byte_Count", "Flow_Rate", "Label", "Attack_Category"])
    
    for line in f_in:
        try:
            ev = json.loads(line)
            if ev.get("event_type") == "alert":
                writer.writerow([
                    ev.get("timestamp", ""),
                    ev.get("src_ip", ""),
                    ev.get("dest_ip", ""),
                    ev.get("src_port", 0),
                    ev.get("dest_port", 0),
                    ev.get("proto", "TCP"),
                    ev.get("flow", {}).get("age", 0.1),
                    ev.get("flow", {}).get("pkts_toserver", 1),
                    ev.get("flow", {}).get("bytes_toserver", 60),
                    1000.0,
                    "SUSPICIOUS",
                    ev.get("alert", {}).get("category", "Unknown Anomaly")
                ])
        except Exception:
            continue`;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-850">
        <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
          <span>Packet Capture & Security Tool Integrations</span>
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Ingestion pipelines for Wireshark PCAPs, Zeek (Bro) connection telemetry, and Suricata IDS alerts.
        </p>
      </div>

      {/* Architecture Disclaimer */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300 space-y-1">
        <div className="font-semibold text-cyan-400 flex items-center gap-1.5">
          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          <span>Operational Integration Model</span>
        </div>
        <p className="text-slate-400 leading-relaxed">
          NETGUARD AI is intentionally designed as an offline and edge SOC analytical engine. Rather than requiring privileged root kernel packet sockets, the system ingests standardized network flow metadata exported from enterprise packet probes (Wireshark, Zeek, Suricata). This architecture preserves security boundary isolation and supports reproducible academic evaluation.
        </p>
      </div>

      {/* Tool 1: Wireshark / TShark */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-blue-950 border border-blue-800 flex items-center justify-center text-blue-400">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">1. Wireshark & Tshark PCAP Export</h3>
              <p className="text-xs text-slate-400">Converting raw full-packet PCAPs into flow-level CSV records</p>
            </div>
          </div>
          <button
            onClick={() => handleCopy('tshark', tsharkCmd)}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1 font-mono transition-colors"
          >
            {copiedKey === 'tshark' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Command</span>
          </button>
        </div>

        <div className="p-3 bg-slate-950 border border-slate-850 rounded font-mono text-xs text-cyan-300 overflow-x-auto">
          <code>{tsharkCmd}</code>
        </div>

        <div className="text-xs text-slate-400 space-y-1">
          <strong className="text-slate-300">GUI Export Steps:</strong>
          <ol className="list-decimal list-inside space-y-0.5 text-slate-400 pl-1">
            <li>Open Wireshark and load your target `.pcap` or `.pcapng` capture file.</li>
            <li>Navigate to <code>File &gt; Export Packet Dissections &gt; As CSV...</code></li>
            <li>Save as <code>traffic_capture.csv</code> and upload directly via NETGUARD AI's Data Management tab.</li>
          </ol>
        </div>
      </div>

      {/* Tool 2: Zeek (Bro) */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-amber-950 border border-amber-800 flex items-center justify-center text-amber-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">2. Zeek (Bro) conn.log Ingestion</h3>
              <p className="text-xs text-slate-400">Extracting 5-tuples and connection metrics from Zeek logs</p>
            </div>
          </div>
          <button
            onClick={() => handleCopy('zeek', zeekCmd)}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1 font-mono transition-colors"
          >
            {copiedKey === 'zeek' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Command</span>
          </button>
        </div>

        <div className="p-3 bg-slate-950 border border-slate-850 rounded font-mono text-xs text-cyan-300 overflow-x-auto">
          <code>{zeekCmd}</code>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          NETGUARD AI automatically recognizes Zeek column aliases (e.g. <code>id.orig_h</code> for Source IP, <code>id.resp_h</code> for Destination IP, <code>id.resp_p</code> for Destination Port, and <code>duration</code>).
        </p>
      </div>

      {/* Tool 3: Suricata IDS */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-red-950 border border-red-800 flex items-center justify-center text-red-400">
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">3. Suricata eve.json Alert Converter</h3>
              <p className="text-xs text-slate-400">Python ETL script to parse Suricata JSON alerts into NETGUARD format</p>
            </div>
          </div>
          <button
            onClick={() => handleCopy('suricata', suricataPythonScript)}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1 font-mono transition-colors"
          >
            {copiedKey === 'suricata' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Python Script</span>
          </button>
        </div>

        <div className="p-3 bg-slate-950 border border-slate-850 rounded font-mono text-xs text-slate-300 max-h-48 overflow-y-auto">
          <pre>{suricataPythonScript}</pre>
        </div>
      </div>
    </div>
  );
};
