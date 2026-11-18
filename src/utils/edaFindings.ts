import { FlowRecord, EDAFinding } from '../types';

/**
 * Computes Pearson correlation coefficient between two numeric arrays
 */
export function computePearsonCorrelation(x: number[], y: number[]): number {
  const n = x.length;
  if (n === 0 || y.length === 0) return 0;
  const meanX = x.reduce((a, b) => a + b, 0) / n;
  const meanY = y.reduce((a, b) => a + b, 0) / n;

  let numerator = 0;
  let denomX = 0;
  let denomY = 0;

  for (let i = 0; i < n; i++) {
    const dx = x[i] - meanX;
    const dy = y[i] - meanY;
    numerator += dx * dy;
    denomX += dx * dx;
    denomY += dy * dy;
  }

  const denom = Math.sqrt(denomX * denomY);
  if (denom === 0) return 0;
  return parseFloat((numerator / denom).toFixed(3));
}

/**
 * Extracts at least 10 real automated security data findings from loaded traffic records
 */
export function generateEDAFindings(records: FlowRecord[]): EDAFinding[] {
  if (records.length === 0) return [];

  const findings: EDAFinding[] = [];
  const total = records.length;

  // 1. Most frequent protocol
  const protoCounts: Record<string, number> = {};
  records.forEach(r => {
    protoCounts[r.protocol] = (protoCounts[r.protocol] || 0) + 1;
  });
  const sortedProtos = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);
  const dominantProto = sortedProtos[0];
  const dominantProtoPct = Math.round((dominantProto[1] / total) * 100);

  findings.push({
    id: 'FIND-01',
    category: 'Protocol Distribution',
    title: 'Dominant Transport Protocol',
    metric: `${dominantProto[0]} (${dominantProtoPct}%)`,
    description: `${dominantProto[0]} represents the vast majority of network activity with ${dominantProto[1].toLocaleString()} flows (${dominantProtoPct}% of total monitored traffic).`,
    severity: dominantProto[0] === 'ICMP' ? 'warning' : 'info',
  });

  // 2. Proportion of records classified as suspicious
  const susCount = records.filter(r => r.label === 'SUSPICIOUS').length;
  const susPct = parseFloat(((susCount / total) * 100).toFixed(1));
  const normalCount = total - susCount;

  findings.push({
    id: 'FIND-02',
    category: 'Threat Composition',
    title: 'Suspicious Traffic Proportion',
    metric: `${susPct}% (${susCount} flows)`,
    description: `${susCount} out of ${total} records are classified as suspicious or malicious. ${normalCount} flows are baseline benign traffic.`,
    severity: susPct > 25 ? 'critical' : susPct > 10 ? 'warning' : 'info',
  });

  // 3. Most frequent attack category
  const catCounts: Record<string, number> = {};
  records.filter(r => r.label === 'SUSPICIOUS').forEach(r => {
    const cat = r.attackCategory || 'Unknown Anomaly';
    catCounts[cat] = (catCounts[cat] || 0) + 1;
  });
  const sortedCats = Object.entries(catCounts).sort((a, b) => b[1] - a[1]);
  const dominantCat: [string, number] = sortedCats.length > 0 ? [sortedCats[0][0], sortedCats[0][1]] : ['None detected', 0];

  findings.push({
    id: 'FIND-03',
    category: 'Threat Taxonomy',
    title: 'Leading Threat Vector',
    metric: `${dominantCat[0]} (${dominantCat[1]} occurrences)`,
    description: dominantCat[1] > 0 
      ? `The primary threat vector identified is '${dominantCat[0]}', accounting for ${Math.round((dominantCat[1] / Math.max(susCount, 1)) * 100)}% of all flagged suspicious network records.`
      : 'No malicious attack categories detected in current dataset.',
    severity: dominantCat[1] > 0 ? 'critical' : 'info',
  });

  // 4. Ports receiving the most connections
  const dstPortCounts: Record<number, number> = {};
  records.forEach(r => {
    dstPortCounts[r.destinationPort] = (dstPortCounts[r.destinationPort] || 0) + 1;
  });
  const sortedPorts = Object.entries(dstPortCounts).sort((a, b) => b[1] - a[1]);
  const topPort = sortedPorts[0];
  const portServiceMap: Record<number, string> = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    22: 'SSH',
    21: 'FTP',
    23: 'Telnet',
    25: 'SMTP',
    123: 'NTP',
    445: 'SMB',
    3389: 'RDP',
    8080: 'HTTP-Alt',
    4444: 'Metasploit/C2',
  };
  const topPortDesc = portServiceMap[parseInt(topPort[0], 10)] || 'Application Port';

  findings.push({
    id: 'FIND-04',
    category: 'Target Port Analysis',
    title: 'Most Targeted Destination Port',
    metric: `Port ${topPort[0]} / ${topPortDesc}`,
    description: `Port ${topPort[0]} received ${topPort[1]} connection attempts (${Math.round((topPort[1] / total) * 100)}% of all flows), primarily handling ${topPortDesc} traffic.`,
    severity: [22, 23, 445, 3389, 4444].includes(parseInt(topPort[0], 10)) ? 'critical' : 'info',
  });

  // 5. Unusually long connections
  const durations = records.map(r => r.flowDuration);
  const avgDur = durations.reduce((a, b) => a + b, 0) / total;
  const maxDur = Math.max(...durations);
  const longFlows = records.filter(r => r.flowDuration > 20);

  findings.push({
    id: 'FIND-05',
    category: 'Connection Duration',
    title: 'Duration Extremes & Persistence',
    metric: `Max: ${maxDur.toFixed(2)}s | Avg: ${avgDur.toFixed(2)}s`,
    description: longFlows.length > 0 
      ? `Detected ${longFlows.length} long-lived connections (>20s). The longest connection lasted ${maxDur.toFixed(2)}s, characteristic of continuous data exfiltration or persistent streaming.`
      : `Flow durations are well-bounded, averaging ${avgDur.toFixed(2)} seconds across the dataset.`,
    severity: longFlows.length > 10 ? 'warning' : 'info',
  });

  // 6. Packet count anomalies & bursts
  const packets = records.map(r => r.packetCount);
  const maxPackets = Math.max(...packets);
  const avgPackets = packets.reduce((a, b) => a + b, 0) / total;
  const packetBurstFlows = records.filter(r => r.packetCount > 250);

  findings.push({
    id: 'FIND-06',
    category: 'Volume & Anomaly Detection',
    title: 'High Packet Burst Anomalies',
    metric: `Peak: ${maxPackets.toLocaleString()} pkts`,
    description: packetBurstFlows.length > 0 
      ? `Found ${packetBurstFlows.length} severe packet burst anomalies (>250 pkts/flow). Peak flow reached ${maxPackets.toLocaleString()} packets, indicative of DoS flood behavior.`
      : `Packet counts are typical of enterprise activity (mean: ${Math.round(avgPackets)} packets/flow).`,
    severity: packetBurstFlows.length > 0 ? 'critical' : 'info',
  });

  // 7. Time period with highest traffic
  const timeBuckets: Record<string, number> = {};
  records.forEach(r => {
    const minute = r.timestamp.substring(11, 16); // e.g. "08:15"
    timeBuckets[minute] = (timeBuckets[minute] || 0) + 1;
  });
  const peakTime = Object.entries(timeBuckets).sort((a, b) => b[1] - a[1])[0] || ['08:00', 0];

  findings.push({
    id: 'FIND-07',
    category: 'Temporal Profiling',
    title: 'Peak Traffic Time Window',
    metric: `${peakTime[0]} UTC (${peakTime[1]} flows/min)`,
    description: `Traffic intensity peaked during interval ${peakTime[0]} UTC with ${peakTime[1]} concurrent records, representing the highest network load period.`,
    severity: 'info',
  });

  // 8. Class Imbalance Assessment
  const ratio = parseFloat((normalCount / Math.max(susCount, 1)).toFixed(2));
  let imbalanceSeverity: 'info' | 'warning' | 'critical' = 'info';
  let imbalanceText = 'Balanced dataset distribution.';
  if (ratio > 5) {
    imbalanceSeverity = 'warning';
    imbalanceText = `Class imbalance detected (${ratio}:1 Normal to Suspicious ratio). Stratification and evaluation weighting are recommended.`;
  } else if (ratio < 0.2) {
    imbalanceSeverity = 'warning';
    imbalanceText = `High attack density (${ratio}:1 ratio). Typical of targeted penetration test captures rather than production baselines.`;
  } else {
    imbalanceText = `Good class distribution (${ratio}:1 Normal to Suspicious ratio), providing sufficient training examples for both classes.`;
  }

  findings.push({
    id: 'FIND-08',
    category: 'Data Engineering',
    title: 'Class Imbalance Ratio',
    metric: `${ratio}:1 (Normal:Suspicious)`,
    description: imbalanceText,
    severity: imbalanceSeverity,
  });

  // 9. Feature Correlation
  const corrPacketsBytes = computePearsonCorrelation(records.map(r => r.packetCount), records.map(r => r.byteCount));
  const corrDurBytes = computePearsonCorrelation(records.map(r => r.flowDuration), records.map(r => r.byteCount));

  findings.push({
    id: 'FIND-09',
    category: 'Feature Dynamics',
    title: 'Packet-to-Byte Correlation',
    metric: `r = ${corrPacketsBytes}`,
    description: `Strong positive linear correlation (r = ${corrPacketsBytes}) between packet count and byte count. Duration-to-byte correlation is r = ${corrDurBytes}.`,
    severity: 'info',
  });

  // 10. Concentration of suspicious flows around sensitive ports
  const susPortCounts: Record<number, number> = {};
  records.filter(r => r.label === 'SUSPICIOUS').forEach(r => {
    susPortCounts[r.destinationPort] = (susPortCounts[r.destinationPort] || 0) + 1;
  });
  const topSusPort = Object.entries(susPortCounts).sort((a, b) => b[1] - a[1])[0];
  const topSusPortNum = topSusPort ? parseInt(topSusPort[0], 10) : 0;
  const topSusService = portServiceMap[topSusPortNum] || `Port ${topSusPortNum}`;

  findings.push({
    id: 'FIND-10',
    category: 'Threat Concentration',
    title: 'Suspicious Port Concentration',
    metric: topSusPort ? `${topSusService} (${topSusPort[1]} alerts)` : 'None',
    description: topSusPort 
      ? `${Math.round((topSusPort[1] / Math.max(susCount, 1)) * 100)}% of malicious/suspicious activity focuses on port ${topSusPort[0]} (${topSusService}), suggesting concentrated exploitation or brute forcing against that endpoint.`
      : 'No suspicious port concentration detected.',
    severity: topSusPort && topSusPort[1] > 10 ? 'critical' : 'warning',
  });

  return findings;
}
