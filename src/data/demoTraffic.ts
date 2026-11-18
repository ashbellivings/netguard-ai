import { FlowRecord } from '../types';

/**
 * Generates a realistic synthetic demonstration dataset for NETGUARD AI.
 * Clearly designated as DEMONSTRATION DATA with realistic flow attributes,
 * protocols, port numbers, duration, packet count, byte count, and flow rate.
 */
export function generateDemoDataset(): FlowRecord[] {
  const records: FlowRecord[] = [];
  const baseTime = new Date('2026-11-09T08:00:00Z').getTime();

  // Helper random generator with fixed seed simulation for reproducibility
  let seed = 42;
  function random(): number {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }

  function randomRange(min: number, max: number): number {
    return min + random() * (max - min);
  }

  function randomInt(min: number, max: number): number {
    return Math.floor(randomRange(min, max + 1));
  }

  function formatTime(offsetSeconds: number): string {
    const d = new Date(baseTime + offsetSeconds * 1000);
    return d.toISOString().replace('T', ' ').substring(0, 19);
  }

  const internalSubnets = ['192.168.1.', '10.0.4.'];
  const attackerIps = [
    '185.220.101.5',  // Port scanner
    '45.142.122.9',   // Brute forcer (SSH)
    '194.26.29.112',  // Brute forcer (RDP)
    '91.240.118.88',  // DoS Attacker
    '103.151.125.4',  // DDoS Node 1
    '185.196.220.33', // DDoS Node 2
    '77.88.55.66',    // Web App Attacker
    '203.0.113.19',   // Botnet C2
  ];

  let recordCounter = 1;

  // 1. Normal Web & Cloud Traffic (TCP 443 / 80) ~ 220 records
  for (let i = 0; i < 220; i++) {
    const srcIp = `${internalSubnets[i % 2]}${randomInt(10, 150)}`;
    const dstIp = `142.250.${randomInt(1, 200)}.${randomInt(1, 250)}`; // CDN / Cloud
    const srcPort = randomInt(49152, 65535);
    const dstPort = random() > 0.15 ? 443 : 80;
    const duration = parseFloat(randomRange(0.2, 28.5).toFixed(3));
    const packetCount = randomInt(12, 180);
    const byteCount = packetCount * randomInt(400, 1420);
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.05)).toFixed(2));
    const timeOffset = i * 20 + randomInt(0, 15);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: srcIp,
      destinationIp: dstIp,
      sourcePort: srcPort,
      destinationPort: dstPort,
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'NORMAL',
      attackCategory: 'Normal',
    });
  }

  // 2. Normal DNS & NTP Traffic (UDP 53 / 123) ~ 70 records
  for (let i = 0; i < 70; i++) {
    const srcIp = `${internalSubnets[i % 2]}${randomInt(10, 150)}`;
    const dstIp = i % 2 === 0 ? '192.168.1.1' : '8.8.8.8';
    const isDns = random() > 0.2;
    const dstPort = isDns ? 53 : 123;
    const srcPort = randomInt(50000, 62000);
    const duration = parseFloat(randomRange(0.005, 0.08).toFixed(4));
    const packetCount = randomInt(2, 6);
    const byteCount = packetCount * randomInt(68, 140);
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.005)).toFixed(2));
    const timeOffset = i * 45 + randomInt(0, 30);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: srcIp,
      destinationIp: dstIp,
      sourcePort: srcPort,
      destinationPort: dstPort,
      protocol: 'UDP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'NORMAL',
      attackCategory: 'Normal',
    });
  }

  // 3. Normal ICMP Echo Traffic ~ 20 records
  for (let i = 0; i < 20; i++) {
    const srcIp = `192.168.1.${randomInt(20, 60)}`;
    const dstIp = '192.168.1.1';
    const duration = parseFloat(randomRange(0.001, 0.02).toFixed(4));
    const packetCount = randomInt(2, 4);
    const byteCount = packetCount * 64;
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.005)).toFixed(2));
    const timeOffset = i * 120 + randomInt(0, 40);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: srcIp,
      destinationIp: dstIp,
      sourcePort: 0,
      destinationPort: 0,
      protocol: 'ICMP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'NORMAL',
      attackCategory: 'Normal',
    });
  }

  // 4. Port Scanning Activity (Suspicious) ~ 55 records
  const targetHost = '192.168.1.50';
  const scannedPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443, 8888];
  for (let i = 0; i < 55; i++) {
    const dstPort = scannedPorts[i % scannedPorts.length];
    const duration = parseFloat(randomRange(0.001, 0.04).toFixed(4));
    const packetCount = randomInt(1, 3);
    const byteCount = packetCount * 44; // SYN probe packets
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.002)).toFixed(2));
    const timeOffset = 900 + i * 4 + randomInt(0, 2);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: attackerIps[0],
      destinationIp: targetHost,
      sourcePort: randomInt(40000, 60000),
      destinationPort: dstPort,
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'SUSPICIOUS',
      attackCategory: 'Port Scan',
    });
  }

  // 5. Brute Force Login Attacks (SSH & RDP) ~ 45 records
  for (let i = 0; i < 45; i++) {
    const isSsh = i % 2 === 0;
    const dstPort = isSsh ? 22 : 3389;
    const srcIp = isSsh ? attackerIps[1] : attackerIps[2];
    const duration = parseFloat(randomRange(0.4, 2.2).toFixed(3));
    const packetCount = randomInt(8, 22);
    const byteCount = randomInt(850, 3200);
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.2)).toFixed(2));
    const timeOffset = 1500 + i * 18 + randomInt(0, 5);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: srcIp,
      destinationIp: '192.168.1.10', // Server
      sourcePort: randomInt(35000, 61000),
      destinationPort: dstPort,
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'SUSPICIOUS',
      attackCategory: 'Brute Force',
    });
  }

  // 6. DoS / DDoS Flood Traffic ~ 50 records
  for (let i = 0; i < 50; i++) {
    const isDistributed = i % 3 === 0;
    const srcIp = isDistributed ? attackerIps[4 + (i % 2)] : attackerIps[3];
    const duration = parseFloat(randomRange(0.01, 0.15).toFixed(3));
    const packetCount = randomInt(350, 2400); // intense flood burst
    const byteCount = packetCount * randomInt(512, 1200);
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.02)).toFixed(2));
    const timeOffset = 2600 + i * 6 + randomInt(0, 3);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: srcIp,
      destinationIp: '192.168.1.80', // Web Server target
      sourcePort: randomInt(1024, 65535),
      destinationPort: 80,
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'SUSPICIOUS',
      attackCategory: 'DoS / DDoS',
    });
  }

  // 7. Web Application Exploitation (SQLi / XSS probes) ~ 25 records
  for (let i = 0; i < 25; i++) {
    const duration = parseFloat(randomRange(0.8, 4.5).toFixed(3));
    const packetCount = randomInt(15, 65);
    const byteCount = randomInt(4500, 28000); // abnormally large HTTP request payloads
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.5)).toFixed(2));
    const timeOffset = 3100 + i * 35 + randomInt(0, 10);

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: attackerIps[6],
      destinationIp: '192.168.1.80',
      sourcePort: randomInt(40000, 59000),
      destinationPort: 8080,
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'SUSPICIOUS',
      attackCategory: 'Web Attack',
    });
  }

  // 8. Botnet C2 Beaconing ~ 15 records
  for (let i = 0; i < 15; i++) {
    const duration = parseFloat(randomRange(0.05, 0.2).toFixed(3));
    const packetCount = randomInt(4, 8);
    const byteCount = randomInt(320, 680);
    const flowRate = parseFloat((byteCount / Math.max(duration, 0.05)).toFixed(2));
    const timeOffset = 4000 + i * 90; // regular interval beaconing

    records.push({
      id: `FLW-${String(recordCounter++).padStart(5, '0')}`,
      timestamp: formatTime(timeOffset),
      sourceIp: '192.168.1.105', // Compromised internal host
      destinationIp: attackerIps[7],
      sourcePort: randomInt(49200, 50200),
      destinationPort: 4444, // Metasploit / C2 default port
      protocol: 'TCP',
      flowDuration: duration,
      packetCount,
      byteCount,
      flowRate,
      label: 'SUSPICIOUS',
      attackCategory: 'Botnet / C2',
    });
  }

  // Sort by timestamp
  records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return records;
}

export type TrafficScenario = 'balanced' | 'ddos' | 'portscan' | 'bruteforce' | 'botnet';

export interface ScenarioInfo {
  id: TrafficScenario;
  name: string;
  tagline: string;
  description: string;
  badge: string;
  dominantAttack: string;
}

export const SCENARIOS: ScenarioInfo[] = [
  {
    id: 'balanced',
    name: 'Enterprise Baseline & Multi-Threat Feed',
    tagline: 'Balanced SOC telemetry across all 5 threat vectors',
    description: 'Realistic mix of normal HTTPS/DNS traffic (70%) combined with port sweeps, brute-force logins, DoS packet bursts, and botnet C2 activity (30%).',
    badge: 'Standard Baseline',
    dominantAttack: 'Multi-Vector',
  },
  {
    id: 'ddos',
    name: 'Volumetric DDoS Attack Outbreak',
    tagline: 'High packet-rate denial of service flooding',
    description: 'Simulates intensive SYN flooding and UDP amplification targeting public web services with extreme packet volumes and bandwidth saturation.',
    badge: 'Active Threat',
    dominantAttack: 'DoS / DDoS',
  },
  {
    id: 'portscan',
    name: 'Reconnaissance & Subnet Port Scan',
    tagline: 'Systematic reconnaissance across core server ports',
    description: 'Rapid single-packet connection probes targeting SSH, RDP, SMB, HTTP, and SQL ports to enumerate listening network services.',
    badge: 'Reconnaissance',
    dominantAttack: 'Port Scan',
  },
  {
    id: 'bruteforce',
    name: 'Administrative Credential Brute Force',
    tagline: 'Targeted dictionary attacks on SSH & RDP',
    description: 'Repeated authentication connection bursts targeting SSH (port 22) and RDP (port 3389) servers from malicious external IP addresses.',
    badge: 'Credential Attack',
    dominantAttack: 'Brute Force',
  },
  {
    id: 'botnet',
    name: 'Botnet C2 Infiltration & Beaconing',
    tagline: 'Command & Control communication channels',
    description: 'Simulates infected enterprise endpoints maintaining periodic communication beacons with external command and control servers on port 4444.',
    badge: 'Lateral Threat',
    dominantAttack: 'Botnet / C2',
  },
];

export function generateScenarioDataset(scenario: TrafficScenario = 'balanced'): { flows: FlowRecord[]; name: string } {
  const allRecords = generateDemoDataset();
  let filtered: FlowRecord[] = [];
  let name = 'Enterprise Baseline Telemetry (490 Flows)';

  if (scenario === 'balanced') {
    return { flows: allRecords, name: 'Enterprise Baseline & Multi-Threat Telemetry' };
  }

  const normalFlows = allRecords.filter(r => r.label === 'NORMAL');

  if (scenario === 'ddos') {
    const ddosFlows = allRecords.filter(r => r.attackCategory === 'DoS / DDoS');
    // Replicate / intensify DDoS flows
    const intensifiedDDoS: FlowRecord[] = [];
    for (let i = 0; i < 60; i++) {
      const template = ddosFlows[i % ddosFlows.length];
      intensifiedDDoS.push({
        ...template,
        id: `FLW-DOS-${String(i + 1).padStart(4, '0')}`,
        packetCount: template.packetCount * (1 + (i % 3)),
        byteCount: template.byteCount * (1 + (i % 3)),
        flowRate: template.flowRate * (1 + (i % 4)),
      });
    }
    filtered = [...normalFlows.slice(0, 100), ...ddosFlows, ...intensifiedDDoS];
    name = 'Volumetric DDoS Attack Outbreak (Active Incident)';
  } else if (scenario === 'portscan') {
    const scanFlows = allRecords.filter(r => r.attackCategory === 'Port Scan');
    const extraScans: FlowRecord[] = [];
    const targetPorts = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080];
    for (let i = 0; i < 75; i++) {
      extraScans.push({
        id: `FLW-SCN-${String(i + 1).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - (75 - i) * 2000).toISOString().replace('T', ' ').substring(0, 19),
        sourceIp: '185.220.101.5',
        destinationIp: `192.168.1.${(i % 15) + 10}`,
        sourcePort: 49000 + i,
        destinationPort: targetPorts[i % targetPorts.length],
        protocol: 'TCP',
        flowDuration: 0.005,
        packetCount: 1,
        byteCount: 64,
        flowRate: 12800,
        label: 'SUSPICIOUS',
        attackCategory: 'Port Scan',
      });
    }
    filtered = [...normalFlows.slice(0, 90), ...scanFlows, ...extraScans];
    name = 'Stealth Reconnaissance & Subnet Port Scan';
  } else if (scenario === 'bruteforce') {
    const bruteFlows = allRecords.filter(r => r.attackCategory === 'Brute Force');
    const extraBrute: FlowRecord[] = [];
    for (let i = 0; i < 65; i++) {
      extraBrute.push({
        id: `FLW-BRT-${String(i + 1).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - (65 - i) * 3000).toISOString().replace('T', ' ').substring(0, 19),
        sourceIp: i % 2 === 0 ? '45.142.122.9' : '194.26.29.112',
        destinationIp: '192.168.1.10',
        sourcePort: 51000 + i,
        destinationPort: i % 2 === 0 ? 22 : 3389,
        protocol: 'TCP',
        flowDuration: 0.25,
        packetCount: 8,
        byteCount: 1420,
        flowRate: 5680,
        label: 'SUSPICIOUS',
        attackCategory: 'Brute Force',
      });
    }
    filtered = [...normalFlows.slice(0, 90), ...bruteFlows, ...extraBrute];
    name = 'Administrative Credential Brute Force (SSH/RDP)';
  } else if (scenario === 'botnet') {
    const botFlows = allRecords.filter(r => r.attackCategory === 'Botnet / C2');
    const extraBeacons: FlowRecord[] = [];
    for (let i = 0; i < 45; i++) {
      extraBeacons.push({
        id: `FLW-C2-${String(i + 1).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - (45 - i) * 12000).toISOString().replace('T', ' ').substring(0, 19),
        sourceIp: '192.168.1.105',
        destinationIp: '203.0.113.19',
        sourcePort: 49500 + i,
        destinationPort: 4444,
        protocol: 'TCP',
        flowDuration: 0.12,
        packetCount: 6,
        byteCount: 540,
        flowRate: 4500,
        label: 'SUSPICIOUS',
        attackCategory: 'Botnet / C2',
      });
    }
    filtered = [...normalFlows.slice(0, 100), ...botFlows, ...extraBeacons];
    name = 'Internal Botnet Infiltration & C2 Beaconing';
  }

  filtered.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return { flows: filtered, name };
}

/**
 * Returns raw CSV string of any flow record array for download
 */
export function convertFlowsToCSV(data: FlowRecord[]): string {
  const escapeCell = (val: string | number | undefined | null): string => {
    if (val === undefined || val === null) return '""';
    let s = String(val);
    if (/^[=+\-@\t\r]/.test(s)) {
      s = `'${s}`;
    }
    if (/[",\n\r]/.test(s) || s.startsWith("'")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const headers = [
    'Timestamp',
    'Source_IP',
    'Destination_IP',
    'Source_Port',
    'Destination_Port',
    'Protocol',
    'Flow_Duration',
    'Packet_Count',
    'Byte_Count',
    'Flow_Rate',
    'Label',
    'Attack_Category'
  ];

  const rows = data.map(r => [
    escapeCell(r.timestamp),
    escapeCell(r.sourceIp),
    escapeCell(r.destinationIp),
    r.sourcePort,
    r.destinationPort,
    escapeCell(r.protocol),
    r.flowDuration,
    r.packetCount,
    r.byteCount,
    r.flowRate,
    escapeCell(r.label || 'NORMAL'),
    escapeCell(r.attackCategory || 'Normal')
  ]);

  return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
}

/**
 * Returns raw CSV string of the demonstration dataset for download
 */
export function getDemoDatasetAsCSV(): string {
  return convertFlowsToCSV(generateDemoDataset());
}
