/*
tshark-interface.js

/**
 * TShark Interface Module
 * 
 * This module provides functions to interact with TShark for network packet capture.
 * It handles executing TShark commands, parsing output, and error handling.
 

import { spawn } from 'child_process';
import { processRawPacketData } from './data-processing.js';
import { calculateNetworkMetrics } from '../network-metrics.js';

// Configuration for TShark command
const TSHARK_CONFIG = {
  command: 'D:\\PXMonitor\\pxmonitor\\tshark_libs\\tshark.exe',
  defaultInterface: 'Wi-Fi',
  outputFormat: 'fields',
  headerFormat: 'y',
  separator: ',',
  fields: [
    'frame.time_epoch',
    'ip.src',
    'ip.dst',
    '_ws.col.Protocol',
    'frame.len',
    'tcp.srcport',
    'tcp.dstport',
    'ip.ttl',
    'tcp.flags',
    'tcp.window_size_value',
    'tcp.analysis.ack_rtt',
    'tcp.analysis.retransmission',
    'frame.time_delta',
    'dns.time'
  ]
};

// Set the current interface (can be updated from frontend)
let currentInterface = TSHARK_CONFIG.defaultInterface;

// Function to update the interface
function setNetworkInterface(interfaceName) {
  if (interfaceName === 'ethernet') {
    currentInterface = 'Ethernet';
  } else {
    currentInterface = 'Wi-Fi';
  }
  console.log(`TShark interface updated to: ${currentInterface}`);
  return currentInterface;
}

// Function to get the current interface
function getCurrentInterface() {
  return currentInterface;
}

// Build TShark command based on configuration
function buildTSharkCommand(networkInterface = currentInterface) {
  const args = [
    '-i', networkInterface,
    '-T', TSHARK_CONFIG.outputFormat,
    '-E', `header=${TSHARK_CONFIG.headerFormat}`,
    '-E', `separator=${TSHARK_CONFIG.separator}`
  ];
  
  TSHARK_CONFIG.fields.forEach(field => {
    args.push('-e', field);
  });
  
  return { command: TSHARK_CONFIG.command, args };
}

// Capture packets using TShark
function capturePackets(networkInterface, duration = 5, callback) {
  const { command, args } = buildTSharkCommand(networkInterface || currentInterface);
  
  args.push('-a', `duration:${duration}`);
  
  let rawData = '';
  let errorOutput = '';
  
  try {
    const tsharkProcess = spawn(command, args);
    
    tsharkProcess.stdout.on('data', (data) => {
      rawData += data.toString();
    });
    
    tsharkProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
    
    tsharkProcess.on('close', (code) => {
      if (code !== 0) {
        callback(new Error(`TShark exited with code ${code}: ${errorOutput}`));
        return;
      }
      
      try {
        const packets = processRawPacketData(rawData);
        callback(null, packets);
      } catch (err) {
        callback(new Error(`Failed to process TShark output: ${err.message}`));
      }
    });
  } catch (err) {
    callback(new Error(`Failed to start TShark: ${err.message}`));
  }
}

// Start continuous packet capture
function startContinuousCapture(networkInterface, processingCallback, errorCallback) {
  const { command, args } = buildTSharkCommand(networkInterface || currentInterface);
  let tsharkProcess = null;
  let buffer = '';
  let running = false;
  
  function start() {
    if (running) return false;
    
    try {
      running = true;
      tsharkProcess = spawn(command, args);
      
      tsharkProcess.stdout.on('data', (data) => {
        buffer += data.toString();
        
        const lines = buffer.split('\n');
        if (lines.length > 1) {
          buffer = lines.pop();
          
          const output = lines.join('\n');
          try {
            const packets = processRawPacketData(output);
            if (packets.length > 0) {
              const metrics = calculateNetworkMetrics(packets);
              processingCallback(packets, metrics);
            }
          } catch (err) {
            errorCallback(new Error(`Data processing error: ${err.message}`));
          }
        }
      });
      
      tsharkProcess.stderr.on('data', (data) => {
        errorCallback(new Error(`TShark error: ${data.toString()}`));
      });
      
      tsharkProcess.on('close', (code) => {
        if (code !== 0 && running) {
          errorCallback(new Error(`TShark process exited with code ${code}`));
        }
        running = false;
      });
      
      return true;
    } catch (err) {
      running = false;
      errorCallback(new Error(`Failed to start TShark: ${err.message}`));
      return false;
    }
  }
  
  function stop() {
    if (!running) return false;
    
    try {
      running = false;
      if (tsharkProcess) {
        tsharkProcess.kill();
        tsharkProcess = null;
      }
      return true;
    } catch (err) {
      errorCallback(new Error(`Failed to stop TShark: ${err.message}`));
      return false;
    }
  }
  
  return {
    start,
    stop,
    isRunning: () => running
  };
}

// Use ES module exports
export {
  capturePackets,
  startContinuousCapture,
  setNetworkInterface,
  getCurrentInterface
};


=====================================================================
===============================================================================



/**
 * Network Metrics Generator
 * 
 * This module implements the functionality from the provided Python code,
 * adapted to Node.js. It provides functions for collecting and analyzing
 * network packet data, calculating metrics, and identifying applications.
 

// Mock implementation of the identify_top_applications function
function identifyTopApplications(data, topN = 5) {
  if (!data || data.length === 0) {
    return [];
  }
  
  // Port to application mapping
  const portMap = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
    1194: "OpenVPN",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
  };

  // Group data by application
  const applications = {};
  data.forEach(packet => {
    const srcPort = packet.tcp_src_port;
    const dstPort = packet.tcp_dst_port;
    
    let appName = "Unknown";
    if (portMap[srcPort]) {
      appName = portMap[srcPort];
    } else if (portMap[dstPort]) {
      appName = portMap[dstPort];
    } else if (dstPort > 1024 && dstPort < 49151) {
      appName = `App-Port-${dstPort}`;
    }
    
    if (!applications[appName]) {
      applications[appName] = 0;
    }
    applications[appName] += packet.frameLen;
  });
  
  // Convert to array and sort
  const appArray = Object.entries(applications).map(([application, frameLen]) => ({
    application,
    'frame.len': frameLen
  }));
  
  // Sort and return top N
  return appArray
    .sort((a, b) => b['frame.len'] - a['frame.len'])
    .slice(0, topN);
}

// Mock implementation of the calculate_metrics function
function calculateNetworkMetrics(data) {
  if (!data || data.length === 0) {
    return {
      timestamp: Date.now() / 1000,
      latency: 0,
      jitter: 0,
      bandwidth: 0,
      packet_loss: 0,
      dns_delay: 0,
      health_score: 50,
      stability: "Stable",
      congestion_level: "Low",
      packet_count: 0,
      protocol_counts: {},
      packet_sizes: [],
      top_apps: []
    };
  }
  
  // Calculate metrics
  const latency = calculateAverage(data.filter(p => p.ack_rtt).map(p => p.ack_rtt * 1000));
  const jitter = calculateStdDev(data.filter(p => p.time_delta).map(p => p.time_delta * 1000));
  const totalBytes = data.reduce((sum, p) => sum + p.frameLen, 0);
  
  const times = data.map(p => p.time);
  const timeSpan = Math.max(...times) - Math.min(...times);
  const bandwidth = timeSpan > 0 ? (totalBytes * 8) / (timeSpan * 1000000) : 0;
  
  const retransmissions = data.filter(p => p.retransmission).length;
  const packet_loss = data.length > 0 ? (retransmissions / data.length) * 100 : 0;
  
  const dnsPackets = data.filter(p => p.protocol === "DNS");
  const dns_delay = calculateAverage(dnsPackets.map(p => p.time_delta * 1000));
  
  const avgWindow = calculateAverage(data.filter(p => p.window_size).map(p => p.window_size));
  
  // Determine congestion level
  let congestion_level = "Low";
  if (!(avgWindow > 8000 && bandwidth > 5)) {
    congestion_level = (avgWindow > 4000 || bandwidth > 2) ? "Moderate" : "High";
  }
  
  // Determine stability
  let stability = "Stable";
  if (!(jitter < 10 && packet_loss < 1)) {
    stability = (jitter < 30 && packet_loss < 5) ? "Unstable" : "Very Unstable";
  }
  
  // Calculate health score
  const latencyScore = Math.max(0, 100 - (latency / 2)) * 0.3;
  const jitterScore = Math.max(0, 100 - (jitter * 2)) * 0.2;
  const packetLossScore = Math.max(0, 100 - (packet_loss * 10)) * 0.25;
  const bandwidthScore = Math.min(100, bandwidth * 10) * 0.15;
  const dnsScore = Math.max(0, 100 - (dns_delay * 2)) * 0.1;
  
  let health_score = Math.round(latencyScore + jitterScore + packetLossScore + bandwidthScore + dnsScore);
  health_score = Math.max(1, Math.min(100, health_score));
  
  // Count protocols
  const protocol_counts = {};
  data.forEach(p => {
    const protocol = p.protocol || "Unknown";
    protocol_counts[protocol] = (protocol_counts[protocol] || 0) + 1;
  });
  
  return {
    timestamp: Date.now() / 1000,
    latency,
    jitter,
    bandwidth,
    packet_loss,
    dns_delay,
    health_score,
    stability,
    congestion_level,
    packet_count: data.length,
    protocol_counts,
    packet_sizes: data.map(p => p.frameLen),
    top_apps: identifyTopApplications(data)
  };
}

// Helper functions for statistics
function calculateAverage(array) {
  if (!array || array.length === 0) return 0;
  return array.reduce((a, b) => a + b, 0) / array.length;
}

function calculateStdDev(array) {
  if (!array || array.length <= 1) return 0;
  const avg = calculateAverage(array);
  const squareDiffs = array.map(value => {
    const diff = value - avg;
    return diff * diff;
  });
  const avgSquareDiff = calculateAverage(squareDiffs);
  return Math.sqrt(avgSquareDiff);
}

export { identifyTopApplications, calculateNetworkMetrics };



==================================================================================================================
==========================================================================================================================


index.js


import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import express from 'express';
import { startContinuousCapture, setNetworkInterface, getCurrentInterface } from './scripts/tshark-interface.js';
import { calculateNetworkMetrics } from './network-metrics.js';
import * as geminiService from './services/gemini-service.js';
// ... rest unchanged

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server , pingInterval: 1000 });

// Middleware to parse JSON
app.use(express.json());

// Store capture controller
let captureController = null;

// Start packet capture on application start
// const initializeCapture = () => {
//   captureController = startContinuousCapture(
//     getCurrentInterface(),
//     (packets, metrics) => {
//       // Process packets into frontend-compatible format
//       const frontendMetrics = {
//         latency: metrics.latency || 0,
//         jitter: metrics.jitter || 0,
//         packetLoss: metrics.packet_loss || 0,
//         bandwidth: metrics.bandwidth || 0,
//         dnsDelay: metrics.dns_delay || 0,
//         healthScore: metrics.health_score || 50,
//         stability: metrics.stability.toLowerCase() || 'stable',
//         congestion: metrics.congestion_level.toLowerCase() || 'stable',
//         protocolData: Object.entries(metrics.protocol_counts).map(([name, value]) => ({
//           name,
//           value
//         })),
//         topAppsData: metrics.top_apps.map(app => ({
//           name: app.application,
//           value: app['frame.len']
//         }))
//       };

//       // Broadcast to all connected WebSocket clients
//       wss.clients.forEach(client => {
//         if (client.readyState === client.OPEN) {
//           client.send(JSON.stringify({
//             type: 'metrics',
//             data: frontendMetrics
//           }));
//         }
//       });
//     },
//     (error) => {
//       console.error('Capture error:', error.message);
//       wss.clients.forEach(client => {
//         if (client.readyState === client.OPEN) {
//           client.send(JSON.stringify({
//             type: 'error',
//             message: error.message
//           }));
//         }
//       });
//     }
//   );

//   captureController.start();
// };

const initializeCapture = () => {
  console.log('Initializing capture for interface:', getCurrentInterface());
  
  captureController = startContinuousCapture(
    getCurrentInterface(),
    (packets, metrics) => {
      console.log('Received packets:', packets?.length || 0);
      console.log('Received metrics:', metrics);
      
      // Check if metrics object exists and has expected properties
      if (!metrics) {
        console.error('No metrics received');
        return;
      }
      
      // Process packets into frontend-compatible format
      const frontendMetrics = {
        latency: metrics.latency || 0,
        jitter: metrics.jitter || 0,
        packetLoss: metrics.packet_loss || 0,
        bandwidth: metrics.bandwidth || 0,
        dnsDelay: metrics.dns_delay || 0,
        healthScore: metrics.health_score || 50,
        stability: (metrics.stability || 'stable').toLowerCase(),
        congestion: (metrics.congestion_level || 'stable').toLowerCase(),
        protocolData: metrics.protocol_counts ? Object.entries(metrics.protocol_counts).map(([name, value]) => ({
          name,
          value
        })) : [],
        topAppsData: metrics.top_apps ? metrics.top_apps.map(app => ({
          name: app.application,
          value: app['frame.len']
        })) : []
      };
      
      console.log('Sending frontend metrics:', frontendMetrics);
      
      // Broadcast to all connected WebSocket clients
      wss.clients.forEach(client => {
        if (client.readyState === client.OPEN) {
          client.send(JSON.stringify({
            type: 'metrics',
            data: frontendMetrics
          }));
        }
      });
    },
    (error) => {
      console.error('Capture error details:', error);
      wss.clients.forEach(client => {
        if (client.readyState === client.OPEN) {
          client.send(JSON.stringify({
            type: 'error',
            message: error.message
          }));
        }
      });
    }
  );
  
  console.log('Starting capture controller...');
  captureController.start();
};

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('WebSocket client connected');
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString()); // Convert Buffer to string
      if (data.type === 'setInterface') {
        setNetworkInterface(data.interface);
        if (captureController) {
          captureController.stop();
          initializeCapture();
        }
      }
    } catch (err) {
      console.error('WebSocket message error:', err.message);
    }
  });

  ws.on('close', () => {
    console.log('WebSocket client disconnected');
  });
});

// API to get current interface
app.get('/interface', (req, res) => {
  res.json({ interface: getCurrentInterface() });
});

// API to set network interface
app.post('/interface', (req, res) => {
  const { interfaceName } = req.body;
  if (!interfaceName) {
    return res.status(400).json({ error: 'Interface name required' });
  }
  setNetworkInterface(interfaceName);
  if (captureController) {
    captureController.stop();
    initializeCapture();
  }
  res.json({ interface: getCurrentInterface() });
});

// API to get AI-powered explanation
app.get('/explain/:component', async (req, res) => {
  try {
    const explanation = await geminiService.explainNetworkComponent(req.params.component);
    res.json({ explanation });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API to get AI-powered network analysis
app.post('/analyze', async (req, res) => {
  try {
    const analysis = await geminiService.analyzeNetworkMetrics(req.body);
    res.json({ analysis });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server and initialize capture
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  initializeCapture();
});

// Graceful shutdown
process.on('SIGTERM', () => {
  if (captureController) {
    captureController.stop();
  }
  server.close(() => {
    console.log('Server shut down');
    process.exit(0);
  });
});

export const calculateHealthScore = (metrics) => {
  const latencyScore = Math.max(0, 100 - (metrics.latency / 2)) * 0.3;
  const jitterScore = Math.max(0, 100 - (metrics.jitter * 2)) * 0.2;
  const packetLossScore = Math.max(0, 100 - (metrics.packetLoss * 10)) * 0.25;
  const bandwidthScore = Math.min(100, metrics.bandwidth * 10) * 0.15;
  const dnsScore = Math.max(0, 100 - (metrics.dnsDelay * 2)) * 0.1;
  return Math.max(1, Math.min(100, Math.round(latencyScore + jitterScore + packetLossScore + bandwidthScore + dnsScore)));
};

export const getComponentExplanation = async (componentName) => {
  return await geminiService.explainNetworkComponent(componentName);
};

export const getNetworkAnalysis = async (metrics) => {
  return await geminiService.analyzeNetworkMetrics(metrics);
};


========================================================================================================================================
==========================================================================


data-processing.js



/**
 * Network Data Processing Module
 * 
 * This module handles the processing of network packet data
 * captured using TShark. It transforms raw packet data into
 * structured format for analysis and visualization.
 

// Process raw TShark output into structured data
function processRawPacketData(rawData) {
  if (!rawData || !rawData.trim()) {
    return [];
  }
  
  const rows = rawData.trim().split('\n');
  const headers = rows[0].split(',').map(h => h.trim());
  const packets = [];
  
  // Skip the header row
  for (let i = 1; i < rows.length; i++) {
    const values = rows[i].split(',').map(v => v.trim());
    if (values.length < headers.length) continue;
    
    const packet = {};
    headers.forEach((header, index) => {
      const value = values[index];
      
      switch (header) {
        case 'frame.time_epoch':
          packet.time = value ? parseFloat(value) : null;
          break;
        case 'ip.src':
          packet.srcIp = value || 'Unknown';
          break;
        case 'ip.dst':
          packet.dstIp = value || 'Unknown';
          break;
        case '_ws.col.Protocol':
          packet.protocol = value || 'Unknown';
          break;
        case 'frame.len':
          packet.frameLen = value ? parseFloat(value) : 0;
          break;
        case 'tcp.srcport':
          packet.tcp_src_port = value ? parseFloat(value) : null;
          break;
        case 'tcp.dstport':
          packet.tcp_dst_port = value ? parseFloat(value) : null;
          break;
        case 'ip.ttl':
          packet.ttl = value ? parseFloat(value) : null;
          break;
        case 'tcp.flags':
          if (value) {
            packet.tcpFlags = value.startsWith('0x') ? 
              parseInt(value.substring(2), 16) : parseFloat(value);
          } else {
            packet.tcpFlags = null;
          }
          break;
        case 'tcp.window_size_value':
          packet.window_size = value ? parseFloat(value) : null;
          break;
        case 'tcp.analysis.ack_rtt':
          packet.ack_rtt = value ? parseFloat(value) : null;
          break;
        case 'tcp.analysis.retransmission':
          packet.retransmission = value ? parseInt(value) : 0;
          break;
        case 'frame.time_delta':
          packet.time_delta = value ? parseFloat(value) : null;
          break;
        case 'dns.time':
          packet.dns_time = value ? parseFloat(value) : null;
          break;
        default:
          packet[header] = value;
      }
    });
    
    packets.push(packet);
  }
  
  return packets;
}

// Batch process packets for efficient analysis
function batchProcessPackets(packets, batchSize = 100) {
  const results = [];
  
  for (let i = 0; i < packets.length; i += batchSize) {
    const batch = packets.slice(i, i + batchSize);
    results.push(batch);
  }
  
  return results;
}

// Clean and filter packet data to remove anomalies
function cleanPacketData(packets) {
  if (!packets || packets.length === 0) return [];
  
  return packets.filter(packet => {
    // Remove packets with missing essential data
    if (!packet.time || !packet.protocol) {
      return false;
    }
    
    // Filter out anomalous values
    if (packet.frameLen > 100000 || // Unrealistically large packets
        (packet.ack_rtt !== null && packet.ack_rtt > 10)) { // Very high RTT
      return false;
    }
    
    return true;
  });
}

export {
  processRawPacketData,
  batchProcessPackets,
  cleanPacketData
};



*/

/*
dahsborad

import { useState, useEffect } from "react";
import NetworkHealthGauge from "@/components/dashboard/NetworkHealthGauge";
import MetricCard from "@/components/dashboard/MetricCard";
import StatusCard from "@/components/dashboard/StatusCard";
import AlertBanner from "@/components/dashboard/AlertBanner";
import ProtocolDistribution from "@/components/dashboard/ProtocolDistribution";
import MultiLineChart from "@/components/dashboard/MultiLineChart";
import NetworkAnalysis from "@/components/dashboard/NetworkAnalysis";
import { Clock, Wifi, FileTerminal, Database, Activity } from "lucide-react";

interface MetricsData {
  latency: number;
  jitter: number;
  packetLoss: number;
  bandwidth: number;
  dnsDelay: number;
  healthScore: number;
  stability: "stable" | "unstable" | "critical";
  congestion: "stable" | "unstable" | "critical";
  protocolData: { name: string; value: number }[];
  topAppsData: { name: string; value: number }[];
}

interface LatencyDataPoint {
  timestamp: number;
  latency: number;
  baseline: number;
}

interface BandwidthDataPoint {
  timestamp: number;
  bandwidth: number;
  target: number;
}

interface JitterDataPoint {
  timestamp: number;
  jitter: number;
  packetLoss: number;
}

const Dashboard = () => {
  const [metrics, setMetrics] = useState<MetricsData>({
    latency: 0,
    jitter: 0,
    packetLoss: 0,
    bandwidth: 0,
    dnsDelay: 0,
    healthScore: 50,
    stability: "stable",
    congestion: "stable",
    protocolData: [],
    topAppsData: []
  });
  const [latencyData, setLatencyData] = useState<LatencyDataPoint[]>([]);
  const [bandwidthData, setBandwidthData] = useState<BandwidthDataPoint[]>([]);
  const [jitterData, setJitterData] = useState<JitterDataPoint[]>([]);
  const [protocolData, setProtocolData] = useState<{ name: string; value: number }[]>([]);
  const [topAppsData, setTopAppsData] = useState<{ name: string; value: number }[]>([]);
  const [showAlert, setShowAlert] = useState(false);
  const [showNotifications, setShowNotifications] = useState(true);

  useEffect(() => {
   
    const savedSettings = localStorage.getItem('pxmonitor-settings');
    if (savedSettings) {
      try {
        const parsedSettings = JSON.parse(savedSettings);
        const notificationsSetting = parsedSettings
          .find((group: any) => group.id === "general")
          ?.settings.find((setting: any) => setting.id === "notifications")?.value;
        if (notificationsSetting !== undefined) {
          setShowNotifications(notificationsSetting);
        }
      } catch (error) {
        console.error("Error loading notification settings:", error);
      }
    }

    // WebSocket connection
    const ws = new WebSocket('ws://localhost:3001');

    ws.onopen = () => {
      console.log('Connected to WebSocket server');
    };

    ws.onmessage = (event) => {
      try {
        const { type, data, message } = JSON.parse(event.data);
        if (type === 'metrics') {
          setMetrics({
            latency: data.latency,
            jitter: data.jitter,
            packetLoss: data.packetLoss,
            bandwidth: data.bandwidth,
            dnsDelay: data.dnsDelay,
            healthScore: data.healthScore,
            stability: data.stability,
            congestion: data.congestion,
            protocolData: data.protocolData,
            topAppsData: data.topAppsData
          });

          const now = Date.now();
          setLatencyData(prev => [
            ...prev.slice(-59),
            { timestamp: now, latency: data.latency, baseline: 50 }
          ]);
          setBandwidthData(prev => [
            ...prev.slice(-59),
            { timestamp: now, bandwidth: data.bandwidth, target: 90 }
          ]);
          setJitterData(prev => [
            ...prev.slice(-59),
            { timestamp: now, jitter: data.jitter, packetLoss: data.packetLoss * 3 }
          ]);
          setProtocolData(data.protocolData);
          setTopAppsData(data.topAppsData);
          setShowAlert(data.healthScore < 50 && showNotifications);
        } else if (type === 'error') {
          console.error('Backend error:', message);
        }
      } catch (err) {
        console.error('WebSocket message error:', err);
      }
    };

    ws.onclose = () => {
      console.log('WebSocket connection closed');
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    return () => {
      ws.close();
    };
  }, [showNotifications]);

  useEffect(() => {
    const handleSettingsUpdate = (event: any) => {
      if (event.detail?.showNotifications !== undefined) {
        setShowNotifications(event.detail.showNotifications);
      }
    };
    window.addEventListener('settingsUpdated', handleSettingsUpdate);
    return () => window.removeEventListener('settingsUpdated', handleSettingsUpdate);
  }, []);

  const handleFixNetwork = async () => {
    try {
      const response = await fetch('http://localhost:3001/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(metrics)
      });
      const { analysis } = await response.json();
      console.log('Network fix suggestions:', analysis);
      // Simulate improvement (in a real scenario, apply suggested fixes)
      setMetrics(prev => ({
        ...prev,
        healthScore: Math.min(85, prev.healthScore + 40),
        latency: Math.max(20, prev.latency - 50),
        packetLoss: Math.max(0.2, prev.packetLoss - 5),
        bandwidth: Math.min(95, prev.bandwidth + 20),
        stability: "stable" as const,
        congestion: "stable" as const
      }));
      setShowAlert(false);
    } catch (err) {
      console.error('Error fixing network:', err);
    }
  };

  return (
    <div className="grid-bg">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold font-montserrat">Network Dashboard</h1>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-muted/20 text-muted-foreground text-sm">
          <Clock size={16} />
          <span>Updated just now</span>
        </div>
      </div>
      
      {showAlert && (
        <AlertBanner
          message="Your network performance is degraded!"
          type="error"
          actionText="Fix Now"
          onAction={handleFixNetwork}
          className="mb-6 max-w-4xl"
        />
      )}
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <NetworkHealthGauge score={metrics.healthScore} />
        <StatusCard 
          title="Connection Stability" 
          status={metrics.stability} 
          description={
            metrics.stability === "stable" 
              ? "Your connection is reliable and stable" 
              : "Your connection is experiencing issues"
          }
        />
        <StatusCard 
          title="Network Congestion" 
          status={metrics.congestion}
          description={
            metrics.congestion === "stable" 
              ? "Network traffic is flowing smoothly" 
              : "Network traffic is congested"
          }
        />
      </div>
      
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <MetricCard
          title="Latency"
          value={metrics.latency}
          unit="ms"
          icon={<Activity size={18} />}
          status={metrics.latency < 50 ? "success" : metrics.latency < 100 ? "warning" : "danger"}
        />
        <MetricCard
          title="Jitter"
          value={metrics.jitter}
          unit="ms"
          icon={<Activity size={18} />}
          status={metrics.jitter < 10 ? "success" : metrics.jitter < 20 ? "warning" : "danger"}
        />
        <MetricCard
          title="Packet Loss"
          value={metrics.packetLoss}
          unit="%"
          icon={<FileTerminal size={18} />}
          status={metrics.packetLoss < 1 ? "success" : metrics.packetLoss < 3 ? "warning" : "danger"}
        />
        <MetricCard
          title="DNS Delay"
          value={metrics.dnsDelay}
          unit="ms"
          icon={<Database size={18} />}
          status={metrics.dnsDelay < 30 ? "success" : metrics.dnsDelay < 70 ? "warning" : "danger"}
        />
        <MetricCard
          title="Bandwidth"
          value={metrics.bandwidth}
          unit="Mbps"
          icon={<Wifi size={18} />}
          status={metrics.bandwidth > 80 ? "success" : metrics.bandwidth > 40 ? "warning" : "danger"}
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <MultiLineChart
          title="Network Latency & Baseline"
          description="Real-time latency compared to target baseline"
          data={latencyData.map(d => ({ 
            timestamp: d.timestamp, 
            latency: d.latency, 
            baseline: d.baseline 
          }))}
          lines={[
            { id: 'latency', name: 'Latency (ms)', color: '#F87171' },
            { id: 'baseline', name: 'Target', color: '#22C55E' }
          ]}
          yAxisLabel="ms"
          height={250}
        />
        <MultiLineChart
          title="Bandwidth Trend"
          description="Bandwidth usage over time with target threshold"
          data={bandwidthData.map(d => ({ 
            timestamp: d.timestamp, 
            bandwidth: d.bandwidth,
            target: d.target
          }))}
          lines={[
            { id: 'bandwidth', name: 'Bandwidth (Mbps)', color: '#00B7EB' },
            { id: 'target', name: 'Target', color: '#8B5CF6' }
          ]}
          yAxisLabel="Mbps"
          height={250}
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <ProtocolDistribution data={protocolData} />
        <MultiLineChart
          title="Connection Quality"
          description="Jitter and packet loss affecting quality"
          data={jitterData.map(d => ({ 
            timestamp: d.timestamp, 
            jitter: d.jitter,
            packetLoss: d.packetLoss 
          }))}
          lines={[
            { id: 'jitter', name: 'Jitter (ms)', color: '#F06292' },
            { id: 'packetLoss', name: 'Packet Loss (%)', color: '#EF5350' }
          ]}
          yAxisLabel="Value"
          height={250}
        />
      </div>
      
      <div className="mb-6">
        <NetworkAnalysis metrics={metrics} />
      </div>
    </div>
  );
};

export default Dashboard;

*/

/*
Original dashboard

import { useState, useEffect } from "react";
import NetworkHealthGauge from "@/components/dashboard/NetworkHealthGauge";
import MetricCard from "@/components/dashboard/MetricCard";
import StatusCard from "@/components/dashboard/StatusCard";
import AlertBanner from "@/components/dashboard/AlertBanner";
import ProtocolDistribution from "@/components/dashboard/ProtocolDistribution";
import MultiLineChart from "@/components/dashboard/MultiLineChart";
import NetworkAnalysis from "@/components/dashboard/NetworkAnalysis";
import { Clock, Wifi, FileTerminal, Database, Activity } from "lucide-react";

interface MetricsData {
  latency: number;
  jitter: number;
  packetLoss: number;
  bandwidth: number;
  dnsDelay: number;
  healthScore: number;
  stability: "stable" | "unstable" | "critical";
  congestion: "stable" | "unstable" | "critical";
  protocolData: { name: string; value: number }[];
  topAppsData: { name: string; value: number }[];
}

interface LatencyDataPoint {
  timestamp: number;
  latency: number;
  baseline: number;
}

interface BandwidthDataPoint {
  timestamp: number;
  bandwidth: number;
  target: number;
}

interface JitterDataPoint {
  timestamp: number;
  jitter: number;
  packetLoss: number;
}

const Dashboard = () => {
  const [metrics, setMetrics] = useState<MetricsData>({
    latency: 0,
    jitter: 0,
    packetLoss: 0,
    bandwidth: 0,
    dnsDelay: 0,
    healthScore: 50,
    stability: "stable",
    congestion: "stable",
    protocolData: [],
    topAppsData: []
  });
  const [latencyData, setLatencyData] = useState<LatencyDataPoint[]>([]);
  const [bandwidthData, setBandwidthData] = useState<BandwidthDataPoint[]>([]);
  const [jitterData, setJitterData] = useState<JitterDataPoint[]>([]);
  const [protocolData, setProtocolData] = useState<{ name: string; value: number }[]>([]);
  const [topAppsData, setTopAppsData] = useState<{ name: string; value: number }[]>([]);
  const [showAlert, setShowAlert] = useState(false);
  const [showNotifications, setShowNotifications] = useState(true);

  const fetchMetrics = async () => {
    try {
      const response = await fetch('http://localhost:3001/metrics');
      if (!response.ok) throw new Error('Failed to fetch metrics');
      const data = await response.json();
      setMetrics({
        latency: data.latency,
        jitter: data.jitter,
        packetLoss: data.packetLoss,
        bandwidth: data.bandwidth,
        dnsDelay: data.dnsDelay,
        healthScore: data.healthScore,
        stability: data.stability,
        congestion: data.congestion,
        protocolData: data.protocolData,
        topAppsData: data.topAppsData
      });

      const now = Date.now();
      setLatencyData(prev => [
        ...prev.slice(-59),
        { timestamp: now, latency: data.latency, baseline: 50 }
      ]);
      setBandwidthData(prev => [
        ...prev.slice(-59),
        { timestamp: now, bandwidth: data.bandwidth, target: 90 }
      ]);
      setJitterData(prev => [
        ...prev.slice(-59),
        { timestamp: now, jitter: data.jitter, packetLoss: data.packetLoss * 3 }
      ]);
      setProtocolData(data.protocolData);
      setTopAppsData(data.topAppsData);
      setShowAlert(data.healthScore < 50 && showNotifications);
    } catch (err) {
      console.error('Fetch metrics error:', err);
    }
  };

  useEffect(() => {
    const savedSettings = localStorage.getItem('pxmonitor-settings');
    if (savedSettings) {
      try {
        const parsedSettings = JSON.parse(savedSettings);
        const notificationsSetting = parsedSettings
          .find((group: any) => group.id === "general")
          ?.settings.find((setting: any) => setting.id === "notifications")?.value;
        if (notificationsSetting !== undefined) {
          setShowNotifications(notificationsSetting);
        }
      } catch (error) {
        console.error("Error loading notification settings:", error);
      }
    }

    // Fetch metrics initially and every 5 seconds
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);

    return () => clearInterval(interval);
  }, [showNotifications]);

  useEffect(() => {
    const handleSettingsUpdate = (event: any) => {
      if (event.detail?.showNotifications !== undefined) {
        setShowNotifications(event.detail.showNotifications);
      }
    };
    window.addEventListener('settingsUpdated', handleSettingsUpdate);
    return () => window.removeEventListener('settingsUpdated', handleSettingsUpdate);
  }, []);

  const handleFixNetwork = async () => {
    try {
      const response = await fetch('http://localhost:3001/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(metrics)
      });
      const { analysis } = await response.json();
      console.log('Network fix suggestions:', analysis);
      setMetrics(prev => ({
        ...prev,
        healthScore: Math.min(85, prev.healthScore + 40),
        latency: Math.max(20, prev.latency - 50),
        packetLoss: Math.max(0.2, prev.packetLoss - 5),
        bandwidth: Math.min(95, prev.bandwidth + 20),
        stability: "stable" as const,
        congestion: "stable" as const
      }));
      setShowAlert(false);
    } catch (err) {
      console.error('Error fixing network:', err);
    }
  };

  return (
    <div className="grid-bg">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold font-montserrat">Network Dashboard</h1>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-muted/20 text-muted-foreground text-sm">
          <Clock size={16} />
          <span>Updated just now</span>
        </div>
      </div>
      
      {showAlert && (
        <AlertBanner
          message="Your network performance is degraded!"
          type="error"
          actionText="Fix Now"
          onAction={handleFixNetwork}
          className="mb-6 max-w-4xl"
        />
      )}
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <NetworkHealthGauge score={metrics.healthScore} />
        <StatusCard 
          title="Connection Stability" 
          status={metrics.stability} 
          description={
            metrics.stability === "stable" 
              ? "Your connection is reliable and stable" 
              : "Your connection is experiencing issues"
          }
        />
        <StatusCard 
          title="Network Congestion" 
          status={metrics.congestion}
          description={
            metrics.congestion === "stable" 
              ? "Network traffic is flowing smoothly" 
              : "Network traffic is congested"
          }
        />
      </div>
      
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <MetricCard
          title="Latency"
          value={metrics.latency}
          unit="ms"
          icon={<Activity size={18} />}
          status={metrics.latency < 50 ? "success" : metrics.latency < 100 ? "warning" : "danger"}
        />
        <MetricCard
          title="Jitter"
          value={metrics.jitter}
          unit="ms"
          icon={<Activity size={18} />}
          status={metrics.jitter < 10 ? "success" : metrics.jitter < 20 ? "warning" : "danger"}
        />
        <MetricCard
          title="Packet Loss"
          value={metrics.packetLoss}
          unit="%"
          icon={<FileTerminal size={18} />}
          status={metrics.packetLoss < 1 ? "success" : metrics.packetLoss < 3 ? "warning" : "danger"}
        />
        <MetricCard
          title="DNS Delay"
          value={metrics.dnsDelay}
          unit="ms"
          icon={<Database size={18} />}
          status={metrics.dnsDelay < 30 ? "success" : metrics.dnsDelay < 70 ? "warning" : "danger"}
        />
        <MetricCard
          title="Bandwidth"
          value={metrics.bandwidth}
          unit="Mbps"
          icon={<Wifi size={18} />}
          status={metrics.bandwidth > 80 ? "success" : metrics.bandwidth > 40 ? "warning" : "danger"}
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <MultiLineChart
          title="Network Latency & Baseline"
          description="Real-time latency compared to target baseline"
          data={latencyData.map(d => ({ 
            timestamp: d.timestamp, 
            latency: d.latency, 
            baseline: d.baseline 
          }))}
          lines={[
            { id: 'latency', name: 'Latency (ms)', color: '#F87171' },
            { id: 'baseline', name: 'Target', color: '#22C55E' }
          ]}
          yAxisLabel="ms"
          height={250}
        />
        <MultiLineChart
          title="Bandwidth Trend"
          description="Bandwidth usage over time with target threshold"
          data={bandwidthData.map(d => ({ 
            timestamp: d.timestamp, 
            bandwidth: d.bandwidth,
            target: d.target
          }))}
          lines={[
            { id: 'bandwidth', name: 'Bandwidth (Mbps)', color: '#00B7EB' },
            { id: 'target', name: 'Target', color: '#8B5CF6' }
          ]}
          yAxisLabel="Mbps"
          height={250}
        />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <ProtocolDistribution data={protocolData} />
        <MultiLineChart
          title="Connection Quality"
          description="Jitter and packet loss affecting quality"
          data={jitterData.map(d => ({ 
            timestamp: d.timestamp, 
            jitter: d.jitter,
            packetLoss: d.packetLoss 
          }))}
          lines={[
            { id: 'jitter', name: 'Jitter (ms)', color: '#F06292' },
            { id: 'packetLoss', name: 'Packet Loss (%)', color: '#EF5350' }
          ]}
          yAxisLabel="Value"
          height={250}
        />
      </div>
      
      <div className="mb-6">
        <NetworkAnalysis metrics={metrics} />
      </div>
    </div>
  );
};

export default Dashboard;
*/