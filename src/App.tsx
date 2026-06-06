/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import {
  Play,
  Square,
  Plus,
  Layers,
  Terminal,
  Copy,
  Check,
  RotateCcw,
  Settings,
  Activity,
  Wifi,
  ArrowRight,
  Lock,
  Unlock,
  FileCode,
  ShieldCheck,
  Filter,
  Sliders,
  HelpCircle,
  Eye,
  RefreshCw,
  Clock,
  Briefcase
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { CODEBASE_FILES, CodeFile } from "./codebase";

// Constants for Simulator defaults
const DUMMY_SRC_IP = "10.0.0.5";
const DEFAULT_PEM_SHA = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890";

interface PacketSim {
  id: string;
  type: "IPv4" | "IPv6" | "Padding" | "Management";
  size: number; // Payload size in bytes
  payload: string;
  isPriority: boolean;
  dscpName?: string;
  timestamp: string;
}

interface TransmittedChunk {
  id: string;
  timestamp: string;
  packets: PacketSim[];
  paddingBytesAdded: number;
  totalSerializedBytes: number;
  paddingModeUsed: number;
  filteredOutCount: number;
}

export default function App() {
  // Config States
  const [bunchSize, setBunchSize] = useState<number>(1000);
  const [syncTimeout, setSyncTimeout] = useState<number>(0.8); // seconds
  const [paddingMode, setPaddingMode] = useState<number>(2); // 1 = None, 2 = Full, 3 = Random
  const [packetFilter, setPacketFilter] = useState<number>(0); // 0 = None, 4 = IPv4, 6 = IPv6
  const [sslMode, setSslMode] = useState<"secure" | "trusted" | "insecure">("insecure");
  const [clientIp, setClientIp] = useState<string>(DUMMY_SRC_IP);
  const [customFingerprint, setCustomFingerprint] = useState<string>(DEFAULT_PEM_SHA);

  // Connection & Handshake Simulator state
  const [connected, setConnected] = useState<boolean>(false);
  const [handshaking, setHandshaking] = useState<boolean>(false);
  const [assignedClientId, setAssignedClientId] = useState<string>("");
  const [negotiatedTimeout, setNegotiatedTimeout] = useState<number>(0.8);
  const [negotiatedPaddingMode, setNegotiatedPaddingMode] = useState<number>(2);

  // Traffic Queue & Stats Simulator state
  const [packetQueue, setPacketQueue] = useState<PacketSim[]>([]);
  const [chunks, setChunks] = useState<TransmittedChunk[]>([]);
  const [terminalLogs, setTerminalLogs] = useState<Array<{ id: string; msg: string; level: "INFO" | "DEBUG" | "WARN" | "ERR" | "SYS"; timestamp: string }>>([]);
  const [firstPacketTime, setFirstPacketTime] = useState<number | null>(null);
  const [countdownPercent, setCountdownPercent] = useState<number>(0);

  // UI tabs & view options
  const [activeTab, setActiveTab] = useState<"playground" | "codebase" | "guide">("playground");
  const [selectedFile, setSelectedFile] = useState<CodeFile>(CODEBASE_FILES[0]);
  const [copiedFileIndex, setCopiedFileIndex] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // Statistics State
  const [stats, setStats] = useState({
    totalRx: 0,
    totalTx: 0,
    payloadBytes: 0,
    paddedBytes: 0,
    packetsFiltered: 0,
  });

  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Initialize Terminal Logs with System Message
  useEffect(() => {
    addLog("SSL TCP Tunnel Server init logic. Invoking self-signed cert validation check...", "SYS");
    addLog("Default server credentials mapped. Bind complete: SSL listener on 0.0.0.0:18443", "SYS");
  }, []);

  // Handle auto-scroll for terminal logs
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLogs]);

  // Helper: Append console log
  const addLog = (msg: string, level: "INFO" | "DEBUG" | "WARN" | "ERR" | "SYS") => {
    const timeStr = new Date().toLocaleTimeString("en-GB", { hour12: false });
    setTerminalLogs((prev) => [
      ...prev,
      {
        id: Math.random().toString(36).substr(2, 9),
        msg,
        level,
        timestamp: timeStr,
      },
    ]);
  };

  // Clear visual simulation states
  const resetSimulator = () => {
    setPacketQueue([]);
    setChunks([]);
    setFirstPacketTime(null);
    setCountdownPercent(0);
    setStats({
      totalRx: 0,
      totalTx: 0,
      payloadBytes: 0,
      paddedBytes: 0,
      packetsFiltered: 0,
    });
    addLog("Simulation states and queues reset successfully.", "INFO");
  };

  // Core Connection Establishment Handshake Simulation
  const handleConnectToggle = () => {
    if (connected) {
      // Disconnecting
      addLog(`Sending client closure interrupt frame to server gateway.`, "INFO");
      addLog(`Tunnel connection terminated gracefully for Client: ${assignedClientId}`, "WARN");
      setConnected(false);
      setAssignedClientId("");
      setPacketQueue([]);
      setFirstPacketTime(null);
      setCountdownPercent(0);
    } else {
      // Connecting
      setHandshaking(true);
      addLog(`Initiating TCP SSL socket connection to 127.0.0.1:18443 (SSL verification Mode: ${sslMode})`, "INFO");
      
      if (sslMode === "trusted") {
        addLog(`Analyzing peer SHA256 Certificate Fingerprint...`, "DEBUG");
        addLog(`Found Peer Hash: ${DEFAULT_PEM_SHA.substring(0, 16)}...`, "DEBUG");
        if (customFingerprint.toLowerCase().trim().replace(/:/g, "") !== DEFAULT_PEM_SHA) {
          setTimeout(() => {
            addLog(`SSL Security Alert: Certificate Fingerprint mismatch! Secure socket terminated.`, "ERR");
            setHandshaking(false);
          }, 1200);
          return;
        }
        addLog(`Cryptographic signature matched reference fingerprint! Validation succeeded.`, "DEBUG");
      } else if (sslMode === "secure") {
        addLog(`Verifying certificate chain with local OS trusted CAs...`, "DEBUG");
        addLog(`Chain verified successfully.`, "DEBUG");
      } else {
        addLog(`Insecure SSL mode selected. Bypassing peer certificate authority checks safely.`, "WARN");
      }

      // Step 2: Protocol Handshake suggestion
      setTimeout(() => {
        addLog(`[Client Tx] Sending MGMT_HANDSHAKE suggestion (Version 0, Subtype 1): clientId=${clientIp}, paddingMode=${paddingMode}, syncingTimeout=${syncTimeout}s, backend=echo`, "INFO");
        
        setTimeout(() => {
          // Server accepts and allocates ID
          let allocated = clientIp;
          if (clientIp === "0.0.0.0" || !clientIp.trim()) {
            allocated = "10.0.0.1";
            addLog(`[Server Rx] Client proposed ID=0.0.0.0. Allocating new unique Client ID: ${allocated}`, "WARN");
          } else {
            addLog(`[Server Rx] Handshake suggestion received relative to client ${clientIp}. Checking socket pool...`, "DEBUG");
          }

          addLog(`[Server Tx] Emitting negotiated setup reply (Version 0, Subtype 1): clientId=${allocated}, paddingMode=${paddingMode}, syncingTimeout=${syncTimeout}s, backend=echo`, "INFO");

          setTimeout(() => {
            setAssignedClientId(allocated);
            setNegotiatedTimeout(syncTimeout);
            setNegotiatedPaddingMode(paddingMode);
            setConnected(true);
            setHandshaking(false);
            addLog(`[Client Rx] Connection Handshake success! Mapped Client ID: ${allocated}. Tunnel established! Ready to route frames.`, "SYS");
          }, 500);

        }, 600);

      }, 800);
    }
  };

  // Periodic scheduler verifying queuing timers and forcing timeouts flush
  useEffect(() => {
    if (!connected) return;

    const interval = setInterval(() => {
      if (packetQueue.length === 0) {
        setCountdownPercent(0);
        return;
      }

      const now = Date.now();
      const startTime = firstPacketTime || now;
      const elapsedMs = now - startTime;
      const targetTimeoutMs = negotiatedTimeout * 1000;

      if (negotiatedTimeout === 0.0) {
        // Sync 0 means immediate transmission
        executeFlush();
        return;
      }

      const percent = Math.min(100, (elapsedMs / targetTimeoutMs) * 100);
      setCountdownPercent(percent);

      if (elapsedMs >= targetTimeoutMs) {
        addLog(`[Queue Sync] Timeout threshold (${negotiatedTimeout}s) expired since first packet queue entry. Flushing...`, "DEBUG");
        executeFlush();
      }
    }, 40);

    return () => clearInterval(interval);
  }, [connected, packetQueue, firstPacketTime, negotiatedTimeout]);

  // Execute Buncher Flush
  const executeFlush = () => {
    if (packetQueue.length === 0) return;

    // Calculate current bunch size
    // Each packet occupies: 5 bytes header + cargo size
    let currentSize = packetQueue.reduce((acc, p) => acc + (5 + p.size), 0);
    let paddingBytes = 0;
    const initialSize = currentSize;

    // Resolve padding modes
    if (negotiatedPaddingMode === 2) { // Full padding to preferred bunch size
      const maxPadding = bunchSize - currentSize;
      if (maxPadding >= 5) {
        paddingBytes = maxPadding;
        currentSize += paddingBytes;
      }
    } else if (negotiatedPaddingMode === 3) { // Random padding
      const maxPadding = bunchSize - currentSize;
      if (maxPadding >= 5) {
        paddingBytes = Math.floor(Math.random() * (maxPadding - 5)) + 5;
        currentSize += paddingBytes;
      }
    }

    // Packet type filtering inside Client/Server echo backend logic
    let echoedPackets: PacketSim[] = [];
    let filteredOut = 0;

    packetQueue.forEach((pkt) => {
      let isAllowed = true;
      if (packetFilter !== 0) {
        const verCode = pkt.type === "IPv4" ? 4 : (pkt.type === "IPv6" ? 6 : 0);
        if (verCode !== packetFilter) {
          isAllowed = false;
        }
      }

      if (isAllowed) {
        // Server Echo backend bounces it back
        echoedPackets.push({
          ...pkt,
          id: Math.random().toString(36).substr(2, 9),
          payload: `[ECHO-REPLY] ${pkt.payload}`,
          timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false })
        });
      } else {
        filteredOut++;
      }
    });

    const newChunk: TransmittedChunk = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
      packets: [...packetQueue],
      paddingBytesAdded: paddingBytes,
      totalSerializedBytes: currentSize,
      paddingModeUsed: negotiatedPaddingMode,
      filteredOutCount: filteredOut
    };

    // Update chunks visual list
    setChunks((prev) => [newChunk, ...prev].slice(0, 8));

    // Update Stats
    setStats((prev) => ({
      ...prev,
      totalTx: prev.totalTx + packetQueue.length,
      totalRx: prev.totalRx + echoedPackets.length,
      payloadBytes: prev.payloadBytes + initialSize,
      paddedBytes: prev.paddedBytes + paddingBytes,
      packetsFiltered: prev.packetsFiltered + filteredOut
    }));

    // Logs
    addLog(`[Tunnel Tx] Buncher emitted TCP SSL core segment! PacketsCount=${packetQueue.length}, PayloadBytes=${initialSize}B, PaddingPacketsVer15Bytes=${paddingBytes}B. Total Segment size=${currentSize}B`, "INFO");
    if (paddingBytes > 0) {
      addLog(`[Tunnel Padding] Sub-framed 1 Version 15 Padding Packet of length ${paddingBytes - 5} bytes into the bunch.`, "DEBUG");
    }

    if (filteredOut > 0) {
      addLog(`[Server Filter] Echo backend suppressed ${filteredOut} packets. Rule policy: Filter only IPv${packetFilter}`, "WARN");
    }

    if (echoedPackets.length > 0) {
      addLog(`[Server Rx/Tx] Echo Backend successfully parsed client payload packets, translated remote ID ${assignedClientId} -> IPv6 address ::ffff:${assignedClientId}, and bounced back ${echoedPackets.length} packets successfully.`, "SYS");
    }

    // Reset queue state
    setPacketQueue([]);
    setFirstPacketTime(null);
    setCountdownPercent(0);
  };

  // Trigger outbound package payload injection
  const injectPacket = (type: "IPv4" | "IPv6", isPriority: boolean = false) => {
    if (!connected) {
      addLog("Cannot inject traffic packet: Establish the SSL tunnel connection first.", "ERR");
      return;
    }

    const idStr = Math.random().toString(36).substr(2, 9);
    const sizeBytes = isPriority ? 64 : Math.floor(Math.random() * 120) + 40; // payload size
    
    // Simulate DSCP tags
    let dscpTag = "";
    if (isPriority) {
      dscpTag = type === "IPv4" ? "VoIP EF-46 (Type of Service=0xB8)" : "SSH Interactive CS5-40 (Traffic Class=0xA0)";
    }

    const payloadName = isPriority 
      ? `Real-time Priority Frame: ${type} ${dscpTag}` 
      : `Ordinary ${type} packet data block`;

    const newPkt: PacketSim = {
      id: idStr,
      type,
      size: sizeBytes,
      payload: payloadName,
      isPriority,
      dscpName: dscpTag ? dscpTag : undefined,
      timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false })
    };

    addLog(`[Client App] Injected packet: ${type} payload of ${sizeBytes} bytes.`, "DEBUG");

    if (isPriority) {
      addLog(`[Priority Interrupt] High priority DSCP tag detected (${dscpTag}) on incoming packet. Demanding IMMEDIATE transmission!`, "WARN");
    }

    // Buncher logic flow
    // 1. Check if adding this packet would exceed our Preferred Bunch Size limit
    const currentQueueSerialized = packetQueue.reduce((acc, p) => acc + (5 + p.size), 0);
    const incomingSerialized = 5 + sizeBytes;

    if (currentQueueSerialized + incomingSerialized > bunchSize) {
      addLog(`[Buncher Limit] Incoming packet of ${incomingSerialized} bytes exceeds remaining segment capacity (${bunchSize - currentQueueSerialized}B left out of ${bunchSize}B target size). Forcing sync on existing queue.`, "WARN");
      
      // Flush first
      executeFlush();

      // Enqueue the new one
      setPacketQueue([newPkt]);
      setFirstPacketTime(Date.now());
      addLog(`Enqueued ${type} packet to new bunch.`, "DEBUG");

      // If priority, immediately send this new queue as well!
      if (isPriority) {
        addLog(`[Priority Interrupt] Instantly flushing new priority entry...`, "DEBUG");
        // We can schedule instant flush
        setTimeout(() => executeFlush(), 10);
      }
    } else {
      // Normal queuing add
      setPacketQueue((prev) => {
        const nextQueue = [...prev, newPkt];
        if (prev.length === 0) {
          setFirstPacketTime(Date.now());
        }
        return nextQueue;
      });

      // If priority, trigger immediate flush
      if (isPriority) {
        setTimeout(() => executeFlush(), 10);
      }
    }
  };

  // Helper file copy to clipboard
  const handleCopyCode = () => {
    navigator.clipboard.writeText(selectedFile.content);
    setCopiedFileIndex(true);
    setTimeout(() => setCopiedFileIndex(false), 2000);
  };

  // Helper copy CLI command
  const handleCopyCmd = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  // Calculate dynamic CLI parameters
  const serverCmd = `async-tunnel server --host 0.0.0.0 --port 18443 --pem server.pem --console-level INFO`;
  const clientCmd = `async-tunnel client --host 127.0.0.1 --port 18443 --client-id ${clientIp} --padding ${paddingMode} --timeout ${syncTimeout} --ssl-mode ${sslMode} ${sslMode === "trusted" ? `--fingerprint ${customFingerprint.substring(0,12)}` : ""}`;

  return (
    <div id="tunnel-dashboard-root" className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased overflow-x-hidden selection:bg-cyan-500 selection:text-slate-900">
      
      {/* 1. HEADER SECTION */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex flex-wrap justify-between items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-br from-cyan-500 to-indigo-600 p-2.5 rounded-xl text-slate-950 shadow-lg shadow-cyan-500/10">
            <Layers className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-sans font-medium text-lg tracking-tight text-white">Async SSL TCP Tunnel Simulator</span>
              <span className="text-[10px] bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded font-mono border border-cyan-500/20 uppercase">v1.0.0</span>
            </div>
            <p className="text-xs text-slate-400">Interactive packet bunching, random padding & dual-IP routing playground</p>
          </div>
        </div>

        {/* Global Connection state badge */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 bg-slate-900 px-3.5 py-1.5 rounded-lg border border-slate-800">
            <span className={`h-2.5 w-2.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : (handshaking ? 'bg-amber-500 animate-spin border-t-2 border-transparent' : 'bg-slate-600')}`} />
            <span className="text-xs font-mono font-medium text-slate-300">
              {connected ? `TUNNEL ACTIVE: ${assignedClientId}` : (handshaking ? "TLS HANDSHAKE..." : "TUNNEL OFFLINE")}
            </span>
          </div>

          <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab("playground")}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === "playground" ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-white'}`}
            >
              Playground
            </button>
            <button
              onClick={() => setActiveTab("codebase")}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === "codebase" ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-white'}`}
            >
              Explore Code
            </button>
            <button
              onClick={() => setActiveTab("guide")}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === "guide" ? 'bg-cyan-500 text-slate-950 font-semibold' : 'text-slate-400 hover:text-white'}`}
            >
              Usage Guide
            </button>
          </div>
        </div>
      </header>

      {/* 2. MAIN WORKSPACE */}
      <main className="flex-1 max-w-[1700px] w-full mx-auto p-6">
        <AnimatePresence mode="wait">
          {activeTab === "playground" && (
            <motion.div
              key="playground"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              transition={{ duration: 0.25 }}
              className="grid grid-cols-1 xl:grid-cols-12 gap-6"
            >
              
              {/* PANEL 1: CONTROL SIDEBAR (4 columns) */}
              <section className="xl:col-span-4 flex flex-col gap-6">
                
                {/* Connection Widget */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-5 shadow-2xl relative overflow-hidden group">
                  <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                    <Wifi className="h-24 w-24 text-slate-200" />
                  </div>
                  
                  <h3 className="text-sm font-sans font-medium text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Sliders className="h-4 w-4 text-cyan-400" />
                    SSL Tunnel Initiation
                  </h3>

                  <div className="flex flex-col gap-4">
                    
                    {/* Input Client IP */}
                    <div>
                      <label className="block text-xs text-slate-400 font-medium mb-1.5 font-sans">
                        Requested Client Identity (IPv4-style)
                      </label>
                      <input
                        type="text"
                        value={clientIp}
                        onChange={(e) => setClientIp(e.target.value)}
                        disabled={connected || handshaking}
                        placeholder="e.g. 10.0.0.5 (or 0.0.0.0 for auto)"
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50"
                      />
                      <p className="text-[10px] text-slate-500 mt-1">
                        Passed inside handshake. Suggest standard IPv4 address representation.
                      </p>
                    </div>

                    {/* SSL Mode Selection */}
                    <div>
                      <label className="block text-xs text-slate-400 font-medium mb-1.5">
                        SSL Authentication & Self-Signed Verification
                      </label>
                      <div className="grid grid-cols-3 gap-2">
                        {(["insecure", "trusted", "secure"] as const).map((mode) => (
                          <button
                            key={mode}
                            onClick={() => setSslMode(mode)}
                            disabled={connected || handshaking}
                            className={`px-2 py-2 rounded-xl text-xs font-medium border capitalize flex flex-col items-center justify-center gap-1.5 transition-all ${sslMode === mode ? 'bg-cyan-500/10 border-cyan-400 text-cyan-400 font-semibold' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-300'}`}
                          >
                            {mode === "secure" ? <Lock className="h-3.5 w-3.5" /> : (mode === "trusted" ? <ShieldCheck className="h-3.5 w-3.5" /> : <Unlock className="h-3.5 w-3.5" />)}
                            {mode}
                          </button>
                        ))}
                      </div>

                      {sslMode === "trusted" && (
                        <div className="mt-3">
                          <label className="block text-[10px] text-slate-400 mb-1">
                            Preshared Reference Cert Hash (SHA-256)
                          </label>
                          <input
                            type="text"
                            value={customFingerprint}
                            onChange={(e) => setCustomFingerprint(e.target.value)}
                            disabled={connected || handshaking}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono uppercase focus:outline-none focus:border-cyan-500"
                          />
                          <p className="text-[9px] text-slate-500 mt-0.5">
                            Tip: Matches actual self-signed hash validation. Clear mismatch triggers secure shutdown.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* BIG HANDSHAKE TRIGGER BUTTON */}
                    <button
                      onClick={handleConnectToggle}
                      disabled={handshaking}
                      className={`w-full py-3 px-4 rounded-xl font-medium tracking-wide text-sm flex items-center justify-center gap-2 cursor-pointer border shadow-lg transition-all ${connected ? 'bg-red-500 hover:bg-red-600 text-white border-red-400 shadow-red-500/10' : (handshaking ? 'bg-slate-900 text-amber-500 border-slate-800 hover:none' : 'bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold border-cyan-400/30' )}`}
                    >
                      {handshaking ? (
                        <>
                          <RefreshCw className="h-4 w-4 animate-spin" />
                          Handshaking SSL Gate...
                        </>
                      ) : connected ? (
                        <>
                          <Square className="h-4 w-4" />
                          Terminate SSL Tunnel
                        </>
                      ) : (
                        <>
                          <Play className="h-4 w-4" fill="currentColor" />
                          Establish SSL Connection
                        </>
                      )}
                    </button>

                  </div>
                </div>

                {/* Bunching Protocol Configuration Panel */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-5 shadow-2xl flex flex-col gap-5">
                  <h3 className="text-sm font-sans font-medium text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Sliders className="h-4 w-4 text-cyan-400" />
                    Bunching & Padding Settings
                  </h3>

                  {/* Bunch target preferred Size */}
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="text-xs text-slate-400 font-medium">
                        Preferred Bunch Size (TCP segment limit)
                      </label>
                      <span className="text-xs font-mono font-semibold text-cyan-400">
                        {bunchSize} bytes
                      </span>
                    </div>
                    <input
                      type="range"
                      min="300"
                      max="1500"
                      step="50"
                      value={bunchSize}
                      onChange={(e) => setBunchSize(Number(e.target.value))}
                      className="w-full h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                    />
                    <div className="flex justify-between text-[9px] text-slate-600 mt-1 font-mono">
                      <span>300 B (Small Segment)</span>
                      <span>1500 B (Ethernet MTU / MSS target)</span>
                    </div>
                  </div>

                  {/* Timeout parameter slider */}
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="text-xs text-slate-400 font-medium">
                        Syncing Timeout (Seconds)
                      </label>
                      <span className="text-xs font-mono font-semibold text-cyan-400">
                        {syncTimeout === 0 ? "0.0s (Instant-sync)" : `${syncTimeout}s`}
                      </span>
                    </div>
                    <input
                      type="range"
                      min="0.0"
                      max="3.0"
                      step="0.2"
                      value={syncTimeout}
                      onChange={(e) => {
                        const val = Number(e.target.value);
                        setSyncTimeout(val);
                        if (connected) {
                          // Update on runtime simulated negotiatedTimeout
                          setNegotiatedTimeout(val);
                          addLog(`[Config renegotiate] Syncing timeout renegotiated dynamically on connected node -> ${val}s`, "INFO");
                        }
                      }}
                      className="w-full h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                    />
                    <div className="flex justify-between text-[9px] text-slate-600 mt-1 font-mono">
                      <span>0.0s (Immediate Flush)</span>
                      <span>3.0s (Large buffering window)</span>
                    </div>
                  </div>

                  {/* Padding Modes Selection */}
                  <div>
                    <label className="block text-xs text-slate-400 font-medium mb-1.5">
                      Stream Padding Options (Version 15 Junk Packets)
                    </label>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { modeObj: 1, label: "None", desc: "No padding" },
                        { modeObj: 2, label: "Full Bunch", desc: "Pad to Bunch target size" },
                        { modeObj: 3, label: "Random size", desc: "Pad randomly to target" }
                      ].map((item) => (
                        <button
                          key={item.modeObj}
                          onClick={() => {
                            setPaddingMode(item.modeObj);
                            if (connected) {
                              setNegotiatedPaddingMode(item.modeObj);
                              addLog(`[Config renegotiate] Padding mode shifted to mode ${item.modeObj} (${item.label}) in server gateway session`, "INFO");
                            }
                          }}
                          className={`px-1.5 py-2 border rounded-xl text-xs transition-all flex flex-col items-center justify-center gap-1 ${paddingMode === item.modeObj ? 'bg-cyan-500/10 border-cyan-400 text-cyan-400 font-semibold' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-300'}`}
                        >
                          <span className="font-medium text-[11px]">{item.label}</span>
                          <span className="text-[8px] text-slate-500 text-center uppercase leading-none">{item.desc}</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Echo Backend Filter Option */}
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="text-xs text-slate-400 font-medium flex items-center gap-1.5">
                        <Filter className="h-3 w-3 text-cyan-400" />
                        Echo Backend Packet Filter
                      </label>
                      <span className="text-xs font-mono font-semibold text-cyan-400">
                        {packetFilter === 0 ? "None (Echo all)" : `IPv${packetFilter} only`}
                      </span>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { val: 0, label: "No Filter" },
                        { val: 4, label: "Filter IPv4" },
                        { val: 6, label: "Filter IPv6" }
                      ].map((item) => (
                        <button
                          key={item.val}
                          onClick={() => setPacketFilter(item.val)}
                          className={`px-2 py-2 border rounded-xl text-xs text-center font-medium transition-all ${packetFilter === item.val ? 'bg-cyan-500/10 border-cyan-400 text-cyan-400 font-semibold' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-300'}`}
                        >
                          {item.label}
                        </button>
                      ))}
                    </div>
                  </div>

                </div>

                {/* Dashboard Stats */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-5 shadow-2xl">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-sm font-sans font-medium text-slate-200 uppercase tracking-wider flex items-center gap-2">
                      <Activity className="h-4 w-4 text-cyan-400" />
                      Session Statistics
                    </h3>
                    <button
                      onClick={resetSimulator}
                      className="text-slate-500 hover:text-slate-300 transition-colors"
                      title="Reset statistics"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/40">
                      <span className="block text-[10px] text-slate-400 uppercase tracking-wider">Packets Sent (TX)</span>
                      <span className="text-xl font-mono font-bold text-white">{stats.totalTx}</span>
                    </div>
                    <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/40">
                      <span className="block text-[10px] text-slate-400 uppercase tracking-wider">Packets Recv (RX)</span>
                      <span className="text-xl font-mono font-bold text-white">{stats.totalRx}</span>
                    </div>
                    <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/40">
                      <span className="block text-[10px] text-slate-400 uppercase tracking-wider">Raw Payload Bytes</span>
                      <span className="text-base font-mono font-semibold text-cyan-400">{stats.payloadBytes} B</span>
                    </div>
                    <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/40">
                      <span className="block text-[10px] text-slate-400 uppercase tracking-wider">Junk Padding Added</span>
                      <span className="text-base font-mono font-semibold text-fuchsia-400">{stats.paddedBytes} B</span>
                    </div>
                  </div>
                </div>

              </section>

              {/* PANEL 2: PLAYGROUND INTERACTIVE WORKSPACE (8 columns) */}
              <section className="xl:col-span-8 flex flex-col gap-6">
                
                {/* Visual Section: Network Tunnel State & Packet Injector */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-6 shadow-2xl relative">
                  
                  <div className="flex justify-between items-center mb-6">
                    <h3 className="text-base font-sans font-medium text-slate-100 tracking-tight flex items-center gap-2">
                      <Layers className="h-5 w-5 text-cyan-400" />
                      Client Packet Bunching Queue & Injectors
                    </h3>
                    {connected && (
                      <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2.5 py-1 rounded-full border border-emerald-500/20 font-mono">
                        SSL Connection: ESTABLISHED
                      </span>
                    )}
                  </div>

                  {/* Packet Injectors Rows */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-6">
                    <button
                      onClick={() => injectPacket("IPv4", false)}
                      disabled={!connected}
                      className="px-4 py-3 bg-slate-900 border border-slate-850 hover:bg-slate-800/80 disabled:opacity-50 text-xs font-semibold rounded-xl text-slate-200 transition-all flex items-center justify-center gap-2"
                    >
                      <Plus className="h-4 w-4 text-cyan-400" />
                      Inject IPv4 (Regular)
                    </button>
                    <button
                      onClick={() => injectPacket("IPv6", false)}
                      disabled={!connected}
                      className="px-4 py-3 bg-slate-900 border border-slate-850 hover:bg-slate-800/80 disabled:opacity-50 text-xs font-semibold rounded-xl text-slate-200 transition-all flex items-center justify-center gap-2"
                    >
                      <Plus className="h-4 w-4 text-cyan-400" />
                      Inject IPv6 (Regular)
                    </button>
                    <button
                      onClick={() => injectPacket("IPv4", true)}
                      disabled={!connected}
                      className="px-4 py-3 bg-cyan-950/20 text-cyan-400 border border-cyan-800/30 hover:bg-cyan-900/20 disabled:opacity-50 text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2"
                    >
                      <Activity className="h-4 w-4 text-cyan-400" />
                      Inject IPv4 (VoIP EF Priority)
                    </button>
                    <button
                      onClick={() => injectPacket("IPv6", true)}
                      disabled={!connected}
                      className="px-4 py-3 bg-indigo-950/20 text-indigo-400 border border-indigo-800/30 hover:bg-indigo-900/20 disabled:opacity-50 text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2"
                    >
                      <Clock className="h-4 w-4 text-indigo-400" />
                      Inject IPv6 (SSH Priority)
                    </button>
                  </div>

                  {/* Client side Buffer Queue Visualization */}
                  <div className="bg-slate-900/60 rounded-xl p-5 border border-slate-900 relative">
                    <div className="flex justify-between items-center mb-3 text-xs text-slate-400">
                      <span className="font-medium flex items-center gap-1.5 uppercase tracking-wider text-[11px]">
                        <Settings className="h-3 w-3 text-cyan-400" />
                        Client Bunch Queue ({packetQueue.length} packet{packetQueue.length === 1 ? '' : 's'})
                      </span>
                      <span className="font-mono">
                        Current serialized size: <strong className="text-white">{packetQueue.reduce((acc, p) => acc + (5 + p.size), 0)} B</strong> / {bunchSize} B
                      </span>
                    </div>

                    <div className="min-h-[140px] flex items-center justify-center relative bg-slate-950/40 rounded-xl p-4 border border-slate-900/55">
                      {packetQueue.length === 0 ? (
                        <div className="text-center p-6 text-slate-500">
                          <Eye className="h-10 w-10 mx-auto opacity-20 mb-3" />
                          <p className="text-xs">Queue is currently empty. Inject IPv4 or IPv6 packets to watch how they accumulate in real-time before sending.</p>
                        </div>
                      ) : (
                        <div className="w-full flex flex-wrap gap-3 items-center justify-start content-start">
                          <AnimatePresence>
                            {packetQueue.map((pkt) => (
                              <motion.div
                                key={pkt.id}
                                layoutId={pkt.id}
                                initial={{ scale: 0.8, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.8, opacity: 0 }}
                                className={`p-3 rounded-xl border flex flex-col gap-1 text-[11px] font-mono min-w-[130px] transition-all ${pkt.isPriority ? 'bg-gradient-to-b from-cyan-950/40 to-slate-900 border-cyan-500 text-cyan-200' : 'bg-slate-900 border-slate-800 text-slate-300'}`}
                              >
                                <div className="flex justify-between items-center gap-2">
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${pkt.type === 'IPv4' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-indigo-500/10 text-indigo-400'}`}>
                                    {pkt.type}
                                  </span>
                                  {pkt.isPriority && (
                                    <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
                                  )}
                                  <span className="text-[10px] text-slate-500">{pkt.size}B</span>
                                </div>
                                <div className="mt-1 font-sans text-[10px] text-slate-400 truncate max-w-[150px]">
                                  {pkt.payload}
                                </div>
                                {pkt.isPriority && (
                                  <div className="text-[8px] bg-cyan-500/10 text-cyan-300 rounded px-1 mt-0.5 whitespace-nowrap overflow-hidden text-ellipsis">
                                    {pkt.dscpName}
                                  </div>
                                )}
                              </motion.div>
                            ))}
                          </AnimatePresence>
                        </div>
                      )}
                    </div>

                    {/* Sync countdown progress bar */}
                    {packetQueue.length > 0 && negotiatedTimeout > 0 && (
                      <div className="mt-4">
                        <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                          <span>Syncing Timeout countdown schedule</span>
                          <span className="font-mono">{countdownPercent.toFixed(0)}% elapsed</span>
                        </div>
                        <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                          <div
                            className="bg-cyan-500 h-full transition-all duration-75"
                            style={{ width: `${countdownPercent}%` }}
                          />
                        </div>
                      </div>
                    )}

                  </div>

                </div>

                {/* Simulated Output Blocks: Transmitted Segments Stream */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-6 shadow-2xl flex flex-col gap-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-sans font-medium text-slate-200 uppercase tracking-wider flex items-center gap-2">
                      <Layers className="h-4 w-4 text-cyan-400" />
                      TCP SSL Tunnel: Live Segments Transmitted
                    </h3>
                  </div>

                  <div className="min-h-[200px] flex flex-col gap-3 max-h-[400px] overflow-y-auto">
                    {chunks.length === 0 ? (
                      <div className="flex-1 flex flex-col items-center justify-center text-slate-600 border border-dashed border-slate-900 p-8 rounded-xl">
                        <HelpCircle className="h-8 w-8 text-slate-700 mb-3 opacity-30" />
                        <p className="text-xs">No TCP segments sent yet. Wait for syncing timeouts or inject priorities to see bunching and Version 15 payload frames.</p>
                      </div>
                    ) : (
                      chunks.map((chunk) => (
                        <div key={chunk.id} className="bg-slate-900/50 rounded-xl p-4 border border-slate-800/40 relative group hover:border-slate-800 transition-colors">
                          <div className="flex flex-wrap justify-between items-center text-xs mb-3 gap-2 border-b border-slate-800/50 pb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-sans font-semibold text-slate-200">Segment {chunk.id}</span>
                              <span className="text-slate-500 font-mono text-[10px]">{chunk.timestamp}</span>
                            </div>
                            <span className="bg-slate-800 text-slate-300 font-mono text-[10px] px-2 py-0.5 rounded">
                              Size Frame: <strong className="text-cyan-400">{chunk.totalSerializedBytes} bytes</strong>
                            </span>
                          </div>

                          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                            {/* Inner real packets */}
                            {chunk.packets.map((pkt, pIdx) => (
                              <div key={pIdx} className={`px-2 py-1.5 rounded-lg border border-slate-800 ${pkt.isPriority ? 'bg-cyan-500/5 border-cyan-400/30' : 'bg-slate-950'}`}>
                                <span className={pkt.type === 'IPv4' ? 'text-cyan-400' : 'text-indigo-400'}>{pkt.type}</span> ({pkt.size}B)
                              </div>
                            ))}

                            {/* visual indicator showing padding packets */}
                            {chunk.paddingBytesAdded > 0 && (
                              <div className="px-2 py-1.5 rounded-lg border border-dashed bg-fuchsia-950/20 border-fuchsia-500 text-fuchsia-300 flex items-center gap-1">
                                <Layers className="h-3 w-3" />
                                Padding Packet Ver.15 ({chunk.paddingBytesAdded}B)
                              </div>
                            )}
                          </div>

                          {chunk.filteredOutCount > 0 && (
                            <div className="mt-2 text-[10px] text-amber-400 font-mono">
                              * {chunk.filteredOutCount} packet{chunk.filteredOutCount === 1 ? '' : 's'} suppressed by backend filtering rules.
                            </div>
                          )}

                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Live Terminal Console logs (INFO / DEBUG / WARN) */}
                <div className="bg-slate-950 border border-slate-900 rounded-2xl p-4 shadow-2xl flex flex-col gap-2 relative">
                  <div className="flex justify-between items-center px-2 pb-2 border-b border-slate-900">
                    <span className="text-xs font-mono font-bold uppercase text-slate-400 flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-cyan-400" />
                      Client/Server Runtime logs
                    </span>
                    <button
                      onClick={() => setTerminalLogs([])}
                      className="text-[10px] text-slate-500 hover:text-slate-300 underline font-mono cursor-pointer"
                    >
                      Clear Logs
                    </button>
                  </div>

                  <div className="bg-slate-950 text-slate-300 rounded-lg p-3 h-[180px] overflow-y-auto font-mono text-[11px] leading-relaxed flex flex-col gap-1.5 select-text">
                    {terminalLogs.length === 0 ? (
                      <span className="text-slate-600 block italic">Shell idle. Log stream ready.</span>
                    ) : (
                      terminalLogs.map((log) => {
                        let colorClass = "text-slate-400";
                        if (log.level === "ERR") colorClass = "text-red-400 font-semibold";
                        if (log.level === "WARN") colorClass = "text-amber-400 font-medium";
                        if (log.level === "SYS") colorClass = "text-cyan-400 font-medium";
                        if (log.level === "INFO") colorClass = "text-slate-300";
                        if (log.level === "DEBUG") colorClass = "text-slate-500";

                        return (
                          <div key={log.id} className="flex gap-2 items-start justify-start hover:bg-slate-900/30 py-0.5 px-1 rounded transition-colors group">
                            <span className="text-slate-600 select-none text-[10px]">{log.timestamp}</span>
                            <span className={`text-[10px] font-bold select-none group-hover:opacity-100 opacity-80 min-w-[45px] inline-block`}>
                              [{log.level}]
                            </span>
                            <span className={colorClass}>{log.msg}</span>
                          </div>
                        );
                      })
                    )}
                    <div ref={terminalEndRef} />
                  </div>
                </div>

              </section>

            </motion.div>
          )}

          {activeTab === "codebase" && (
            <motion.div
              key="codebase"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              transition={{ duration: 0.25 }}
              className="grid grid-cols-1 xl:grid-cols-4 gap-6"
            >
              
              {/* Left sidebar: File selector list */}
              <div className="xl:col-span-1 bg-slate-950 border border-slate-900 rounded-2xl p-4 shadow-2xl flex flex-col gap-3">
                <h3 className="text-xs text-slate-400 uppercase tracking-wider px-2 font-mono flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-cyan-400" />
                  Codebase Tree
                </h3>
                <div className="flex flex-col gap-1 overflow-y-auto max-h-[600px]">
                  {CODEBASE_FILES.map((file, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setSelectedFile(file);
                        setCopiedFileIndex(false);
                      }}
                      className={`flex items-start gap-2.5 px-3 py-2.5 rounded-xl text-left border transition-all text-xs ${selectedFile.path === file.path ? 'bg-cyan-500/10 border-cyan-400 text-cyan-400 font-semibold shadow-lg' : 'bg-slate-900/50 border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900'}`}
                    >
                      <FileCode className="h-4 w-4 mt-0.5 flex-shrink-0" />
                      <div>
                        <div className="font-mono text-[11px] leading-tight text-white">{file.name}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">{file.path}</div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Right panel: Static Code viewer with simple highlights */}
              <div className="xl:col-span-3 bg-slate-950 border border-slate-900 rounded-2xl p-5 shadow-2xl flex flex-col gap-4">
                
                <div className="flex flex-wrap justify-between items-center gap-3 border-b border-slate-900 pb-3">
                  <div>
                    <h3 className="font-sans font-semibold text-lg text-white">{selectedFile.name}</h3>
                    <p className="text-xs text-slate-500 font-mono">{selectedFile.path}</p>
                  </div>
                  
                  <button
                    onClick={handleCopyCode}
                    className="flex items-center gap-2 px-4 py-2 border border-slate-800 bg-slate-900 text-xs font-semibold rounded-xl text-slate-200 hover:bg-slate-800 transition-all select-none"
                  >
                    {copiedFileIndex ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        Copied File!
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5 text-cyan-400" />
                        Copy Code
                      </>
                    )}
                  </button>
                </div>

                {/* Code body block */}
                <div className="bg-slate-960 rounded-xl overflow-hidden border border-slate-900 flex-1 flex flex-col relative max-h-[640px]">
                  <div className="bg-slate-900/40 p-2.5 border-b border-slate-900 flex items-center justify-between text-xs text-slate-500 font-mono">
                    <span>Language: <span className="capitalize text-slate-200 font-bold">{selectedFile.language}</span></span>
                    <span>Ready for pip run</span>
                  </div>
                  
                  <pre className="p-5 font-mono text-xs text-slate-300 leading-relaxed overflow-auto flex-1 select-text scrollbar-thin scrollbar-thumb-slate-800">
                    <code>
                      {selectedFile.content.split("\n").map((line, lIdx) => (
                        <div key={lIdx} className="table-row">
                          <span className="table-cell select-none text-right opacity-20 pr-4 text-[10px] font-mono min-w-[25px]">{lIdx + 1}</span>
                          <span className="table-cell whitespace-pre">{line}</span>
                        </div>
                      ))}
                    </code>
                  </pre>
                </div>

              </div>

            </motion.div>
          )}

          {activeTab === "guide" && (
            <motion.div
              key="guide"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              transition={{ duration: 0.25 }}
              className="grid grid-cols-1 md:grid-cols-12 gap-6"
            >
              
              {/* Left bento: Dynamic Terminal Commands */}
              <div className="md:col-span-12 lg:col-span-6 bg-slate-950 border border-slate-900 rounded-2xl p-6 shadow-2xl flex flex-col gap-6">
                <div>
                  <h3 className="text-base font-sans font-semibold text-white tracking-tight flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-cyan-400" />
                    Cascaded Command Line Generator
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    These commands update in real-time as you tweak configurations on the Playground sidebar. Use them to execute the actual Python package locally.
                  </p>
                </div>

                {/* Core commands terminal */}
                <div className="flex flex-col gap-4">
                  
                  {/* Server terminal block */}
                  <div className="bg-slate-900/60 rounded-xl p-4 border border-slate-905 relative">
                    <div className="flex justify-between items-center text-xs text-slate-400 mb-2 font-mono">
                      <span>1. Launch SSL TCP Tunnel server listener daemon</span>
                      <button
                        onClick={() => handleCopyCmd("srv", serverCmd)}
                        className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 cursor-pointer select-none"
                      >
                        {copiedCmd === "srv" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        {copiedCmd === "srv" ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre className="bg-slate-950 rounded-lg p-3 text-xs text-slate-200 font-mono overflow-x-auto border border-slate-900">
                      <code>{serverCmd}</code>
                    </pre>
                  </div>

                  {/* Client terminal block */}
                  <div className="bg-slate-900/60 rounded-xl p-4 border border-slate-905 relative">
                    <div className="flex justify-between items-center text-xs text-slate-400 mb-2 font-mono">
                      <span>2. Connect SSL Tunnel client node with negotiated bunching settings</span>
                      <button
                        onClick={() => handleCopyCmd("cli", clientCmd)}
                        className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 cursor-pointer select-none"
                      >
                        {copiedCmd === "cli" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        {copiedCmd === "cli" ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre className="bg-slate-950 rounded-lg p-3 text-xs text-slate-200 font-mono overflow-x-auto border border-slate-900 selection:bg-cyan-500/20">
                      <code>{clientCmd}</code>
                    </pre>
                  </div>

                </div>

                {/* Local Environment setup */}
                <div className="border-t border-slate-900 pt-5">
                  <h4 className="text-xs text-slate-450 uppercase tracking-wider font-mono mb-3">Local Setup Requirements</h4>
                  <ul className="text-xs text-slate-400 flex flex-col gap-2.5 leading-relaxed">
                    <li className="flex items-start gap-2.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5" />
                      <span><strong>Zero Outside Dependencies</strong>: Runs out of the box using vanilla Python 3.8+ as it leverages only Python's standard <code>asyncio</code>, <code>ssl</code>, <code>struct</code>, and <code>argparse</code> libraries.</span>
                    </li>
                    <li className="flex items-start gap-2.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5" />
                      <span><strong>Interactive Certificates</strong>: The Python server will automatically invoke openssl to generate its combined cert+key <code>server.pem</code> if not already present.</span>
                    </li>
                    <li className="flex items-start gap-2.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5" />
                      <span><strong>Testing unittests</strong>: Run <code>python -m unittest discover -s tests</code> to test packet headers mapping, priorities, or echo.</span>
                    </li>
                  </ul>
                </div>

              </div>

              {/* Right bento: Protocol Overview & Architectures */}
              <div className="md:col-span-12 lg:col-span-6 bg-slate-950 border border-slate-900 rounded-2xl p-6 shadow-2xl flex flex-col gap-6 font-sans">
                <div>
                  <h3 className="text-base font-sans font-semibold text-white tracking-tight flex items-center gap-2">
                    <Sliders className="h-5 w-5 text-cyan-400" />
                    How Tunnel Session Bunching & Handshaking Operates
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    An in-depth map tracing how packages are handled step-by-step.
                  </p>
                </div>

                <div className="flex flex-col gap-4">
                  
                  {/* Step list bento cards */}
                  {[
                    {
                      step: "01",
                      title: "Secure SSL TLS Sockets",
                      body: "Client initializes SSL connection utilizing one of 3 secure tiers: insecure (skips verifications), trusted (crypto peer-cert fingerprint SHA-256 validation checks), or secure CA chains."
                    },
                    {
                      step: "02",
                      title: "Handshake Negotiator Negotiation",
                      body: "A client initiates suggestions mapping clientID, segment bounds, syncing timeouts, and preferred backend targets. The server evaluates, handles ID collision, reserves sessions, and replies with actual server approved configurations."
                    },
                    {
                      step: "03",
                      title: "Adaptive Bunching Accumulation",
                      body: "A background flusher task tracks packet queues. The outbound stream sleeps until: size exceeds TCP segment MSS bounds, syncing timeout expires, or an incoming VoIP (EF) or SSH (CS) DSCP priority packet triggers instantaneous force flush."
                    },
                    {
                      step: "04",
                      title: "Segment Junk Padding (Ver 15)",
                      body: "If Padding mode 2 (Full) or 3 (Random) are configured, a dummy packet of Version 15 is sub-framed into the TCP bunch. The server automatically strips these out, leaving real core cargo intact."
                    },
                    {
                      step: "05",
                      title: "Multi-Client Mapping & Routing",
                      body: "The Echo service resolves incoming packets, maps the 4-octet Client ID (A.B.C.D), makes payload-specific conversions to IPv6 address strings (RFC 4291 mapping), filters depending on parameters, and echoes payloads back."
                    }
                  ].map((step, idx) => (
                    <div key={idx} className="bg-slate-900/40 p-4 rounded-xl border border-slate-905 flex gap-3 pb-4">
                      <span className="font-mono text-cyan-400 font-bold text-sm bg-cyan-950/20 rounded p-1 h-fit leading-none">{step.step}</span>
                      <div>
                        <h4 className="text-xs font-semibold text-white">{step.title}</h4>
                        <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.body}</p>
                      </div>
                    </div>
                  ))}

                </div>

              </div>

            </motion.div>
          )}

        </AnimatePresence>
      </main>

      {/* 3. CORE DESIGN FOOTER */}
      <footer className="border-t border-slate-900 bg-slate-950 px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-2.5 text-[11px] text-slate-500 font-mono">
        <div className="flex items-center gap-2">
          <span>Secure asyncio SSL TCP Tunnel Gateway Framework and Playground.</span>
          <span className="text-slate-700">|</span>
          <span className="text-cyan-500/80">Zero dependencies</span>
        </div>
        <div>
          <span>Target Platform: Cloud Run preview matching 0.0.0.0:3000 mapping layout.</span>
        </div>
      </footer>

    </div>
  );
}
