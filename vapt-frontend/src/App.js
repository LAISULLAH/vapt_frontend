import React, { useState, useRef, useEffect } from "react";

// Blinking header/logo component
const BlinkingText = ({ text, colors = ["#00ff00", "#ff0000"], interval = 500, style = {} }) => {
  const [colorIndex, setColorIndex] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setColorIndex(prev => (prev + 1) % colors.length), interval);
    return () => clearInterval(id);
  }, [colors, interval]);

  return <span style={{ color: colors[colorIndex], ...style }}>{text}</span>;
};

function App() {
  // Start with legal page shown (no password/login)
  const [legalPage, setLegalPage] = useState(true);

  const [targetInput, setTargetInput] = useState("");
  const [scanOutput, setScanOutput] = useState([]);
  const [loading, setLoading] = useState(false);

  const [chatInput, setChatInput] = useState("");
  const [chatLogs, setChatLogs] = useState([]);

  const scanEndRef = useRef(null);
  const chatEndRef = useRef(null);

  // Scroll scan output to bottom
  useEffect(() => {
    scanEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [scanOutput]);

  // Scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatLogs]);

  // Handle legal notice agreement
  const handleLegalAgree = () => {
    setLegalPage(false);
  };

  // Run all scans (real-time streaming via SSE)
  const handleRunScan = () => {
    if (!targetInput) return;
    setScanOutput([]); // clear previous output
    setLoading(true);

    // SSE connection
    const evtSource = new EventSource(`http://127.0.0.1:5001/run_all_scans?target=${encodeURIComponent(targetInput)}`);

    evtSource.onmessage = (e) => {
      setScanOutput(prev => [...prev, e.data]);
    };

    evtSource.onerror = (err) => {
      console.error("SSE connection error:", err);
      setScanOutput(prev => [...prev, "[ERROR] Connection lost or scan ended."]);
      try { evtSource.close(); } catch (e) {}
      setLoading(false);
    };
  };

  // Chat send handler
  const handleChatSend = async () => {
    if (!chatInput) return;
    const userMessage = { sender: "You", text: chatInput };
    setChatLogs(prev => [...prev, userMessage]);
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:5001/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: chatInput, target: targetInput }),
      });
      const data = await res.json();
      const botResponse = { sender: "AI", text: data.response };
      setChatLogs(prev => [...prev, botResponse]);
    } catch (err) {
      console.error(err);
      setChatLogs(prev => [...prev, { sender: "AI", text: "[ERROR] Failed to connect backend" }]);
    }
    setChatInput("");
    setLoading(false);
  };

  // If legal notice is showing
  if (legalPage) {
    return (
      <div style={{ background: "#000", color: "#0f0", minHeight: "100vh", fontFamily: "monospace", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", padding: "20px" }}>
        <h1 style={{ fontSize: "2.5rem", marginBottom: "20px" }}>⚠️ LEGAL NOTICE / DISCLAIMER ⚠️</h1>
        <p style={{ marginBottom: "20px", lineHeight: "1.5", maxWidth: 800 }}>
          ⚠️ This tool is intended for <strong>authorized penetration testing and educational purposes only</strong>. 
          Unauthorized scanning or attacks on systems you do not own or do not have explicit permission for is <strong>illegal</strong>.
        </p>
        <p style={{ marginBottom: "20px", fontWeight: "bold" }}>⚠️ By clicking AGREE, you confirm that you understand and accept these terms. ⚠️</p>
        <button onClick={handleLegalAgree} style={{ padding: "10px 20px", background: "#111", color: "#0f0", border: "1px solid #0f0", cursor: "pointer",fontSize: "1.5rem" }}>I AGREE</button>
      </div>
    );
  }

  // Main App (after legal agreement)
  return (
    <div style={{ display: "flex", background: "#000", minHeight: "100vh", color: "#0f0", fontFamily: "monospace" }}>
      {/* Sidebar */}
      <div style={{ width: "250px", borderRight: "1px solid #0f0", padding: "20px" }}>
        <h2><BlinkingText text="WHITE HAT" /></h2>
        <h3>Port Scan</h3>
      </div>

      {/* Main content */}
      <div style={{ flex: 1, padding: "20px" }}>
        <div style={{ background: "#111", minHeight: "60px", padding: "10px", border: "1px solid #0f0", marginBottom: "10px" }}>
          {loading ? "Running all scans..." : `Enter target IP/domain and press RUN to execute all tools`}
        </div>

        <div style={{ marginBottom: "20px" }}>
          <input
            type="text"
            value={targetInput}
            onChange={e => setTargetInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") handleRunScan(); }}
            placeholder="Enter IP/domain..."
            style={{ padding: "8px", width: "60%", background: "#000", color: "#0f0", border: "1px solid #0f0", marginRight: "10px" }}
          />
          <button onClick={handleRunScan} style={{ padding: "8px 16px", background: "#111", color: "#0f0", border: "1px solid #0f0" }}>RUN</button>
        </div>

        {/* Scan output */}
        <div style={{ background: "#111", minHeight: "400px", overflowY: "auto", padding: "10px", border: "1px solid #0f0", whiteSpace: "pre-wrap", marginBottom: "20px" }}>
          {scanOutput.map((line, idx) => (
            <div key={idx} style={{ color: line.includes("[ERROR]") ? "red" : "#0f0" }}>{line}</div>
          ))}
          <div ref={scanEndRef}></div>
        </div>

        {/* Chatbot */}
        <h2>AI Chatbot</h2>
        <div style={{ background: "#111", minHeight: "150px", overflowY: "auto", padding: "10px", border: "1px solid #0f0", marginBottom: "10px" }}>
          {chatLogs.map((log, idx) => (
            <div key={idx}><strong>{log.sender}:</strong> {log.text}</div>
          ))}
          <div ref={chatEndRef}></div>
        </div>
        <input
          type="text"
          value={chatInput}
          onChange={e => setChatInput(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") handleChatSend(); }}
          placeholder="Type a message..."
          style={{ width: "80%", padding: "8px", background: "#000", color: "#0f0", border: "1px solid #0f0", marginRight: "10px" }}
        />
        <button onClick={handleChatSend} style={{ padding: "8px 16px", background: "#111", color: "#0f0", border: "1px solid #0f0" }}>Send</button>
      </div>
    </div>
  );
}

export default App;
