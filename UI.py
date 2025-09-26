import React, { useState, useEffect, useRef } from "react";
import axios from "axios";

function App() {
  const [logs, setLogs] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatOutput, setChatOutput] = useState([]);
  const logsEndRef = useRef(null);

  // Scroll console to bottom
  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  // Fetch real-time scan logs from backend
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get("http://localhost:5000/api/logs"); // tera backend endpoint
        setLogs(res.data); // assume backend returns array of log strings
      } catch (err) {
        console.error("Error fetching logs:", err);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleChatSubmit = async (e) => {
    e.preventDefault();
    if (!chatInput) return;
    try {
      const res = await axios.post("http://localhost:5000/api/chat", {
        message: chatInput,
      });
      setChatOutput((prev) => [...prev, { user: chatInput, bot: res.data }]);
      setChatInput("");
    } catch (err) {
      console.error("Chat error:", err);
    }
  };

  const containerStyle = {
    display: "flex",
    height: "100vh",
    fontFamily: "Courier New, monospace",
    backgroundColor: "#000",
    color: "#00ff00",
  };

  const panelStyle = {
    flex: 1,
    padding: "20px",
    borderRight: "1px solid #00ff00",
    display: "flex",
    flexDirection: "column",
  };

  const outputStyle = {
    flex: 1,
    backgroundColor: "#000",
    padding: "10px",
    border: "1px solid #00ff00",
    overflowY: "scroll",
    marginBottom: "10px",
  };

  const inputStyle = {
    width: "80%",
    padding: "5px",
    backgroundColor: "#000",
    color: "#00ff00",
    border: "1px solid #00ff00",
  };

  const buttonStyle = {
    padding: "5px 10px",
    backgroundColor: "#000",
    color: "#00ff00",
    border: "1px solid #00ff00",
    cursor: "pointer",
    marginLeft: "10px",
  };

  return (
    <div style={containerStyle}>
      <div style={panelStyle}>
        <h2>AI VAPT Console</h2>
        <div style={outputStyle}>
          {logs.map((log, idx) => (
            <div key={idx}>{log}</div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>

      <div style={panelStyle}>
        <h2>AI Chat</h2>
        <div style={outputStyle}>
          {chatOutput.map((c, idx) => (
            <div key={idx}>
              <b>You:</b> {c.user}
              <br />
              <b>Bot:</b> {c.bot}
            </div>
          ))}
        </div>
        <form
          onSubmit={handleChatSubmit}
          style={{ display: "flex", alignItems: "center" }}
        >
          <input
            type="text"
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            placeholder="Ask the AI..."
            style={inputStyle}
          />
          <button type="submit" style={buttonStyle}>
            Send
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;
