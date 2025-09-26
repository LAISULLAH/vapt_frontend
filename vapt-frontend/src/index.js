import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
// import logo from "./logo.png"; // Apna logo src folder me rakho

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <div style={{ textAlign: "center", padding: "20px", background: "#000" }}>
      {/* <img src={logo} alt="AI VAPT Logo" style={{ width: "120px", marginBottom: "10px" }} /> */}
    </div>
    <App />
  </React.StrictMode>
);
