import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import EngagementDetail from "./views/EngagementDetail";
import EngagementList from "./views/EngagementList";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<EngagementList />} />
        <Route path="/engagements/:id" element={<EngagementDetail />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
