import { createRoot } from "react-dom/client";
import { applyStatusTheme, readInitialStatusTheme } from "./theme";
import { StatusApp } from "./StatusApp";
import "./status.css";

applyStatusTheme(readInitialStatusTheme());

createRoot(document.getElementById("root")!).render(<StatusApp />);
