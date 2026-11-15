import { createRoot } from "react-dom/client";
import { readInitialStatusTheme, syncStatusTheme } from "./theme";
import { StatusApp } from "./StatusApp";
import "./status.css";

syncStatusTheme(readInitialStatusTheme());

createRoot(document.getElementById("root")!).render(<StatusApp />);
