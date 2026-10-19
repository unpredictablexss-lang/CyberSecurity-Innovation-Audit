import React from "react";
import { createRoot } from "react-dom/client";
import WorkbenchApp from "./features/workbench/WorkbenchApp";

createRoot(document.getElementById("root")!).render(<WorkbenchApp />);
