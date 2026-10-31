import { createContext, useContext } from "react";
import type { App } from "./state";

export const AppContext = createContext<App>(null as unknown as App);
export const useApp = () => useContext(AppContext);
