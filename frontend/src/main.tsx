import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { setLocale } from "./i18n";
import { suiteBridge } from "./suiteBridge";

// 当前套件已经具备文案国际化，主控语言变化后由 SDK 推送到 React 外部状态。
suiteBridge.subscribeLocale(({ locale }) => setLocale(locale));
suiteBridge.ready();

createRoot(document.getElementById("root")!).render(<App />);
