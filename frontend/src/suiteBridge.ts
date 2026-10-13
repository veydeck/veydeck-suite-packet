import { createSuiteBridge } from "@veydeck/suite-sdk";

// 套件桥接单例：主控运行时接入统一能力，独立运行时由 SDK 自动降级。
export const suiteBridge = createSuiteBridge({
  capabilities: ["theme", "locale", "window", "notification"],
  supportedLocales: ["zh-CN", "en-US"],
  defaultLocale: "zh-CN",
});
