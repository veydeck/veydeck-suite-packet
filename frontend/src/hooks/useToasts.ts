import { useCallback, useState } from "react";
import type { ToastItem, ToastType } from "../types";
import { suiteBridge } from "../suiteBridge";

export function useToasts() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const addToast = useCallback(
    (type: ToastType, title: string, message: string) => {
      const deliveredToHost = suiteBridge.notify({ type, title, message });
      if (deliveredToHost) return;

      const id = crypto.randomUUID();
      setToasts((current) => [...current, { id, type, title, message }]);
      window.setTimeout(() => removeToast(id), 4000);
    },
    [removeToast],
  );

  return { toasts, addToast, removeToast };
}
