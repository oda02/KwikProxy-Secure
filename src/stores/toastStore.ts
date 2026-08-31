import { create } from "zustand";

export type ToastKind = "info" | "success" | "warning" | "error";

export type Toast = {
  id: number;
  kind: ToastKind;
  /** Заголовок (1-2 слова, моно). Можно опустить — будет только message. */
  title?: string;
  /** Основной текст. Поддерживается «\n» для второй строки. */
  message: string;
  /** Через сколько мс автоматически уйдёт. Ошибки видны 10 с, остальные 5 с. 0 — не уходит. */
  durationMs: number;
};

type ToastInput = Omit<Toast, "id" | "durationMs"> & { durationMs?: number };

type ToastStore = {
  toasts: Toast[];
  push: (t: ToastInput) => number;
  dismiss: (id: number) => void;
};

let nextId = 1;
const MAX_VISIBLE_TOASTS = 3;

export const useToastStore = create<ToastStore>((set, get) => ({
  toasts: [],
  push: (input) => {
    const id = nextId++;
    const toast: Toast = {
      id,
      kind: input.kind,
      title: input.title,
      message: input.message,
      durationMs: input.durationMs ?? (input.kind === "error" ? 10_000 : 5_000),
    };
    // Repeated backend failures used to produce a translucent wall of identical
    // messages. Keep the newest occurrence and bound the visible stack.
    const withoutDuplicate = get().toasts.filter(
      (item) =>
        item.kind !== toast.kind ||
        item.title !== toast.title ||
        item.message !== toast.message
    );
    set({ toasts: [...withoutDuplicate, toast].slice(-MAX_VISIBLE_TOASTS) });
    if (toast.durationMs > 0) {
      window.setTimeout(() => {
        get().dismiss(id);
      }, toast.durationMs);
    }
    return id;
  },
  dismiss: (id) => {
    set({ toasts: get().toasts.filter((t) => t.id !== id) });
  },
}));

/** Удобный helper для использования в компонентах. */
export const showToast = (input: ToastInput) =>
  useToastStore.getState().push(input);
