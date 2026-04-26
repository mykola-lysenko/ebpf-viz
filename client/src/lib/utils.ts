import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * A fast deep equality check.
 * Optionally ignores specific keys at the root object level.
 */
export function deepEqual(a: any, b: any, ignoreRootKeys?: Set<string>): boolean {
  if (a === b) return true;

  if (a == null || typeof a !== "object" || b == null || typeof b !== "object") {
    return false;
  }

  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);

  if (!ignoreRootKeys) {
    if (keysA.length !== keysB.length) return false;
    for (let i = 0; i < keysA.length; i++) {
      const key = keysA[i];
      if (!Object.prototype.hasOwnProperty.call(b, key) || !deepEqual(a[key], b[key])) {
        return false;
      }
    }
    return true;
  }

  // When ignoreRootKeys is provided, only check non-ignored keys
  for (let i = 0; i < keysA.length; i++) {
    const key = keysA[i];
    if (ignoreRootKeys.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(b, key) || !deepEqual(a[key], b[key])) {
      return false;
    }
  }

  for (let i = 0; i < keysB.length; i++) {
    const key = keysB[i];
    if (ignoreRootKeys.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(a, key)) {
      return false;
    }
  }

  return true;
}
