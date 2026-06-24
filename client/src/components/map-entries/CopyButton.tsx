import { useState, type MouseEvent } from "react";
import { Copy } from "lucide-react";

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <button
      onClick={handleCopy}
      className="ml-1.5 p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-white/10 text-white/30 hover:text-white/70 transition-all flex-shrink-0"
      title="Copy"
    >
      {copied ? (
        <span className="text-[10px] text-green-400 font-mono">✓</span>
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}
