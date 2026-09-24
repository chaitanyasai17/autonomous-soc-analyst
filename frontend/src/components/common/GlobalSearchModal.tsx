import React, { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  X,
  Target,
  AlertOctagon,
  Briefcase,
  Fingerprint,
  Network,
  FileText,
  ChevronRight,
  Sparkles,
} from "lucide-react";
import { api } from "../../services/api";

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [results, setResults] = useState<any | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery("");
      setResults(null);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!query.trim()) {
      setResults(null);
      setLoading(false);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const res = await api.get("/search", { params: { q: query.trim(), limit: 5 } });
        if (res.data?.data) {
          setResults(res.data.data);
        }
      } catch {
        // quiet fail on search
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query]);

  if (!isOpen) return null;

  const handleSelect = (url: string) => {
    onClose();
    navigate(url);
  };

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case "incidents":
        return Briefcase;
      case "alerts":
        return AlertOctagon;
      case "detections":
        return Target;
      case "iocs":
        return Fingerprint;
      case "mitre":
        return Network;
      default:
        return FileText;
    }
  };

  const categories = results?.categories || {};
  const hasResults = results && results.total_matches > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div
        className="w-full max-w-2xl bg-[#030B1C]/95 border border-[rgba(0,183,255,0.3)] shadow-[0_0_50px_-10px_rgba(0,140,255,0.3)] rounded-2xl overflow-hidden flex flex-col max-h-[80vh] backdrop-blur-xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Bar Header */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[rgba(0,183,255,0.15)] bg-[#061226]/80">
          <Search className="w-5 h-5 text-[#00D9FF] shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
            }}
            placeholder="Search across incidents, alerts, detections, IOCs, logs, MITRE..."
            className="flex-1 bg-transparent border-none outline-none text-sm text-white placeholder:text-slate-500 font-sans"
          />
          {loading && (
            <div className="w-4 h-4 border-2 border-[#00D9FF] border-t-transparent rounded-full animate-spin shrink-0" />
          )}
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-500 hover:text-slate-300 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {!query.trim() && (
            <div className="py-12 text-center text-slate-500 text-xs">
              <Sparkles className="w-6 h-6 text-[#00D9FF]/50 mx-auto mb-2" />
              <p>Type keywords to search across the entire SOC intelligence graph.</p>
              <p className="text-[11px] text-slate-600 mt-1">
                Examples: "192.168", "brute force", "T1059", "critical", "incident"
              </p>
            </div>
          )}

          {query.trim() && !loading && !hasResults && (
            <div className="py-12 text-center text-slate-500 text-xs">
              No SOC intelligence matches found for "{query}".
            </div>
          )}

          {hasResults && (
            <div className="space-y-4">
              {Object.entries(categories).map(([catKey, items]: [string, any]) => {
                if (!items || items.length === 0) return null;
                const Icon = getCategoryIcon(catKey);
                return (
                  <div key={catKey} className="space-y-1.5">
                    <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[#00D9FF] px-2 font-mono">
                      <Icon className="w-3.5 h-3.5 text-[#00D9FF]" />
                      <span>
                        {catKey} ({items.length})
                      </span>
                    </div>

                    <div className="space-y-1">
                      {items.map((item: any) => (
                        <div
                          key={item.id}
                          onClick={() => handleSelect(item.url)}
                          className="flex items-center justify-between p-2.5 rounded-xl hover:bg-[rgba(0,140,255,0.12)] border border-transparent hover:border-[rgba(0,183,255,0.3)] cursor-pointer group transition"
                        >
                          <div className="min-w-0 pr-3">
                            <p className="text-xs font-semibold text-white group-hover:text-[#00D9FF] transition truncate">
                              {item.title}
                            </p>
                            <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                              {item.subtitle}
                            </p>
                          </div>
                          <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-[#00D9FF] shrink-0 transition" />
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-[#020617] border-t border-[rgba(0,183,255,0.15)] flex items-center justify-between text-[10px] font-mono text-slate-500">
          <span>Global SOC Search Engine</span>
          <span>Press ESC to exit</span>
        </div>
      </div>
    </div>
  );
};
