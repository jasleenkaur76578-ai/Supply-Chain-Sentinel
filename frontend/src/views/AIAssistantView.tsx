import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  Boxes,
  FileText,
  CheckCircle2,
  AlertTriangle,
  RadioTower,
  CornerDownLeft
} from 'lucide-react';
import { api } from '../api/client';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  groundingReferences?: Array<{ entity_type: string; entity_id: string; name: string; details?: string }>;
  confidence?: string;
  suggestedFollowups?: string[];
}

export const AIAssistantView: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        "Welcome to Supply Chain Sentinel AI Intelligence. I am your grounded Software Supply Chain Risk Analyst. " +
        "I query your organization's verified software asset database, vulnerability graphs, and CISA KEV feeds to deliver explainable answers. " +
        "Ask me about affected applications, blast radiuses, high-risk suppliers, or request an executive briefing.",
      suggestedFollowups: [
        'Which applications are affected by Log4Shell?',
        'Explain our highest-risk dependency and blast radius.',
        'Generate an executive security briefing for the CISO.',
        'Which vulnerable components affect multiple applications?'
      ]
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSend = async (queryToSend?: string) => {
    const q = queryToSend || input;
    if (!q.trim() || loading) return;

    const userMsg: Message = { role: 'user', content: q };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const data = await api.chatWithAnalyst(q);
      const assistantMsg: Message = {
        role: 'assistant',
        content: data.response,
        groundingReferences: data.grounding_references,
        confidence: data.confidence,
        suggestedFollowups: data.suggested_followups
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Unable to complete intelligence analysis: ${err.message || 'API connection failed'}`
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-[calc(100vh-130px)] flex flex-col rounded-xl bg-[#111C30] border border-slate-800 overflow-hidden">
      {/* Header Bar */}
      <div className="px-6 py-4 border-b border-slate-800 bg-[#0F172A] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-purple-500 to-indigo-600 flex items-center justify-center">
            <Bot className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              <span>Sentinel AI Security Intelligence Analyst</span>
              <span className="text-[10px] bg-purple-500/20 text-purple-300 font-mono px-1.5 py-0.5 rounded border border-purple-500/30">
                Grounded RAG
              </span>
            </h2>
            <p className="text-[11px] text-slate-400 font-mono">
              Strict read-only verification over internal asset graphs • No arbitrary SQL execution
            </p>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Grounded Database Verification: ACTIVE</span>
        </div>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'} space-y-2`}
          >
            <div className="flex items-center gap-2 font-mono text-[10px] text-slate-500 uppercase">
              {msg.role === 'user' ? (
                <span>Security Analyst (You)</span>
              ) : (
                <span className="flex items-center gap-1 text-purple-400 font-bold">
                  <Sparkles className="w-3 h-3" />
                  <span>Sentinel Intelligence Core</span>
                </span>
              )}
            </div>

            <div
              className={`max-w-3xl rounded-2xl p-4 text-xs font-mono leading-relaxed whitespace-pre-wrap ${
                msg.role === 'user'
                  ? 'bg-sky-500/20 text-sky-100 border border-sky-500/30 rounded-tr-none'
                  : 'bg-slate-900 text-slate-200 border border-slate-800 rounded-tl-none shadow-xl'
              }`}
            >
              {msg.content}
            </div>

            {/* Grounding References */}
            {msg.groundingReferences && msg.groundingReferences.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap pt-1 font-mono text-[11px]">
                <span className="text-slate-500 text-[10px] uppercase font-bold">Grounded Records:</span>
                {msg.groundingReferences.map((ref, rIdx) => (
                  <span
                    key={rIdx}
                    className="px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700 flex items-center gap-1"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                    <span>{ref.name}</span>
                  </span>
                ))}
              </div>
            )}

            {/* Suggested Followups Chips */}
            {msg.suggestedFollowups && msg.suggestedFollowups.length > 0 && (
              <div className="pt-2 flex flex-wrap gap-2">
                {msg.suggestedFollowups.map((followup, fIdx) => (
                  <button
                    key={fIdx}
                    onClick={() => handleSend(followup)}
                    className="text-left px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-purple-500/50 text-slate-400 hover:text-purple-300 text-[11px] font-mono transition-colors"
                  >
                    {followup}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs font-mono text-purple-400 animate-pulse p-4 rounded-xl bg-slate-900/60 border border-slate-800 w-fit">
            <Sparkles className="w-4 h-4 animate-spin" />
            <span>Retrieving dependency topologies and formulating grounded analysis...</span>
          </div>
        )}
      </div>

      {/* Input Form */}
      <div className="p-4 border-t border-slate-800 bg-[#0F172A] shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex gap-3"
        >
          <input
            type="text"
            placeholder="Ask about software supply chain exposure, CVEs, attack paths, or request briefings..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="px-5 py-3 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 text-white font-bold text-xs font-mono flex items-center gap-2 transition-all shadow-lg shadow-purple-500/10"
          >
            <span>Ask Analyst</span>
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
};
