import React, { useState } from "react";
import { Lock, User, AlertCircle, Loader2 } from "lucide-react";
import { useAegisStore } from "@/hooks/useAegisStore";

export const LoginPage: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const { login, authError } = useAegisStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!username.trim() || !password) {
      setLocalError("Please enter both username and password");
      return;
    }

    setIsSubmitting(true);
    try {
      const success = await login(username.trim(), password);
      if (!success) {
        // authError in store is populated
      }
    } catch (err: any) {
      setLocalError(err.message || "Failed to sign in");
    } finally {
      setIsSubmitting(false);
    }
  };

  const displayError = localError || authError;

  return (
    <div className="min-h-screen bg-[#0a1128] text-[#eef1f8] font-sans flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0c142e] border border-[#22305e] rounded-xl shadow-2xl p-8 backdrop-blur-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <img src="/aegisdpi-mark.svg" alt="AegisDPI" className="h-16 w-16 mx-auto mb-3 block" />
          <h1 className="text-2xl font-bold tracking-wider uppercase font-mono text-[#eef1f8]">
            AEGIS <span className="text-[#ff5a2b]">DPI</span>
          </h1>
          <p className="text-[11px] text-[#8b9ac6] font-mono tracking-wider whitespace-nowrap mt-1">
            DEEP PACKET INSPECTION & ANOMALY DEFENSE
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono uppercase text-[#8b9ac6] mb-1.5">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#8b9ac6]">
                <User className="h-4 w-4" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                autoComplete="username"
                autoFocus
                disabled={isSubmitting}
                className="w-full pl-9 pr-3 py-2 bg-[#081022] border border-[#22305e] rounded font-mono text-sm text-[#eef1f8] placeholder-[#425280] focus:outline-none focus:border-[#ff5a2b] transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-[#8b9ac6] mb-1.5">
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#8b9ac6]">
                <Lock className="h-4 w-4" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                disabled={isSubmitting}
                className="w-full pl-9 pr-3 py-2 bg-[#081022] border border-[#22305e] rounded font-mono text-sm text-[#eef1f8] placeholder-[#425280] focus:outline-none focus:border-[#ff5a2b] transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 py-2.5 px-4 bg-[#ff5a2b] hover:bg-[#ff7a54] text-white font-mono font-semibold rounded text-sm transition-colors flex items-center justify-center space-x-2 disabled:opacity-50 cursor-pointer shadow-lg shadow-[#ff5a2b]/20"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Signing in...</span>
              </>
            ) : (
              <span>Sign in</span>
            )}
          </button>

          {/* Error Message Under the Form */}
          {displayError && (
            <div className="mt-4 p-3 rounded bg-[#ff5a2b]/10 border border-[#ff5a2b]/40 text-[#ff5a2b] text-xs font-mono flex items-center space-x-2 animate-in fade-in duration-200">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{displayError}</span>
            </div>
          )}
        </form>

        <div className="mt-6 pt-5 border-t border-[#16204a] text-center text-[11px] font-mono text-[#8b9ac6]">
          <span>Protected Defense Console • 8h Session</span>
        </div>
      </div>
    </div>
  );
};
