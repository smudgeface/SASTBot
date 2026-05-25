import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BookOpen, ShieldCheck } from "lucide-react";

import { useLogin, useMe } from "@/api/queries/auth";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/use-toast";

export default function LoginPage() {
  const navigate = useNavigate();
  const login = useLogin();
  const { data: user } = useMe();
  const { toast } = useToast();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Rate-limit countdown: number of seconds remaining, null when not rate-limited.
  const [retryAfterSecs, setRetryAfterSecs] = useState<number | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // If the user is already authenticated (e.g. returning visit), skip login.
  useEffect(() => {
    if (user) navigate("/dashboard", { replace: true });
  }, [user, navigate]);

  // Tick the countdown down every second.
  const startCountdown = useCallback((seconds: number) => {
    // Clear any previous interval.
    if (countdownRef.current !== null) clearInterval(countdownRef.current);

    setRetryAfterSecs(seconds);

    countdownRef.current = setInterval(() => {
      setRetryAfterSecs((prev) => {
        if (prev === null || prev <= 1) {
          clearInterval(countdownRef.current!);
          countdownRef.current = null;
          return null;
        }
        return prev - 1;
      });
    }, 1_000);
  }, []);

  // Clean up interval on unmount.
  useEffect(() => {
    return () => {
      if (countdownRef.current !== null) clearInterval(countdownRef.current);
    };
  }, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    // Don't submit while rate-limited.
    if (retryAfterSecs !== null) return;

    try {
      await login.mutateAsync({ email, password });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        // Extract Retry-After from the error body (fastify/rate-limit sets it).
        // The header value is in seconds; fall back to 60 if missing or unparseable.
        const body = err.body as Record<string, unknown> | null;
        const rawRetryAfter =
          body && typeof body === "object" && "retryAfter" in body
            ? body["retryAfter"]
            : null;
        const seconds =
          typeof rawRetryAfter === "number"
            ? Math.ceil(rawRetryAfter)
            : typeof rawRetryAfter === "string"
              ? Math.ceil(Number(rawRetryAfter))
              : 60;
        startCountdown(isNaN(seconds) || seconds <= 0 ? 60 : seconds);
        return;
      }

      const description =
        err instanceof ApiError
          ? err.status === 401
            ? "Invalid email or password."
            : err.message
          : "Something went wrong. Please try again.";
      toast({ variant: "destructive", title: "Sign-in failed", description });
    }
  };

  const isRateLimited = retryAfterSecs !== null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2 text-primary">
            <ShieldCheck className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-tight">SASTBot</span>
          </div>
          <CardTitle className="text-lg">Sign in</CardTitle>
          <CardDescription>Use your organization credentials.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit} noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isRateLimited}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isRateLimited}
              />
            </div>
            {isRateLimited && (
              <p className="text-sm text-destructive">
                Too many attempts. Please wait {retryAfterSecs}s before trying again.
              </p>
            )}
            <Button
              type="submit"
              className="w-full"
              disabled={login.isPending || isRateLimited}
            >
              {login.isPending
                ? "Signing in…"
                : isRateLimited
                  ? `Wait ${retryAfterSecs}s…`
                  : "Sign in"}
            </Button>
          </form>
          <div className="mt-4 border-t border-border pt-3 text-center text-xs text-muted-foreground">
            New here?{" "}
            <Link to="/manual/quick-start" className="inline-flex items-center gap-1 text-primary hover:underline">
              <BookOpen className="h-3 w-3" />
              Read the quick-start guide
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
