import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryCache, MutationCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import App from "./App";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ApiError } from "@/api/client";
import { meQueryKey } from "@/api/queries/auth";
import "./index.css";

// Constructed first so the cache callbacks can close over it.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
  queryCache: new QueryCache({
    onError: (err) => {
      if (err instanceof ApiError && err.status === 401) {
        // Invalidate the /me query so RequireAuth redirects to /login.
        queryClient.invalidateQueries({ queryKey: meQueryKey });
      }
    },
  }),
  mutationCache: new MutationCache({
    onError: (err) => {
      if (err instanceof ApiError && err.status === 401) {
        queryClient.invalidateQueries({ queryKey: meQueryKey });
      }
    },
  }),
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={200}>
          <BrowserRouter>
            <App />
            <Toaster />
          </BrowserRouter>
        </TooltipProvider>
        {import.meta.env.DEV ? <ReactQueryDevtools initialIsOpen={false} /> : null}
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
