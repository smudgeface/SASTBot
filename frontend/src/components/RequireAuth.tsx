import { Loader2 } from "lucide-react";
import { Navigate, useLocation } from "react-router-dom";

import { useMe } from "@/api/queries/auth";

interface Props {
  children: React.ReactNode;
}

/**
 * Gate for authenticated routes.
 *
 * `useMe()` converts a 401 response into `null` (instead of throwing), which
 * means the query succeeds even when the user isn't logged in. That keeps the
 * initial render free of uncaught errors when the backend is down or the
 * session has expired.
 */
export function RequireAuth({ children }: Props) {
  const { data: user, isLoading, isError } = useMe();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-full w-full items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" aria-label="Loading" />
      </div>
    );
  }

  // Network failure (backend down) — treat as unauthenticated so the user lands
  // on the login page instead of an error surface.
  if (isError || !user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <>{children}</>;
}
