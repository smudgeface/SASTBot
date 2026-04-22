import { ShieldAlert } from "lucide-react";

import { useMe } from "@/api/queries/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface Props {
  children: React.ReactNode;
}

/**
 * Admin gate. Must be wrapped in <RequireAuth /> first.
 * Real authorization is enforced server-side; this is purely for UX.
 */
export function RequireAdmin({ children }: Props) {
  const { data: user } = useMe();

  if (!user || user.role !== "admin") {
    return (
      <div className="flex h-full w-full items-center justify-center p-6">
        <Card className="max-w-md">
          <CardHeader className="flex flex-row items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-destructive" />
            <div>
              <CardTitle>Access denied</CardTitle>
              <CardDescription>This page is restricted to administrators.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Contact your administrator if you believe this is a mistake.
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}
