import React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error: unknown): State {
    const message =
      error instanceof Error ? error.message : "An unexpected error occurred.";
    return { hasError: true, message };
  }

  override componentDidCatch(error: unknown, info: React.ErrorInfo) {
    // Log to console so developers can still see the full stack.
    console.error("[ErrorBoundary] Uncaught render error:", error, info);
  }

  override render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center p-8">
          <Card className="max-w-md w-full">
            <CardHeader>
              <CardTitle>Something went wrong</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                {this.state.message ||
                  "The application encountered an unexpected error. Reloading usually fixes this."}
              </p>
              <Button onClick={() => window.location.reload()}>Reload</Button>
            </CardContent>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}
