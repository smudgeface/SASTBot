import { FileSearch } from "lucide-react";

import { useScans } from "@/api/queries/scans";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function ScansPage() {
  const scans = useScans();
  const empty = !scans.isLoading && (!scans.data || scans.data.length === 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Scan Results</h1>
        <p className="text-sm text-muted-foreground">All scans run across your repositories.</p>
      </div>

      {scans.isLoading ? (
        <Card>
          <CardContent className="p-8 text-sm text-muted-foreground">Loading…</CardContent>
        </Card>
      ) : null}

      {empty ? (
        <Card>
          <CardHeader className="flex flex-row items-center gap-3">
            <FileSearch className="h-5 w-5 text-muted-foreground" />
            <div>
              <CardTitle>No scans yet</CardTitle>
              <CardDescription>
                Add a repository and trigger a scan. (M2+)
              </CardDescription>
            </div>
          </CardHeader>
        </Card>
      ) : null}
    </div>
  );
}
