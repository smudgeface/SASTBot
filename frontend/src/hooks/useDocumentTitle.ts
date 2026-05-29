import { useEffect } from "react";

/**
 * Sets `document.title` while the component is mounted.
 * Restores "SASTBot" on unmount so navigating away doesn't leave a stale title.
 */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title;
    return () => {
      document.title = "SASTBot";
    };
  }, [title]);
}
