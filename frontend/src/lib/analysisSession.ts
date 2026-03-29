import type { FileInfo } from '@/components/FileIntakePanel';

let pendingFileInfo: FileInfo | null = null;

export function setPendingFileInfo(fileInfo: FileInfo) {
  pendingFileInfo = fileInfo;
}

export function consumePendingFileInfo() {
  const next = pendingFileInfo;
  pendingFileInfo = null;
  return next;
}
