"use client";

import { ExternalLink, FileDiff } from "lucide-react";
import { useState } from "react";

interface PatchFile {
  path: string;
  status: string;
  additions: number;
  deletions: number;
  hunks: Array<{
    header: string;
    lines: Array<{
      type: "context" | "addition" | "deletion";
      oldLine: number | null;
      newLine: number | null;
      content: string;
    }>;
  }>;
}

interface Patch {
  attempt: number;
  filesChanged: number;
  additions: number;
  deletions: number;
  rawUrl: string | null;
  files: PatchFile[];
}

function titleCase(value: string) {
  return value.replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase());
}

export function PatchViewer({ patch, initialPath }: { patch: Patch; initialPath?: string }) {
  const initialFile = patch.files.find((file) => file.path === initialPath) ?? patch.files[0];
  const [selectedPath, setSelectedPath] = useState(initialFile.path);
  const selectedFile = patch.files.find((file) => file.path === selectedPath) ?? initialFile;

  function selectFile(path: string) {
    setSelectedPath(path);
    const url = new URL(window.location.href);
    url.searchParams.set("attempt", String(patch.attempt));
    url.searchParams.set("artifact", "patch");
    url.searchParams.set("file", path);
    window.history.replaceState(window.history.state, "", url);
  }

  return (
    <div aria-label="Task patch">
      <div className="flex flex-col gap-4 border-y border-line py-4 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted"><strong className="font-medium text-ink">{patch.filesChanged} changed files</strong> · <span className="text-positive data-text">+{patch.additions}</span> · <span className="text-negative data-text">-{patch.deletions}</span></p>
        {patch.rawUrl ? <a href={patch.rawUrl} className="inline-flex items-center gap-1.5 text-xs font-medium text-accent">Raw patch <ExternalLink aria-hidden="true" size={12} /></a> : null}
      </div>
      <div className="mt-6 grid min-w-0 gap-6 lg:grid-cols-[18rem_minmax(0,1fr)] lg:gap-0 lg:border-y lg:border-line">
        <nav aria-label="Changed files" className="min-w-0 border-y border-line lg:border-y-0 lg:border-r">
          <p className="px-4 py-3 text-xs font-medium text-muted">Changed files</p>
          {patch.files.map((file) => {
            const current = file.path === selectedFile.path;
            return (
              <button
                key={file.path}
                type="button"
                onClick={() => selectFile(file.path)}
                aria-current={current ? "true" : undefined}
                className={`grid w-full cursor-pointer grid-cols-[minmax(0,1fr)_auto] gap-3 border-0 border-t border-line px-4 py-3 text-left ${current ? "bg-diff-gutter text-ink" : "bg-transparent text-muted hover:text-ink"}`}
              >
                <span className="min-w-0 break-all text-xs leading-5 data-text">{file.path}</span>
                <span className="text-xs data-text"><span className="text-positive">+{file.additions}</span>{file.deletions ? <span className="ml-2 text-negative">-{file.deletions}</span> : null}</span>
              </button>
            );
          })}
        </nav>
        <section aria-labelledby="selected-file-title" className="min-w-0 border-y border-line lg:border-y-0">
          <header className="flex flex-col gap-2 border-b border-line px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <h3 id="selected-file-title" className="flex min-w-0 items-center gap-2 break-all text-sm font-medium text-ink data-text"><FileDiff aria-hidden="true" size={15} className="shrink-0 text-accent" />{selectedFile.path}</h3>
            <span className="text-xs text-muted">{titleCase(selectedFile.status)}</span>
          </header>
          <div className="h-[32rem] overflow-auto sm:h-[42rem]">
            <div className="min-w-[48rem] text-xs leading-5 data-text">
              {selectedFile.hunks.map((hunk) => <div key={hunk.header}>
                <div className="grid grid-cols-[3rem_3rem_1.25rem_minmax(0,1fr)] border-b border-line bg-accent-soft text-accent"><span /><span /><span className="py-1">@@</span><span className="whitespace-pre py-1 pr-4">{hunk.header.replace(/^@@\s*/, "")}</span></div>
                {hunk.lines.map((line, index) => {
                  const background = line.type === "addition" ? "bg-diff-add" : line.type === "deletion" ? "bg-diff-delete" : "bg-surface";
                  const marker = line.type === "addition" ? "+" : line.type === "deletion" ? "-" : " ";
                  return <div key={`${hunk.header}-${index}`} className={`grid grid-cols-[3rem_3rem_1.25rem_minmax(0,1fr)] ${background}`}><span className="select-none border-r border-line px-2 text-right text-faint">{line.oldLine}</span><span className="select-none border-r border-line px-2 text-right text-faint">{line.newLine}</span><span className={`select-none text-center ${line.type === "addition" ? "text-positive" : line.type === "deletion" ? "text-negative" : "text-faint"}`}>{marker}</span><span className="whitespace-pre pr-4 text-ink">{line.content || " "}</span></div>;
                })}
              </div>)}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
