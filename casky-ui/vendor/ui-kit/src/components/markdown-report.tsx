import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '../lib/cn';

export interface MarkdownReportProps {
  markdown: string;
  className?: string;
}

/**
 * Renders a markdown string (headers, lists, bold, tables, code, etc.) with
 * the same prose styling apps/web's markdown-block.tsx uses, but without any
 * app-specific import — this is the standalone, ui-kit version of that
 * component so both apps/web and casky-runner render markdown identically.
 */
export function MarkdownReport({ markdown, className }: MarkdownReportProps) {
  return (
    <div
      className={cn(
        'prose prose-sm prose-invert max-w-none',
        'prose-p:my-1 prose-p:leading-relaxed',
        'prose-ol:my-1 prose-ol:pl-4 prose-li:my-0.5 prose-li:leading-relaxed',
        'prose-ul:my-1 prose-ul:pl-4',
        'prose-strong:text-white prose-strong:font-semibold',
        'prose-code:text-emerald-300 prose-code:bg-slate-700 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-code:before:content-none prose-code:after:content-none',
        'prose-pre:bg-slate-900 prose-pre:text-emerald-300 prose-pre:text-xs prose-pre:rounded prose-pre:p-3',
        'prose-headings:text-white prose-headings:font-semibold prose-headings:mt-2 prose-headings:mb-1',
        'prose-table:w-full prose-table:text-xs prose-table:border-collapse',
        'prose-thead:border-b prose-thead:[border-color:rgba(255,255,255,0.1)]',
        'prose-tr:border-b prose-tr:[border-color:rgba(255,255,255,0.05)]',
        'prose-th:text-left prose-th:py-2 prose-th:pr-4 prose-th:font-semibold prose-th:[color:rgba(255,255,255,0.5)]',
        'prose-td:py-1.5 prose-td:pr-4 prose-td:align-top',
        '[&>*:first-child]:mt-0 [&>*:last-child]:mb-0',
        className
      )}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
    </div>
  );
}
