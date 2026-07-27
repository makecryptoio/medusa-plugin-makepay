import { ArrowUpRightMini } from "@medusajs/icons";
import type { ReactNode } from "react";

import { safeExternalUrl } from "../lib/format";

type ExternalLinkProps = {
  children: ReactNode;
  href?: string;
  label: string;
};

export const ExternalLink = ({ children, href, label }: ExternalLinkProps) => {
  const safeHref = safeExternalUrl(href);
  if (!safeHref) {
    return null;
  }

  return (
    <a
      aria-label={label}
      className="text-ui-fg-interactive hover:text-ui-fg-interactive-hover txt-compact-small-plus inline-flex items-center gap-x-1"
      href={safeHref}
      rel="noopener noreferrer"
      target="_blank"
    >
      {children}
      <ArrowUpRightMini aria-hidden="true" />
    </a>
  );
};
