import { StatusBadge } from "@medusajs/ui";

import { humanizeStatus, statusColor } from "../lib/format";

type MakePayStatusBadgeProps = {
  status?: string;
};

export const MakePayStatusBadge = ({ status }: MakePayStatusBadgeProps) => (
  <StatusBadge color={statusColor(status)}>
    {humanizeStatus(status)}
  </StatusBadge>
);
