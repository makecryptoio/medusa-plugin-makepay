import { Text } from "@medusajs/ui";

type ErrorNoticeProps = {
  title?: string;
  message: string;
};

export const ErrorNotice = ({
  title = "MakePay is unavailable",
  message,
}: ErrorNoticeProps) => (
  <div
    className="bg-ui-bg-subtle border-ui-border-error flex flex-col gap-y-1 rounded-lg border px-4 py-3"
    role="alert"
  >
    <Text size="small" weight="plus" className="text-ui-fg-error">
      {title}
    </Text>
    <Text size="small" className="text-ui-fg-subtle">
      {message}
    </Text>
  </div>
);
