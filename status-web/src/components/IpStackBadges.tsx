// Public IP stack presence indicator (never displays or receives IP addresses).
export function IpStackBadges({
  ipv4,
  ipv6,
}: {
  ipv4?: boolean;
  ipv6?: boolean;
}) {
  if (!ipv4 && !ipv6) return null;
  return (
    <>
      {ipv4 ? <span className="monIpBadge">V4</span> : null}
      {ipv6 ? (
        <span className="monIpBadge" data-v6="true">
          V6
        </span>
      ) : null}
    </>
  );
}
