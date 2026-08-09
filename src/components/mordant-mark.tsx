export function MordantMark({ className }: { readonly className?: string }) {
  return (
    <svg className={className} viewBox="0 0 100 100" aria-hidden="true">
      <rect x="43" width="14" height="100" />
      <rect y="43" width="100" height="14" />
      <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
      <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
    </svg>
  );
}
