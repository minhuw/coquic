type PageHeaderProps = {
  eyebrow: string;
  title: string;
};

export function PageHeader({ eyebrow, title }: PageHeaderProps) {
  return (
    <header className="page-header">
      <span className="eyebrow">{eyebrow}</span>
      <h1 className="page-title">{title}</h1>
    </header>
  );
}
