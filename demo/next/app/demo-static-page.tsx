import Script from 'next/script';

import { readFileSync } from 'node:fs';
import path from 'node:path';

type DemoRoute = 'workbench' | 'perf-comparison' | 'interop-results' | 'coverage-results';

type DemoStaticPageProps = {
  route: DemoRoute;
  script: string;
  moduleScript?: boolean;
};

function readRouteAsset(route: DemoRoute, name: string) {
  return readFileSync(path.join(process.cwd(), 'app', route, name), 'utf8');
}

export default function DemoStaticPage({ route, script, moduleScript = false }: DemoStaticPageProps) {
  const css = readRouteAsset(route, 'page.css');
  const body = readRouteAsset(route, 'body.html');

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />
      <div dangerouslySetInnerHTML={{ __html: body }} />
      <Script src={script} strategy="afterInteractive" type={moduleScript ? 'module' : undefined} />
    </>
  );
}
