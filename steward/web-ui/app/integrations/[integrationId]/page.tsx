import { IntegrationDetailRoute } from "../../integration-detail";

export default async function IntegrationPage({ params }: { params: Promise<{ integrationId: string }> }) {
  const { integrationId } = await params;
  return <IntegrationDetailRoute integrationId={integrationId} />;
}
