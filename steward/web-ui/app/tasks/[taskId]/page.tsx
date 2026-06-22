import { TaskDetailRoute } from "../../task-detail";

export default async function TaskPage({ params }: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await params;
  return <TaskDetailRoute taskId={taskId} />;
}
