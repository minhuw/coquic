from .sqlite import SQLiteTaskStore

TaskStore = SQLiteTaskStore

__all__ = ["SQLiteTaskStore", "TaskStore"]
