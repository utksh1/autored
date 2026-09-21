"""AutoRed persistence layer.

Provides:
  * ``filesystem`` — engagement folder layout + JSON state snapshots.
  * ``sqlite_saver`` — LangGraph ``AsyncSqliteSaver`` checkpointer factory
    that stores checkpoints inside each engagement folder for
    resume-after-crash capability.
"""
