"""StateInspectorScreen — browse the full EngagementState tree (spec §17.5).

Depth capped at 5, lists capped at 10 items (+ "… N more"), strings
truncated at 50 chars — a 30-fingerprint state must stay renderable.

Phase 6 Task 15 adaptation: this screen inherits from ``Screen`` (not
``Container`` — Textual requires ``Screen`` for ``push_screen`` routing;
a ``Container`` raised ``ScreenError`` when ``AutoRedApp.push_screen``
tried to mount it in earlier Phase 6 review).
"""
from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, Tree

MAX_DEPTH = 5
MAX_LIST_ITEMS = 10
MAX_STRING = 50


class StateInspectorScreen(Screen):
    """Browse the full EngagementState as a collapsible tree.

    Takes a live ``EngagementState`` (NOT a dict) — ``on_mount`` calls
    ``state.model_dump()`` so the tree sees plain dicts / lists /
    scalars, which is what Textual's ``TreeNode.add`` expects.
    """

    def __init__(self, state: Any) -> None:
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold]Engagement State Inspector[/]", id="title")
        yield Tree("EngagementState", id="state-tree")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — State Inspector"
        tree = self.query_one(Tree)
        # ``model_dump()`` recurses through nested Pydantic models (Host,
        # Service, Vulnerability, ...) into plain dicts so the tree
        # population stays type-agnostic — a Phase 5 state with MovementPath
        # objects doesn't need a special-case branch here.
        self._populate_tree(tree.root, self.state.model_dump(), depth=0)
        tree.root.expand()

    def _populate_tree(self, node, data: Any, depth: int = 0) -> None:
        """Recursively walk ``data`` into ``node``.

        Depth-capped at ``MAX_DEPTH`` (5) — beyond that a "…
        (depth cap)" leaf is added so the operator sees the cap
        explicitly rather than an empty branch. Lists are sliced at
        ``MAX_LIST_ITEMS`` (10) with an "… N more" leaf so a
        30-fingerprint scan doesn't expand the tree to 300 lines.
        Strings longer than ``MAX_STRING`` (50 chars) are truncated
        with an ellipsis.
        """
        if depth > MAX_DEPTH:
            node.add_leaf("[dim]… (depth cap)[/]")
            return
        if isinstance(data, dict):
            for key, value in data.items():
                # Branch on container types; scalars are leaf values.
                if isinstance(value, (dict, list)) and value:
                    branch = node.add(f"[cyan]{key}[/]")
                    self._populate_tree(branch, value, depth + 1)
                else:
                    display = self._format_value(value)
                    node.add_leaf(f"[cyan]{key}[/]: {display}")
        elif isinstance(data, list):
            # Cap list rendering at MAX_LIST_ITEMS so a 30-fingerprint
            # state doesn't expand the tree to 300 leaf rows; the cap
            # is announced as an explicit "… N more" leaf so the
            # operator knows there's more data they can't see.
            for i, item in enumerate(data[:MAX_LIST_ITEMS]):
                if isinstance(item, (dict, list)):
                    branch = node.add(f"[{i}]")
                    self._populate_tree(branch, item, depth + 1)
                else:
                    node.add_leaf(f"[{i}] {self._format_value(item)}")
            if len(data) > MAX_LIST_ITEMS:
                node.add_leaf(
                    f"[dim]… {len(data) - MAX_LIST_ITEMS} more[/]"
                )
        else:
            # Scalar at the root (state was a bare value) — render as a
            # leaf directly. In practice ``state.model_dump()`` always
            # returns a dict so this branch is defensive.
            node.add_leaf(self._format_value(data))

    def _format_value(self, value: Any) -> str:
        """Format a scalar for tree display.

        ``None`` → dim "null" (Rich markup preserved by Tree's
        ``markup=True`` default). Strings > 50 chars are truncated with
        an ellipsis so a 200-char description doesn't blow out the
        layout. Everything else falls through to ``str(value)``.
        """
        if value is None:
            return "[dim]null[/]"
        if isinstance(value, str) and len(value) > MAX_STRING:
            return f'"{value[:MAX_STRING - 3]}..."'
        return str(value)
