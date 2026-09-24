"""AttackGraphScreen — pivot path visualization (spec §17.5).

Rich Tree rendering (NOT the Neo4j UI — spec is explicit). One root per
foothold host; successful pivots are children annotated with the MITRE
technique ID from the report's mapping; failed pivots render dimmed so
the operator sees attempted paths too.

Phase 6 Task 16 adaptation: the screen inherits from ``Screen`` (not
``Container`` — Textual requires ``Screen`` for ``push_screen`` routing;
matches the pattern established by StateInspectorScreen /
FindingsTableScreen in Task 15). The ``build_attack_graph_tree`` helper
is a pure function over ``state`` that constructs a standalone ``Tree``
widget (no app mount needed) so the second test can assert against its
structure directly.

The screen ``compose()`` method calls ``build_attack_graph_tree(state)``
and yields the resulting ``Tree`` widget directly — the helper already
populated it, so on_mount just expands the root.
"""
from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, Tree


def build_attack_graph_tree(state: Any, tree_id: str | None = None) -> Tree:
    """Build the pivot-path tree from state (pure construction helper).

    Returns a freshly constructed, fully-populated ``Tree`` widget.
    One branch per foothold; each branch's children are the pivots
    attempted from that host — successful pivots are bold yellow with
    an optional MITRE technique annotation; failed pivots are dimmed
    so the operator still sees the attempted paths.

    MITRE annotation: the report's ``mitre_mappings`` carry a
    ``source`` field naming the state collection the technique came
    from. For pivot annotations we filter ``source == "pivot"`` and
    match the pivot's ``target_host`` against the mapping's
    ``detail`` (which the Report Agent formats as ``"<method> to
    <target_host>"``).
    """
    tree: Tree[str] = Tree("Attack Graph", id=tree_id)

    mitre_by_detail = {
        m.detail: m.technique_id
        for m in getattr(state, "mitre_mappings", []) if m.source == "pivot"
    }

    footholds = list(getattr(state, "footholds", []) or [])
    pivots = list(getattr(state, "pivots", []) or [])

    if not footholds and not pivots:
        tree.root.add_leaf(
            "[dim]No lateral movement recorded — no attack graph to draw.[/]"
        )
        return tree

    for foothold in footholds:
        root_label = (
            f"[bold red]{foothold.host_ip}[/] "
            f"({foothold.username} via {foothold.method})"
        )
        branch = tree.root.add(root_label)
        # PivotRecord (spec §9.2) only carries ``target_host`` +
        # ``method`` — no source-host IP — so we can't attribute a
        # pivot to a specific foothold from the record alone. In
        # practice the Report Agent typically issues pivots from a
        # single foothold at a time, so the visual duplication is
        # rare; if it occurs, the operator still sees every path
        # under every branch.
        pivots_from_host = list(pivots)
        for pivot in pivots_from_host:
            technique_id = next(
                (tid for detail, tid in mitre_by_detail.items()
                 if pivot.target_host in detail),
                None,
            )
            annotation = f" [{technique_id}]" if technique_id else ""
            if pivot.success:
                branch.add_leaf(
                    f"→ [bold yellow]{pivot.target_host}[/] via "
                    f"{pivot.method}{annotation}"
                )
            else:
                branch.add_leaf(
                    f"[dim]↯ {pivot.target_host} via {pivot.method} "
                    f"(failed)[/]"
                )
        if not pivots_from_host:
            branch.add_leaf("[dim](no pivots attempted)[/]")

    return tree


class AttackGraphScreen(Screen):
    """Graph view of pivot paths (Rich rendering, not Neo4j)."""

    def __init__(self, state: Any) -> None:
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold]Attack Graph — pivot paths[/]", id="title")
        # Build the tree from state up-front — the helper returns a
        # fully-populated widget that we yield directly so the screen
        # mounts with all branches already attached to its root.
        yield build_attack_graph_tree(self.state, tree_id="attack-tree")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Attack Graph"
        tree = self.query_one(Tree)
        tree.root.expand()
