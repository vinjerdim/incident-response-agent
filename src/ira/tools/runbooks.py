from __future__ import annotations

from pydantic import Field

from ira.tools.base import ReadOnlyTool, ToolInput, ToolOutput


class SearchRunbooksInput(ToolInput):
    query: str | None = Field(default=None, description="Keywords; omit to list all runbooks.")


class SearchRunbooks(ReadOnlyTool):
    name = "search_runbooks"
    description = "Find runbooks by keyword. Returns slug, title and a snippet. Read-only."
    Input = SearchRunbooksInput

    def run(self, args: SearchRunbooksInput) -> ToolOutput:
        books = self.backend.search_runbooks(query=args.query)
        rows = []
        for r in books:
            snippet = " ".join(r.body.split())[:160]
            rows.append(f"{r.slug}: {r.title} -- {snippet}")
        return ToolOutput(
            "\n".join([f"{len(rows)} runbooks.", *rows]),
            [{"slug": r.slug, "title": r.title} for r in books],
        )


class GetRunbookInput(ToolInput):
    slug: str = Field(min_length=1, description="Runbook slug from search_runbooks.")


class GetRunbook(ReadOnlyTool):
    name = "get_runbook"
    description = "Read a runbook in full. Read-only."
    Input = GetRunbookInput

    def run(self, args: GetRunbookInput) -> ToolOutput:
        r = self.backend.get_runbook(slug=args.slug)
        if r is None:
            return ToolOutput(f"No runbook with slug {args.slug!r}.", None)
        return ToolOutput(r.body, {"slug": r.slug, "title": r.title})
