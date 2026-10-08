from __future__ import annotations

from datetime import datetime

from pydantic import Field

from ira.tools.base import ReadOnlyTool, ToolInput, ToolOutput, fmt_ts


class ListDeploysInput(ToolInput):
    service: str | None = Field(default=None, description="Exact service name filter.")
    since: datetime | None = Field(
        default=None, description="ISO-8601 start. Defaults to 7 days before the alert."
    )
    until: datetime | None = Field(
        default=None, description="ISO-8601 end. Defaults to 15 minutes after the alert."
    )


class ListDeploys(ReadOnlyTool):
    name = "list_deploys"
    description = (
        "List code deploys and config changes (kind=code|config), oldest first, with minutes "
        "relative to the alert. Read-only."
    )
    Input = ListDeploysInput

    def run(self, args: ListDeploysInput) -> ToolOutput:
        since = args.since or self.ctx.fired_at - self.ctx.deploy_lookback
        until = args.until or self.ctx.default_until
        deploys = self.backend.list_deploys(service=args.service, since=since, until=until)
        rows = []
        for d in deploys:
            rel = (d.ts - self.ctx.fired_at).total_seconds() / 60
            rows.append(
                f"{d.id} {fmt_ts(d.ts)} ({rel:+.0f} min vs alert) kind={d.kind} "
                f"service={d.service} version={d.version} author={d.author}: {d.summary}"
            )
        return ToolOutput(
            "\n".join([f"{len(rows)} deploys between {fmt_ts(since)} and {fmt_ts(until)}.", *rows]),
            [d.model_dump(mode="json", exclude={"diff"}) for d in deploys],
        )


class GetDeployDiffInput(ToolInput):
    deploy_id: str = Field(min_length=1, description="Deploy id from list_deploys.")


class GetDeployDiff(ReadOnlyTool):
    name = "get_deploy_diff"
    description = "Show the diff for one deploy or config change. Read-only."
    Input = GetDeployDiffInput

    def run(self, args: GetDeployDiffInput) -> ToolOutput:
        d = self.backend.get_deploy(deploy_id=args.deploy_id)
        if d is None:
            return ToolOutput(f"No deploy with id {args.deploy_id!r}.", None)
        head = (
            f"{d.id} {d.kind} {d.service} {d.version} by {d.author} at {fmt_ts(d.ts)}: {d.summary}"
        )
        return ToolOutput(f"{head}\n{d.diff}", d.model_dump(mode="json"))
