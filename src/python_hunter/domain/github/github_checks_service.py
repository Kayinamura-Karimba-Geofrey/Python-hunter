"""GitHub Check Run, Annotation, and PR Comment Service."""

import logging
from typing import Any, Dict, List, Optional
from python_hunter.domain.github.github_models import (
    GitHubAnnotation,
    GitHubCheckRun,
    PolicyResultStatus,
    PullRequestSecurityResult,
    PullRequestSecuritySummary,
)

logger = logging.getLogger("python_hunter.checks_service")

MAX_ANNOTATIONS_PER_CHECK = 50
MAX_ANNOTATION_MESSAGE_LEN = 1000


class GitHubChecksService:
    """Formats and posts GitHub Check Runs with inline annotations."""

    def build_check_run(
        self,
        res: PullRequestSecurityResult,
        summary: PullRequestSecuritySummary,
        max_annotations: int = MAX_ANNOTATIONS_PER_CHECK,
    ) -> GitHubCheckRun:
        """Constructs GitHub Check Run payload with PASS / WARN / FAIL status and bounded annotations."""
        if res.policy_result == PolicyResultStatus.PASS:
            conclusion = "success"
        elif res.policy_result == PolicyResultStatus.WARN:
            conclusion = "neutral"
        else:
            conclusion = "failure"

        annotations: List[GitHubAnnotation] = []
        # Sort new findings by risk/severity so top priority findings get annotated first
        sorted_findings = sorted(
            res.new_findings,
            key=lambda f: f.get("risk_score", 0.0),
            reverse=True,
        )

        for finding in sorted_findings[:max_annotations]:
            sev = finding.get("severity", "MEDIUM").upper()
            level = "failure" if sev in ("CRITICAL", "HIGH") else "warning"
            file_path = finding.get("file_path", "unknown")
            line = finding.get("line_number", 1)
            msg = finding.get("description", "Security vulnerability detected.")

            if len(msg) > MAX_ANNOTATION_MESSAGE_LEN:
                msg = msg[:MAX_ANNOTATION_MESSAGE_LEN - 3] + "..."

            annotations.append(
                GitHubAnnotation(
                    path=file_path,
                    start_line=line,
                    end_line=line,
                    annotation_level=level,
                    title=f"[{sev}] {finding.get('title', 'Security Finding')}",
                    message=msg,
                    raw_details=f"Rule: {finding.get('rule_id')} | Risk: {finding.get('risk_score')}",
                )
            )

        text_body = summary.summary_markdown
        if len(res.new_findings) > max_annotations:
            text_body += f"\n\n> [!NOTE]\n> Exceeded maximum annotation limit of {max_annotations}. {len(res.new_findings) - max_annotations} remaining findings are summarized in the report above."

        return GitHubCheckRun(
            name="Python Hunter Security Gate",
            head_sha=res.head_sha,
            status="completed",
            conclusion=conclusion,
            summary=f"Security Gate {res.policy_result.value}: Score {res.head_score}/100 (Delta {res.score_delta:+d})",
            text=text_body,
            annotations=annotations,
        )


class GitHubCommentService:
    """Manages PR summary comments idempotently (updating existing comment if present)."""

    def __init__(self) -> None:
        self._comments_store: Dict[str, str] = {}  # repo#pr_num -> comment_id

    def post_or_update_pr_comment(
        self,
        repo: str,
        pr_number: int,
        summary_markdown: str,
        comments_enabled: bool = True,
    ) -> Dict[str, Any]:
        """Creates a new PR comment or updates Python Hunter's existing PR comment."""
        if not comments_enabled:
            return {"status": "DISABLED", "message": "PR comments are disabled by configuration."}

        key = f"{repo}#{pr_number}"
        if key in self._comments_store:
            comment_id = self._comments_store[key]
            logger.info(f"Updating existing PR comment {comment_id} for {key}")
            return {
                "status": "UPDATED",
                "comment_id": comment_id,
                "body": summary_markdown,
            }
        else:
            comment_id = f"comment-{pr_number}-pyh-1"
            self._comments_store[key] = comment_id
            logger.info(f"Created new PR comment {comment_id} for {key}")
            return {
                "status": "CREATED",
                "comment_id": comment_id,
                "body": summary_markdown,
            }
