"""Pure merge algebra for control-loop overhead usage models.

Additive merges preserve known counters while clearing derived subtotals that
cannot be reconciled after combining partial evidence.  Cost filling is
intentionally separate: it replaces only missing values and never adds costs.
"""

from __future__ import annotations

from .models import UsageCosts, UsageCoverage, UsageTokens


def _optional_sum(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return left + right


def merge_usage_tokens(left: UsageTokens, right: UsageTokens) -> UsageTokens:
    """Add token counters and discard unreconciled derived subtotals."""

    values = {
        "inputTokens": _optional_sum(left.input_tokens, right.input_tokens),
        "cachedInputTokens": _optional_sum(
            left.cached_input_tokens, right.cached_input_tokens
        ),
        "uncachedInputTokens": _optional_sum(
            left.uncached_input_tokens, right.uncached_input_tokens
        ),
        "outputTokens": _optional_sum(left.output_tokens, right.output_tokens),
        "reasoningOutputTokens": _optional_sum(
            left.reasoning_output_tokens, right.reasoning_output_tokens
        ),
        "totalTokens": _optional_sum(left.total_tokens, right.total_tokens),
    }
    if values["inputTokens"] is not None and values["cachedInputTokens"] is not None:
        if values["cachedInputTokens"] > values["inputTokens"]:
            values["cachedInputTokens"] = None
        else:
            expected = values["inputTokens"] - values["cachedInputTokens"]
            if values["uncachedInputTokens"] != expected:
                values["uncachedInputTokens"] = None
    if values["outputTokens"] is not None and values["reasoningOutputTokens"] is not None:
        if values["reasoningOutputTokens"] > values["outputTokens"]:
            values["reasoningOutputTokens"] = None
    if (
        values["inputTokens"] is not None
        and values["outputTokens"] is not None
        and values["totalTokens"] is not None
        and values["totalTokens"] != values["inputTokens"] + values["outputTokens"]
    ):
        values["totalTokens"] = None
    return UsageTokens(**values)


def merge_usage_costs(left: UsageCosts, right: UsageCosts) -> UsageCosts:
    """Add cost components and retain only a reconciled total."""

    values = {
        "uncachedInputMicroUsd": _optional_sum(
            left.uncached_input_micro_usd, right.uncached_input_micro_usd
        ),
        "cachedInputMicroUsd": _optional_sum(
            left.cached_input_micro_usd, right.cached_input_micro_usd
        ),
        "outputMicroUsd": _optional_sum(
            left.output_micro_usd, right.output_micro_usd
        ),
        "totalMicroUsd": _optional_sum(left.total_micro_usd, right.total_micro_usd),
    }
    components = (
        values["uncachedInputMicroUsd"],
        values["cachedInputMicroUsd"],
        values["outputMicroUsd"],
    )
    if values["totalMicroUsd"] is not None and all(
        item is not None for item in components
    ):
        if values["totalMicroUsd"] != sum(
            item for item in components if item is not None
        ):
            values["totalMicroUsd"] = None
    present = [item is not None for item in values.values()]
    if all(present) and left.status == right.status == "Complete":
        status = "Complete"
    elif any(present):
        status = "Partial"
    else:
        status = "N.A."
    return UsageCosts(status=status, **values)


def merge_usage_coverage(left: UsageCoverage, right: UsageCoverage) -> UsageCoverage:
    """Add coverage counts and promote status only for complete evidence."""

    covered = left.covered_invocations + right.covered_invocations
    expected = left.expected_invocations + right.expected_invocations
    if expected == 0 or covered == 0:
        status = "N.A."
    elif covered == expected and left.status == right.status == "Complete":
        status = "Complete"
    else:
        status = "Partial"
    return UsageCoverage(
        coveredInvocations=covered,
        expectedInvocations=expected,
        status=status,
    )


def fill_usage_costs(left: UsageCosts, right: UsageCosts) -> UsageCosts:
    """Fill missing left cost values without adding or replacing known values."""

    values = {
        "uncachedInputMicroUsd": (
            left.uncached_input_micro_usd
            if left.uncached_input_micro_usd is not None
            else right.uncached_input_micro_usd
        ),
        "cachedInputMicroUsd": (
            left.cached_input_micro_usd
            if left.cached_input_micro_usd is not None
            else right.cached_input_micro_usd
        ),
        "outputMicroUsd": (
            left.output_micro_usd
            if left.output_micro_usd is not None
            else right.output_micro_usd
        ),
        "totalMicroUsd": (
            left.total_micro_usd
            if left.total_micro_usd is not None
            else right.total_micro_usd
        ),
    }
    components = (
        values["uncachedInputMicroUsd"],
        values["cachedInputMicroUsd"],
        values["outputMicroUsd"],
    )
    if values["totalMicroUsd"] is not None and all(
        item is not None for item in components
    ):
        if values["totalMicroUsd"] != sum(
            item for item in components if item is not None
        ):
            values["totalMicroUsd"] = None
    present = [item is not None for item in values.values()]
    if all(present):
        # A catalog can fill an unavailable contribution without turning a
        # partial capture into complete evidence.  Existing numeric costs are
        # otherwise immutable and retain their original coverage status.
        status = (
            "Partial"
            if left.status == "Partial" or right.status == "Partial"
            else "Complete"
        )
    else:
        status = "Partial" if any(present) else "N.A."
    return UsageCosts(status=status, **values)


__all__ = [
    "fill_usage_costs",
    "merge_usage_costs",
    "merge_usage_coverage",
    "merge_usage_tokens",
]
