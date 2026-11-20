from backend.app.intelligence.schemas import (
    ClassificationStatus,
    TaskClassification,
    TaskType,
)


class DeterministicTaskClassifier:
    """Conservative, deterministic task classification without model inference."""

    EXPLICIT_TASK_ALIASES = {
        "conversation": TaskType.CONVERSATION,
        "general": TaskType.CONVERSATION,
        "chat": TaskType.CONVERSATION,
        "language_lookup": TaskType.LANGUAGE_LOOKUP,
        "language": TaskType.LANGUAGE_LOOKUP,
        "provider_status": TaskType.PROVIDER_STATUS,
        "providers": TaskType.PROVIDER_STATUS,
        "unsupported": TaskType.UNSUPPORTED,
    }

    UNSUPPORTED_PATTERNS = (
        "delete file",
        "send email",
        "send an email",
        "send text",
        "send a text",
        "make payment",
        "transfer money",
        "place call",
        "place a call",
        "run shell",
        "execute command",
        "execute a shell command",
    )

    LANGUAGE_LOOKUP_PATTERNS = (
        "language code",
        "lookup language",
        "list languages",
        "language metadata",
    )

    PROVIDER_STATUS_PATTERNS = (
        "provider status",
        "provider health",
        "list providers",
    )

    def classify(
        self,
        text: str,
        explicit_task_type: str | None = None,
    ) -> TaskClassification:
        if explicit_task_type:
            normalized = explicit_task_type.strip().lower().replace("-", "_")
            explicit_type = self.EXPLICIT_TASK_ALIASES.get(normalized)
            if explicit_type is None:
                return TaskClassification(
                    task_type=TaskType.UNSUPPORTED,
                    status=ClassificationStatus.UNSUPPORTED,
                    confidence=1.0,
                    reason=f"Unknown explicit task type: {normalized}",
                )
            if explicit_type == TaskType.UNSUPPORTED:
                return TaskClassification(
                    task_type=TaskType.UNSUPPORTED,
                    status=ClassificationStatus.UNSUPPORTED,
                    confidence=1.0,
                    reason="The requested task is explicitly unsupported",
                )
            return TaskClassification(
                task_type=explicit_type,
                status=ClassificationStatus.EXPLICIT,
                confidence=1.0,
                reason="Task type was explicitly selected",
            )

        normalized_text = text.lower().strip()
        if not normalized_text:
            return TaskClassification(
                task_type=TaskType.UNSUPPORTED,
                status=ClassificationStatus.UNSUPPORTED,
                confidence=1.0,
                reason="No input text was provided",
            )

        explanatory_prefixes = (
            "how ",
            "what ",
            "why ",
            "when ",
            "where ",
            "who ",
            "explain ",
            "describe ",
            "does ",
            "do ",
            "can ",
            "could ",
            "would ",
            "is ",
            "are ",
        )
        starts_explanatory = any(
            normalized_text.startswith(prefix)
            for prefix in explanatory_prefixes
        )

        if not starts_explanatory:
            if any(
                pattern in normalized_text
                for pattern in self.UNSUPPORTED_PATTERNS
            ):
                return TaskClassification(
                    task_type=TaskType.UNSUPPORTED,
                    status=ClassificationStatus.UNSUPPORTED,
                    confidence=0.9,
                    reason="The request appears to require an unsupported consequential action",
                )

        if any(
            pattern in normalized_text
            for pattern in self.PROVIDER_STATUS_PATTERNS
        ):
            return TaskClassification(
                task_type=TaskType.PROVIDER_STATUS,
                status=ClassificationStatus.DEFAULT,
                confidence=0.8,
                reason="Text matches provider status terminology",
            )

        if any(
            pattern in normalized_text
            for pattern in self.LANGUAGE_LOOKUP_PATTERNS
        ):
            return TaskClassification(
                task_type=TaskType.LANGUAGE_LOOKUP,
                status=ClassificationStatus.DEFAULT,
                confidence=0.8,
                reason="Text matches language metadata terminology",
            )

        return TaskClassification(
            task_type=TaskType.CONVERSATION,
            status=ClassificationStatus.DEFAULT,
            confidence=0.5,
            reason="No capability-specific terms were matched; classified conservatively",
        )
