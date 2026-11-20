import pytest

from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.schemas import (
    ClassificationStatus,
    TaskType,
)


@pytest.fixture
def classifier() -> DeterministicTaskClassifier:
    return DeterministicTaskClassifier()


@pytest.mark.parametrize(
    ("explicit", "expected"),
    [
        ("conversation", TaskType.CONVERSATION),
        ("general", TaskType.CONVERSATION),
        ("language_lookup", TaskType.LANGUAGE_LOOKUP),
        ("provider_status", TaskType.PROVIDER_STATUS),
        ("unsupported", TaskType.UNSUPPORTED),
    ],
)
def test_explicit_task_classification(
    classifier: DeterministicTaskClassifier,
    explicit: str,
    expected: TaskType,
) -> None:
    result = classifier.classify("Irrelevant text", explicit)

    assert result.task_type == expected
    assert result.status in {
        ClassificationStatus.EXPLICIT,
        ClassificationStatus.UNSUPPORTED,
    }


def test_unknown_explicit_task_is_unsupported(
    classifier: DeterministicTaskClassifier,
) -> None:
    result = classifier.classify("Hello", "send_a_rocket")

    assert result.task_type == TaskType.UNSUPPORTED
    assert result.status == ClassificationStatus.UNSUPPORTED
    assert "Unknown explicit task type" in result.reason


def test_default_conversation_classification(
    classifier: DeterministicTaskClassifier,
) -> None:
    result = classifier.classify("Hello, how are you?")

    assert result.task_type == TaskType.CONVERSATION
    assert result.status == ClassificationStatus.DEFAULT
    assert result.confidence == 0.5


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Show provider status", TaskType.PROVIDER_STATUS),
        ("Lookup language metadata", TaskType.LANGUAGE_LOOKUP),
        ("Send an email for me", TaskType.UNSUPPORTED),
        ("Execute a shell command", TaskType.UNSUPPORTED),
    ],
)
def test_default_pattern_classification(
    classifier: DeterministicTaskClassifier,
    text: str,
    expected: TaskType,
) -> None:
    assert classifier.classify(text).task_type == expected


def test_empty_input_is_unsupported(
    classifier: DeterministicTaskClassifier,
) -> None:
    result = classifier.classify("   ")

    assert result.task_type == TaskType.UNSUPPORTED
    assert result.status == ClassificationStatus.UNSUPPORTED


@pytest.mark.parametrize(
    "text",
    [
        "How do I send an email?",
        "Can you explain what sending a text means?",
        "Why would someone place a call?",
        "What does execute a shell command mean?",
        "Is delete file dangerous?",
    ],
)
def test_explanatory_questions_are_not_marked_consequential(
    classifier: DeterministicTaskClassifier,
    text: str,
) -> None:
    result = classifier.classify(text)

    assert result.task_type != TaskType.UNSUPPORTED
