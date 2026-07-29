import pytest

from app.services.llm.prompt_template import PromptTemplate, PromptTemplateError


def test_render_substitutes_variables():
    template = PromptTemplate(name="extract", version="1", template="Summarize: $text")
    assert template.render(text="hello") == "Summarize: hello"


def test_id_combines_name_and_version():
    template = PromptTemplate(name="extract", version="2", template="$x")
    assert template.id == "extract@2"


def test_missing_variable_raises_actionable_error():
    template = PromptTemplate(name="extract", version="1", template="Summarize: $text")
    with pytest.raises(PromptTemplateError, match="extract@1"):
        template.render()


def test_template_does_not_evaluate_arbitrary_expressions():
    # string.Template only substitutes $name — it must not evaluate
    # anything resembling code even if document content contains it.
    template = PromptTemplate(name="t", version="1", template="Data: $text")
    rendered = template.render(text="${__import__('os')}")
    assert rendered == "Data: ${__import__('os')}"
