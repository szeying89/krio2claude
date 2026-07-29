import json

from app.services.intel.extraction import INTEL_EXTRACTION_TEMPLATE, extract_intel
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams

PARAMS = CompletionParams(model="fake-model")

MESSY_ARTICLE_RESPONSE = json.dumps(
    {
        "technique_ids": ["T1190", "AML.T0015"],
        "cves": ["CVE-2024-1234"],
        "affected_products": [{"vendor": "nginx", "product": "nginx", "version": "1.24"}],
        "actor": "APT99",
        "targeted_sectors": ["financial services"],
        "campaign_start": "2024-03-01",
        "campaign_end": None,
        "ttp_summary": "APT99 exploited a public-facing nginx server for initial access.",
        "source_credibility": "medium",
    }
)


def test_article_text_is_quoted_between_delimiters_in_the_rendered_prompt():
    rendered = INTEL_EXTRACTION_TEMPLATE.render(article_text="hostile <<content>> here")
    assert "BEGIN_ARTICLE" in rendered
    assert "END_ARTICLE" in rendered
    assert "hostile <<content>> here" in rendered
    # "BEGIN_ARTICLE"/"END_ARTICLE" are also named in the instructional
    # prose itself, so anchor on the actual delimiter markers (the last
    # occurrence of each), not the first mention.
    begin = rendered.rindex("BEGIN_ARTICLE")
    end = rendered.rindex("END_ARTICLE")
    assert begin < rendered.index("hostile <<content>> here") < end


def test_extract_intel_parses_a_messy_fixture_into_the_strict_schema(tmp_path):
    gateway = LLMGateway(FakeProvider(respond=lambda _p: MESSY_ARTICLE_RESPONSE), cache_dir=tmp_path / "cache")
    extracted = extract_intel(gateway, PARAMS, "some messy real-world article text")

    assert extracted.technique_ids == ("T1190", "AML.T0015")
    assert extracted.cves == ("CVE-2024-1234",)
    assert len(extracted.affected_products) == 1
    assert extracted.affected_products[0].vendor == "nginx"
    assert extracted.affected_products[0].version == "1.24"
    assert extracted.actor == "APT99"
    assert extracted.targeted_sectors == ("financial services",)
    assert extracted.campaign_start == "2024-03-01"
    assert extracted.campaign_end is None
    assert extracted.source_credibility == "medium"


def test_extract_intel_defaults_are_empty_when_article_states_nothing(tmp_path):
    empty_response = json.dumps({})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: empty_response), cache_dir=tmp_path / "cache")
    extracted = extract_intel(gateway, PARAMS, "an article with nothing extractable")

    assert extracted.technique_ids == ()
    assert extracted.cves == ()
    assert extracted.affected_products == ()
    assert extracted.actor is None
    assert extracted.source_credibility == "unknown"
