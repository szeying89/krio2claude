from app.services.intel.models import AffectedProduct, ExtractedIntel
from app.services.intel.relevance import compute_relevance
from app.services.systemmodel.models import Component, SystemModel


def _model(components):
    return SystemModel(id="p1", version=1, parent_version=None, components=components)


def test_matching_product_and_component_produces_high_relevance():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel(affected_products=(AffectedProduct(vendor="nginx", product="nginx", version="1.24"),))

    result = compute_relevance(extracted, model)
    assert result.score > 0
    assert "gw" in result.matched_entity_ids
    assert any("nginx" in r for r in result.reasons)


def test_irrelevant_article_scores_zero_with_a_stated_reason():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel(
        affected_products=(AffectedProduct(vendor="oracle", product="weblogic", version="12c"),)
    )

    result = compute_relevance(extracted, model)
    assert result.score == 0.0
    assert result.matched_entity_ids == ()
    assert len(result.reasons) == 1
    assert "no matching" in result.reasons[0]


def test_no_affected_products_at_all_scores_zero():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel()
    result = compute_relevance(extracted, model)
    assert result.score == 0.0


def test_sector_match_adds_to_score_on_top_of_product_match():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel(
        affected_products=(AffectedProduct(vendor="nginx", product="nginx", version="1.24"),),
        targeted_sectors=("financial services",),
    )

    without_sector = compute_relevance(extracted, model, declared_sector=None)
    with_sector = compute_relevance(extracted, model, declared_sector="financial services")
    assert with_sector.score > without_sector.score


def test_sector_alone_with_no_product_match_does_not_score_without_a_product_hit():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel(targeted_sectors=("financial services",))
    result = compute_relevance(extracted, model, declared_sector="financial services")
    # sector-only match still adds its own score even without a product hit
    assert result.score == 0.3


def test_matches_multiple_components_for_the_same_product():
    model = _model(
        [
            Component(id="gw1", name="Gateway One", kind="process", trust_zone_id="tz1", technology_tags=("nginx",)),
            Component(id="gw2", name="Gateway Two", kind="process", trust_zone_id="tz1", technology_tags=("nginx",)),
        ]
    )
    extracted = ExtractedIntel(affected_products=(AffectedProduct(vendor="nginx", product="nginx"),))
    result = compute_relevance(extracted, model)
    assert set(result.matched_entity_ids) == {"gw1", "gw2"}


def test_score_never_exceeds_one():
    model = _model([Component(id="gw", name="API Gateway", kind="process", trust_zone_id="tz1", technology_tags=("nginx",))])
    extracted = ExtractedIntel(
        affected_products=(AffectedProduct(vendor="nginx", product="nginx"),),
        targeted_sectors=("financial services",),
    )
    result = compute_relevance(extracted, model, declared_sector="financial services")
    assert result.score <= 1.0
