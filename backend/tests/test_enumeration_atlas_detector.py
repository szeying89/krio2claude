from app.services.enumeration.atlas_detector import detect_atlas_indicators
from app.services.systemmodel.models import Component


def _component(id_: str, name: str, tags: tuple[str, ...] = ()) -> Component:
    return Component(id=id_, name=name, kind="process", trust_zone_id="tz1", technology_tags=tags)


def test_model_serving_indicator_fires():
    findings = detect_atlas_indicators([_component("c1", "TorchServe Model Server")])
    assert any(f.category == "model_serving" for f in findings)


def test_training_pipeline_indicator_fires():
    findings = detect_atlas_indicators([_component("c1", "Kubeflow Training Pipeline")])
    assert any(f.category == "training_pipeline" for f in findings)


def test_inference_endpoint_indicator_fires():
    findings = detect_atlas_indicators([_component("c1", "Customer Scoring Inference Endpoint")])
    assert any(f.category == "inference_endpoint" for f in findings)


def test_vector_store_indicator_fires_via_technology_tag():
    findings = detect_atlas_indicators([_component("c1", "Knowledge Base", tags=("Pinecone",))])
    assert any(f.category == "vector_store" for f in findings)


def test_agent_framework_indicator_fires():
    findings = detect_atlas_indicators([_component("c1", "Support Bot", tags=("LangChain",))])
    assert any(f.category == "agent_framework" for f in findings)


def test_stays_silent_on_pure_it_design():
    components = [
        _component("c1", "Payment Gateway"),
        _component("c2", "Auth Service", tags=("OAuth2", "JWT")),
        _component("c3", "User Database", tags=("PostgreSQL",)),
    ]
    findings = detect_atlas_indicators(components)
    assert findings == []


def test_whole_word_matching_avoids_false_positive_substring():
    # "chroma" (a vector store) must not fire on "chromatography" — the
    # same false-positive class the out-of-scope detector guards against.
    findings = detect_atlas_indicators([_component("c1", "Chromatography Lab Scheduler")])
    assert findings == []


def test_multiple_indicator_categories_on_one_design():
    components = [
        _component("c1", "Training Pipeline", tags=("MLflow",)),
        _component("c2", "Vector Database", tags=("Weaviate",)),
        _component("c3", "Model Inference API"),
    ]
    findings = detect_atlas_indicators(components)
    categories = {f.category for f in findings}
    assert categories == {"training_pipeline", "vector_store", "inference_endpoint"}


def test_finding_carries_subject_id_and_indicator():
    findings = detect_atlas_indicators([_component("c1", "Triton Inference Server")])
    finding = next(f for f in findings if f.category == "model_serving")
    assert finding.subject_id == "c1"
    assert finding.indicator == "triton inference server"
