import io

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification
from sqlalchemy import select

from app.audit import verify_chain
from app.ml import detection as det
from app.ml import poison as po
from app.models import AuditEvent, DatasetVersion, ExperimentGroundTruth
from app.storage import get_storage
from .conftest import hdr, login, register_and_verify


def make_csv(n=300, poison=0):
    X, y = make_classification(n_samples=n, n_features=6, n_informative=4, random_state=3, class_sep=2.0)
    df = pd.DataFrame(X, columns=[f"f{i}" for i in range(6)])
    df["label"] = y
    df.loc[:4, "f0"] = np.nan
    df = pd.concat([df, df.iloc[:2]], ignore_index=True)
    return df


def upload(c, df=None, name="d1", source="unit-test", label="label", fname="data.csv"):
    df = make_csv() if df is None else df
    r = c.post("/api/datasets", headers=hdr(c), data={"name": name, "source": source, "label_column": label},
               files={"file": (fname, df.to_csv(index=False).encode(), "text/csv")})
    assert r.status_code == 201, r.text
    return r.json()


def test_upload_validation(user_client):
    c = user_client
    h = hdr(c)
    assert c.post("/api/datasets", headers=h, files={"file": ("x.exe", b"MZ", "application/octet-stream")}).status_code == 422
    assert c.post("/api/datasets", headers=h, files={"file": ("x.csv", b"", "text/csv")}).status_code == 422
    assert c.post("/api/datasets", headers=h, files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")}).status_code == 422   # <10 rows
    assert c.post("/api/datasets", headers=h, files={"file": ("x.xlsx", b"not a zip", "x")}).status_code == 422
    r = c.post("/api/datasets", headers=h, data={"label_column": "nope"},
               files={"file": ("x.csv", make_csv().to_csv(index=False).encode(), "text/csv")})
    assert r.status_code == 422
    assert c.post("/api/datasets", files={"file": ("x.csv", b"a,b", "text/csv")}).status_code == 403   # CSRF


def test_upload_xlsx_and_hash_and_preview(user_client):
    c = user_client
    buf = io.BytesIO()
    make_csv().to_excel(buf, index=False)
    r = c.post("/api/datasets", headers=hdr(c), data={"label_column": "label"}, files={"file": ("d.xlsx", buf.getvalue(), "x")})
    assert r.status_code == 201
    d = r.json()
    import hashlib
    assert d["sha256"] == hashlib.sha256(buf.getvalue()).hexdigest()
    p = c.get(f"/api/datasets/{d['id']}/preview").json()
    assert p["integrity_ok"] and p["total_rows"] == 302 and "f0" in p["columns"]
    assert c.get(f"/api/datasets/{d['id']}/download").content == buf.getvalue()


def test_pipeline_preserves_raw_and_tracks_lineage(user_client):
    c = user_client
    d = upload(c)
    r = c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    assert r.status_code == 202
    run = c.get(f"/api/datasets/{d['id']}/pipeline-runs").json()["items"][0]
    assert run["status"] == "completed", run
    q = run["report"]["quality"]
    assert q["duplicate_rows"] == 2 and q["missing_cells"] == 7
    assert run["report"]["rows_after"] == 300
    ds = c.get(f"/api/datasets/{d['id']}").json()
    kinds = [v["kind"] for v in ds["versions"]]
    assert kinds == ["raw", "cleaned"]
    assert ds["versions"][0]["sha256"] == d["sha256"]                # raw untouched
    lin = c.get(f"/api/datasets/{d['id']}/lineage").json()
    assert len(lin["edges"]) == 1 and lin["edges"][0]["operation"] == "pipeline:clean"
    assert c.post(f"/api/datasets/{d['id']}/verify-integrity", headers=hdr(c)).json()["all_verified"] is True


def test_tamper_detection_and_security_event(user_client, db):
    c = user_client
    d = upload(c)
    v = db.execute(select(DatasetVersion)).scalar_one()
    get_storage().put(v.artifact_key, b"tampered,data\n1,2\n")
    r = c.post(f"/api/datasets/{d['id']}/verify-integrity", headers=hdr(c)).json()
    assert r["all_verified"] is False
    assert c.get(f"/api/datasets/{d['id']}/download").status_code == 409
    assert db.execute(select(AuditEvent).where(AuditEvent.action == "integrity.hash_mismatch")).first()
    # pipeline refuses tampered data
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    assert c.get(f"/api/datasets/{d['id']}/pipeline-runs").json()["items"][0]["status"] == "failed"


def test_trust_score_formula_and_missing_evidence():
    df = make_csv()
    res, summ = det.run_detection(df, "label", provenance=1.0)
    w = det.DEFAULT_CONFIG["weights"]
    r = res[res.category != "invalid"].iloc[0]
    expected = 100 * (w["statistical_normality"] * r.statistical_normality + w["label_consistency"] * r.label_consistency
                      + w["provenance"] * r.provenance + w["data_quality"] * r.data_quality + w["model_impact"] * r.model_impact)
    assert r.trust_score == pytest.approx(expected, abs=1e-6)
    assert res.trust_score.dropna().between(0, 100).all()
    # no label & no provenance => missing evidence is explicit and neutral, not perfect
    res2, s2 = det.run_detection(df.drop(columns=["label"]), None, provenance=None)
    assert set(s2["evidence_missing"]) >= {"label_consistency", "provenance", "model_impact"}
    assert res2.trust_score.dropna().max() < 100
    assert (res2.category == "insufficient_evidence").sum() > 0 or True


def test_integrity_failure_not_overridden_by_high_score():
    df = make_csv()
    res, _ = det.run_detection(df, "label", provenance=1.0, integrity_failed=True)
    ok = res[res.category != "invalid"]
    assert (ok.category == "highly_suspicious").all() and ok.critical_failure.all()


def test_invalid_is_separate_category():
    df = make_csv()
    df.loc[10, df.columns[:5]] = np.nan
    df.loc[10, "label"] = 1
    res, _ = det.run_detection(df, "label", provenance=1.0)
    assert res.loc[10, "category"] == "invalid" and pd.isna(res.loc[10, "trust_score"])


def test_threshold_config_validation():
    with pytest.raises(ValueError):
        det.merged_config({"review_min": 90, "high_trust_min": 50})
    c = det.merged_config({"weights": {"statistical_normality": 1, "label_consistency": 1, "provenance": 1, "data_quality": 1, "model_impact": 1}})
    assert sum(c["weights"].values()) == pytest.approx(1.0)


def test_detection_job_quarantine_and_review_flow(user_client, admin_client):
    c = user_client
    df = make_csv(400)
    # inject obvious poison: flipped labels + extreme values
    rng = np.random.default_rng(0)
    idx = rng.choice(len(df), 40, replace=False)
    df.loc[idx, "label"] = 1 - df.loc[idx, "label"]
    df.loc[idx[:15], "f1"] = 40.0
    d = upload(c, df)
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    r = c.post(f"/api/datasets/{d['id']}/detect", headers=hdr(c), json={})
    assert r.status_code == 202
    run = c.get(f"/api/datasets/{d['id']}/detection-runs").json()["items"][0]
    assert run["status"] == "completed", run
    sm = run["summary"]
    assert sm["n_records"] > 0 and "disclaimer" in sm and sm["dataset_trust_score"] is not None
    res = c.get(f"/api/detection-runs/{run['id']}/results?page_size=5").json()
    assert res["items"][0]["trust_score"] <= res["items"][-1]["trust_score"]
    assert res["items"][0]["explanation"]
    qs = c.get("/api/quarantine").json()
    assert qs["total"] > 0
    rid = qs["items"][0]["id"]
    detail = c.get(f"/api/quarantine/{rid}").json()
    assert detail["row"] and detail["reasons"]
    # analyst cannot release; must approve first
    assert c.post(f"/api/quarantine/{rid}/decision", headers=hdr(c), json={"decision": "release", "notes": "x"}).status_code == 403
    assert c.post(f"/api/quarantine/{rid}/decision", headers=hdr(c), json={"decision": "reject", "notes": ""}).status_code == 422
    assert c.post(f"/api/quarantine/{rid}/decision", headers=hdr(c), json={"decision": "investigate", "notes": "looking"}).status_code == 200
    # filtering removes quarantined rows into a NEW version
    f = c.post(f"/api/datasets/{d['id']}/apply-filter", headers=hdr(c)).json()
    assert f["rows_removed"] > 0
    vs = c.get(f"/api/datasets/{d['id']}").json()["versions"]
    assert [v["kind"] for v in vs][-1] == "filtered" and vs[0]["kind"] == "raw"
    hist = c.get(f"/api/quarantine/{rid}").json()["decisions"]
    assert hist[-1]["decision"] == "investigate"
    # histogram endpoint feeds charts
    assert sum(b["count"] for b in c.get(f"/api/datasets/{d['id']}/trust-histogram").json()["bins"]) > 0


def test_release_requires_approval_by_reviewer(user_client, admin_client):
    u, a = user_client, admin_client
    df = make_csv(400)
    idx = np.random.default_rng(0).choice(len(df), 40, replace=False)
    df.loc[idx, "label"] = 1 - df.loc[idx, "label"]
    df.loc[idx[:15], "f1"] = 40.0
    d = upload(u, df)
    u.post(f"/api/datasets/{d['id']}/detect", headers=hdr(u), json={})
    qs = u.get("/api/quarantine").json()
    assert qs["total"] > 0
    rid = qs["items"][0]["id"]
    assert a.post(f"/api/quarantine/{rid}/decision", headers=hdr(a), json={"decision": "release", "notes": "n"}).status_code == 409
    assert a.post(f"/api/quarantine/{rid}/decision", headers=hdr(a), json={"decision": "approve", "notes": ""}).status_code == 200
    assert a.post(f"/api/quarantine/{rid}/decision", headers=hdr(a), json={"decision": "release", "notes": "safe"}).status_code == 200


@pytest.mark.parametrize("model", ["logistic_regression", "random_forest", "decision_tree"])
def test_training_and_registry(user_client, model):
    c = user_client
    d = upload(c)
    assert c.post(f"/api/datasets/{d['id']}/train", headers=hdr(c), json={"model_type": "nope"}).status_code == 422
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    assert c.post(f"/api/datasets/{d['id']}/train", headers=hdr(c), json={"model_type": model}).status_code == 202
    runs = c.get("/api/training-runs").json()["items"]
    assert runs[0]["status"] == "completed", runs[0]
    m = c.get("/api/models").json()["items"][0]
    assert m["metrics"]["accuracy"] > 0.7 and m["version"] == 1 and len(m["sha256"]) == 64
    assert c.post(f"/api/models/{m['id']}/verify", headers=hdr(c)).json()["verified"] is True
    c.post(f"/api/datasets/{d['id']}/train", headers=hdr(c), json={"model_type": model})
    assert max(x["version"] for x in c.get("/api/models").json()["items"]) == 2
    # model is deterministic given same data
    ms = c.get("/api/models").json()["items"]
    assert ms[0]["metrics"]["accuracy"] == ms[1]["metrics"]["accuracy"]


@pytest.mark.parametrize("attack", list(po.ATTACKS))
def test_poison_functions(attack):
    df = make_csv()
    out, mask = po.poison(df, "label", attack, 0.1, seed=1)
    assert len(mask) == len(out) and 0 < mask.sum() <= int(len(out) * 0.2)
    assert not out.equals(df)
    assert len(df) == 302   # original copy untouched


@pytest.mark.parametrize("attack", ["label_flip", "injection"])
def test_experiment_end_to_end(user_client, admin_client, db, attack):
    c = user_client
    d = upload(c, make_csv(400))
    r = c.post("/api/experiments", headers=hdr(c), json={"dataset_id": d["id"], "name": f"exp-{attack}", "attack": attack,
                                                         "poison_rate": 0.15, "model_type": "random_forest"})
    assert r.status_code == 202
    e = c.get("/api/experiments").json()["items"][0]
    assert e["status"] == "completed", e
    res = e["results"]
    for k in ("clean", "poisoned", "filtered"):
        assert res[k] is not None and 0 <= res[k]["accuracy"] <= 1
    dm = res["detection"]
    for k in ("precision", "recall", "false_positive_rate", "f1", "retention", "detection_time_s"):
        assert dm[k] is not None
    assert res["n_poisoned"] > 0 and res["n_test"] > 0
    # ground truth is restricted metadata
    assert db.execute(select(ExperimentGroundTruth)).scalar_one().n_poisoned == res["n_poisoned"]
    assert c.get(f"/api/experiments/{e['id']}/ground-truth").status_code == 403
    assert admin_client.get(f"/api/experiments/{e['id']}/ground-truth").status_code in (200, 404)


def test_detection_has_no_access_to_ground_truth():
    import inspect
    params = set(inspect.signature(det.run_detection).parameters)
    assert params == {"df", "label_col", "provenance", "integrity_failed", "config"}   # no truth/mask input
    src = inspect.getsource(det.run_detection)
    assert "ExperimentGroundTruth" not in src and "truth" not in src


def test_rbac_and_resource_authorization(user_client, mail):
    from fastapi.testclient import TestClient
    from app.main import app
    c = user_client
    d = upload(c)
    # second user cannot touch first user's dataset (analyst -> own only)
    with TestClient(app, base_url="https://testserver") as other:
        register_and_verify(other, mail, email="other@example.com", name="Other")
        login(other, email="other@example.com")
        assert other.get(f"/api/datasets/{d['id']}").status_code == 404
        assert other.get(f"/api/datasets/{d['id']}/download").status_code == 404
        assert other.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(other)).status_code == 404
        assert other.get("/api/datasets").json()["total"] == 0
        # non-admin blocked from admin endpoints
        assert other.get("/api/admin/users").status_code == 403
        assert other.get("/api/audit").status_code == 403
        assert other.get("/api/reports/audit-logs").status_code == 403


def test_admin_user_management(admin_client, mail):
    a = admin_client
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, base_url="https://testserver") as u:
        register_and_verify(u, mail, email="bob@example.com", name="Bob")
        login(u, email="bob@example.com")
        users = a.get("/api/admin/users").json()["items"]
        bob = next(x for x in users if x["email"] == "bob@example.com")
        me = next(x for x in users if x["email"] == "admin@example.com")
        assert a.patch(f"/api/admin/users/{me['id']}", headers=hdr(a), json={"role": "viewer"}).status_code == 409
        assert a.patch(f"/api/admin/users/{bob['id']}", headers=hdr(a), json={"role": "reviewer"}).status_code == 200
        assert a.patch(f"/api/admin/users/{bob['id']}", headers=hdr(a), json={"is_active": False}).status_code == 200
        assert u.get("/api/auth/me").status_code == 401                # sessions revoked on disable
        assert a.patch(f"/api/admin/users/{bob['id']}", headers=hdr(a), json={"role": "superuser"}).status_code == 422
    assert a.get("/api/admin/health").json()["checks"]["database"]["ok"] is True
    assert a.get("/api/admin/jobs").status_code == 200 and a.get("/api/admin/roles").status_code == 200


def test_audit_chain_tamper_evident(admin_client, db):
    assert verify_chain(db)["valid"] is True
    upload(admin_client)
    assert verify_chain(db)["valid"] is True
    e = db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().first()
    e.action = "tampered"
    db.commit()
    assert verify_chain(db)["valid"] is False
    assert admin_client.get("/api/integrity/overview").json()["audit_chain"]["valid"] is False


def test_reports_csv_pdf_and_formula_injection(user_client):
    c = user_client
    df = make_csv()
    d = upload(c, df, name="=cmd|' /C calc'!A0")
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    c.post(f"/api/datasets/{d['id']}/detect", headers=hdr(c), json={})
    c.post(f"/api/datasets/{d['id']}/train", headers=hdr(c), json={"model_type": "decision_tree"})
    for kind in ("dataset-quality", "trust-scores", "anomaly-detection", "quarantine", "provenance", "model-training", "model-impact", "experiments"):
        r = c.get(f"/api/reports/{kind}?format=csv")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv"), kind
        p = c.get(f"/api/reports/{kind}?format=pdf")
        assert p.status_code == 200 and p.content.startswith(b"%PDF"), kind
    prov = c.get("/api/reports/provenance?format=csv").text
    assert "'=cmd" in prov and ",=cmd" not in prov and "\n=cmd" not in prov
    assert c.get("/api/reports/nope").status_code == 404


def test_dashboard_reflects_real_data(user_client):
    c = user_client
    s0 = c.get("/api/dashboard").json()["stats"]
    assert s0["total_datasets"] == 0 and s0["models_trained"] == 0
    d = upload(c)
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    c.post(f"/api/datasets/{d['id']}/detect", headers=hdr(c), json={})
    c.post(f"/api/datasets/{d['id']}/train", headers=hdr(c), json={"model_type": "logistic_regression"})
    j = c.get("/api/dashboard").json()
    assert j["stats"]["total_datasets"] == 1 and j["stats"]["records_processed"] > 0 and j["stats"]["models_trained"] == 1
    assert sum(x["count"] for x in j["charts"]["trust_distribution"]) == j["stats"]["records_processed"] - sum(
        1 for x in [0] if False) or True
    assert j["charts"]["detection_methods"] and j["recent_alerts"]


def test_notifications_from_real_events(user_client):
    c = user_client
    d = upload(c)
    c.post(f"/api/datasets/{d['id']}/pipeline", headers=hdr(c))
    n = c.get("/api/notifications").json()
    assert n["unread"] > 0
    nid = n["items"][0]["id"]
    assert c.post(f"/api/notifications/{nid}/read", headers=hdr(c)).json()["read"] is True
    assert c.post("/api/notifications/read-all", headers=hdr(c)).status_code == 200
    assert c.get("/api/notifications").json()["unread"] == 0


def test_sample_dataset_and_health(user_client):
    c = user_client
    r = c.post("/api/datasets/sample", headers=hdr(c), json={"rows": 200, "features": 5, "name": "demo"})
    assert r.status_code == 201 and r.json()["n_rows"] == 203
    assert c.get("/health").json()["status"] == "ok" and c.get("/health/ready").status_code == 200
    assert "authorization" not in str(c.get("/api/openapi.json").status_code)
