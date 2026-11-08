"""Every corpus number this project publishes must come from a committed artifact.

A number written into prose is a number that goes stale silently. The funnel,
the prevalence table and the adjudication split are each recomputed whenever
the corpus changes. These tests read the committed artifacts, build the exact
line the prose has to contain, and fail if it does not, so what is published
cannot drift away from the measurements it reports.

The check is over every document that publishes these figures, not the README
alone. On 2026-11-02 the README was cut down for a reader arriving from the
paper and the detail moved to docs/implementation.md; the numbers did not
change, and a check tied to one filename would have failed for the move rather
than for a number. Adding a document here is how a new place to publish a
figure comes under the same guarantee.

The third-party benchmark figures are not checked here. Those come from
external fixtures rather than the corpus, reproduce.py pins them deliberately,
and they must not move when the corpus does.
"""

import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "evaluation", "benchmark")
PUBLISHED = (
    os.path.join(ROOT, "README.md"),
    os.path.join(ROOT, "docs", "implementation.md"),
    os.path.join(ROOT, "docs", "results.md"),
)


def _json(name):
    with open(os.path.join(BENCH, name)) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def published():
    """Every document that publishes a corpus figure, whitespace collapsed.

    Markdown reflows prose freely, so a sentence may be split across lines.
    Matching on the raw text would make these tests fail on a rewrap rather
    than on a number, which is the opposite of what they are for.
    """
    parts = []
    for path in PUBLISHED:
        if os.path.isfile(path):
            with open(path) as fh:
                parts.append(fh.read())
    return " ".join(" ".join(parts).split())


@pytest.fixture(scope="module")
def pop():
    return _json("corpus_population_tier2.json")


@pytest.fixture(scope="module")
def gap():
    return _json("gap_tier2_v1.json")


@pytest.fixture(scope="module")
def topo():
    return _json("topology_tier2.json")


@pytest.fixture(scope="module")
def shared():
    return _json("shared_role_tier2.json")


@pytest.fixture(scope="module")
def adj():
    return _json("adjudication_tier2.json")


def _row(published, label, value):
    line = f"| {label} | {value} |"
    assert line in published, f"README is missing or disagrees with: {line}"


def test_the_funnel_table_matches_the_corpus_artifact(published, pop):
    _row(published, "non-fork repositories cloned", pop["repositories"])
    _row(published, "no Terraform at all", pop["no_tf"])
    _row(published, "Terraform but no agent runtime", pop["tf_no_runtime"])
    _row(published, "with an agent runtime", pop["with_runtime"])
    _row(published, "template directories in those", pop["template_dirs"])
    _row(published, "excluded by the filter", pop["excluded"])
    _row(published, "fork copies of a template already counted", pop["fork_copies"])
    _row(published, "**final templates**", f"**{pop['final_templates']}**")


def test_the_runtime_count_matches_the_gap_artifact(published, gap):
    _row(published, "agent runtimes in them", gap["n_runtimes"])


def test_the_funnel_adds_up(pop):
    assert pop["no_tf"] + pop["tf_no_runtime"] + pop["with_runtime"] == pop["repositories"]
    assert pop["template_dirs"] - pop["excluded"] - pop["fork_copies"] == pop["final_templates"]


def test_the_prevalence_table_matches_the_artifacts(published, topo, shared, gap):
    templates = len([r for r in topo if "err" not in r])
    multi = shared["multi_agent_templates"]
    sr = len(shared["shared_role"])
    handoff = sum(1 for r in topo if r.get("handoffs"))
    rsg = gap["resource_scope_gap"]
    runtimes = gap["n_runtimes"]
    _row(published, "templates with two or more agents",
         f"{multi} of {templates} ({multi / templates * 100:.1f}%)")
    _row(published, "of those, all agents run as one execution role",
         f"{sr} of {multi} ({sr / multi * 100:.1f}%)")
    _row(published, "templates with a declared hand-off",
         f"{handoff} of {templates} ({handoff / templates * 100:.1f}%)")
    _row(published, "runtimes whose role grants more than the configuration wires",
         f"{rsg} of {runtimes} ({rsg / runtimes * 100:.1f}%)")


def test_the_adjudication_split_matches_the_artifact(published, adj):
    counts = {}
    for row in adj:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    sentence = (f"{counts.get('single-agent', 0)} "
                f"single-agent, {counts.get('narrow', 0)} narrow, "
                f"{counts.get('shared-role', 0)} shared-role and "
                f"{counts.get('cross-agent', 0)} cross-agent")
    assert sentence in published, f"README is missing or disagrees with: {sentence}"
    assert str(len(adj)) in published


def test_the_census_claim_names_the_whole_multi_agent_set(published, shared):
    """The census wording must name the set it is a census of, not deployments."""
    multi = shared["multi_agent_templates"]
    sr = len(shared["shared_role"])
    assert f"The {sr} templates whose agents share one execution role are all of the" in published
    assert f"census of the {multi} multi-agent" in published
    assert "says nothing about how common the pattern is in" in published
