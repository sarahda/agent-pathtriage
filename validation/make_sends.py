#!/usr/bin/env python3
"""Turn the gated disclosure packages into messages that can be sent.

Reads the gate pack and the per repository packages, groups the repositories by
the channel their owner publishes, and writes one message per channel. Nothing
about a repository, an owner, a role, an action or a date is written into this
file: it all comes from the pack, the packages, the channel config and the
command line. A repository whose owner is not in the channel config stops the
run rather than being guessed at.

  python3 make_sends.py \
      --pack validation/pr/pr_pack.json \
      --channels validation/channels.json \
      --out validation/sends \
      --sender-name "..." --sender-affiliation "..." \
      --paper-date 2026-12-16
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys


def read_section(text: str, heading: str) -> str:
    """Return the body of one '## heading' section, without the heading line."""
    lines = text.splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = line[3:].strip().lower().startswith(heading.lower())
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip("\n")


def bullets(section: str) -> list[str]:
    """Top level bullets only. Sub bullets are qualifiers and travel with them."""
    items: list[str] = []
    for line in section.splitlines():
        if re.match(r"^- ", line):
            items.append(line)
        elif re.match(r"^\s+- ", line) and items:
            items[-1] += "\n" + line
    return items


def owner_of(repo_key: str) -> str:
    """Pack keys are owner__name. Fall back to a slash if one is used."""
    if "__" in repo_key:
        return repo_key.split("__", 1)[0]
    if "/" in repo_key:
        return repo_key.split("/", 1)[0]
    raise ValueError(f"cannot read an owner out of {repo_key!r}")


def slug_to_path(repo_key: str) -> str:
    return repo_key.replace("__", "/", 1) if "__" in repo_key else repo_key


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True, type=pathlib.Path)
    ap.add_argument("--cdk", type=pathlib.Path, default=None,
                    help="cdk_packages.json. These are recorded separately "
                         "because the codereq and validated_repairs gates do "
                         "not run on CDK source, so they are named as not "
                         "applicable in the message rather than filled in.")
    ap.add_argument("--channels", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--summary", type=pathlib.Path, default=None,
                    help="write a machine readable count of what was sent")
    ap.add_argument("--sender-name", required=True)
    ap.add_argument("--sender-affiliation", required=True)
    ap.add_argument("--sender-email", default="")
    ap.add_argument("--paper-date", required=True,
                    help="the date named in the message, ISO form")
    ap.add_argument("--repo-url", default="",
                    help="where the tool can be obtained, if it is public yet")
    ap.add_argument("--tool-public", choices=["yes", "no"], required=True,
                    help="whether the recipient can obtain the tool today. If no, "
                         "the reproduction block is sent as the command the "
                         "recipient will be able to run, with the date it becomes "
                         "available, instead of as something they can run now.")
    ap.add_argument("--tool-public-date", default="",
                    help="required when --tool-public no: when it becomes available")
    args = ap.parse_args()
    if args.tool_public == "no" and not args.tool_public_date:
        print("stop: --tool-public no needs --tool-public-date", file=sys.stderr)
        return 2

    pack = json.loads(args.pack.read_text())
    cfg = json.loads(args.channels.read_text())
    owners = cfg["owners"]

    pack_dir = args.pack.parent
    root = pack_dir.parent.parent

    # The limitations block is identical in every package by design. Take it
    # from the first one and check the rest match, because the gate that
    # promises it is unedited is only worth anything if it is checked here too.
    limits: str | None = None
    entries = []
    for item in pack:
        key = item["repo"]
        owner = owner_of(key)
        if owner not in owners:
            print(f"stop: no channel configured for owner {owner!r} "
                  f"(repository {key}). Add it to {args.channels}.",
                  file=sys.stderr)
            return 2
        pkg_path = root / item["package"] if not (pack_dir / pathlib.Path(item["package"]).name).exists() \
            else pack_dir / pathlib.Path(item["package"]).name
        if not pkg_path.exists():
            print(f"stop: package file missing for {key}: {pkg_path}", file=sys.stderr)
            return 2
        text = pkg_path.read_text()
        found = read_section(text, "What was found")
        repro = read_section(text, "Reproduce")
        fix = read_section(text, "Suggested change")
        lim = read_section(text, "Limitations")
        if not found:
            print(f"stop: {key} has no findings section", file=sys.stderr)
            return 2
        if limits is None:
            limits = lim
        elif lim != limits:
            print(f"stop: {key} limitations differ from the first package. "
                  f"The gate claims they are carried through unedited.",
                  file=sys.stderr)
            return 2
        # The pack records the template path with the corpus directory name on
        # the front. The recipient has the repository, not the corpus, so the
        # path they can act on is the one relative to their own root.
        tmpl = item["template"]
        prefix = key + "/"
        if tmpl.startswith(prefix):
            tmpl_rel = tmpl[len(prefix):]
        elif tmpl == key:
            tmpl_rel = "."
        else:
            print(f"stop: template {tmpl!r} for {key} does not sit under the "
                  f"repository directory, so the repository relative path cannot "
                  f"be derived. Fix the pack or this rule.", file=sys.stderr)
            return 2
        entries.append({
            "key": key, "owner": owner, "path": slug_to_path(key),
            "template": tmpl, "template_rel": tmpl_rel,
            "classes": item["classes"],
            "claims": item["claims_passing"],
            "over_granted": item.get("over_granted", []),
            "repairs": item.get("validated_repairs", 0),
            "found": found, "repro": repro, "fix": fix,
            "pkg": str(pkg_path.relative_to(root)),
        })

    cdk_method = None
    if args.cdk:
        cdk = json.loads(args.cdk.read_text())
        cdk_method = cdk.get("method")
        for pkg in cdk["packages"]:
            key = pkg["package"]
            owner = owner_of(key)
            if owner not in owners:
                print(f"stop: no channel configured for owner {owner!r} "
                      f"(CDK package {key}).", file=sys.stderr)
                return 2
            found = "\n".join(f"- {f}" for f in pkg["findings"])
            lines = ", ".join(str(n) for n in pkg["role_argument_lines"])
            repro = (f"    git clone --depth 1 https://github.com/{pkg['repo']} t\n"
                     f"    cd t && git checkout {pkg['commit_read']}\n"
                     f"    # the role is constructed at line "
                     f"{pkg['role_construct_line']} and passed at lines {lines}\n"
                     f"    sed -n '{pkg['role_construct_line']}p;"
                     + ";".join(f"{n}p" for n in pkg["role_argument_lines"])
                     + f"' {pkg['app']}")
            entries.append({
                "key": key, "owner": owner, "path": pkg["repo"],
                "template": pkg["app"], "template_rel": pkg["app"],
                "classes": pkg["classes"], "claims": [], "over_granted": [],
                "repairs": 0, "found": found, "repro": repro, "fix": "",
                "pkg": "validation/pr/cdk_packages.json",
                "is_cdk": True, "language": pkg["language"],
                "runtimes": pkg["runtimes"],
                "role_construct_id": pkg["role_construct_id"],
                "commit_read": pkg["commit_read"],
                "commit_date": pkg["commit_date"],
                "hand_confirmed": pkg.get("hand_confirmed", False),
                "gates_na": pkg.get("gates_not_applicable", []),
                "gates_na_reason": pkg.get("gates_not_applicable_reason", ""),
                "source_comment": pkg.get("source_comment_on_sharing"),
            })

    groups: dict[str, list[dict]] = {}
    for e in entries:
        groups.setdefault(owners[e["owner"]]["group_as"], []).append(e)

    args.out.mkdir(parents=True, exist_ok=True)
    written = []
    for gname, members in sorted(groups.items()):
        owner_cfg = owners[members[0]["owner"]]
        single = len(members) == 1
        repos = ", ".join(m["path"] for m in members)

        if single:
            subject = (f"Shared IAM execution role across two AgentCore agents in "
                       f"{members[0]['path']} (static analysis, no deployment)")
        else:
            subject = (f"Shared IAM execution role across AgentCore agents in "
                       f"{len(members)} published sample repositories "
                       f"(static analysis, no deployment)")

        L: list[str] = []
        L.append(f"# Send: {gname}")
        L.append("")
        L.append(f"- Channel: **{owner_cfg['channel']}** - {owner_cfg['channel_detail']}")
        if owner_cfg.get("channel_alternate"):
            L.append(f"- Alternate: {owner_cfg['channel_alternate']}")
        L.append(f"- Public issue allowed: {owner_cfg['public_issue_allowed']}")
        L.append(f"- Why this channel: {owner_cfg['public_issue_note']}")
        L.append(f"- Repositories in this send: {repos}")
        L.append(f"- Packages: {', '.join(m['pkg'] for m in members)}")
        L.append("")
        L.append("---")
        L.append("")
        L.append(f"**Subject:** {subject}")
        L.append("")
        L.append(owner_cfg["salutation"])
        L.append("")
        who = f"I am {args.sender_name}, {args.sender_affiliation}."
        kinds = sorted({("CDK" if m.get("is_cdk") else "Terraform") for m in members})
        corpus_phrase = " and ".join(kinds)
        L.append(f"{who} I am measuring how IAM permissions compose across agents "
                 "that run on the same platform. While going through a corpus of "
                 f"public Bedrock AgentCore {corpus_phrase}, the "
                 f"{'repository' if single else 'repositories'} below came up, and "
                 "I wanted to send this to you before it appears in anything I "
                 "publish.")
        L.append("")
        L.append("This is a report about configuration as published, not about a "
                 "deployed account. I did not deploy anything, call any API or use "
                 "any credential to produce it.")
        L.append("")

        composes = ("More than one agent runtime is declared with the same "
                    "execution role. "
                    "On AgentCore the execution role is the identity the agent "
                    "presents when it calls out, so the union of what either agent "
                    "needs becomes what both of them hold. A weakness in the agent "
                    "with the smaller job reaches everything the other one is "
                    "trusted with, and the access logs cannot tell the two apart, "
                    "because both calls carry the same role.")
        if not single:
            # Say it once, not once per repository: it is the same mechanism in
            # each, and repeating the paragraph three times reads as padding.
            L.append(f"**The pattern, in all {len(members)}.** {composes}")
            L.append("")
            L.append("Each repository follows, with the agents and the role it "
                     "declares.")
            L.append("")

        for m in members:
            if not single:
                L.append(f"## {m['path']}")
                L.append("")
                L.append(f"Template, relative to the repository root: "
                         f"`{m['template_rel']}`")
                L.append("")
            if m.get("is_cdk"):
                L.append(f"This one is {m['language']} CDK, not Terraform. I read "
                         f"the source at commit `{m['commit_read']}` "
                         f"({m['commit_date']}) rather than synthesising the app, "
                         f"and confirmed by hand that the "
                         f"{m['runtimes']} runtimes take the one "
                         f"`{m['role_construct_id']}` construct.")
                L.append("")
            L.append("**What I found.**")
            L.append("")
            for b in bullets(m["found"]):
                L.append(b)
            L.append("")
            if m.get("source_comment"):
                L.append(f"The file says so itself: {m['source_comment']}")
                L.append("")
            if m.get("gates_na"):
                L.append("**Checks that did not run on this one.** "
                         + ", ".join(f"`{g}`" for g in m["gates_na"])
                         + ". " + m.get("gates_na_reason", "")
                         + ". They are named here rather than left to look like "
                           "they passed.")
                L.append("")
            if single:
                L.append(f"**Why it composes.** {composes}")
                L.append("")
            if m["over_granted"]:
                n_act = len(m["over_granted"])
                head = ("**One action in particular.** This action is granted but is"
                        if n_act == 1 else
                        f"**{n_act} actions in particular.** These are granted but are")
                L.append(f"{head} not used by anything the configuration wires up:")
                L.append("")
                for a in m["over_granted"]:
                    L.append(f"- `{a}`")
                L.append("")
            if m["fix"] and "No repair passed" not in m["fix"]:
                L.append("**A change that survives re-analysis.** This was applied to "
                         "the parsed configuration and the analysis re-run. The "
                         "finding is gone afterwards and no new finding appeared "
                         "elsewhere.")
                L.append("")
                for b in bullets(m["fix"]):
                    L.append(b)
                L.append("")
            elif m.get("is_cdk"):
                L.append("**No change offered.** The repair step runs on parsed "
                         "configuration, not on CDK source, so nothing was tried "
                         "here and nothing was re-checked. I am not proposing a "
                         "change I have not put back through the analysis.")
                L.append("")
            else:
                L.append("**No change offered.** Nothing I tried survived re-analysis "
                         "here, so this is a report and not a pull request. Offering a "
                         "change that does not pass the tool's own check would waste "
                         "your time.")
                L.append("")
            if m.get("is_cdk"):
                L.append("**How to check it yourself,** with no tool, no deployment "
                         "and no credentials. The role construct and the "
                         f"{m['runtimes']} call sites that take it are these lines:")
                L.append("")
                L.append(m["repro"])
                L.append("")
            elif args.tool_public == "yes":
                L.append("**How to check it yourself,** without deploying anything "
                         "and without AWS credentials:")
                L.append("")
                L.append(m["repro"])
                L.append("")
            else:
                L.append("**How to check it.** The finding above is the whole of it: "
                         "the two runtime declarations and the one role they share, "
                         "which you can read in the template without any tool. The "
                         "tool I used is not public yet. It is released on "
                         f"{args.tool_public_date}, and this is the command that "
                         "reproduces the finding from a fresh clone once it is:")
                L.append("")
                L.append(m["repro"])
                L.append("")
                L.append("If you would rather not wait, I will send you the full "
                         "output and the parsed configuration it was computed from.")
                L.append("")

        # The package's limitations section opens with a paragraph written for
        # the record ("this list is sent unedited with every report"). That is a
        # note to self and it reads as a form letter to the person receiving it,
        # so only the list itself goes out.
        lim_list = "\n".join(
            ln for ln in (limits or "").splitlines()
            if ln.startswith("- ") or ln.startswith("  ") or not ln.strip()
        ).strip("\n")
        if not lim_list:
            print("stop: the limitations list came out empty after trimming the "
                  "preamble. Check the package format.", file=sys.stderr)
            return 2
        L.append("**What I may have wrong.**")
        L.append("")
        L.append(lim_list)
        if any(m.get("is_cdk") for m in members) and cdk_method:
            L.append(f"- For the CDK {'repository' if sum(1 for m in members if m.get('is_cdk')) == 1 else 'repositories'} "
                     f"above: {cdk_method}")
        L.append("")
        L.append("**Timing.** I intend to submit a paper on "
                 f"{args.paper_date}. I would rather describe this with your "
                 f"{'repository' if single else 'repositories'} named and your "
                 "response included than anonymised. Would you be willing to agree "
                 "to publication before then? If not, I will anonymise and record "
                 "only that it was reported and acknowledged.")
        L.append("")
        L.append("If this does not match how you deploy it, I would like to "
                 "know what I read wrong.")
        L.append("")
        if args.repo_url:
            L.append(f"Tool: {args.repo_url}")
            L.append("")
        L.append(args.sender_name)
        if args.sender_email:
            L.append(args.sender_email)

        path = args.out / f"{gname}.md"
        path.write_text("\n".join(L) + "\n")
        written.append((gname, len(members), str(path), owner_cfg["channel"]))

    print(f"{len(entries)} repositories -> {len(written)} sends")
    for gname, n, path, channel in written:
        print(f"  {gname}: {n} repo(s) -> {path}")

    if args.summary:
        by_channel = collections.Counter(c for _, _, _, c in written)
        summary = {
            "method": "counted from the sends this run produced, one per "
                      "channel group, with the channel taken from channels.json",
            "reports": len(written),
            "repositories_covered": sum(n for _, n, _, _ in written),
            "reports_by_channel": dict(sorted(by_channel.items())),
            "sends": [{"group": g, "repositories": n, "channel": c}
                      for g, n, _, c in written],
        }
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=1) + "\n")
        print(f"written: {args.summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
