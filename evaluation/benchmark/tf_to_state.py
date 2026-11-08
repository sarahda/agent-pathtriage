#!/usr/bin/env python3
"""
AgentPathTriage - Terraform source to state-shaped JSON (tf_to_state)

Why this exists: extract_iam.py reads `terraform show -json`, which only exists
after a deployment. That made every external benchmark cost an AWS account and a
bill, and it sat awkwardly next to the project's claim that cross-agent privilege
is computable from the deployment's own configuration. This module reads raw .tf
source and emits the same shape `terraform show -json` produces, so the existing
graph builder, check and propagate run unchanged on configuration alone.

What it does:
  - scans *.tf under a directory (sorted, so a run is reproducible), skipping
    .terraform caches
  - finds resource blocks by brace matching that is aware of strings, comments and
    heredocs, because policy documents are full of braces
  - parses HCL values into native Python, including the jsonencode(...) and
    <<EOF ... EOF forms that policy documents actually use, so a policy becomes a
    real document rather than an opaque string
  - resolves references between resources (aws_iam_role.x.arn and friends) using
    the names parsed from the source, and synthesises an ARN for each IAM
    principal and policy so that ARN-keyed matching works without an account

What it does not do, stated plainly so results are not over-claimed:
  - no variable, local, data source, count, for_each or module expansion. An
    unresolved reference stays in the value as the literal text ${...}. Resources
    created by count or for_each appear once, not N times.
  - no provider defaults and no computed attributes beyond the synthesised ARNs.
  - a value this parser cannot read is kept as its raw source text rather than
    dropped, so a downstream matcher sees something honest rather than nothing.

Usage:
  python3 tf_to_state.py --tfdir path/to/terraform --json state.json
  python3 extract_iam.py --state state.json --json iam_graph.json
"""
import argparse, glob, json, os, re

ACCOUNT = "000000000000"   # placeholder account for synthesised ARNs
REGION = "us-east-1"

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")
NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
REF_START = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_*][A-Za-z0-9_\-]*)+")
# A count or for_each subscript: [0], [count.index], [each.key], [*], ["name"].
INDEX_REF = re.compile(r"\[[^\[\]]*\]")
# What may follow a subscript and still belong to the same reference, so that
# aws_iam_role.agentcore[0].id is one reference rather than a reference followed
# by stray text.
REF_TAIL = re.compile(r"(?:\.[A-Za-z_*][A-Za-z0-9_\-]*|\[[^\[\]]*\])+")
# A whole traversal and nothing else, used to tell a bare reference from an
# expression when a ternary branch arrives as raw HCL.
REF_WHOLE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*"
                       r"(?:\.[A-Za-z_*][A-Za-z0-9_\-]*|\[[^\[\]]*\])+")


# ---------------------------------------------------------------- scanning ---

def strip_comments(text):
    """Blank out comments without changing offsets, so slices stay valid."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2; continue
                if text[i] == '"':
                    i += 1; break
                i += 1
            continue
        if text.startswith("<<", i):
            m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            if m:
                tag = m.group(1)
                end = re.search(r"^\s*" + re.escape(tag) + r"\s*$", text[i:], re.M)
                i = i + (end.end() if end else (n - i))
                continue
        if c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def match_brace(text, i):
    """Index just past the block that opens at text[i] == '{'."""
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2; continue
                if text[i] == '"':
                    break
                i += 1
        elif text.startswith("<<", i):
            m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            if m:
                tag = m.group(1)
                end = re.search(r"^\s*" + re.escape(tag) + r"\s*$", text[i:], re.M)
                i = i + (end.end() - 1 if end else (n - i - 1))
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


# ----------------------------------------------------------------- parsing ---

class Parser:
    """Recursive-descent reader for the HCL value subset policies are written in."""

    def __init__(self, text):
        self.t = text
        self.i = 0

    def ws(self):
        n = len(self.t)
        while self.i < n and self.t[self.i] in " \t\r\n,":
            self.i += 1

    def value(self):
        self.ws()
        if self.i >= len(self.t):
            return None
        c = self.t[self.i]
        if c == '"':
            return self.string()
        if c == "[":
            return self.array()
        if c == "{":
            return self.obj()
        if self.t.startswith("<<", self.i):
            return self.heredoc()
        m = NUMBER.match(self.t, self.i)
        if m and (self.i == 0 or not IDENT.match(self.t[self.i - 1])):
            self.i = m.end()
            v = m.group(0)
            return float(v) if "." in v else int(v)
        m = IDENT.match(self.t, self.i)
        if m:
            word = m.group(0)
            after = self.t[m.end():m.end() + 1]
            if word in ("true", "false") and after not in (".", "("):
                self.i = m.end()
                return word == "true"
            if word == "null" and after not in (".", "("):
                self.i = m.end()
                return None
            if after == "(":
                return self.call(word, m.end())
            return self.reference()
        # anything else: consume to the next separator and keep the raw text
        return self.raw()

    def string(self):
        """Read a quoted string, keeping interpolations intact.

        An interpolation can contain its own quoted strings, as in
        "${replace(var.stack_name, "-", "_")}_${var.name}". Scanning for the next
        double quote ends the string at the one inside replace(), which silently
        truncates the value. Two resources whose names truncate to the same text
        then look like the same resource, so edges between them are attributed to
        whichever was seen last. Interpolation depth is tracked to prevent that.
        """
        self.i += 1
        buf = []
        n = len(self.t)
        depth = 0                      # how many ${ } we are inside
        while self.i < n:
            c = self.t[self.i]
            if c == "\\":
                nxt = self.t[self.i + 1:self.i + 2]
                buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
                self.i += 2
                continue
            if c == "$" and self.t[self.i + 1:self.i + 2] == "{":
                depth += 1
                buf.append("${")
                self.i += 2
                continue
            if c == "}" and depth > 0:
                depth -= 1
                buf.append("}")
                self.i += 1
                continue
            if c == '"':
                if depth == 0:
                    self.i += 1
                    break
                # a quoted argument inside an interpolation: keep it and read on
                buf.append('"')
                self.i += 1
                while self.i < n:
                    if self.t[self.i] == "\\":
                        buf.append(self.t[self.i:self.i + 2])
                        self.i += 2
                        continue
                    buf.append(self.t[self.i])
                    if self.t[self.i] == '"':
                        self.i += 1
                        break
                    self.i += 1
                continue
            buf.append(c)
            self.i += 1
        return "".join(buf)

    def heredoc(self):
        m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\r?\n", self.t[self.i:])
        if not m:
            return self.raw()
        tag = m.group(1)
        start = self.i + m.end()
        end = re.search(r"^\s*" + re.escape(tag) + r"\s*$", self.t[start:], re.M)
        body = self.t[start:start + end.start()] if end else self.t[start:]
        self.i = start + (end.end() if end else len(self.t) - start)
        try:
            return json.loads(body)
        except Exception:
            return body

    def array(self):
        self.i += 1
        out = []
        n = len(self.t)
        while self.i < n:
            self.ws()
            if self.i < n and self.t[self.i] == "]":
                self.i += 1
                break
            before = self.i
            out.append(self.value())
            if self.i == before:
                self.i += 1
        return out

    def obj(self):
        self.i += 1
        out = {}
        n = len(self.t)
        while self.i < n:
            self.ws()
            if self.i < n and self.t[self.i] == "}":
                self.i += 1
                break
            if self.t[self.i] == '"':
                key = self.string()
            else:
                m = IDENT.match(self.t, self.i)
                if not m:
                    self.i += 1
                    continue
                key = m.group(0)
                self.i = m.end()
            self.ws()
            if self.i < n and self.t[self.i] in "=:":
                self.i += 1
            before = self.i
            out[key] = self.value()
            if self.i == before:
                self.i += 1
        return out

    def call(self, name, open_paren):
        depth = 0
        i = open_paren
        n = len(self.t)
        while i < n:
            if self.t[i] == '"':
                i += 1
                while i < n and self.t[i] != '"':
                    i += 2 if self.t[i] == "\\" else 1
            elif self.t[i] == "(":
                depth += 1
            elif self.t[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        inner = self.t[open_paren + 1:i]
        self.i = i + 1
        if name in ("jsonencode", "yamlencode"):
            return Parser(inner).value()
        # any other function: keep the whole call as text so nothing is invented
        return "${" + name + "(" + inner.strip() + ")}"

    def reference(self):
        """A traversal such as aws_iam_role.agentcore[0].id, kept whole.

        REF_START stops at the first `[`, which used to leave the subscript and
        every attribute after it unconsumed: the value became
        `${aws_iam_role.agentcore}` and the `.id` was dropped on the floor. A
        policy whose `role =` is an indexed role reference then had an owner key
        that matched no identity, so the role looked as though it held no
        permissions at all. The tail is consumed here and the subscript is
        collapsed at lookup time.
        """
        m = REF_START.match(self.t, self.i)
        if not m:
            return self.raw()
        self.i = m.end()
        ref = m.group(0)
        if self.i < len(self.t) and self.t[self.i] == "[":
            tail = REF_TAIL.match(self.t, self.i)
            if tail:
                self.i = tail.end()
                ref += tail.group(0)
        return "${" + ref + "}"

    def expression_tail(self):
        """Whatever is left of the current expression after its first value.

        Reads to the end of the line at bracket depth zero, so an operator, a
        comparison or a ternary that follows a parsed reference is carried along
        instead of being left in the stream to corrupt the next key. Returns ""
        when the value already ended the expression.
        """
        n = len(self.t)
        start = self.i
        depth = 0
        while self.i < n:
            c = self.t[self.i]
            if c == '"':
                self.string()
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c in "\n," and depth == 0:
                break
            elif depth == 0 and self.i > start and self.t[self.i - 1].isspace():
                # a new `ident =` begins, so the expression ended even though the
                # line did not. HCL requires a newline between attributes, but a
                # generated or minified file may not have one, and swallowing the
                # next attribute would lose it entirely.
                nxt = IDENT.match(self.t, self.i)
                if nxt:
                    after = self.t[nxt.end():]
                    if re.match(r"\s*=[^=]", after):
                        break
            self.i += 1
        return self.t[start:self.i].strip()

    def raw(self):
        n = len(self.t)
        start = self.i
        depth = 0
        while self.i < n:
            c = self.t[self.i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c in ",\n" and depth == 0:
                break
            self.i += 1
        return self.t[start:self.i].strip()


def parse_block_body(body):
    """Top-level `ident = value` pairs of a resource block (nested blocks kept raw)."""
    p = Parser(body)
    p.i = 1                      # step past the opening brace
    out = {}
    n = len(body)
    while p.i < n:
        p.ws()
        if p.i >= n or body[p.i] == "}":
            break
        if body[p.i] == '"':
            key = p.string()
        else:
            m = IDENT.match(body, p.i)
            if not m:
                p.i += 1
                continue
            key = m.group(0)
            p.i = m.end()
        p.ws()
        if p.i < n and body[p.i] == "=":
            p.i += 1
            before = p.i
            val = p.value()
            # An expression such as `a = var.x != null ? var.x : y.z` parses its
            # first reference and stops at the operator, leaving `!= null ? ...`
            # in the stream. The next key read then starts mid-token and the rest
            # of the block is mis-synchronised: in one corpus module this turned
            # `role_arn` into `ole_arn` and lost the role entirely. The remainder
            # of the expression is taken as raw text and the whole line is kept,
            # so an expression is either understood or preserved, never truncated.
            rest = p.expression_tail()
            if rest:
                val = f"{val}{rest}" if isinstance(val, str) else rest
            out[key] = val
            if p.i == before:
                p.i += 1
        elif p.i < n and body[p.i] == "{":
            end = match_brace(body, p.i)
            out.setdefault("_blocks", {}).setdefault(key, []).append(
                parse_block_body(body[p.i:end]))
            p.i = end
        elif p.i < n and body[p.i] == '"':
            # labelled nested block, e.g. dynamic "statement" { ... }
            p.string()
            p.ws()
            if p.i < n and body[p.i] == "{":
                p.i = match_brace(body, p.i)
        else:
            p.i += 1
    return out


def parse_tf_text(text):
    """Yield (type, name, values) for every resource block in one file."""
    t = strip_comments(text)
    for m in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', t):
        start = t.find("{", m.end() - 1)
        end = match_brace(t, start)
        yield m.group(1), m.group(2), parse_block_body(t[start:end])


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def policy_document_json(body):
    """Turn an aws_iam_policy_document block into the IAM JSON it renders to.

    A pass that cannot read these blocks is blind to the policies of a large
    share of the population. The size of that share is measured rather than
    asserted here: corpus_population.py counts it over the final template set
    and writes `policy_document_blocks` and `templates_using_policy_document`
    into corpus_population_tier2.json, so it cannot go stale when the corpus
    changes. The shape is regular: repeated `statement` blocks with actions,
    effect, resources and optional `condition` and `principals` sub-blocks.
    """
    doc = {"Version": body.get("version", "2012-10-17"), "Statement": []}
    for st in (body.get("_blocks", {}) or {}).get("statement", []):
        out = {"Effect": st.get("effect", "Allow")}
        if st.get("sid"):
            out["Sid"] = st["sid"]
        for src, dst in (("actions", "Action"), ("not_actions", "NotAction"),
                         ("resources", "Resource"), ("not_resources", "NotResource")):
            vals = _as_list(st.get(src))
            if vals:
                out[dst] = vals
        conds = {}
        for c in (st.get("_blocks", {}) or {}).get("condition", []):
            test, var = c.get("test"), c.get("variable")
            if not test or not var:
                continue
            conds.setdefault(str(test), {})[str(var)] = _as_list(c.get("values"))
        if conds:
            out["Condition"] = conds
        principals = {}
        for pb_key, neg in (("principals", False), ("not_principals", True)):
            for pb in (st.get("_blocks", {}) or {}).get(pb_key, []):
                ptype = str(pb.get("type", "AWS"))
                ids = _as_list(pb.get("identifiers"))
                if ids:
                    principals.setdefault(ptype, []).extend(ids)
            if principals and not neg:
                out["Principal"] = principals
                principals = {}
        doc["Statement"].append(out)
    return doc


def parse_data_blocks(text):
    """Yield (type, name, values) for every data block, with policy documents
    rendered into the `json` attribute the way Terraform exposes them."""
    t = strip_comments(text)
    for m in re.finditer(r'data\s+"([^"]+)"\s+"([^"]+)"\s*\{', t):
        start = t.find("{", m.end() - 1)
        end = match_brace(t, start)
        dtype, dname = m.group(1), m.group(2)
        body = parse_block_body(t[start:end])
        if dtype == "aws_iam_policy_document":
            import json as _json
            body["json"] = _json.dumps(policy_document_json(body))
        yield dtype, dname, body


def parse_locals(text):
    """Yield (name, value) for every `locals { }` assignment.

    Real modules route a resource reference through a local before using it:
    `role_arn = var.role_arn != null ? var.role_arn : aws_iam_role.agentcore[0].arn`
    then `role_arn = local.role_arn` on the runtime. Without locals in the table
    the runtime's role is an unresolved `${local.role_arn}`, the execution role is
    never matched, and the runtime is scored as holding no permissions. This was
    21% of agent runtimes in the corpus.
    """
    t = strip_comments(text)
    for m in re.finditer(r'(?:^|\n)\s*locals\s*\{', t):
        start = t.find("{", m.end() - 1)
        end = match_brace(t, start)
        for name, val in parse_block_body(t[start:end]).items():
            if name != "_blocks":
                yield name, val


# A ternary whose branches may each be a reference. Terraform conditions depend on
# input values that do not exist at analysis time, so no branch can be decided.
TERNARY = re.compile(r"^\s*(?P<cond>.+?)\s*\?\s*(?P<a>[^?:]+?)\s*:\s*(?P<b>[^?:]+?)\s*$")


def ternary_branches(text):
    """The two branches of a top-level ternary, or None.

    Splitting is refused when the text contains a nested ternary or an unbalanced
    bracket, because a wrong split invents a value, and inventing a value is worse
    than leaving it unresolved.
    """
    s = str(text).strip()
    if s.count("?") != 1 or s.count(":") < 1:
        return None
    for open_c, close_c in (("(", ")"), ("[", "]"), ("{", "}")):
        if s.count(open_c) != s.count(close_c):
            return None
    m = TERNARY.match(s)
    if not m:
        return None
    return m.group("a"), m.group("b")


# -------------------------------------------------------------- resolution ---

# Account, region and partition arrive as data sources in most real Terraform, and
# an ARN built from an unresolved one cannot be matched against an ARN built from a
# resolved one. These normalise to the same placeholders the synthesised ARNs use,
# which is sound because the reference resolves to the deploying account by
# definition: it is the same account the resources land in.
DATA_NORMALISE = {
    # `.id` on aws_caller_identity is the account id too, and real configurations
    # use both spellings. Missing one leaves an ARN that cannot be compared with an
    # ARN built from the other, which silently drops edges.
    r"data\.aws_caller_identity\.[A-Za-z0-9_\-]+\.(account_id|id)": ACCOUNT,
    r"data\.aws_region\.[A-Za-z0-9_\-]+\.(name|id|region)": REGION,
    r"data\.aws_partition\.[A-Za-z0-9_\-]+\.partition": "aws",
}


def normalise_data_refs(text):
    for pat, val in DATA_NORMALISE.items():
        text = re.sub(r"\$\{" + pat + r"\}", val, text)
    return text


# ARN shapes for the non-IAM resources that policies point at. Without these a
# statement like Resource = aws_bedrockagent_knowledge_base.kb.arn stays an
# unresolved ${...} string, so the resource is invisible and an escalation that
# reaches it cannot be seen. The account and region are the placeholders above,
# which is consistent across the whole deployment.
RESOURCE_ARN_SHAPES = {
    "aws_bedrockagent_knowledge_base": "arn:aws:bedrock:{region}:{acct}:knowledge-base/{name}",
    "aws_bedrockagent_agent": "arn:aws:bedrock:{region}:{acct}:agent/{name}",
    "aws_bedrockagentcore_memory": "arn:aws:bedrock-agentcore:{region}:{acct}:memory/{name}",
    "aws_bedrockagentcore_runtime": "arn:aws:bedrock-agentcore:{region}:{acct}:runtime/{name}",
    "aws_bedrockagentcore_agent_runtime": "arn:aws:bedrock-agentcore:{region}:{acct}:runtime/{name}",
    "aws_bedrockagentcore_code_interpreter":
        "arn:aws:bedrock-agentcore:{region}:{acct}:code-interpreter/{name}",
    "aws_bedrockagentcore_gateway": "arn:aws:bedrock-agentcore:{region}:{acct}:gateway/{name}",
    "aws_bedrockagentcore_browser": "arn:aws:bedrock-agentcore:{region}:{acct}:browser/{name}",
    "aws_ecr_repository": "arn:aws:ecr:{region}:{acct}:repository/{name}",
    "aws_s3_bucket": "arn:aws:s3:::{name}",
    "aws_dynamodb_table": "arn:aws:dynamodb:{region}:{acct}:table/{name}",
    "aws_lambda_function": "arn:aws:lambda:{region}:{acct}:function:{name}",
    "aws_sqs_queue": "arn:aws:sqs:{region}:{acct}:{name}",
    "aws_secretsmanager_secret": "arn:aws:secretsmanager:{region}:{acct}:secret:{name}",
    # compute resources that run as a role, needed for the takeover edge
    "aws_glue_dev_endpoint": "arn:aws:glue:{region}:{acct}:devEndpoint/{name}",
    "aws_cloudformation_stack": "arn:aws:cloudformation:{region}:{acct}:stack/{name}",
    "aws_sagemaker_notebook_instance":
        "arn:aws:sagemaker:{region}:{acct}:notebook-instance/{name}",
    "aws_instance": "arn:aws:ec2:{region}:{acct}:instance/{name}",
    "aws_elastic_beanstalk_environment":
        "arn:aws:elasticbeanstalk:{region}:{acct}:environment/{name}",
    "aws_ecs_task_definition": "arn:aws:ecs:{region}:{acct}:task-definition/{name}",
    "aws_codebuild_project": "arn:aws:codebuild:{region}:{acct}:project/{name}",
}


# Attribute names a provider exposes for a resource's ARN and id, beyond plain
# `arn` and `id`. Measured against the corpus: every one of the 205 agent runtime
# blocks names itself with `agent_runtime_name`, and a hand-off between two agents
# is written as `aws_bedrockagentcore_agent_runtime.<x>.agent_runtime_arn`.
ARN_ATTR_ALIASES = {
    "aws_bedrockagentcore_agent_runtime": ("agent_runtime_arn",),
    "aws_bedrockagentcore_agent_runtime_endpoint": ("agent_runtime_endpoint_arn",
                                                    "agent_runtime_arn"),
    "aws_bedrockagentcore_memory": ("memory_arn",),
    "aws_bedrockagentcore_gateway": ("gateway_arn",),
    "aws_bedrockagentcore_code_interpreter": ("code_interpreter_arn",),
    "aws_bedrockagentcore_browser": ("browser_arn",),
    "aws_bedrockagent_agent": ("agent_arn",),
    "aws_bedrockagent_knowledge_base": ("knowledge_base_arn",),
    "aws_ecr_repository": ("repository_url",),
}
ID_ATTR_ALIASES = {
    "aws_bedrockagentcore_agent_runtime": ("agent_runtime_id",),
    "aws_bedrockagentcore_memory": ("memory_id",),
    "aws_bedrockagentcore_gateway": ("gateway_id", "gateway_url"),
    "aws_bedrockagentcore_code_interpreter": ("code_interpreter_id",),
    "aws_bedrockagentcore_browser": ("browser_id",),
    "aws_bedrockagent_agent": ("agent_id",),
    "aws_bedrockagent_knowledge_base": ("knowledge_base_id",),
}


def synth_arns(resources):
    """name/arn/id for each resource we can address, keyed by `type.name.attr`."""
    table = {}
    for rtype, rname, v in resources:
        label = f"{rtype}.{rname}"
        logical = v.get("name")
        if rtype == "aws_iam_role" and logical is not None:
            arn = f"arn:aws:iam::{ACCOUNT}:role/{logical}"
        elif rtype == "aws_iam_user" and logical is not None:
            arn = f"arn:aws:iam::{ACCOUNT}:user/{logical}"
        elif rtype == "aws_iam_group" and logical is not None:
            arn = f"arn:aws:iam::{ACCOUNT}:group/{logical}"
        elif rtype == "aws_iam_policy" and logical is not None:
            arn = f"arn:aws:iam::{ACCOUNT}:policy/{logical}"
        elif rtype == "aws_iam_instance_profile" and logical is not None:
            arn = f"arn:aws:iam::{ACCOUNT}:instance-profile/{logical}"
        elif rtype in RESOURCE_ARN_SHAPES:
            # a non-IAM resource a policy may point at. Terraform names many of
            # these with a field other than `name`, so fall back to the block label,
            # which is unique within the module and stable across runs.
            label_name = logical
            for key in ("bucket", "function_name", "table_name", "repository_name",
                        "agent_runtime_name", "memory_name", "gateway_name"):
                if label_name is None and v.get(key) is not None:
                    label_name = v.get(key)
            if label_name is None:
                label_name = rname
            arn = RESOURCE_ARN_SHAPES[rtype].format(region=REGION, acct=ACCOUNT,
                                                    name=label_name)
        else:
            arn = v.get("arn")
        if logical is not None:
            table[f"{label}.name"] = logical
            table.setdefault(f"{label}.id", logical)
        if arn is not None:
            table[f"{label}.arn"] = arn
            table.setdefault(f"{label}.id", arn)
        # Providers expose a resource's ARN under its own attribute name as well as
        # `arn`, and agent platforms use the long form. Without these aliases a
        # hand-off written as agent_runtime_arn stays an unresolved ${...} string
        # and the edge between two agents is never seen.
        for alias in ARN_ATTR_ALIASES.get(rtype, ()):
            if arn is not None:
                table.setdefault(f"{label}.{alias}", arn)
        for alias in ID_ATTR_ALIASES.get(rtype, ()):
            if logical is not None:
                table.setdefault(f"{label}.{alias}", logical)
    return table


def resolve(value, table, depth=0):
    """Replace ${type.name.attr} with the parsed value where it is known."""
    if depth > 6:
        return value
    if isinstance(value, dict):
        return {k: resolve(v, table, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, table, depth + 1) for v in value]
    if not isinstance(value, str):
        return value
    value = normalise_data_refs(value)

    def lookup(ref):
        """Resolve a reference, collapsing a count or for_each index.

        A resource created with count is addressed as aws_iam_role.x[0].id. The
        index is dropped here and the single declared resource is used, because
        count is not expanded. Measured on the corpus, 32 of the 181 agent runtime
        template directories use an indexed reference, and before this every policy
        attached to such a role was orphaned: the owner key became the raw ${...}
        text, so the role appeared to hold no permissions at all.
        """
        if ref in table:
            return table[ref]
        stripped = INDEX_REF.sub("", ref)
        return table.get(stripped)

    def pick_branch(text):
        """A ternary resolves to whichever branch this analysis can see.

        Neither branch can be decided, so the resolvable one is taken. That is
        over-approximation in the direction model/act-scope.md commits to: the
        branch that names a resource in this configuration is the branch whose
        permissions can be checked, and the other branch names something outside
        it that no analysis here could have checked anyway. When both branches
        resolve, or neither does, the text is left alone rather than guessed.
        """
        br = ternary_branches(text)
        if not br:
            return None
        known = []
        for b in br:
            b = b.strip()
            if "${" not in b and REF_WHOLE.fullmatch(b):
                # a branch arrives as raw HCL, so a bare traversal carries no ${}
                got = lookup(b)
                # the branch is known when the traversal was found, even if the
                # value it resolves to still carries an unresolved variable: an
                # ARN containing ${var.name} matches the same ARN built for the
                # resource itself, so the edge is still recoverable
                if got is not None:
                    known.append(resolve(got, table, depth + 1))
            elif b[:1] in "\"'" or not re.search(r"[A-Za-z_]", b.split("${")[0] or "x"):
                known.append(b.strip("\"'"))
        return known[0] if len(known) == 1 else None

    whole = re.fullmatch(r"\$\{([^{}]+)\}", value)
    if whole:
        got = lookup(whole.group(1))
        if got is not None:
            return got

    def sub(m):
        got = lookup(m.group(1))
        return str(got) if got is not None else m.group(0)
    out = re.sub(r"\$\{([^{}]+)\}", sub, value)
    if "${" in str(out) or "?" in str(out):
        picked = pick_branch(out)
        if picked is not None:
            return picked
    return out


def to_state(tfdir):
    files = sorted(p for p in glob.glob(os.path.join(tfdir, "**", "*.tf"), recursive=True)
                   if os.sep + ".terraform" + os.sep not in p)
    resources, datas, locals_ = [], [], []
    for p in files:
        try:
            text = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for rtype, rname, v in parse_tf_text(text):
            resources.append((rtype, rname, v))
        for dtype, dname, v in parse_data_blocks(text):
            datas.append((dtype, dname, v))
        for lname, lval in parse_locals(text):
            locals_.append((lname, lval))

    table = synth_arns(resources)
    # data source attributes resolve like resource attributes, so a policy written
    # as data.aws_iam_policy_document.x.json becomes the document itself
    for dtype, dname, v in datas:
        for attr, val in v.items():
            if attr != "_blocks" and isinstance(val, (str, int, float, bool)):
                table.setdefault(f"data.{dtype}.{dname}.{attr}", val)
    # locals resolve against the resource table, and a local may name another
    # local, so the pass repeats until nothing more becomes resolvable. The bound
    # stops a cycle; a local that is still unresolved then stays unresolved.
    for _ in range(4):
        progress = False
        for lname, lval in locals_:
            key = f"local.{lname}"
            if key in table:
                continue
            got = resolve(lval, table)
            # A value that still names a local is not finished, so it waits for
            # the next pass. A value that still names a variable IS finished:
            # the variable is a module input that nothing in this directory can
            # supply, and it appears identically in the ARN synthesised for the
            # resource itself, so the two still match.
            if (isinstance(got, (str, int, float, bool))
                    and "${local." not in str(got)
                    and str(got).strip() != str(lval).strip()):
                table[key] = got
                progress = True
        if not progress:
            break
    out = []
    for rtype, rname, v in resources:
        v = {k: val for k, val in v.items() if k != "_blocks"}
        v = resolve(v, table)
        label = f"{rtype}.{rname}"
        if f"{label}.arn" in table:
            v.setdefault("arn", resolve(table[f"{label}.arn"], table))
        v.setdefault("name", rname)
        # policy documents must reach the consumer as JSON text, the same way
        # terraform show -json emits them
        for key in ("policy", "assume_role_policy"):
            if key in v and not isinstance(v[key], str):
                v[key] = json.dumps(v[key])
        out.append({"type": rtype, "name": rname, "values": v})
    return {"format_version": "tf_to_state/1",
            "values": {"root_module": {"resources": out}}}, len(files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir", required=True)
    ap.add_argument("--json", default="state.json")
    a = ap.parse_args()
    state, nfiles = to_state(a.tfdir)
    res = state["values"]["root_module"]["resources"]
    kinds = {}
    for r in res:
        kinds[r["type"]] = kinds.get(r["type"], 0) + 1
    print(f"files: {nfiles}   resources: {len(res)}")
    for k in sorted(kinds):
        if k.startswith("aws_iam") or "bedrock" in k:
            print(f"   {k:44s} {kinds[k]}")
    json.dump(state, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()
