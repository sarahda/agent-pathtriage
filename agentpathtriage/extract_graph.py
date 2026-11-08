#!/usr/bin/env python3
"""
AgentPathTriage - unified extractor (extract_graph v1)

Replaces extract.py (agentic, roles only) and extract_iam.py (generic IAM, users
included). Those two disagreed on the wildcard test, on whether users can delegate,
on whether trust edges exist and on managed policies, so the same configuration got
different verdicts depending on the entry point. There is now one extractor and one
policy evaluator (iam_eval).

Node kinds
  user, role      IAM principals
  service         a service principal named in a trust policy, for example
                  bedrock-agentcore.amazonaws.com. Without this node the mechanism
                  behind the published AgentCore escalations cannot be expressed.
  agent           an agent runtime declared by the agent platform
  resource        a concrete or type-level resource an act edge reaches

Edge relations, matching model/formal-spec.md
  assume(agent, role)     the agent executes under this role
  act(role, resource)     the role is authorised for the resource, with the matched
                          scope recorded (exact, pattern or any)
  delegate(p, role)       p can obtain that role: iam:PassRole, sts:AssumeRole, or a
                          trust policy naming p. Carries the scope of the match.
  trusts(service, role)   the role trusts this service principal, with `scoped`
                          recording whether a condition narrows who may use it. Two
                          roles trusted by one service with scoped=False are
                          interchangeable to anything that can make that service act,
                          which is the shared-trust escalation.
  handoff(agent, agent)   one agent is configured to call another. This is the edge
                          that makes the graph agentic rather than a relabelled IAM
                          role graph: it is declared in the agent platform's own
                          configuration and no IAM analysis has it.

Input is the shape `terraform show -json` produces. tf_to_state.py produces the same
shape from raw .tf, so the extractor runs on configuration alone, without deploying.

Usage:
  python3 extract_graph.py --state state.json --json graph.json
  python3 extract_graph.py --tfdir path/to/terraform --json graph.json
"""
import argparse, json, os, pathlib, re, subprocess, sys
import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iam_eval as E

CONTROL_PLANE = "AWS control plane"
ADMIN_ACTIONS = ("*", "iam:*", "sts:*", "*:*")
ADMIN_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}
DELEGATION_ACTIONS = ("iam:PassRole", "sts:AssumeRole")

# Obtaining another identity does not always mean being handed it. These actions
# obtain one by rewriting what it may do, or by minting a way to sign in as it.
# They were previously called out of scope, which was a modelling gap dressed up
# as a scope decision: each of them makes eff(p) larger than auth(p), which is the
# definition this project works to.
#
#   control    p can rewrite what the target identity is allowed to do
#   become     p can mint credentials for the target identity and sign in as it
#   join       p can add itself to a group and inherit the group's permissions
#   retrust    p can rewrite who may assume the target role
# A policy document is not an identity, so controlling one is resolved to the
# identities that document is attached to.
CONTROL_ACTIONS = {
    "aws_iam_user": ("iam:PutUserPolicy", "iam:AttachUserPolicy"),
    "aws_iam_role": ("iam:PutRolePolicy", "iam:AttachRolePolicy"),
    "aws_iam_group": ("iam:PutGroupPolicy", "iam:AttachGroupPolicy"),
}
BECOME_ACTIONS = ("iam:CreateAccessKey", "iam:CreateLoginProfile",
                  "iam:UpdateLoginProfile")
JOIN_ACTIONS = ("iam:AddUserToGroup",)
RETRUST_ACTIONS = ("iam:UpdateAssumeRolePolicy",)
POLICY_CONTROL_ACTIONS = ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion")

# Resources that execute as a role, and the attribute naming that role. Whoever can
# change or drive one of these obtains that role's reach without ever being handed
# the role, which is the same escalation by a different route.
RUNS_AS_ATTRS = ("role", "role_arn", "iam_role_arn", "execution_role_arn",
                 "service_role", "service_role_arn", "iam_instance_profile")
# Which actions let a caller change or drive an existing resource? This used to be a
# hand-written list per service, and an ablation showed the list was carrying the
# benchmark result rather than the method, so it is now derived from AWS's own
# Service Authorization Reference through policy_sentry, which ships offline.
#
# A takeover candidate is a Write-level action in the service that owns the
# resource. Two services can reach an EC2 instance without being "ec2", so those
# are named as extra namespaces to consult rather than as a list of actions.
EXTRA_TAKEOVER_NAMESPACES = {"ec2": ["ssm", "ec2-instance-connect"]}
# Write level alone is too loose: AWS classifies a data-plane call such as
# bedrock:RetrieveAndGenerate as Write, and querying a knowledge base plainly does
# not hand you the role behind it. Taking over a deputy means changing what it will
# do, so the action has to alter the resource's definition. These are verb stems,
# not a list of actions, so the rule generalises to services nobody has looked at.
# Ordered most explanatory first. Several actions on one resource can all qualify,
# and the one named on the edge is what a reader sees, so "UpdateFunctionCode" has
# to win over "CreateAlias" even though both are takeovers.
MUTATION_VERBS = ("update", "put", "modify", "replace", "write", "deploy", "import",
                  "set", "register", "create", "add", "attach", "associate")
# Namespaces whose purpose is to run commands inside an existing resource. Here the
# resource definition does not change, the attacker simply executes within it, so
# every Write action in the namespace counts.
REMOTE_EXEC_NAMESPACES = {"ssm", "ec2-instance-connect", "ssm-guiconnect"}
_TAKEOVER_CACHE = {}


def resource_type_of(arn):
    """The resource type an ARN names, as the authorisation reference spells it.

    An ARN is arn:partition:service:region:account:<type>/<id> or
    arn:...:<type>:<id>. Both forms appear, and for a takeover the type is what
    has to match the action's documented resource format, because the id is
    deployment specific and often an unresolved variable.
    """
    parts = str(arn).split(":", 5)
    if len(parts) < 6:
        return ""
    tail = parts[5]
    if "/" in tail:
        return tail.split("/", 1)[0].lower()
    if ":" in tail:
        return tail.split(":", 1)[0].lower()
    return ""


# Request members that mean the caller decides what the deputy executes. Matched
# as substrings of the lowercased member name, so roleArn, executionRoleArn and
# Role all match "role", and ImageUri, ZipFile and S3Key all match an artifact
# stem. Kept deliberately short: a member that merely tunes how the deputy runs,
# such as MemorySize or networkConfiguration, is not control over what it runs.
# Request members that mean the caller decides what the deputy executes, or the
# identity it executes as. Matched against the words of the member name rather
# than as substrings: a naive substring test made "description" qualify through
# "script", which marked almost every action as control. A member name is split
# on camel case and separators, and each word and each pair of adjacent words is
# compared, so agentRuntimeArtifact, ZipFile, S3Key, taskDefinition and roleArn
# all match while description and agentRuntimeVersion do not.
EXEC_CONTROL_MEMBERS = frozenset((
    "artifact", "code", "image", "zip", "zipfile", "s3key", "handler",
    "command", "entrypoint", "layer", "layers", "taskdefinition",
    "containerdefinition", "containerdefinitions", "script", "scriptlocation",
))
IDENTITY_MEMBERS = frozenset(("role", "instanceprofile"))
# The second route to a deputy. Route one replaces what it runs or changes who
# it runs as. Route two obtains interactive access to it and executes inside,
# which the IAM-Vulnerable benchmark carries twice: a presigned notebook URL
# opens a shell in an instance holding a role, and adding a public key to a Glue
# development endpoint opens ssh to one. The resource definition is not being
# replaced, so the member test above cannot see either, and dropping them was a
# false negative against an answer key written outside this project.
#
# Signalled by the operation name, which AWS spells consistently across
# services, or by a request member that installs a key or a library in the
# resource. This is a rule over published operation names, not a list of
# services, so it generalises the way the namespace exemption below does not.
ACCESS_VERB_WORDS = frozenset((
    "presigned", "session", "command", "connect", "exec", "tunnel",
))
ACCESS_MEMBERS = frozenset((
    "publickey", "publickeys", "libraries", "library",
))
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+")


def member_words(name):
    """The words of a member name, plus each pair of adjacent words joined."""
    w = [m.group(0).lower() for m in _WORD.finditer(str(name))]
    return set(w) | {a + b for a, b in zip(w, w[1:])}
_BOTOCORE_CACHE = {}
_SHAPE_CACHE = {}


def _service_models(ns):
    """Every botocore model a policy namespace might be documented against.

    A policy namespace and a botocore service name are usually but not always
    the same string, and one namespace can span two models: bedrock-agentcore
    covers both the data plane service of that name and the control plane
    service bedrock-agentcore-control, and UpdateAgentRuntime lives only in the
    second. Returning all of them and letting the caller pick the one that has
    the operation avoids resolving to the first model that merely exists.
    Candidates are tried rather than mapped by hand so a service nobody has
    looked at still resolves.
    """
    if ns in _BOTOCORE_CACHE:
        return _BOTOCORE_CACHE[ns]
    models = []
    try:
        import botocore.session
        sess = botocore.session.get_session()
        for cand in (ns, f"{ns}-control", f"{ns}control",
                     ns.replace("-", ""), f"{ns}-service"):
            try:
                models.append(sess.get_service_model(cand))
            except Exception:
                continue
    except Exception:
        models = []
    _BOTOCORE_CACHE[ns] = models
    return models


def exec_control(ns, action):
    """Can this action set what the deputy runs, or the identity it runs as?

    Returns (verdict, evidence). verdict is True, False, or None when the
    operation could not be resolved and the question is therefore open.
    """
    key = (ns, action)
    if key in _SHAPE_CACHE:
        return _SHAPE_CACHE[key]
    op = action.split(":", 1)[-1]
    out = (None, "operation not resolved in the api model")
    for model in _service_models(ns):
        try:
            shape = model.operation_model(op).input_shape
        except Exception:
            continue
        members = sorted((shape.members or {}).keys()) if shape else []
        hits = []
        for m in members:
            words = member_words(m)
            if (words & EXEC_CONTROL_MEMBERS or words & IDENTITY_MEMBERS
                    or words & ACCESS_MEMBERS):
                hits.append(m)
        if not hits and member_words(op) & ACCESS_VERB_WORDS:
            hits.append(f"{op} grants access inside the resource")
        out = (bool(hits), ", ".join(hits) if hits
               else "no member sets what it runs or who it runs as")
        break
    _SHAPE_CACHE[key] = out
    return out


def _action_meta(ns, action):
    """(resource types other than *, dependent actions) for one action."""
    try:
        from policy_sentry.querying.actions import get_action_data
        data = get_action_data(ns, action.split(":", 1)[-1]) or {}
    except Exception:
        return set(), ()
    types, deps = set(), set()
    for rows in data.values():
        for row in rows or []:
            if str(row.get("action", "")).lower() != action.lower():
                continue
            fmt = str(row.get("resource_arn_format") or "")
            if fmt and fmt != "*":
                t = resource_type_of(fmt)
                if t:
                    types.add(t)
            for d in row.get("dependent_actions") or []:
                if d:
                    deps.add(str(d))
    return types, tuple(sorted(deps))


def _takeover_cache_file():
    """Where the derived action table is kept between runs.

    The table is derived from the Service Authorization Reference and from
    botocore's api models, so it changes only when those packages change, and
    recomputing it costs about a second per service. A corpus walk runs as many
    short processes, each starting with an empty in-memory cache, so without a
    file the same table is rebuilt hundreds of times. The file is keyed by the
    versions it was derived from, so an upgrade invalidates it rather than
    silently serving a stale table.
    """
    try:
        import botocore
        bv = botocore.__version__
    except Exception:
        bv = "none"
    try:
        from importlib.metadata import version
        pv = version("policy_sentry")
    except Exception:
        pv = "none"
    d = pathlib.Path(__file__).resolve().parent / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"takeover_actions.botocore-{bv}.policy_sentry-{pv}.json"


def _load_takeover_cache():
    f = _takeover_cache_file()
    if f.is_file():
        try:
            raw = json.loads(f.read_text())
            return {k: [(a, set(t) if t is not None else None, tuple(d), c, w)
                        for a, t, d, c, w in v] for k, v in raw.items()}
        except Exception:
            return {}
    return {}


def _save_takeover_cache(table):
    f = _takeover_cache_file()
    try:
        f.write_text(json.dumps(
            {k: [[a, sorted(t) if t is not None else None, list(d), c, w]
                 for a, t, d, c, w in v] for k, v in table.items()}))
    except Exception:
        pass


def takeover_actions(service):
    """Write-level actions that let a caller change or drive a resource of `service`.

    Each entry is (action, resource types it is authorised against, dependent
    actions AWS requires with it). An action authorised only against "*" is
    excluded: it creates or addresses something other than the resource being
    taken over, so allowing it on that resource's ARN says nothing about
    controlling it.
    """
    if not _TAKEOVER_CACHE:
        _TAKEOVER_CACHE.update(_load_takeover_cache())
    if service in _TAKEOVER_CACHE:
        return _TAKEOVER_CACHE[service]
    ranked = []
    try:
        from policy_sentry.querying.actions import get_actions_with_access_level
        for ns in [service] + EXTRA_TAKEOVER_NAMESPACES.get(service, []):
            writes = get_actions_with_access_level(ns, "Write") or []
            if ns in REMOTE_EXEC_NAMESPACES:
                # running a command inside the resource is the clearest takeover,
                # and the resource definition is not being changed, so the
                # resource format test does not apply and nothing is passed
                ranked.extend((-1, a, None, (), True,
                               "runs a command inside the resource")
                              for a in writes)
                continue
            for a in writes:
                verb = a.split(":", 1)[-1].lower()
                for rank, stem in enumerate(MUTATION_VERBS):
                    if verb.startswith(stem):
                        types, deps = _action_meta(ns, a)
                        if not types:
                            break
                        ctrl, why = exec_control(ns, a)
                        if ctrl is False:
                            # The request cannot set what the deputy runs or
                            # who it runs as, so allowing it is not control of
                            # that identity.
                            break
                        ranked.append((rank, a, types, deps, ctrl, why))
                        break
    except Exception:
        ranked = []
    acts = [(a, t, d, c, w) for _, a, t, d, c, w
            in sorted(ranked, key=lambda x: (x[0], x[1]))]
    _TAKEOVER_CACHE[service] = acts
    _save_takeover_cache(_TAKEOVER_CACHE)
    return acts

# Agentic resource types, keyed by the ARN infix that identifies them. The label is
# only a name for the node; whether an act edge is cross-agent is decided by the
# matched resource scope, never by the label.
ARN_LABEL = {
    ":memory/": "Agent memory",
    ":runtime/": "Agent runtimes",
    ":repository/": "ECR images",
    ":code-interpreter/": "Code interpreters",
    ":gateway/": "Gateways",
    ":browser/": "Browsers",
    ":knowledge-base/": "Knowledge bases",
}
# Probe actions used to ask the evaluator what a role can reach. Each probe pairs an
# action with the resource type it acts on.
PROBES = [
    ("ecr:BatchGetImage", "ECR images", "arn:aws:ecr:{r}:{a}:repository/{x}"),
    ("ecr:GetDownloadUrlForLayer", "ECR images", "arn:aws:ecr:{r}:{a}:repository/{x}"),
    ("bedrock-agentcore:InvokeCodeInterpreter", "Code interpreters",
     "arn:aws:bedrock-agentcore:{r}:{a}:code-interpreter/{x}"),
    ("bedrock-agentcore:InvokeAgentRuntime", "Agent runtimes",
     "arn:aws:bedrock-agentcore:{r}:{a}:runtime/{x}"),
    ("bedrock-agentcore:GetMemoryRecord", "Agent memory",
     "arn:aws:bedrock-agentcore:{r}:{a}:memory/{x}"),
    ("bedrock-agentcore:RetrieveMemoryRecords", "Agent memory",
     "arn:aws:bedrock-agentcore:{r}:{a}:memory/{x}"),
    ("bedrock:Retrieve", "Knowledge bases", "arn:aws:bedrock:{r}:{a}:knowledge-base/{x}"),
    ("s3:GetObject", "S3 objects", "arn:aws:s3:::{x}/*"),
]
AGENT_RESOURCE_TYPES = ("aws_bedrockagentcore_agent_runtime", "aws_bedrockagent_agent")


def load_state(tfdir=None, state_path=None):
    if state_path:
        return json.load(open(state_path))
    out = subprocess.check_output(["terraform", "show", "-json"], cwd=tfdir)
    return json.loads(out)


def iter_resources(state):
    root = state.get("values", {}).get("root_module", {})
    for r in root.get("resources", []):
        yield r["type"], r["name"], r.get("values", {})
    stack = list(root.get("child_modules", []))
    while stack:
        m = stack.pop()
        for r in m.get("resources", []):
            yield r["type"], r["name"], r.get("values", {})
        stack.extend(m.get("child_modules", []))


def as_list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def account_of(arn, default="000000000000"):
    parts = str(arn).split(":")
    return parts[4] if len(parts) > 5 and parts[4] else default


class Index:
    """Everything the graph needs, read once from the state."""

    def __init__(self, state, managed=None):
        self.managed = {}        # policy arn -> statements
        self.inline = {}         # principal key -> statements
        self.attached = {}       # principal key -> [policy arn]
        self.arn = {}            # principal name -> arn
        self.kind = {}           # principal name -> role | user
        self.trust = {}          # role name -> trust entries
        self.agents = {}         # agent name -> {role, env, type}
        self.exec_resources = []  # [{arn, role, service, type}] resources that run as a role
        self.profiles = {}       # instance profile name -> role name
        self.member_of = {}      # user name -> [group name]
        self.policy_attached_to = {}   # policy arn -> [principal name]
        self.account = "000000000000"

        # AWS managed policy documents, when a snapshot was supplied. Seeded
        # before the configuration is read so that a policy the configuration
        # declares overwrites it: the configuration is the ground truth for
        # anything it states, and the snapshot only fills what the
        # configuration cannot carry. A policy absent from the snapshot stays
        # unexpanded and keeps being reported by unreadable_managed.
        for _arn, _stmts in (managed or {}).items():
            self.managed[str(_arn)] = _stmts

        # Names that arrived as an expression rather than a string. Kept so a
        # caller can say which resources were keyed by their logical name.
        self.unresolved_names = []

        rows = list(iter_resources(state))
        for rtype, rname, v in rows:
            if rtype == "aws_iam_instance_profile":
                pname, punres = self._key_name(v.get("name"), rname)
                if punres is not None:
                    self.unresolved_names.append(
                        {"resource": rname, "type": rtype, "field": "name",
                         "expression": punres})
                self.profiles[pname] = self._owner_name(v.get("role"))
        for rtype, rname, v in rows:
            if rtype == "aws_iam_policy":
                self.managed[v.get("arn")] = E.parse_statements(v.get("policy"),
                                                                source=v.get("arn"))
        # groups first: a user's own permissions include its groups', so the group
        # has to exist before any user is resolved. Ignoring groups made auth(p)
        # wrong for every user in one, not just the group privesc paths.
        for rtype, rname, v in rows:
            if rtype == "aws_iam_group":
                name, gunres = self._key_name(v.get("name"), rname)
                if gunres is not None:
                    self.unresolved_names.append(
                        {"resource": rname, "type": rtype, "field": "name",
                         "expression": gunres})
                self.kind[name] = "group"
                if v.get("arn"):
                    self.arn[name] = v["arn"]
        for rtype, rname, v in rows:
            if rtype in ("aws_iam_group_membership", "aws_iam_user_group_membership"):
                group = self._owner_name(v.get("group"))
                users = v.get("users") or v.get("user") or []
                if isinstance(users, str):
                    users = [u.strip().strip("'\"") for u in
                             users.strip("[]").split(",") if u.strip()]
                for u in users:
                    self.member_of.setdefault(self._owner_name(u), []).append(group)
            elif rtype == "aws_iam_group_policy_attachment":
                g = self._owner_name(v.get("group"))
                if g and v.get("policy_arn"):
                    self.attached.setdefault(g, []).append(v["policy_arn"])
                    self.policy_attached_to.setdefault(v["policy_arn"], []).append(g)
            elif rtype == "aws_iam_group_policy":
                g = self._owner_name(v.get("group") or rname)
                self.inline.setdefault(g, []).extend(
                    E.parse_statements(v.get("policy"), source=rname))

        for rtype, rname, v in rows:
            if rtype in ("aws_iam_role", "aws_iam_user"):
                kind = "role" if rtype == "aws_iam_role" else "user"
                name = v.get("name") or rname
                self.kind[name] = kind
                if v.get("arn"):
                    self.arn[name] = v["arn"]
                    self.account = account_of(v["arn"], self.account)
                for m in as_list(v.get("managed_policy_arns")):
                    self.attached.setdefault(name, []).append(m)
                for blk in as_list(v.get("inline_policy")):
                    if isinstance(blk, dict) and blk.get("policy"):
                        self.inline.setdefault(name, []).extend(
                            E.parse_statements(blk["policy"], source="inline_policy"))
                if kind == "role" and v.get("assume_role_policy"):
                    self.trust[name] = E.trust_entries_from_policy(v["assume_role_policy"])
            elif rtype in ("aws_iam_role_policy", "aws_iam_user_policy"):
                owner = v.get("role") or v.get("user") or rname
                owner = self._owner_name(owner)
                self.inline.setdefault(owner, []).extend(
                    E.parse_statements(v.get("policy"), source=rname))
            elif rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"):
                owner = self._owner_name(v.get("role") or v.get("user"))
                if owner and v.get("policy_arn"):
                    self.attached.setdefault(owner, []).append(v["policy_arn"])
                    self.policy_attached_to.setdefault(v["policy_arn"], []).append(owner)
            elif rtype in AGENT_RESOURCE_TYPES:
                declared = v.get("name") or v.get("agent_runtime_name")
                name, unresolved = self._key_name(declared, rname)
                if unresolved is not None:
                    self.unresolved_names.append(
                        {"resource": rname, "type": rtype, "field": "name",
                         "expression": unresolved})
                role = v.get("role_arn") or v.get("agent_resource_role_arn")
                self.agents[name] = {"role_arn": role, "raw": v, "type": rtype}

            # any resource that declares the role it runs as is a potential deputy
            if not rtype.startswith("aws_iam_") and v.get("arn"):
                for attr in RUNS_AS_ATTRS:
                    if not v.get(attr):
                        continue
                    ref = str(v[attr])
                    role = (self.profiles.get(ref) if attr == "iam_instance_profile"
                            else self._owner_name(ref))
                    if not role:
                        continue
                    svc = str(v["arn"]).split(":")[2] if str(v["arn"]).count(":") > 2 else ""
                    self.exec_resources.append({"arn": v["arn"], "role": role,
                                                "service": svc, "type": rtype})
                    break

        # synthesise missing ARNs so pattern matching has something to match on
        for name, kind in self.kind.items():
            self.arn.setdefault(
                name, f"arn:aws:iam::{self.account}:{'role' if kind=='role' else 'user'}/{name}")
        self.name_of_arn = {a: n for n, a in self.arn.items()}

    @staticmethod
    def _key_name(declared, rname):
        """A dict key for a resource whose declared name may be an expression.

        A CloudFormation name arrives as an intrinsic, so `name` can be a dict.
        A dict cannot be a key, and str() of one is not a name. The resource's
        logical name is used instead: it is always a string and it is unique
        within the template, which is what a key has to be.

        Returns the key and the expression that did not resolve, or None when
        there was nothing to resolve. The caller records the second value so an
        unresolved name is visible rather than looking like a resolved one.
        """
        if isinstance(declared, str) and declared:
            return declared, None
        if declared is None:
            return rname, None
        return rname, declared

    @staticmethod
    def _owner_name(raw):
        """A role/user reference may arrive as a name, an id, or an ARN.

        Names are used as the key everywhere, and the last ARN segment is the name,
        so one rule covers both forms.
        """
        if raw is None:
            return None
        raw = str(raw)
        return raw.rsplit("/", 1)[-1] if raw.startswith("arn:") else raw

    def statements(self, principal, _seen=None):
        """Everything this principal is allowed, including through its groups."""
        out = list(self.inline.get(principal, []))
        for arn in self.attached.get(principal, []):
            out.extend(self.managed.get(arn, []))
        seen = _seen or {principal}
        for g in self.member_of.get(principal, []):
            if g in seen:
                continue
            seen.add(g)
            out.extend(self.statements(g, seen))
        return out

    def is_admin_managed(self, principal):
        return any(a in ADMIN_MANAGED for a in self.attached.get(principal, []))

    def unreadable_managed(self, principal):
        """AWS-managed policies attached to this principal whose document is not in
        the configuration. Their contents live at AWS, so a static pass cannot know
        what they grant. Reporting them is the difference between a silent miss and
        a stated unknown: an escalation into a role carrying one of these is real,
        its extent is simply not measurable from config.
        """
        out = []
        for arn in self.attached.get(principal, []):
            a = str(arn)
            if a.startswith("arn:aws:iam::aws:policy/") and a not in ADMIN_MANAGED \
                    and a not in self.managed:
                out.append(a)
        return sorted(set(out))


def build(state, managed=None):
    ix = Index(state, managed)
    G = nx.DiGraph()
    acct = ix.account

    for name, kind in ix.kind.items():
        G.add_node(name, kind=kind, arn=ix.arn.get(name))

    # ---- act edges -----------------------------------------------------------
    # An act edge is added when the principal's policies allow a probe action on a
    # probe resource. The matched resource scope is recorded, so "reaches exactly
    # its own memory" and "reaches any memory in the account" are different edges
    # rather than the same boolean.
    for name in list(ix.kind):
        stmts = ix.statements(name)
        if ix.is_admin_managed(name):
            G.add_node(CONTROL_PLANE, kind="resource")
            G.add_edge(name, CONTROL_PLANE, rel="act", action="* (admin managed)",
                       scope="any", wildcard=True, conditional=False)
        # admin-grade: a statement whose action pattern is itself a wildcard over a
        # whole service or everything, granted on a wildcard resource. Probing with
        # iam:CreateUser asks the evaluator the question, so a Deny is honoured.
        d = E.evaluate(stmts, "iam:CreateUser", f"arn:aws:iam::{acct}:user/anyone")
        if d.allowed and any(any(p in ADMIN_ACTIONS for p in s.actions)
                             and s.resource_is_wildcard() for s in d.allow_statements):
            G.add_node(CONTROL_PLANE, kind="resource")
            G.add_edge(name, CONTROL_PLANE, rel="act", action="* (admin)",
                       scope="any", wildcard=True, conditional=d.conditional)
        for action, label, template in PROBES:
            own = template.format(r="us-east-1", a=acct, x=f"own-{name}")
            other = template.format(r="us-east-1", a=acct, x="other-agent")
            d_own = E.evaluate(stmts, action, own)
            d_other = E.evaluate(stmts, action, other)
            if not (d_own.allowed or d_other.allowed):
                continue
            # cross-agent reach is the real test: the policy allows the action on a
            # resource this principal does not own
            scope = "any" if d_other.allowed else "exact"
            G.add_node(label, kind="resource")
            prev = G.get_edge_data(name, label)
            cond = (d_other if d_other.allowed else d_own).conditional
            if prev and prev.get("rel") == "act":
                if scope == "any":
                    prev["scope"] = "any"
                    prev["wildcard"] = True
                prev.setdefault("actions", []).append(action)
            else:
                G.add_edge(name, label, rel="act", action=action, actions=[action],
                           scope=scope, wildcard=(scope == "any"), conditional=cond)

    # ---- delegate edges from PassRole / AssumeRole ----------------------------
    role_arns = [ix.arn[n] for n, k in ix.kind.items() if k == "role"]
    for name in list(ix.kind):
        stmts = ix.statements(name)
        for action in DELEGATION_ACTIONS:
            hits = E.delegation_targets(stmts, action, role_arns)
            for arn, meta in hits.items():
                tgt = ix.name_of_arn.get(arn)
                if not tgt or tgt == name:
                    continue
                _add_delegate(G, name, tgt, action, meta["scope"], meta["conditional"])

    # ---- identity-control edges: rewrite, or sign in as, another identity ----
    kind_by_resource = {"user": "aws_iam_user", "role": "aws_iam_role",
                        "group": "aws_iam_group"}
    for p in list(ix.kind):
        stmts = ix.statements(p)
        if not stmts:
            continue
        for q, qkind in ix.kind.items():
            if q == p:
                continue
            qarn = ix.arn.get(q)
            if not qarn:
                continue
            rtype = kind_by_resource.get(qkind)
            for action in CONTROL_ACTIONS.get(rtype, ()):
                d = E.evaluate(stmts, action, qarn)
                if d.allowed:
                    _add_delegate(G, p, q, f"control:{action}",
                                  "any" if any(s.resource_is_wildcard()
                                               for s in d.allow_statements) else "exact",
                                  d.conditional)
                    break
            if qkind == "user":
                for action in BECOME_ACTIONS:
                    if E.evaluate(stmts, action, qarn).allowed:
                        _add_delegate(G, p, q, f"become:{action}", "exact", False)
                        break
            if qkind == "group" and ix.kind.get(p) == "user":
                for action in JOIN_ACTIONS:
                    if E.evaluate(stmts, action, qarn).allowed:
                        _add_delegate(G, p, q, f"join:{action}", "exact", False)
                        break
            if qkind == "role":
                for action in RETRUST_ACTIONS:
                    if E.evaluate(stmts, action, qarn).allowed:
                        _add_delegate(G, p, q, f"retrust:{action}", "exact", False)
                        break

        # rewriting one's own permissions is not reaching another identity, it is
        # reaching everything, so it is an edge to the control plane instead
        own_arn = ix.arn.get(p)
        own_rtype = kind_by_resource.get(ix.kind.get(p))
        if own_arn and own_rtype:
            for action in CONTROL_ACTIONS.get(own_rtype, ()):
                d = E.evaluate(stmts, action, own_arn)
                if d.allowed:
                    G.add_node(CONTROL_PLANE, kind="resource")
                    G.add_edge(p, CONTROL_PLANE, rel="act",
                               action=f"* (via {action} on itself)", scope="any",
                               wildcard=True, conditional=d.conditional)
                    break

        # controlling a policy document reaches every identity it is attached to
        for parn in ix.managed:
            if not parn:
                continue
            for action in POLICY_CONTROL_ACTIONS:
                if not E.evaluate(stmts, action, str(parn)).allowed:
                    continue
                for holder in ix.policy_attached_to.get(parn, []):
                    if holder == p:
                        G.add_node(CONTROL_PLANE, kind="resource")
                        G.add_edge(p, CONTROL_PLANE, rel="act",
                                   action=f"* (via {action} on an attached policy)",
                                   scope="any", wildcard=True, conditional=False)
                    else:
                        _add_delegate(G, p, holder, f"control:{action}", "exact", False)
                break

    # ---- takeover edges: control an existing resource that runs as a role -----
    # Nobody passes the attacker a role here. They change, or drive, something that
    # is already running as one. The reach gained is the same, so under
    # eff(p) \\ auth(p) it is the same kind of escalation and belongs in the graph.
    blocked_takeovers = []
    for name in list(ix.kind):
        stmts = ix.statements(name)
        for r in ix.exec_resources:
            if r["role"] == name or r["role"] not in ix.kind:
                continue
            rtype = resource_type_of(r["arn"])
            for action, types, deps, ctrl, why in takeover_actions(r["service"]):
                # The action has to be one AWS authorises against this kind of
                # resource. types is None for the remote execution namespaces,
                # where the resource definition is not being changed.
                if types is not None and rtype and rtype not in types:
                    continue
                d = E.evaluate(stmts, action, r["arn"])
                if not d.allowed:
                    continue
                # AWS lists what else the call needs. iam:PassRole is asked
                # about the role being taken over, because that is the role the
                # request carries; anything else is asked about the resource.
                role_arn = ix.arn.get(r["role"]) or \
                    f"arn:aws:iam::{ix.account}:role/{r['role']}"
                missing = []
                for dep in deps:
                    tgt = role_arn if dep.lower() == "iam:passrole" else r["arn"]
                    if not E.evaluate(stmts, dep, tgt).allowed:
                        missing.append(dep)
                if missing:
                    # One permission away from usable is not the same as absent,
                    # so it is recorded instead of silently dropped.
                    blocked_takeovers.append({
                        "principal": name, "target_role": r["role"],
                        "action": action, "resource": r["arn"],
                        "missing_dependent_actions": missing,
                    })
                    continue
                scope = "any" if any(s.resource_is_wildcard() for s in d.allow_statements) \
                    else "exact"
                _add_delegate(G, name, r["role"], f"takeover:{action}", scope, d.conditional)
                G[name][r["role"]]["takeover_resource"] = r["arn"]
                # True when the api model showed the request sets what the
                # deputy runs or who it runs as, None when the operation could
                # not be resolved and the question is open.
                G[name][r["role"]]["exec_control_verified"] = ctrl is True
                G[name][r["role"]]["exec_control_evidence"] = why
                break
    G.graph["blocked_takeovers"] = blocked_takeovers

    # ---- trust edges, including service principals ----------------------------
    for role, entries in ix.trust.items():
        for e in entries:
            if e["kind"].lower() == "service":
                svc = e["value"]
                G.add_node(svc, kind="service")
                G.add_edge(svc, role, rel="trusts", scoped=e["scoped"],
                           condition_keys=e["condition_keys"])
            else:
                src = ix.name_of_arn.get(e["value"])
                if src and src != role:
                    _add_delegate(G, src, role, "trust", "exact", not e["scoped"])

    # ---- agents, assume edges and handoff edges -------------------------------
    for agent, meta in ix.agents.items():
        G.add_node(agent, kind="agent", agent_type=meta["type"])
        role = ix.name_of_arn.get(meta["role_arn"])
        if not role and meta["role_arn"]:
            role = str(meta["role_arn"]).rsplit("/", 1)[-1]
        if role:
            G.add_node(role, kind=G.nodes.get(role, {}).get("kind", "role"))
            G.add_edge(agent, role, rel="assume")
    _add_handoffs(G, ix)
    return G, ix


def _add_delegate(G, src, tgt, via, scope, conditional):
    G.add_node(tgt, kind=G.nodes.get(tgt, {}).get("kind", "role"))
    G.add_node(src, kind=G.nodes.get(src, {}).get("kind", "role"))
    if G.has_edge(src, tgt) and G[src][tgt].get("rel") == "delegate":
        d = G[src][tgt]
        if via not in d.setdefault("vias", []):
            d["vias"].append(via)
        if scope == "any" or d.get("scope") == "any":
            d["scope"] = "any"
        elif scope == "pattern":
            d["scope"] = "pattern"
    else:
        G.add_edge(src, tgt, rel="delegate", via=via, vias=[via], scope=scope,
                   conditional=conditional)


# An environment variable whose NAME suggests it addresses another agent. Measured
# against the corpus, the name on its own is a poor signal: of 64 agent-sounding
# variables on agent runtimes, most are AGENT_MODEL_ID, AGENT_PORT, AGENT_PERSONA
# and similar settings. So the name is only used for the weaker case where the
# value cannot be resolved, and it is required to look like an address.
HANDOFF_NAME = re.compile(
    r"(specialist|supervisor|orchestrat|collaborat|sub_?agent|child_?agent|peer_?agent|"
    r"downstream|target_?agent|connected_?agent|worker_?agent|a2a|_agent_runtime)", re.I)
ADDRESS_NAME = re.compile(r"(_arn|_url|_endpoint|_runtime_id|_agent_id)$", re.I)
INVOKE_AGENT = "bedrock-agentcore:InvokeAgentRuntime"

# Which action actually invokes a given kind of agent. AgentCore runtimes and
# classic Bedrock agents are different services with different call verbs, and
# probing one verb against both is wrong in both directions: a role holding
# `bedrock-agentcore:*` on `*` appeared able to invoke a classic Bedrock agent,
# which it cannot, while a role holding `bedrock:InvokeAgent` on a named classic
# agent produced no edge at all. Measured on the corpus, the first case produced
# one permitted hand-off edge that does not exist.
INVOKE_ACTIONS = {
    "aws_bedrockagentcore_agent_runtime": ("bedrock-agentcore:InvokeAgentRuntime",),
    "aws_bedrockagent_agent": ("bedrock:InvokeAgent", "bedrock-agent-runtime:InvokeAgent"),
}


def invoke_actions_for(agent_type):
    """The invoke verbs for a target agent, defaulting to the AgentCore one."""
    return INVOKE_ACTIONS.get(agent_type, (INVOKE_AGENT,))


def _env_of(agent_values):
    env = agent_values.get("environment_variables")
    return env if isinstance(env, dict) else {}


def _add_handoffs(G, ix):
    """Agent A is configured, or permitted, to call agent B.

    This edge is what makes the graph agentic rather than a relabelled IAM graph:
    it is declared in the agent platform's own configuration, and no IAM analysis
    has it. It is recovered three ways, strongest first, and each edge records
    which one found it so a reader can discount the weaker ones.

      declared_resolved   an environment variable on A holds B's ARN or id. After
                          reference resolution these are real values, so the target
                          is known. This is the only form that names both ends.
      declared_unresolved an environment variable on A is addressed at an agent
                          (its name says so and it looks like an ARN, URL or id) but
                          the value is a module input, so the target is outside what
                          configuration alone can resolve. The hand-off exists; the
                          other end is unknown.
      permitted           A's execution role may call InvokeAgentRuntime on B. Not
                          evidence that A does, only that nothing stops it, so the
                          scope of the grant is recorded with it.
    """
    # Two agents must not share an address. If an unresolved expression leaves two
    # of them looking identical, attributing an edge to either is a guess, so the
    # address is dropped and the hand-off falls back to the unresolved form.
    arn_owners, id_owners = {}, {}
    for name, meta in ix.agents.items():
        raw = meta["raw"]
        for key in ("arn", "agent_runtime_arn", "agent_arn"):
            if raw.get(key):
                arn_owners.setdefault(str(raw[key]), set()).add(name)
        for key in ("id", "agent_runtime_id", "agent_id"):
            if raw.get(key):
                id_owners.setdefault(str(raw[key]), set()).add(name)
    by_arn = {k: next(iter(v)) for k, v in arn_owners.items() if len(v) == 1}
    by_id = {k: next(iter(v)) for k, v in id_owners.items() if len(v) == 1}

    for a, meta in ix.agents.items():
        env = _env_of(meta["raw"])
        for var, val in env.items():
            sval = str(val)
            target = by_arn.get(sval) or by_id.get(sval)
            if target and target != a:
                G.add_edge(a, target, rel="handoff", evidence="declared_resolved",
                           via_variable=var)
                continue
            if target:
                continue
            if HANDOFF_NAME.search(var) and ADDRESS_NAME.search(var) and "${" in sval:
                node = f"<unresolved agent: {var}>"
                G.add_node(node, kind="agent", resolved=False)
                G.add_edge(a, node, rel="handoff", evidence="declared_unresolved",
                           via_variable=var)

    for a, meta in ix.agents.items():
        role = ix.name_of_arn.get(meta["role_arn"]) or (
            str(meta["role_arn"]).rsplit("/", 1)[-1] if meta["role_arn"] else None)
        if not role or role not in ix.kind:
            continue
        stmts = ix.statements(role)
        if not stmts:
            continue
        for b, bmeta in ix.agents.items():
            if b == a:
                continue
            arn = bmeta["raw"].get("arn") or bmeta["raw"].get("agent_runtime_arn")
            if not arn:
                continue
            allows, used = [], None
            for act in invoke_actions_for(bmeta.get("type")):
                d = E.evaluate(stmts, act, str(arn))
                if d.allowed:
                    allows.extend(d.allow_statements)
                    used = used or act
            if not allows:
                continue
            # `resource_spans_many`, not `resource_is_wildcard`: a pattern
            # such as runtime/mcp/runtime-endpoint/* names ONE runtime, and
            # calling that "permitted to invoke any agent" overstates it. The
            # coarse test also made a correct repair look like it had failed.
            scope = ("any" if any(s.resource_spans_many() for s in allows)
                     else "exact")
            if G.has_edge(a, b) and G[a][b].get("rel") == "handoff":
                G[a][b]["permitted"] = True
                G[a][b]["permitted_scope"] = scope
                G[a][b]["permitted_action"] = used
            else:
                G.add_edge(a, b, rel="handoff", evidence="permitted",
                           permitted=True, permitted_scope=scope,
                           permitted_action=used)


def summarise(G):
    kinds = {}
    for _, d in G.nodes(data=True):
        kinds[d.get("kind")] = kinds.get(d.get("kind"), 0) + 1
    rels = {}
    for _, _, d in G.edges(data=True):
        rels[d.get("rel")] = rels.get(d.get("rel"), 0) + 1
    print("nodes: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items(), key=lambda x: str(x))))
    print("edges: " + ", ".join(f"{k}={v}" for k, v in sorted(rels.items(), key=lambda x: str(x))))
    ho = [d.get("evidence") for _, _, d in G.edges(data=True) if d.get("rel") == "handoff"]
    if ho:
        kinds = {}
        for e in ho:
            kinds[e] = kinds.get(e, 0) + 1
        print("agent hand-offs: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    shared = shared_trust_groups(G)
    if shared:
        print("shared unconditioned service trust:")
        for svc, roles in shared.items():
            print(f"   {svc} -> {len(roles)} roles: {', '.join(sorted(roles))}")
    return G


def shared_trust_groups(G):
    """service -> roles it is trusted by with nothing narrowing the grant.

    Two or more roles in one group are interchangeable to anything that can make
    that service act on its behalf.
    """
    out = {}
    for u, v, d in G.edges(data=True):
        if d.get("rel") == "trusts" and not d.get("scoped"):
            out.setdefault(u, set()).add(v)
    return {k: v for k, v in out.items() if len(v) > 1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--state")
    ap.add_argument("--json", default="graph.json")
    a = ap.parse_args()
    if not a.tfdir and not a.state:
        ap.error("give --tfdir or --state")
    G, _ = build(load_state(a.tfdir, a.state))
    summarise(G)
    json.dump(nx.node_link_data(G), open(a.json, "w"), indent=2)
    print(f"graph json: {a.json}")


if __name__ == "__main__":
    main()
