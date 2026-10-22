<#
.SYNOPSIS
    Validates and profiles any BloodHound OpenGraph JSON payload.

.DESCRIPTION
    Works for any OpenGraph collector output (not tied to one extension). It reports:

      1. Validation against the OpenGraph data rules (graph/metadata structure, node id and
         kinds rules, reserved properties, property types and naming, edge kind pattern,
         reserved tag_ prefix, endpoint match_by rules, post-processed and built-in kinds,
         dangling references, duplicates, self-loops).
      2. Optional extension-schema checks (-SchemaPath): kinds defined, namespace prefix,
         traversability, environments, environmentid / collected / source_kind readiness
         for findings in BloodHound Enterprise.
      3. Counts and profiles: nodes and edges by kind, kind combinations, edge patterns
         (StartKind -[Edge]-> EndKind), property coverage and type consistency, fan-out.
      4. Hybrid / external endpoints: edges that point at nodes NOT defined in the file
         (AD/Azure/other graph nodes matched by name, property, SID or GUID), grouped by
         target domain / group.
      5. Graph structure: isolated nodes, connected components, highest-degree nodes.
      6. Reachability into external targets: which principals / entry points reach the
         most external nodes, which edge kinds those paths depend on (what-if removal),
         and chokepoint nodes / edges.
      7. Optional -BaselinePath comparison: count changes and which new edges add paths.

    Output: console summary, Report.txt, CSV files and a cypher_queries.txt (queries
    return whole nodes or paths, suitable for the BHE Cypher editor).

.PARAMETER Path
    OpenGraph JSON payload to analyse.
.PARAMETER SchemaPath
    Optional extension definition schema (schema.json) for structured-graph checks and
    traversability. Without it, all edges are ASSUMED traversable for path analysis.
.PARAMETER BaselinePath
    Optional older payload from the same collector to compare against.
.PARAMETER TierZeroFile
    Optional list of external target names (one per line, or CSV with a 'name' column).
    When supplied, only paths ending on these targets are counted.
.PARAMETER NonTraversable
    Edge kinds to treat as non-traversable when no schema is supplied.
.PARAMETER OutputFolder
    Output folder. Default .\OG-Analysis-<timestamp>.
.PARAMETER Top
    Rows in "top N" tables. Default 25.
.PARAMETER SkipPathAnalysis
    Skip reachability / what-if analysis (validation and profiling only).

.EXAMPLE
    .\Test-OpenGraphJson.ps1 -Path .\output.json
.EXAMPLE
    .\Test-OpenGraphJson.ps1 -Path .\new.json -SchemaPath .\schema.json -BaselinePath .\old.json

.NOTES
    PowerShell 7+ recommended; Windows PowerShell 5.1 supported. The file is read fully
    into memory; budget roughly 4-6x the file size in RAM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$SchemaPath,
    [string]$BaselinePath,
    [string]$TierZeroFile,
    [string[]]$NonTraversable = @(),
    [string]$OutputFolder,
    [int]$Top = 25,
    [switch]$SkipPathAnalysis
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

#region ---------- Reference data ----------
$script:PostProcessedKinds = @('ADCSESC1', 'ADCSESC3', 'ADCSESC4', 'ADCSESC6a', 'ADCSESC6b', 'ADCSESC9a', 'ADCSESC9b',
    'ADCSESC10a', 'ADCSESC10b', 'ADCSESC13', 'AddMember', 'AdminTo', 'AZAddOwner', 'AZMGAddMember', 'AZMGAddOwner',
    'AZMGAddSecret', 'AZMGGrantAppRoles', 'AZMGGrantRole', 'AZRoleApprover', 'CanPSRemote', 'CanRDP',
    'CoerceAndRelayNTLMToADCS', 'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS', 'CoerceAndRelayNTLMToSMB',
    'DCSync', 'EnrollOnBehalfOf', 'EnterpriseCAFor', 'ExecuteDCOM', 'ExtendedByPolicy', 'GoldenCert', 'HasTrustKeys',
    'IssuedSignedBy', 'Owns', 'OwnsLimitedRights', 'ProtectAdminGroups', 'SyncLAPSPassword', 'SyncedToADUser',
    'SyncedToEntraUser', 'TrustedForNTAuth', 'WriteOwner', 'WriteOwnerLimitedRights')

# Common built-in kinds (not exhaustive). Using them in a payload is legitimate for deliberate
# hybrid edges, but custom kinds should be prefixed (Namespace_Kind).
$script:BuiltinEdgeKinds = @('MemberOf', 'HasSession', 'AdminTo', 'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToDelegate',
    'AllowedToAct', 'AddAllowedToAct', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'OwnsRaw',
    'WriteOwnerRaw', 'AllExtendedRights', 'ForceChangePassword', 'AddMember', 'AddSelf', 'ReadLAPSPassword',
    'ReadGMSAPassword', 'Contains', 'GPLink', 'TrustedBy', 'SQLAdmin', 'HasSIDHistory', 'DCSync', 'GetChanges',
    'GetChangesAll', 'GetChangesInFilteredSet', 'WriteSPN', 'AddKeyCredentialLink', 'WriteAccountRestrictions',
    'SyncLAPSPassword', 'DumpSMSAPassword', 'HasTrustKeys', 'CrossForestTrust', 'SameForestTrust', 'SpoofSIDHistory',
    'AbuseTGTDelegation', 'MemberOfLocalGroup', 'LocalToComputer', 'RemoteInteractiveLogonRight', 'CoerceToTGT',
    'Enroll', 'ManageCA', 'ManageCertificates', 'PublishedTo', 'HostsCAService', 'DelegatedEnrollmentAgent',
    'TrustedForNTAuth', 'RootCAFor', 'IssuedSignedBy', 'EnterpriseCAFor', 'GoldenCert', 'OIDGroupLink', 'ExtendedByPolicy',
    'WritePKIEnrollmentFlag', 'WritePKINameFlag', 'WriteGPLink', 'ClaimSpecialIdentity', 'ContainsIdentity',
    'PropagatesACEsTo', 'GPOAppliesTo', 'CanApplyGPO', 'HasTrustKeys')
$script:BuiltinNodeKinds = @('Base', 'User', 'Computer', 'Group', 'Domain', 'GPO', 'OU', 'Container', 'AIACA', 'RootCA',
    'EnterpriseCA', 'NTAuthStore', 'CertTemplate', 'IssuancePolicy', 'Site', 'SiteServer', 'SiteSubnet', 'SiteContainer')
#endregion

#region ---------- C# engine ----------
if (-not ('OGCheckV1.Ingest' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Management.Automation;
namespace OGCheckV1 {
    public class Issue { public string Sev, Check, Msg, Example; public int Count; }
    public class PropStat { public int Count; public HashSet<string> Types = new HashSet<string>(); }

    public class Ingest {
        // nodes
        public List<string> Label = new List<string>(), Key = new List<string>(), KindOf = new List<string>(), AllKinds = new List<string>();
        public List<bool> External = new List<bool>();
        public List<string> ExtClass = new List<string>(), Group = new List<string>();
        public int Internal;
        // edges
        public List<int> From = new List<int>(), To = new List<int>(), KindId = new List<int>();
        public List<object> Props = new List<object>();
        public List<string> Kinds = new List<string>();
        Dictionary<string, int> kindIdx = new Dictionary<string, int>(StringComparer.Ordinal);
        Dictionary<string, int> idx = new Dictionary<string, int>(StringComparer.Ordinal);
        Dictionary<string, int> idxCI = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        // stats
        public Dictionary<string, Issue> Issues = new Dictionary<string, Issue>();
        public Dictionary<string, int> NodeKindCount = new Dictionary<string, int>(), KindCombo = new Dictionary<string, int>(),
            EdgeKindCount = new Dictionary<string, int>(), EdgePattern = new Dictionary<string, int>(),
            MatchBy = new Dictionary<string, int>(), HybridByKindGroup = new Dictionary<string, int>(),
            ExtClassCount = new Dictionary<string, int>(), EdgeKindHybrid = new Dictionary<string, int>(),
            EndKindFilter = new Dictionary<string, int>(), NamelessByKind = new Dictionary<string, int>(),
            DupNameByKind = new Dictionary<string, int>(), EnvIdByKind = new Dictionary<string, int>(),
            UnknownNodeKinds = new Dictionary<string, int>(), UnknownEdgeKinds = new Dictionary<string, int>();
        public Dictionary<string, Dictionary<string, PropStat>> NodeProps = new Dictionary<string, Dictionary<string, PropStat>>();
        public Dictionary<string, Dictionary<string, PropStat>> EdgeProps = new Dictionary<string, Dictionary<string, PropStat>>();
        public List<string> EnvIdValues = new List<string>();
        public int EnvNodes, EnvNodesCollected, SelfLoops, DupEdges, DupIds;
        public HashSet<string> Sigs = new HashSet<string>(StringComparer.Ordinal);
        Dictionary<string, HashSet<string>> namesByKind = new Dictionary<string, HashSet<string>>();

        static object U(object o) { PSObject p = o as PSObject; return p != null ? p.BaseObject : o; }
        static object G(object d, string k) { IDictionary dd = U(d) as IDictionary; if (dd == null) return null; return dd.Contains(k) ? U(dd[k]) : null; }
        static bool Has(object d, string k) { IDictionary dd = U(d) as IDictionary; return dd != null && dd.Contains(k); }
        static string S(object o) { o = U(o); return o == null ? null : Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture); }
        static bool IsList(object o) { return o is IEnumerable && !(o is string) && !(o is IDictionary); }
        static readonly Regex KindRx = new Regex("^[A-Za-z0-9_]+$");
        static readonly Regex PropNameRx = new Regex("^[a-z0-9_]+$");
        static readonly Regex SidRx = new Regex("^S-1-5-21-\\d+-\\d+-\\d+(-\\d+)?$", RegexOptions.IgnoreCase);
        static readonly Regex SidWellKnownRx = new Regex("^(.+-)?S-1-(5|16)(-\\d+)+$", RegexOptions.IgnoreCase);
        static readonly Regex GuidRx = new Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase);
        static void Inc(Dictionary<string, int> d, string k) { int c; d.TryGetValue(k, out c); d[k] = c + 1; }

        public void AddIssue(string sev, string check, string msg, string example) {
            string key = sev + "|" + check + "|" + msg;
            Issue i; if (!Issues.TryGetValue(key, out i)) { i = new Issue { Sev = sev, Check = check, Msg = msg, Example = example }; Issues[key] = i; }
            i.Count++;
        }
        static string TypeOf(object v) {
            v = U(v);
            if (v == null) return "null";
            if (v is string) return "string";
            if (v is bool) return "bool";
            if (v is IDictionary) return "object";
            if (IsList(v)) return "array";
            return "number";
        }
        void Profile(Dictionary<string, Dictionary<string, PropStat>> store, string kind, object props) {
            IDictionary d = U(props) as IDictionary; if (d == null) return;
            Dictionary<string, PropStat> m; if (!store.TryGetValue(kind, out m)) { m = new Dictionary<string, PropStat>(); store[kind] = m; }
            foreach (DictionaryEntry de in d) {
                string k = Convert.ToString(de.Key); PropStat ps;
                if (!m.TryGetValue(k, out ps)) { ps = new PropStat(); m[k] = ps; }
                ps.Count++; ps.Types.Add(TypeOf(de.Value));
            }
        }
        void CheckProps(object props, string scope, string owner, bool isNode) {
            if (props == null) return;
            IDictionary d = props as IDictionary;
            if (d == null) { AddIssue("ERROR", "properties", scope + ": properties is not an object", owner); return; }
            foreach (DictionaryEntry de in d) {
                object v = U(de.Value); string k = Convert.ToString(de.Key);
                if (isNode && k == "objectid") AddIssue("ERROR", "properties", scope + ": reserved property 'objectid' in properties (root id maps to objectid - ingest fails)", owner);
                if (isNode && k == "lastseen") AddIssue("INFO", "properties", scope + ": 'lastseen' is overwritten by BloodHound at ingest", owner);
                if (isNode && k == "reconcile") AddIssue("INFO", "properties", scope + ": 'reconcile' is stripped at ingest", owner);
                if (!PropNameRx.IsMatch(k)) {
                    if (k.ToLowerInvariant() != k && PropNameRx.IsMatch(k.ToLowerInvariant())) AddIssue("WARN", "properties", scope + ": property names not lowercase (will be enforced later)", owner + " '" + k + "'");
                    else AddIssue("WARN", "properties", scope + ": property names with spaces/special characters", owner + " '" + k + "'");
                }
                if (v == null) { AddIssue("WARN", "properties", scope + ": property '" + k + "' is null (allowed: string/number/bool/array)", owner); continue; }
                if (v is IDictionary) { AddIssue("ERROR", "properties", scope + ": property '" + k + "' is a nested object", owner); continue; }
                if (v is string) continue;
                if (IsList(v)) {
                    bool obj = false; HashSet<string> types = new HashSet<string>();
                    foreach (object item0 in (IEnumerable)v) {
                        object item = U(item0);
                        if (item == null) types.Add("null");
                        else if (item is IDictionary || IsList(item)) obj = true;
                        else types.Add(TypeOf(item));
                    }
                    if (obj) AddIssue("ERROR", "properties", scope + ": property '" + k + "' is an array of objects/arrays", owner);
                    else if (types.Count > 1) { List<string> t = new List<string>(types); t.Sort(); AddIssue("ERROR", "properties", scope + ": property '" + k + "' is a mixed-type array (" + string.Join(",", t.ToArray()) + ")", owner); }
                }
            }
        }
        public static string GroupOf(string v) {
            if (string.IsNullOrEmpty(v)) return "(none)";
            if (SidRx.IsMatch(v)) { string[] p = v.Split('-'); return string.Join("-", p, 0, Math.Min(p.Length, 7)).ToUpperInvariant(); }
            int i = v.IndexOf('@'); if (i >= 0) return v.Substring(i + 1).ToUpperInvariant();
            if (GuidRx.IsMatch(v)) return "(guid)";
            i = v.IndexOf('.'); if (i >= 0 && i < v.Length - 1) return v.Substring(i + 1).ToUpperInvariant();
            return "(none)";
        }
        int AddNode(string key, string label, string kind, string allKinds, bool ext, string cls, string grp) {
            int i = Label.Count; idx[key] = i; Label.Add(label); Key.Add(key); KindOf.Add(kind); AllKinds.Add(allKinds);
            External.Add(ext); ExtClass.Add(cls); Group.Add(grp); return i;
        }
        int Resolve(object ep, string edgeKind, string propGroup, out string matchBy, out string err) {
            err = null;
            matchBy = S(G(ep, "match_by")); if (string.IsNullOrEmpty(matchBy)) matchBy = "id";
            object val = G(ep, "value"); object pm = G(ep, "property_matchers");
            string epKind = S(G(ep, "kind"));
            if (ep == null) { err = "start/end endpoint missing"; matchBy = "missing"; }
            else if (matchBy == "property") {
                bool any = false;
                if (IsList(pm)) foreach (object m in (IEnumerable)pm) {
                    any = true;
                    string op = S(G(m, "operator"));
                    if (op != "equals") err = "property_matchers operator '" + op + "' (only 'equals' supported)";
                    if (string.IsNullOrEmpty(S(G(m, "key")))) err = "property_matchers entry without key";
                    if (!Has(m, "value")) err = "property_matchers entry without value";
                    else { string t = TypeOf(G(m, "value")); if (t != "string" && t != "number" && t != "bool") err = "property_matchers value must be string/number/bool"; }
                }
                if (!any) err = "match_by=property without property_matchers";
                if (val != null) err = "match_by=property with value";
            } else if (matchBy == "id" || matchBy == "name") {
                if (val == null || S(val) == "") err = "match_by=" + matchBy + " without value";
                else if (!(val is string)) err = "endpoint value is not a string";
                if (pm != null) err = "match_by=" + matchBy + " with property_matchers";
            } else err = "unknown match_by '" + matchBy + "'";
            Inc(MatchBy, matchBy + (string.IsNullOrEmpty(epKind) ? "" : " +kind"));
            if (!string.IsNullOrEmpty(epKind)) Inc(EndKindFilter, epKind);
            string v = S(val) ?? "";
            string key, cls;
            if (matchBy == "id" || matchBy == "missing") {
                int hit; if (idx.TryGetValue(v, out hit) && hit < Internal) return hit;
                if (idxCI.ContainsKey(v)) AddIssue("WARN", "dangling", "id reference matches a node id only when ignoring case", edgeKind + " -> " + v);
                key = "ID::" + v;
                cls = SidRx.IsMatch(v) || SidWellKnownRx.IsMatch(v) ? "id: SID (existing AD node?)" : GuidRx.IsMatch(v) ? "id: GUID (existing AD/Azure node?)" : "id: unknown (dangling)";
            } else if (matchBy == "property") {
                List<string> parts = new List<string>();
                if (IsList(pm)) foreach (object m in (IEnumerable)pm) { parts.Add(S(G(m, "key")) + "=" + S(G(m, "value"))); string pv = S(G(m, "value")); if (string.IsNullOrEmpty(propGroup) && pv != null && (pv.Contains("@") || pv.Contains("."))) v = pv; }
                key = "PROP::" + string.Join("&", parts.ToArray()) + (string.IsNullOrEmpty(epKind) ? "" : "|" + epKind);
                cls = "property match";
            } else { key = "NAME::" + v.ToUpperInvariant() + (string.IsNullOrEmpty(epKind) ? "" : "|" + epKind); cls = "name match"; }
            int ix; if (idx.TryGetValue(key, out ix)) return ix;
            string grp = !string.IsNullOrEmpty(propGroup) ? propGroup.ToUpperInvariant() : GroupOf(v);
            string lbl = key.Substring(key.IndexOf("::") + 2);
            Inc(ExtClassCount, cls);
            return AddNode(key, lbl, string.IsNullOrEmpty(epKind) ? "(external)" : "ext:" + epKind, epKind ?? "", true, cls, grp);
        }

        public void Load(object nodes0, object edges0, string[] schemaNodeKinds, string[] schemaEdgeKinds, string[] postKinds,
                         string[] builtinNodes, string[] builtinEdges, string[] envKinds) {
            HashSet<string> snk = schemaNodeKinds == null ? null : new HashSet<string>(schemaNodeKinds);
            HashSet<string> sek = schemaEdgeKinds == null ? null : new HashSet<string>(schemaEdgeKinds);
            HashSet<string> ppk = new HashSet<string>(postKinds ?? new string[0]);
            HashSet<string> bnk = new HashSet<string>(builtinNodes ?? new string[0]);
            HashSet<string> bek = new HashSet<string>(builtinEdges ?? new string[0]);
            HashSet<string> envk = new HashSet<string>(envKinds ?? new string[0]);
            object nodesU = U(nodes0), edgesU = U(edges0);
            if (nodesU != null && !IsList(nodesU)) AddIssue("ERROR", "structure", "graph.nodes is not an array", "");
            if (edgesU != null && !IsList(edgesU)) AddIssue("ERROR", "structure", "graph.edges is not an array", "");
            int ni = 0;
            if (IsList(nodesU)) foreach (object n0 in (IEnumerable)nodesU) {
                object n = U(n0); ni++;
                if (!(n is IDictionary)) { AddIssue("ERROR", "node", "node is not an object", "node #" + ni); continue; }
                object idRaw = G(n, "id");
                string id = S(idRaw);
                if (string.IsNullOrEmpty(id)) { AddIssue("ERROR", "node", "node without id", "node #" + ni); continue; }
                if (!(idRaw is string)) AddIssue("WARN", "node", "id is not a string (schema requires string)", id);
                if (id.Contains(":")) AddIssue("WARN", "node", "id contains ':' (can break search/pathfinding)", id);
                if (id.Trim() != id) AddIssue("WARN", "node", "id has leading/trailing whitespace", "'" + id + "'");
                List<string> kinds = new List<string>();
                object kl = G(n, "kinds");
                if (kl == null) AddIssue("ERROR", "node", "node without 'kinds' array", id);
                else if (!IsList(kl)) AddIssue("ERROR", "node", "'kinds' is not an array", id);
                else foreach (object k0 in (IEnumerable)kl) { object k = U(k0); if (!(k is string)) AddIssue("ERROR", "node", "non-string value in kinds", id); else kinds.Add((string)k); }
                if (kinds.Count == 0) AddIssue("WARN", "node", "node has no kinds (no type or icon in BloodHound)", id);
                if (kinds.Count > 3) AddIssue("ERROR", "node", "more than 3 kinds (schema maxItems 3)", id + " (" + kinds.Count + ")");
                foreach (string k in kinds) {
                    if (k.StartsWith("tag_", StringComparison.OrdinalIgnoreCase)) AddIssue("ERROR", "node kind", "kind '" + k + "' uses reserved tag_ prefix - entire upload rejected", id);
                    if (!KindRx.IsMatch(k)) AddIssue("WARN", "node kind", "kind '" + k + "' contains characters outside [A-Za-z0-9_]", id);
                    if (bnk.Contains(k)) AddIssue("WARN", "node kind", "kind '" + k + "' overlaps a built-in node kind", id);
                    if (snk != null && !snk.Contains(k)) Inc(UnknownNodeKinds, k);
                    if (envk.Contains(k)) EnvNodes++;
                }
                string primary = kinds.Count > 0 ? kinds[0] : "(no kind)";
                if (idx.ContainsKey(id)) { DupIds++; AddIssue("WARN", "node", "duplicate node id (later copies merge/overwrite)", id); continue; }
                if (idxCI.ContainsKey(id)) AddIssue("WARN", "node", "node ids that differ only by case", id);
                object props = G(n, "properties");
                CheckProps(props, "node " + primary, id, true);
                Profile(NodeProps, primary, props);
                string nm = S(G(props, "name"));
                if (string.IsNullOrEmpty(nm)) { Inc(NamelessByKind, primary); nm = id; }
                else {
                    HashSet<string> hs; if (!namesByKind.TryGetValue(primary, out hs)) { hs = new HashSet<string>(StringComparer.OrdinalIgnoreCase); namesByKind[primary] = hs; }
                    if (!hs.Add(nm)) Inc(DupNameByKind, primary);
                }
                string env = S(G(props, "environmentid"));
                if (!string.IsNullOrEmpty(env)) { Inc(EnvIdByKind, primary); EnvIdValues.Add(env); }
                bool isEnv = false; foreach (string k in kinds) if (envk.Contains(k)) isEnv = true;
                if (isEnv) { object c = G(props, "collected"); if (c is bool && (bool)c) EnvNodesCollected++; }
                idxCI[id] = Label.Count;
                AddNode(id, nm, primary, string.Join(",", kinds.ToArray()), false, null, null);
                Inc(NodeKindCount, primary);
                Inc(KindCombo, kinds.Count == 0 ? "(none)" : string.Join(" + ", kinds.ToArray()));
            }
            Internal = Label.Count;
            HashSet<string> edgeKeys = new HashSet<string>(StringComparer.Ordinal);
            int ei = 0;
            if (IsList(edgesU)) foreach (object e0 in (IEnumerable)edgesU) {
                object e = U(e0); ei++;
                string where = "edge #" + ei;
                if (!(e is IDictionary)) { AddIssue("ERROR", "edge", "edge is not an object", where); continue; }
                string k = S(G(e, "kind"));
                if (string.IsNullOrEmpty(k)) { AddIssue("ERROR", "edge kind", "edge without kind", where); k = "(no kind)"; }
                else {
                    if (!KindRx.IsMatch(k)) AddIssue("ERROR", "edge kind", "kind '" + k + "' does not match ^[A-Za-z0-9_]+$ - upload rejected", where);
                    if (k.StartsWith("tag_", StringComparison.OrdinalIgnoreCase)) AddIssue("ERROR", "edge kind", "kind '" + k + "' uses reserved tag_ prefix - entire upload rejected", where);
                    if (ppk.Contains(k)) AddIssue("WARN", "edge kind", "post-processed kind '" + k + "' - deleted and regenerated by BloodHound", where);
                    else if (bek.Contains(k)) AddIssue("INFO", "edge kind", "built-in kind '" + k + "' used - fine for deliberate hybrid edges, otherwise use a prefixed custom kind", where);
                    if (sek != null && !sek.Contains(k)) Inc(UnknownEdgeKinds, k);
                }
                object props = G(e, "properties");
                CheckProps(props, "edge " + k, where, false);
                Profile(EdgeProps, k, props);
                string pGroup = S(G(props, "domain"));
                string smb, tmb, serr, terr;
                int s = Resolve(G(e, "start"), k, pGroup, out smb, out serr);
                int t = Resolve(G(e, "end"), k, pGroup, out tmb, out terr);
                if (serr != null) AddIssue("ERROR", "endpoint", "start: " + serr, where + " " + k);
                if (terr != null) AddIssue("ERROR", "endpoint", "end: " + terr, where + " " + k);
                if (smb == "name" || tmb == "name") AddIssue("WARN", "endpoint", "match_by 'name' is deprecated - use match_by 'property' on name", where + " " + k);
                if (External[s] && ExtClass[s].EndsWith("(dangling)")) AddIssue("WARN", "dangling", "start id not defined in this file (only resolves if the node already exists in BloodHound)", k + ": " + Label[s]);
                if (External[t] && ExtClass[t].EndsWith("(dangling)")) AddIssue("WARN", "dangling", "end id not defined in this file (only resolves if the node already exists in BloodHound)", k + ": " + Label[t]);
                if (s == t) { SelfLoops++; AddIssue("INFO", "edge", "self-loop (start = end)", k + ": " + Label[s]); }
                if (External[s] || External[t]) {
                    Inc(EdgeKindHybrid, k);
                    int ext = External[t] ? t : s;
                    Inc(HybridByKindGroup, k + "|" + ExtClass[ext] + "|" + Group[ext]);
                }
                if (!edgeKeys.Add(k + "|" + s + "|" + t)) { DupEdges++; AddIssue("INFO", "edge", "duplicate edge (same kind/start/end)", k + ": " + Label[s] + " -> " + Label[t]); }
                Inc(EdgeKindCount, k);
                Inc(EdgePattern, KindOf[s] + "|" + k + "|" + KindOf[t]);
                int kid; if (!kindIdx.TryGetValue(k, out kid)) { kid = Kinds.Count; kindIdx[k] = kid; Kinds.Add(k); }
                From.Add(s); To.Add(t); KindId.Add(kid); Props.Add(props);
                Sigs.Add(k + "|" + Key[s] + "|" + Key[t]);
            }
            // property type consistency across nodes of the same kind
            foreach (var kv in NodeProps) foreach (var pv in kv.Value) {
                HashSet<string> ts = new HashSet<string>(pv.Value.Types); ts.Remove("null");
                if (ts.Count > 1) { List<string> l = new List<string>(ts); l.Sort(); AddIssue("WARN", "properties", "node " + kv.Key + ": property '" + pv.Key + "' has different types across nodes (" + string.Join(",", l.ToArray()) + ")", ""); }
            }
            foreach (var kv in EdgeProps) foreach (var pv in kv.Value) {
                HashSet<string> ts = new HashSet<string>(pv.Value.Types); ts.Remove("null");
                if (ts.Count > 1) { List<string> l = new List<string>(ts); l.Sort(); AddIssue("WARN", "properties", "edge " + kv.Key + ": property '" + pv.Key + "' has different types across edges (" + string.Join(",", l.ToArray()) + ")", ""); }
            }
        }
        public bool IdExistsCI(string id) { return idxCI.ContainsKey(id); }
        public bool[] NewMask(HashSet<string> baseline) {
            bool[] r = new bool[From.Count]; if (baseline == null) return r;
            for (int i = 0; i < r.Length; i++) r[i] = !baseline.Contains(Kinds[KindId[i]] + "|" + Key[From[i]] + "|" + Key[To[i]]);
            return r;
        }
        public string PropSummary(int i) {
            IDictionary d = U(Props[i]) as IDictionary; if (d == null) return "";
            List<string> parts = new List<string>();
            foreach (DictionaryEntry de in d) { string v = S(de.Value); if (v != null && v.Length > 40) v = v.Substring(0, 40) + "..."; parts.Add(de.Key + "=" + v); if (parts.Count >= 4) break; }
            return string.Join("; ", parts.ToArray());
        }
    }

    public class RevResult {
        public long[] Bwd; public long[] PairsByGroupP, PairsByGroupE; public long TotalP, TotalE;
        public long[] TargetOriginsP, TargetOriginsE;
    }
    public class FanOut { public int[] MaxOut, MaxNode, DistinctStarts, DistinctEnds; }
    public class Structure { public int[] OutDeg, InDeg; public int Components, Largest, Isolated; }

    public static class Engine {
        static void Csr(int n, int[] a, int[] b, bool[] on, out int[] off, out int[] adj) {
            off = new int[n + 1];
            for (int i = 0; i < a.Length; i++) if (on[i]) off[a[i] + 1]++;
            for (int i = 0; i < n; i++) off[i + 1] += off[i];
            adj = new int[off[n]]; int[] pos = (int[])off.Clone();
            for (int i = 0; i < a.Length; i++) if (on[i]) adj[pos[a[i]]++] = b[i];
        }
        // Reverse BFS from each target: how many origins (type 1 = internal principal, 2 = external entry) reach it,
        // and for every node how many targets it can reach (Bwd).
        public static RevResult Reverse(int n, int[] from, int[] to, bool[] on, int[] targetGroup, int groupCount, int[] originType) {
            int[] roff, radj; Csr(n, to, from, on, out roff, out radj);
            RevResult r = new RevResult();
            r.Bwd = new long[n]; r.PairsByGroupP = new long[groupCount]; r.PairsByGroupE = new long[groupCount];
            r.TargetOriginsP = new long[n]; r.TargetOriginsE = new long[n];
            int[] stamp = new int[n]; int[] q = new int[n]; int st = 0;
            for (int x = 0; x < n; x++) {
                if (targetGroup[x] < 0) continue;
                st++; int h = 0, t = 0; q[t++] = x; stamp[x] = st; long cp = 0, ce = 0;
                while (h < t) {
                    int u = q[h++];
                    if (u != x) { r.Bwd[u]++; if (originType[u] == 1) cp++; else if (originType[u] == 2) ce++; }
                    for (int k = roff[u]; k < roff[u + 1]; k++) { int v = radj[k]; if (stamp[v] != st) { stamp[v] = st; q[t++] = v; } }
                }
                r.TargetOriginsP[x] = cp; r.TargetOriginsE[x] = ce;
                r.PairsByGroupP[targetGroup[x]] += cp; r.PairsByGroupE[targetGroup[x]] += ce; r.TotalP += cp; r.TotalE += ce;
            }
            return r;
        }
        // Forward BFS from each origin: Fwd[v] = number of origins that reach v. Used for chokepoints.
        public static long[] Forward(int n, int[] from, int[] to, bool[] on, int[] origins) {
            int[] off, adj; Csr(n, from, to, on, out off, out adj);
            long[] fwd = new long[n]; int[] stamp = new int[n]; int[] q = new int[n];
            for (int si = 0; si < origins.Length; si++) {
                int s = origins[si], st = si + 1, h = 0, t = 0; q[t++] = s; stamp[s] = st;
                while (h < t) { int u = q[h++]; if (u != s) fwd[u]++; for (int k = off[u]; k < off[u + 1]; k++) { int v = adj[k]; if (stamp[v] != st) { stamp[v] = st; q[t++] = v; } } }
            }
            return fwd;
        }
        public static FanOut Fan(int n, int[] from, int[] to, int[] kindId, int kindCount) {
            FanOut f = new FanOut { MaxOut = new int[kindCount], MaxNode = new int[kindCount], DistinctStarts = new int[kindCount], DistinctEnds = new int[kindCount] };
            Dictionary<long, int> outc = new Dictionary<long, int>(); HashSet<long> ends = new HashSet<long>();
            for (int i = 0; i < from.Length; i++) {
                long key = (long)kindId[i] * n + from[i]; int c; outc.TryGetValue(key, out c); outc[key] = c + 1;
                ends.Add((long)kindId[i] * n + to[i]);
            }
            foreach (KeyValuePair<long, int> kv in outc) {
                int k = (int)(kv.Key / n), node = (int)(kv.Key % n);
                f.DistinctStarts[k]++; if (kv.Value > f.MaxOut[k]) { f.MaxOut[k] = kv.Value; f.MaxNode[k] = node; }
            }
            foreach (long e in ends) f.DistinctEnds[(int)(e / n)]++;
            return f;
        }
        static int Find(int[] p, int x) { while (p[x] != x) { p[x] = p[p[x]]; x = p[x]; } return x; }
        public static Structure Struct(int n, int internalCount, int[] from, int[] to) {
            Structure s = new Structure { OutDeg = new int[n], InDeg = new int[n] };
            int[] p = new int[n]; for (int i = 0; i < n; i++) p[i] = i;
            for (int i = 0; i < from.Length; i++) {
                s.OutDeg[from[i]]++; s.InDeg[to[i]]++;
                int a = Find(p, from[i]), b = Find(p, to[i]); if (a != b) p[a] = b;
            }
            int[] size = new int[n];
            for (int i = 0; i < n; i++) size[Find(p, i)]++;
            for (int i = 0; i < n; i++) if (size[i] > 0) { s.Components++; if (size[i] > s.Largest) s.Largest = size[i]; }
            for (int i = 0; i < internalCount; i++) if (s.OutDeg[i] == 0 && s.InDeg[i] == 0) s.Isolated++;
            return s;
        }
        public static bool[] Mask(int[] kindId, bool[] trav, int excludeKind, bool[] onlyNew) {
            bool[] on = new bool[kindId.Length];
            for (int i = 0; i < on.Length; i++) {
                bool drop = excludeKind != -1 && (excludeKind == -2 || kindId[i] == excludeKind) && (onlyNew == null || onlyNew[i]);
                on[i] = trav[i] && !drop;
            }
            return on;
        }
        public static int[] TopK(long[] score, int k) {
            List<int> ids = new List<int>();
            for (int i = 0; i < score.Length; i++) if (score[i] > 0) ids.Add(i);
            ids.Sort(delegate (int a, int b) { return score[b].CompareTo(score[a]); });
            if (ids.Count > k) ids.RemoveRange(k, ids.Count - k);
            return ids.ToArray();
        }
        public static long[] Mul(long[] a, long[] b, int limit) { long[] r = new long[a.Length]; for (int i = 0; i < limit; i++) r[i] = a[i] * b[i]; return r; }
        public static long[] EdgeScores(int[] from, int[] to, bool[] on, long[] fwdPlusSelf, long[] bwd) {
            long[] r = new long[from.Length]; for (int i = 0; i < r.Length; i++) if (on[i]) r[i] = fwdPlusSelf[from[i]] * (bwd[to[i]] + 1); return r;
        }
    }
}
'@
}
#endregion

#region ---------- Helpers ----------
$script:Report = New-Object 'System.Collections.Generic.List[string]'
function Write-R { param([string]$Text = '', [string]$Color = 'Gray') Write-Host $Text -ForegroundColor $Color; $script:Report.Add($Text) }
function Write-Section([string]$Title) { Write-R ''; Write-R ('=' * 100) 'DarkCyan'; Write-R " $Title" 'Cyan'; Write-R ('=' * 100) 'DarkCyan' }
function Write-Table($Data) {
    if (-not $Data) { Write-R '  (none)' 'DarkGray'; return }
    $s = ($Data | Format-Table -AutoSize | Out-String -Width 400).TrimEnd()
    foreach ($line in ($s -split "`r?`n")) { Write-R $line }
}
function Get-JV($d, [string]$k) {
    if ($null -eq $d -or $d -isnot [System.Collections.IDictionary]) { return $null }
    foreach ($key in $d.Keys) { if ($key -ceq $k) { return , $d[$key] } }   # unary comma: keep 1-item arrays as arrays
    return $null
}
function Get-Keys($d) { if ($d -is [System.Collections.IDictionary]) { @($d.Keys | ForEach-Object { [string]$_ }) } else { @() } }

function Import-OGJson([string]$File) {
    $full = (Resolve-Path -LiteralPath $File).Path
    $len = (Get-Item -LiteralPath $full).Length
    Write-Host ("Loading {0} ({1:N1} MB)..." -f $full, ($len / 1MB)) -ForegroundColor Yellow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8)
    $bom = $false
    if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1); $bom = $true }
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) { $obj = $raw | ConvertFrom-Json -AsHashtable -Depth 200 }
        else {
            Add-Type -AssemblyName System.Web.Extensions
            $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $ser.MaxJsonLength = [int]::MaxValue; $ser.RecursionLimit = 200
            $obj = $ser.DeserializeObject($raw)
        }
    } catch { throw "Not valid JSON: $($_.Exception.Message)" }
    $raw = $null; [GC]::Collect()
    Write-Host ("  parsed in {0:N1}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    [pscustomobject]@{ Path = $full; SizeMB = [math]::Round($len / 1MB, 1); Root = $obj; HadBom = $bom }
}
#endregion

#region ---------- Analysis ----------
function Invoke-OGAnalysis([string]$File, [switch]$NoPaths, $BaselineSigs, $TierZero, $Schema) {
    $loaded = Import-OGJson $File
    $root = $loaded.Root
    $pre = New-Object 'System.Collections.Generic.List[object]'
    function Add-Pre($sev, $check, $msg, $ex) { $pre.Add([pscustomobject]@{ Severity = $sev; Check = $check; Count = 1; Detail = $msg; Example = $ex }) }

    if ($loaded.HadBom) { Add-Pre 'INFO' 'file' 'file starts with a UTF-8 BOM' '' }
    if ($root -isnot [System.Collections.IDictionary]) { throw "$File : top level is not a JSON object." }
    $graph = Get-JV $root 'graph'; $meta = Get-JV $root 'metadata'
    if ($null -eq $graph) { throw "$File has no top-level 'graph' object - not an OpenGraph payload." }
    foreach ($k in (Get-Keys $root)) { if ($k -notin 'graph', 'metadata') { Add-Pre 'WARN' 'structure' "unexpected top-level key '$k'" '' } }
    if ($null -ne (Get-JV $graph 'metadata')) { Add-Pre 'ERROR' 'metadata' 'metadata is nested under graph - it must be top-level (source_kind will not apply)' '' }
    $sourceKind = $null
    if ($null -ne $meta) {
        if ($meta -isnot [System.Collections.IDictionary]) { Add-Pre 'ERROR' 'metadata' 'metadata is not an object' '' }
        else {
            foreach ($k in (Get-Keys $meta)) { if ($k -cne 'source_kind') { Add-Pre 'ERROR' 'metadata' "metadata key '$k' not allowed (only source_kind) - validation error" '' } }
            $sk = Get-JV $meta 'source_kind'
            if ($null -ne $sk -and $sk -isnot [string]) { Add-Pre 'ERROR' 'metadata' 'metadata.source_kind must be a string or null' '' } else { $sourceKind = $sk }
        }
    }
    if (-not $sourceKind) { Add-Pre 'INFO' 'metadata' 'no metadata.source_kind - data is "sourceless" unless the kind is already registered (needed for findings in structured graphs)' '' }
    $nodes = Get-JV $graph 'nodes'; $edges = Get-JV $graph 'edges'
    if ($null -eq $nodes) { Add-Pre 'ERROR' 'structure' 'graph.nodes missing' '' }
    if ($null -eq $edges) { Add-Pre 'ERROR' 'structure' 'graph.edges missing' '' }
    foreach ($k in (Get-Keys $graph)) { if ($k -notin 'nodes', 'edges', 'metadata') { Add-Pre 'INFO' 'structure' "unexpected key graph.$k (ignored)" '' } }

    Write-Host '  indexing and validating...' -ForegroundColor DarkGray
    $ing = New-Object OGCheckV1.Ingest
    $snk = $null; $sek = $null; $envKinds = @()
    if ($Schema) { $snk = [string[]]$Schema.NodeKinds; $sek = [string[]]@($Schema.Traversable.Keys); $envKinds = [string[]]$Schema.EnvKinds }
    $ing.Load($nodes, $edges, $snk, $sek, [string[]]$script:PostProcessedKinds, [string[]]$script:BuiltinNodeKinds, [string[]]$script:BuiltinEdgeKinds, [string[]]$envKinds)
    $nodes = $null; $edges = $null; $graph = $null; $root = $null; $loaded.Root = $null; [GC]::Collect()

    $issues = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $pre) { $issues.Add($p) }
    foreach ($i in $ing.Issues.Values) { $issues.Add([pscustomobject]@{ Severity = $i.Sev; Check = $i.Check; Count = $i.Count; Detail = $i.Msg; Example = $i.Example }) }

    $n = $ing.Label.Count; $internal = $ing.Internal
    $fromA = $ing.From.ToArray(); $toA = $ing.To.ToArray(); $kindIdA = $ing.KindId.ToArray(); $m = $fromA.Length
    $kindNames = $ing.Kinds.ToArray()

    # ---- namespace / schema checks ----
    $allKinds = @($ing.NodeKindCount.Keys) + @($ing.EdgeKindCount.Keys)
    $prefixes = @{}
    foreach ($k in $allKinds) { $pfx = if ($k -match '^([A-Za-z0-9]+)_') { $Matches[1] } else { '(no prefix)' }; $prefixes[$pfx] = 1 + [int]$prefixes[$pfx] }
    $unprefixed = @($ing.EdgeKindCount.Keys | Where-Object { $_ -notmatch '_' -and $script:BuiltinEdgeKinds -notcontains $_ -and $script:PostProcessedKinds -notcontains $_ }) +
                  @($ing.NodeKindCount.Keys | Where-Object { $_ -notmatch '_' -and $script:BuiltinNodeKinds -notcontains $_ -and $_ -ne '(no kind)' })
    if ($unprefixed) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'naming'; Count = $unprefixed.Count; Detail = 'custom kinds without a Namespace_ prefix (risk of colliding with built-in or other extensions'' kinds)'; Example = ($unprefixed | Select-Object -First 5) -join ', ' }) }
    if ($Schema) {
        foreach ($kv in $ing.UnknownNodeKinds.GetEnumerator()) { if ($kv.Key -ne $sourceKind) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'schema'; Count = $kv.Value; Detail = "node kind '$($kv.Key)' not defined in schema"; Example = '' }) } }
        foreach ($kv in $ing.UnknownEdgeKinds.GetEnumerator()) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'schema'; Count = $kv.Value; Detail = "edge kind '$($kv.Key)' not defined in schema - not part of the structured graph"; Example = '' }) }
        if ($Schema.Namespace) {
            $bad = @($allKinds | Where-Object { $_ -notlike "$($Schema.Namespace)_*" -and $_ -ne $sourceKind -and $Schema.EnvSourceKinds -notcontains $_ -and $script:BuiltinEdgeKinds -notcontains $_ -and $script:BuiltinNodeKinds -notcontains $_ })
            if ($bad) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'schema'; Count = $bad.Count; Detail = "kinds not prefixed with schema namespace '$($Schema.Namespace)_'"; Example = ($bad | Select-Object -First 5) -join ', ' }) }
        }
        if ($Schema.EnvKinds.Count -gt 0) {
            if ($ing.EnvNodes -eq 0) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'findings'; Count = 1; Detail = "no environment node ($($Schema.EnvKinds -join ', ')) in payload - findings/metrics need one"; Example = '' }) }
            elseif ($ing.EnvNodesCollected -lt $ing.EnvNodes) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'findings'; Count = $ing.EnvNodes - $ing.EnvNodesCollected; Detail = 'environment node(s) without collected: true - required for findings'; Example = '' }) }
        }
        if ($Schema.SourceKinds.Count -gt 0 -and -not $sourceKind) { $issues.Add([pscustomobject]@{ Severity = 'INFO'; Check = 'findings'; Count = 1; Detail = "no metadata.source_kind; schema registers $($Schema.SourceKinds -join ', ') - fine once registered"; Example = '' }) }
    }
    # environmentid checks (schema or not)
    $envTotal = 0; foreach ($v in $ing.EnvIdByKind.Values) { $envTotal += $v }
    $envMissingRef = 0; $envMissEx = $null
    foreach ($v in ($ing.EnvIdValues | Select-Object -Unique)) { if (-not $ing.IdExistsCI($v)) { $envMissingRef++; if (-not $envMissEx) { $envMissEx = $v } } }
    if ($envMissingRef) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'findings'; Count = $envMissingRef; Detail = 'environmentid value(s) that do not match any node id in this file'; Example = $envMissEx }) }
    if ($Schema -and $Schema.PrincipalKinds.Count -gt 0) {
        foreach ($pk in $Schema.PrincipalKinds) {
            $c = [int]$ing.NodeKindCount[$pk]; $e = [int]$ing.EnvIdByKind[$pk]
            if ($c -gt 0 -and $e -lt $c) { $issues.Add([pscustomobject]@{ Severity = 'WARN'; Check = 'findings'; Count = $c - $e; Detail = "principal kind '$pk' nodes without environmentid - excluded from findings/metrics"; Example = '' }) }
        }
    }

    # ---- traversability ----
    $kindTrav = New-Object bool[] $kindNames.Length
    for ($q = 0; $q -lt $kindNames.Length; $q++) {
        $k = $kindNames[$q]
        if ($Schema) { $kindTrav[$q] = [bool]$Schema.Traversable[$k] }
        else { $kindTrav[$q] = ($NonTraversable -notcontains $k) -and ($script:PostProcessedKinds -notcontains $k) }
    }
    $trav = New-Object bool[] $m
    for ($i = 0; $i -lt $m; $i++) { $trav[$i] = $kindTrav[$kindIdA[$i]] }

    # ---- structure ----
    $st = [OGCheckV1.Engine]::Struct($n, $internal, $fromA, $toA)
    $fan = [OGCheckV1.Engine]::Fan($n, $fromA, $toA, $kindIdA, [math]::Max(1, $kindNames.Length))
    $kindRows = @(for ($q = 0; $q -lt $kindNames.Length; $q++) {
        $k = $kindNames[$q]
        [pscustomobject]@{
            EdgeKind = $k; Count = $ing.EdgeKindCount[$k]
            Traversable = $(if ($Schema) { if ($Schema.Traversable.ContainsKey($k)) { $Schema.Traversable[$k] } else { 'not in schema' } } else { "$($kindTrav[$q]) (assumed)" })
            Hybrid = $(if ($ing.EdgeKindHybrid.ContainsKey($k)) { $ing.EdgeKindHybrid[$k] } else { 0 })
            DistinctStarts = $fan.DistinctStarts[$q]; DistinctEnds = $fan.DistinctEnds[$q]
            MaxFanOut = $fan.MaxOut[$q]; MaxFanOutNode = $ing.Label[$fan.MaxNode[$q]]
        }
    }) | Sort-Object Count -Descending
    $patternRows = @(foreach ($kv in $ing.EdgePattern.GetEnumerator()) { $p = $kv.Key -split '\|', 3; [pscustomobject]@{ StartKind = $p[0]; EdgeKind = $p[1]; EndKind = $p[2]; Count = $kv.Value } }) | Sort-Object Count -Descending
    $nodeKindRows = @(foreach ($kv in $ing.NodeKindCount.GetEnumerator()) {
        $k = $kv.Key; $np = $null; $propCount = 0; $partial = 0; $mixed = 0
        if ($ing.NodeProps.TryGetValue($k, [ref]$np)) { foreach ($pv in $np.GetEnumerator()) { $propCount++; if ($pv.Value.Count -lt $kv.Value) { $partial++ }; $ts = @($pv.Value.Types | Where-Object { $_ -ne 'null' }); if ($ts.Count -gt 1) { $mixed++ } } }
        $iso = 0
        [pscustomobject]@{ NodeKind = $k; Count = $kv.Value; Properties = $propCount; PartialProps = $partial; MixedTypeProps = $mixed
            NoName = [int]$ing.NamelessByKind[$k]; DupNames = [int]$ing.DupNameByKind[$k]; WithEnvId = [int]$ing.EnvIdByKind[$k] }
    }) | Sort-Object Count -Descending
    $propRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($kv in $ing.NodeProps.GetEnumerator()) { $tot = [int]$ing.NodeKindCount[$kv.Key]; foreach ($pv in $kv.Value.GetEnumerator()) { $propRows.Add([pscustomobject]@{ Scope = 'node'; Kind = $kv.Key; Property = $pv.Key; Present = $pv.Value.Count; CoveragePct = $(if ($tot) { [math]::Round(100 * $pv.Value.Count / $tot, 1) } else { 0 }); Types = (@($pv.Value.Types) | Sort-Object) -join ',' }) } }
    foreach ($kv in $ing.EdgeProps.GetEnumerator()) { $tot = [int]$ing.EdgeKindCount[$kv.Key]; foreach ($pv in $kv.Value.GetEnumerator()) { $propRows.Add([pscustomobject]@{ Scope = 'edge'; Kind = $kv.Key; Property = $pv.Key; Present = $pv.Value.Count; CoveragePct = $(if ($tot) { [math]::Round(100 * $pv.Value.Count / $tot, 1) } else { 0 }); Types = (@($pv.Value.Types) | Sort-Object) -join ',' }) } }
    $hybridRows = @(foreach ($kv in $ing.HybridByKindGroup.GetEnumerator()) { $p = $kv.Key -split '\|', 3; [pscustomobject]@{ EdgeKind = $p[0]; MatchType = $p[1]; TargetGroup = $p[2]; Count = $kv.Value } }) | Sort-Object Count -Descending
    $degree = New-Object long[] $n; for ($x = 0; $x -lt $internal; $x++) { $degree[$x] = $st.OutDeg[$x] + $st.InDeg[$x] }
    $topDegree = @(foreach ($x in [OGCheckV1.Engine]::TopK($degree, $Top)) { [pscustomobject]@{ Node = $ing.Label[$x]; Kind = $ing.KindOf[$x]; Out = $st.OutDeg[$x]; In = $st.InDeg[$x]; Id = $ing.Key[$x] } })

    # ---- reachability into external targets ----
    $paths = $null
    if (-not $NoPaths) {
        Write-Host '  path analysis...' -ForegroundColor DarkGray
        $usable = New-Object bool[] $n
        for ($x = $internal; $x -lt $n; $x++) { $usable[$x] = -not $ing.ExtClass[$x].EndsWith('(dangling)') }
        $outT = New-Object bool[] $n; $inT = New-Object bool[] $n
        for ($i = 0; $i -lt $m; $i++) { if ($trav[$i]) { $outT[$fromA[$i]] = $true; $inT[$toA[$i]] = $true } }
        $groups = New-Object 'System.Collections.Generic.List[string]'; $gIdx = @{}
        $targetGroup = New-Object int[] $n; $originType = New-Object int[] $n
        $principalSet = if ($Schema -and $Schema.PrincipalKinds.Count -gt 0) { $Schema.PrincipalKinds } else { $null }
        for ($x = 0; $x -lt $n; $x++) {
            $targetGroup[$x] = -1
            if ($x -ge $internal) {
                if (-not $usable[$x]) { continue }
                if ($inT[$x] -and ($null -eq $TierZero -or $TierZero.Contains(($ing.Label[$x] -replace '\|.*$', '')))) {
                    $g = $ing.Group[$x]; if (-not $gIdx.ContainsKey($g)) { $gIdx[$g] = $groups.Count; $groups.Add($g) }
                    $targetGroup[$x] = $gIdx[$g]
                }
                if ($outT[$x]) { $originType[$x] = 2 }
            } elseif ($outT[$x]) {
                if ($null -eq $principalSet -or $principalSet -contains $ing.KindOf[$x]) { $originType[$x] = 1 }
            }
        }
        $gc = [math]::Max(1, $groups.Count)
        $base = [OGCheckV1.Engine]::Reverse($n, $fromA, $toA, $trav, $targetGroup, $gc, $originType)

        $groupRows = @(for ($g = 0; $g -lt $groups.Count; $g++) {
            $tc = 0; for ($x = $internal; $x -lt $n; $x++) { if ($targetGroup[$x] -eq $g) { $tc++ } }
            [pscustomobject]@{ TargetGroup = $groups[$g]; Targets = $tc; PrincipalToTargetPairs = $base.PairsByGroupP[$g]; EntryToTargetPairs = $base.PairsByGroupE[$g] }
        }) | Sort-Object PrincipalToTargetPairs -Descending

        $originRows = @(for ($x = 0; $x -lt $n; $x++) {
            if ($originType[$x] -gt 0 -and $base.Bwd[$x] -gt 0) {
                [pscustomobject]@{ Origin = $ing.Label[$x]; Kind = $ing.KindOf[$x]; Type = $(if ($originType[$x] -eq 1) { 'principal' } else { 'external entry' }); TargetsReachable = $base.Bwd[$x]; InboundEdges = $st.InDeg[$x]; Id = $ing.Key[$x] }
            }
        }) | Sort-Object TargetsReachable -Descending
        $targetRows = @(for ($x = $internal; $x -lt $n; $x++) {
            if ($targetGroup[$x] -ge 0) { [pscustomobject]@{ Target = $ing.Label[$x]; Group = $ing.Group[$x]; MatchType = $ing.ExtClass[$x]; PrincipalsReaching = $base.TargetOriginsP[$x]; EntriesReaching = $base.TargetOriginsE[$x] } }
        }) | Sort-Object PrincipalsReaching -Descending

        # what-if per traversable kind
        $whatIf = @(for ($q = 0; $q -lt $kindNames.Length; $q++) {
            if (-not $kindTrav[$q]) { continue }
            Write-Host "  what-if: removing $($kindNames[$q])" -ForegroundColor DarkGray
            $r = [OGCheckV1.Engine]::Reverse($n, $fromA, $toA, ([OGCheckV1.Engine]::Mask($kindIdA, $trav, $q, $null)), $targetGroup, $gc, $originType)
            $lost = ($base.TotalP + $base.TotalE) - ($r.TotalP + $r.TotalE)
            $row = [ordered]@{ EdgeKind = $kindNames[$q]; EdgeCount = $ing.EdgeKindCount[$kindNames[$q]]; PairsLost = $lost
                PctOfAll = $(if ($base.TotalP + $base.TotalE) { [math]::Round(100 * $lost / ($base.TotalP + $base.TotalE), 1) } else { 0 }) }
            for ($g = 0; $g -lt [math]::Min($groups.Count, 6); $g++) { $row["Lost:$($groups[$g])"] = ($base.PairsByGroupP[$g] + $base.PairsByGroupE[$g]) - ($r.PairsByGroupP[$g] + $r.PairsByGroupE[$g]) }
            [pscustomobject]$row
        }) | Sort-Object PairsLost -Descending

        # attribution of new edges vs baseline
        $newRows = @(); $withoutNew = $null
        if ($null -ne $BaselineSigs) {
            $isNew = $ing.NewMask($BaselineSigs)
            $r = [OGCheckV1.Engine]::Reverse($n, $fromA, $toA, ([OGCheckV1.Engine]::Mask($kindIdA, $trav, -2, $isNew)), $targetGroup, $gc, $originType)
            $withoutNew = $r.TotalP + $r.TotalE
            $newPer = New-Object int[] $kindNames.Length
            for ($i = 0; $i -lt $m; $i++) { if ($isNew[$i] -and $trav[$i]) { $newPer[$kindIdA[$i]]++ } }
            $newRows = @(for ($q = 0; $q -lt $kindNames.Length; $q++) {
                if ($newPer[$q] -eq 0) { continue }
                $r = [OGCheckV1.Engine]::Reverse($n, $fromA, $toA, ([OGCheckV1.Engine]::Mask($kindIdA, $trav, $q, $isNew)), $targetGroup, $gc, $originType)
                [pscustomobject]@{ EdgeKind = $kindNames[$q]; NewEdges = $newPer[$q]; PairsLost = ($base.TotalP + $base.TotalE) - ($r.TotalP + $r.TotalE) }
            }) | Sort-Object PairsLost -Descending
        }

        # chokepoints (forward pass) - skipped if too expensive
        $origins = @(for ($x = 0; $x -lt $n; $x++) { if ($originType[$x] -gt 0 -and $base.Bwd[$x] -gt 0) { $x } })
        $topNodes = @(); $topEdges = @(); $chokeNote = $null
        if ([double]$origins.Count * $m -gt 3e9) {
            $origins = @($origins | Sort-Object { -$base.Bwd[$_] } | Select-Object -First 2000)
            $chokeNote = "Chokepoints approximated from the 2000 origins with the widest reach (full set too large)."
        }
        if ($origins.Count -gt 0) {
            $fwd = [OGCheckV1.Engine]::Forward($n, $fromA, $toA, $trav, [int[]]$origins)
            $topNodes = @(foreach ($x in [OGCheckV1.Engine]::TopK(([OGCheckV1.Engine]::Mul($fwd, $base.Bwd, $internal)), $Top)) {
                [pscustomobject]@{ Node = $ing.Label[$x]; Kind = $ing.KindOf[$x]; OriginsReaching = $fwd[$x]; TargetsReachable = $base.Bwd[$x]; PairsThrough = $fwd[$x] * $base.Bwd[$x]; Id = $ing.Key[$x] }
            })
            $fwd1 = New-Object long[] $n; for ($x = 0; $x -lt $n; $x++) { $fwd1[$x] = $fwd[$x] + $(if ($originType[$x] -gt 0) { 1 } else { 0 }) }
            $eS = [OGCheckV1.Engine]::EdgeScores($fromA, $toA, $trav, $fwd1, $base.Bwd)
            $topEdges = @(foreach ($i in [OGCheckV1.Engine]::TopK($eS, $Top)) {
                [pscustomobject]@{ EdgeKind = $kindNames[$kindIdA[$i]]; Start = $ing.Label[$fromA[$i]]; End = $ing.Label[$toA[$i]]; PairsThrough = $eS[$i]; Properties = $ing.PropSummary($i) }
            })
        }

        $paths = [pscustomobject]@{
            Targets = ($targetGroup | Where-Object { $_ -ge 0 }).Count; Principals = ($originType | Where-Object { $_ -eq 1 }).Count; Entries = ($originType | Where-Object { $_ -eq 2 }).Count
            TotalP = $base.TotalP; TotalE = $base.TotalE; Groups = $groupRows; OriginRows = $originRows; TargetRows = $targetRows
            WhatIf = $whatIf; NewRows = $newRows; WithoutNew = $withoutNew; TopNodes = $topNodes; TopEdges = $topEdges; ChokeNote = $chokeNote
            PrincipalMode = $(if ($principalSet) { "schema principal kinds: $($principalSet -join ', ')" } else { 'all internal nodes with outgoing edges (no schema principal kinds)' })
        }
    }

    [pscustomobject]@{
        File = $loaded.Path; SizeMB = $loaded.SizeMB; SourceKind = $sourceKind
        Nodes = $internal; External = $n - $internal; Edges = $m; Issues = $issues
        NodeKinds = $nodeKindRows; KindCombos = @($ing.KindCombo.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ Kinds = $_.Key; Count = $_.Value } })
        EdgeKinds = $kindRows; Patterns = $patternRows; PropRows = $propRows; Prefixes = $prefixes
        MatchBy = @($ing.MatchBy.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ Endpoint = $_.Key; Count = $_.Value } })
        ExtClass = @($ing.ExtClassCount.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ ExternalType = $_.Key; DistinctEndpoints = $_.Value } })
        Hybrid = $hybridRows; Struct = $st; TopDegree = $topDegree; SelfLoops = $ing.SelfLoops; DupEdges = $ing.DupEdges; DupIds = $ing.DupIds
        EnvNodes = $ing.EnvNodes; EnvCollected = $ing.EnvNodesCollected; EnvIdNodes = $envTotal
        Paths = $paths; Sigs = $ing.Sigs
        NodeKindCount = $ing.NodeKindCount; EdgeKindCount = $ing.EdgeKindCount
    }
}
#endregion

#region ---------- Main ----------
$schemaInfo = $null
if ($SchemaPath) {
    $sch = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $SchemaPath).Path) | ConvertFrom-Json
    $tr = @{}; foreach ($rk in $sch.relationship_kinds) { $tr[[string]$rk.name] = [bool]$rk.is_traversable }
    $schemaInfo = [pscustomobject]@{
        Name = "$($sch.schema.name) $($sch.schema.version)"; Namespace = [string]$sch.schema.namespace
        NodeKinds = @($sch.node_kinds | ForEach-Object { [string]$_.name }) + @($sch.environments | ForEach-Object { [string]$_.source_kind } | Where-Object { $_ })
        Traversable = $tr
        EnvKinds = @($sch.environments | ForEach-Object { [string]$_.environment_kind } | Where-Object { $_ })
        EnvSourceKinds = @($sch.environments | ForEach-Object { [string]$_.source_kind } | Where-Object { $_ })
        SourceKinds = @($sch.environments | ForEach-Object { [string]$_.source_kind } | Where-Object { $_ })
        PrincipalKinds = @($sch.environments | ForEach-Object { $_.principal_kinds } | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
}
$t0 = $null
if ($TierZeroFile) {
    $t0 = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $tzFull = (Resolve-Path -LiteralPath $TierZeroFile).Path
    if ($tzFull -match '\.csv$') {
        $rows = Import-Csv -LiteralPath $tzFull
        $col = @($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '^(name|label|objectid)$' })[0]; if (-not $col) { $col = @($rows[0].PSObject.Properties.Name)[0] }
        foreach ($r in $rows) { if ($r.$col) { [void]$t0.Add($r.$col.Trim()) } }
    } else { foreach ($line in [IO.File]::ReadAllLines($tzFull)) { if ($line.Trim()) { [void]$t0.Add($line.Trim()) } } }
}
if (-not $OutputFolder) { $OutputFolder = Join-Path (Get-Location) ("OG-Analysis-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) }
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$old = $null
if ($BaselinePath) { $old = Invoke-OGAnalysis -File $BaselinePath -NoPaths -Schema $schemaInfo -TierZero $t0 }
$cur = Invoke-OGAnalysis -File $Path -NoPaths:$SkipPathAnalysis -BaselineSigs $(if ($old) { $old.Sigs } else { $null }) -TierZero $t0 -Schema $schemaInfo

$errs = @($cur.Issues | Where-Object Severity -eq 'ERROR'); $warns = @($cur.Issues | Where-Object Severity -eq 'WARN'); $infos = @($cur.Issues | Where-Object Severity -eq 'INFO')
$status = if ($errs) { 'FAIL - errors that will reject the upload or break ingest' } elseif ($warns) { 'OK WITH WARNINGS' } else { 'OK' }
$statusColor = if ($errs) { 'Red' } elseif ($warns) { 'Yellow' } else { 'Green' }

Write-Section "OpenGraph payload analysis  ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
Write-R "File          : $($cur.File) ($($cur.SizeMB) MB)"
if ($old) { Write-R "Baseline      : $($old.File) ($($old.SizeMB) MB)" }
Write-R "source_kind   : $(if ($cur.SourceKind) { $cur.SourceKind } else { '(none)' })"
Write-R "Schema        : $(if ($schemaInfo) { "$($schemaInfo.Name) (namespace $($schemaInfo.Namespace))" } else { 'none supplied - generic checks only, all edges assumed traversable' })"
Write-R "Nodes         : $($cur.Nodes) defined, $($cur.External) external endpoints referenced (resolved by BloodHound at ingest)"
Write-R "Edges         : $($cur.Edges)  ($($cur.EdgeKinds.Count) edge kinds, $($cur.NodeKinds.Count) node kinds)"
Write-R "Status        : $status  [$($errs.Count) error types, $($warns.Count) warning types, $($infos.Count) info]" $statusColor

Write-Section '1. Validation'
$vrows = @($cur.Issues | Sort-Object @{ e = { @{ ERROR = 0; WARN = 1; INFO = 2 }[$_.Severity] } }, Check, @{ e = { -$_.Count } })
if (-not $vrows) { Write-R '  No validation issues found.' 'Green' }
else { Write-Table ($vrows | Select-Object -First ([math]::Max($Top, 40)) Severity, Check, Count, Detail, @{ n = 'Example'; e = { if ("$($_.Example)".Length -gt 70) { "$($_.Example)".Substring(0, 70) + '...' } else { $_.Example } } }) }
$vrows | Export-Csv (Join-Path $OutputFolder 'validation.csv') -NoTypeInformation

Write-Section '2. Nodes by kind'
Write-Table ($cur.NodeKinds | Select-Object -First $Top)
Write-R ''
Write-R 'Kind combinations (first kind = primary kind / icon):' 'DarkGray'
Write-Table ($cur.KindCombos | Select-Object -First $Top)
Write-R ''
Write-R ("Kind prefixes: {0}" -f (($cur.Prefixes.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join ', '))
$cur.NodeKinds | Export-Csv (Join-Path $OutputFolder 'node_kinds.csv') -NoTypeInformation

Write-Section '3. Edges by kind'
if ($old) {
    $allK = @($cur.EdgeKindCount.Keys) + @($old.EdgeKindCount.Keys) | Sort-Object -Unique
    $kd = @(foreach ($k in $allK) { $c = [int]$cur.EdgeKindCount[$k]; $b = [int]$old.EdgeKindCount[$k]
        [pscustomobject]@{ EdgeKind = $k; Baseline = $b; Current = $c; Delta = $c - $b; Change = $(if ($b) { '{0:+0;-0;0}%' -f (100 * ($c - $b) / $b) } elseif ($c) { 'NEW' } else { 'GONE' }) } }) | Sort-Object { [math]::Abs($_.Delta) } -Descending
    Write-Table ($kd | Select-Object -First $Top)
    $kd | Export-Csv (Join-Path $OutputFolder 'edge_kinds_vs_baseline.csv') -NoTypeInformation
    $allN = @($cur.NodeKindCount.Keys) + @($old.NodeKindCount.Keys) | Sort-Object -Unique
    $nd = @(foreach ($k in $allN) { $c = [int]$cur.NodeKindCount[$k]; $b = [int]$old.NodeKindCount[$k]; if ($c -ne $b) { [pscustomobject]@{ NodeKind = $k; Baseline = $b; Current = $c; Delta = $c - $b } } })
    if ($nd) { Write-R ''; Write-R 'Node kind changes vs baseline:' 'DarkGray'; Write-Table $nd }
    Write-R ''
}
Write-Table ($cur.EdgeKinds | Select-Object -First $Top)
$cur.EdgeKinds | Export-Csv (Join-Path $OutputFolder 'edge_kinds.csv') -NoTypeInformation
Write-R ''
Write-R 'Edge patterns (StartKind -[EdgeKind]-> EndKind):' 'DarkGray'
Write-Table ($cur.Patterns | Select-Object -First $Top)
$cur.Patterns | Export-Csv (Join-Path $OutputFolder 'edge_patterns.csv') -NoTypeInformation

Write-Section '4. Properties'
Write-R 'PartialProps = properties missing on some nodes of that kind; MixedTypeProps = same property with different types.' 'DarkGray'
$propIssues = @($cur.PropRows | Where-Object { $_.Types -match ',' -and ($_.Types -replace '(^|,)null', '') -match ',' })
if ($propIssues) { Write-R 'Properties with inconsistent types:' 'Yellow'; Write-Table ($propIssues | Select-Object -First $Top) }
$lowCov = @($cur.PropRows | Where-Object { $_.Scope -eq 'node' -and $_.CoveragePct -lt 100 } | Sort-Object CoveragePct)
if ($lowCov) { Write-R ''; Write-R 'Least-populated node properties:' 'DarkGray'; Write-Table ($lowCov | Select-Object -First ([math]::Min($Top, 15))) }
Write-R ''
Write-R "Full property profile: properties.csv ($($cur.PropRows.Count) kind/property rows)" 'DarkGray'
$cur.PropRows | Sort-Object Scope, Kind, Property | Export-Csv (Join-Path $OutputFolder 'properties.csv') -NoTypeInformation

Write-Section '5. Endpoint matching and external (hybrid) references'
Write-Table $cur.MatchBy
Write-R ''
Write-Table $cur.ExtClass
Write-R ''
Write-R 'Edges pointing at nodes not defined in this file, by target group (domain / SID domain / suffix):' 'DarkGray'
Write-Table ($cur.Hybrid | Select-Object -First $Top)
$cur.Hybrid | Export-Csv (Join-Path $OutputFolder 'hybrid_edges.csv') -NoTypeInformation

Write-Section '6. Graph structure'
$s = $cur.Struct
Write-R ("Isolated nodes (no edges)   : {0} of {1} ({2:N1}%)" -f $s.Isolated, $cur.Nodes, $(if ($cur.Nodes) { 100 * $s.Isolated / $cur.Nodes } else { 0 }))
Write-R ("Connected components        : {0} (largest {1} nodes, incl. external endpoints)" -f $s.Components, $s.Largest)
Write-R ("Self-loops / duplicate edges: {0} / {1}" -f $cur.SelfLoops, $cur.DupEdges)
Write-R ("Edges per node              : {0:N2}" -f $(if ($cur.Nodes) { $cur.Edges / $cur.Nodes } else { 0 }))
if ($schemaInfo -and $schemaInfo.EnvKinds.Count) { Write-R ("Environment nodes           : {0} ({1} with collected=true); nodes with environmentid: {2}" -f $cur.EnvNodes, $cur.EnvCollected, $cur.EnvIdNodes) }
else { Write-R ("Nodes with environmentid    : {0}" -f $cur.EnvIdNodes) }
Write-R ''
Write-R 'Highest-degree nodes:' 'DarkGray'
Write-Table ($cur.TopDegree | Select-Object Node, Kind, Out, In)
$cur.TopDegree | Export-Csv (Join-Path $OutputFolder 'top_degree_nodes.csv') -NoTypeInformation

$PathRes = $cur.Paths
if ($PathRes) {
    Write-Section '7. Reachability into external targets'
    Write-R "Origins: $($PathRes.PrincipalMode)." 'DarkGray'
    Write-R 'Targets: external endpoints reached by a traversable edge (AD / Azure / other graph nodes). Use -TierZeroFile to narrow.' 'DarkGray'
    Write-R ("Targets {0}; principal origins {1}; external entry points {2}; principal->target pairs {3}; entry->target pairs {4}" -f $PathRes.Targets, $PathRes.Principals, $PathRes.Entries, $PathRes.TotalP, $PathRes.TotalE) 'White'
    Write-Table ($PathRes.Groups | Select-Object -First $Top)
    $PathRes.Groups | Export-Csv (Join-Path $OutputFolder 'target_groups.csv') -NoTypeInformation
    Write-R ''
    Write-R 'Origins reaching the most targets (InboundEdges = 0 means nothing points at it, but it still counts as a principal):' 'DarkGray'
    Write-Table ($PathRes.OriginRows | Select-Object -First $Top Origin, Kind, Type, TargetsReachable, InboundEdges)
    $PathRes.OriginRows | Export-Csv (Join-Path $OutputFolder 'origins.csv') -NoTypeInformation
    Write-R ''
    Write-R 'Most-reached targets:' 'DarkGray'
    Write-Table ($PathRes.TargetRows | Select-Object -First $Top)
    $PathRes.TargetRows | Export-Csv (Join-Path $OutputFolder 'targets.csv') -NoTypeInformation
    if ($PathRes.WhatIf) {
        Write-R ''
        Write-R 'What-if: origin->target pairs lost when each edge kind is removed:' 'DarkGray'
        Write-Table ($PathRes.WhatIf | Select-Object -First $Top)
        $PathRes.WhatIf | Export-Csv (Join-Path $OutputFolder 'whatif_edge_kinds.csv') -NoTypeInformation
    }
    if ($PathRes.ChokeNote) { Write-R ''; Write-R $PathRes.ChokeNote 'Yellow' }
    if ($PathRes.TopNodes) {
        Write-R ''; Write-R 'Chokepoint nodes (origins reaching x targets reachable):' 'DarkGray'
        Write-Table ($PathRes.TopNodes | Select-Object Node, Kind, OriginsReaching, TargetsReachable, PairsThrough)
        Write-R ''; Write-R 'Chokepoint edges:' 'DarkGray'
        Write-Table $PathRes.TopEdges
        $PathRes.TopNodes | Export-Csv (Join-Path $OutputFolder 'top_nodes.csv') -NoTypeInformation
        $PathRes.TopEdges | Export-Csv (Join-Path $OutputFolder 'top_edges.csv') -NoTypeInformation
    }
}

if ($old) {
    Write-Section '8. Changes since baseline'
    $new = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sg in $cur.Sigs) { if (-not $old.Sigs.Contains($sg)) { $p = $sg -split '\|', 3; $new.Add([pscustomobject]@{ EdgeKind = $p[0]; Start = ($p[1] -replace '^(ID|NAME|PROP)::', ''); End = ($p[2] -replace '^(ID|NAME|PROP)::', '') }) } }
    $gone = 0; foreach ($sg in $old.Sigs) { if (-not $cur.Sigs.Contains($sg)) { $gone++ } }
    Write-R "Nodes: $($old.Nodes) -> $($cur.Nodes)   Edges: $($old.Edges) -> $($cur.Edges)   New edge signatures: $($new.Count)   Removed: $gone" 'White'
    if ($new.Count -gt 0.8 * $cur.Edges -and $gone -gt 0.8 * $old.Edges) { Write-R 'Nearly every edge differs - node ids or kind names probably changed between versions. Compare counts, not signatures.' 'Yellow' }
    Write-Table ($new | Group-Object EdgeKind | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ EdgeKind = $_.Name; NewEdges = $_.Count } })
    $new | Export-Csv (Join-Path $OutputFolder 'new_edges_vs_baseline.csv') -NoTypeInformation
    if ($PathRes -and $PathRes.NewRows) {
        Write-R ''
        Write-R ("Origin->target pairs now {0}; without any new edge {1}. Pairs lost when removing only the NEW edges of each kind:" -f ($PathRes.TotalP + $PathRes.TotalE), $PathRes.WithoutNew) 'DarkGray'
        Write-Table $PathRes.NewRows
    }
}

# ---------- Key findings ----------
Write-Section 'KEY FINDINGS'
$kf = New-Object 'System.Collections.Generic.List[string]'
if ($errs) { $kf.Add(('ERRORS: ' + ((@($errs | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Detail) ($($_.Count)x)" })) -join ' | '))) }
foreach ($w in ($warns | Sort-Object Count -Descending | Select-Object -First 4)) { $kf.Add("Warning ($($w.Count)x): $($w.Detail)") }
$topNK = $cur.NodeKinds | Select-Object -First 3 | ForEach-Object { "$($_.NodeKind) $($_.Count)" }
$topEK = $cur.EdgeKinds | Select-Object -First 3 | ForEach-Object { "$($_.EdgeKind) $($_.Count)" }
$kf.Add("Largest kinds: nodes $($topNK -join ', '); edges $($topEK -join ', ').")
if ($cur.Struct.Isolated -gt 0) { $kf.Add(("{0} isolated node(s) ({1:N1}%) have no edges at all." -f $cur.Struct.Isolated, (100 * $cur.Struct.Isolated / [math]::Max(1, $cur.Nodes)))) }
$fanTop = $cur.EdgeKinds | Sort-Object MaxFanOut -Descending | Select-Object -First 1
if ($fanTop -and $fanTop.MaxFanOut -gt 100) { $kf.Add("Largest fan-out: one node ($($fanTop.MaxFanOutNode)) has $($fanTop.MaxFanOut) outgoing $($fanTop.EdgeKind) edges.") }
if ($cur.External -gt 0) { $kf.Add("$($cur.External) external endpoint(s) referenced: $((@($cur.ExtClass | ForEach-Object { "$($_.ExternalType) $($_.DistinctEndpoints)" })) -join ', ').") }
if ($PathRes) {
    if ($PathRes.Groups) { $g = $PathRes.Groups[0]; $kf.Add("Most exposed target group: $($g.TargetGroup) ($($g.Targets) targets, $($g.PrincipalToTargetPairs + $g.EntryToTargetPairs) origin->target pairs).") }
    $noIn = @($PathRes.OriginRows | Where-Object { $_.InboundEdges -eq 0 -and $_.Type -eq 'principal' } | Select-Object -First 3)
    $why = if ($schemaInfo -and $schemaInfo.PrincipalKinds.Count) { 'a schema principal kind, so it counts as an attacker in its own right' } else { 'no schema principal kinds, so every node is treated as a possible origin - check whether this kind is really a principal' }
    foreach ($o in $noIn) { $kf.Add("Origin with no inbound edges reaching $($o.TargetsReachable) external targets: $($o.Origin) [$($o.Kind)] ($why).") }
    $wi = @($PathRes.WhatIf | Where-Object { $_.PairsLost -gt 0 } | Select-Object -First 3)
    if ($wi) { $kf.Add("Paths into external targets depend most on: $((@($wi | ForEach-Object { "$($_.EdgeKind) ($($_.PctOfAll)%)" })) -join ', ').") }
    if ($PathRes.NewRows) { $nr = $PathRes.NewRows[0]; $kf.Add("Since baseline, new $($nr.EdgeKind) edges ($($nr.NewEdges)) add $($nr.PairsLost) origin->target pairs.") }
    if ($PathRes.TopNodes) { $tn = $PathRes.TopNodes[0]; $kf.Add("Biggest chokepoint: $($tn.Node) [$($tn.Kind)] - $($tn.OriginsReaching) origins x $($tn.TargetsReachable) targets.") }
}
if (-not $schemaInfo) { $kf.Add('No schema supplied: traversability was assumed. Re-run with -SchemaPath for structured-graph / findings readiness checks.') }
foreach ($line in $kf) { Write-R " - $line" $(if ($line -like 'ERRORS*') { 'Red' } elseif ($line -like 'Warning*') { 'Yellow' } else { 'Gray' }) }
Write-R ''
Write-R "Overall: $status" $statusColor

# ---------- Cypher ----------
$cy = New-Object 'System.Collections.Generic.List[string]'
$cy.Add('// OpenGraph payload review queries for the BHE Cypher editor. Queries return whole nodes or paths.')
$cy.Add('// Note: BloodHound stores the payload node "id" as the objectid property, and uppercases name/environmentid.')
$cy.Add('')
$cy.Add('// Sample of each edge kind')
foreach ($k in ($cur.EdgeKinds | Select-Object -First 20)) { $cy.Add("MATCH p=()-[:$($k.EdgeKind)]->() RETURN p LIMIT 100") }
$cy.Add('')
$cy.Add('// Isolated nodes per kind')
foreach ($k in ($cur.NodeKinds | Select-Object -First 10)) { if ($k.NodeKind -match '^[A-Za-z0-9_]+$') { $cy.Add("MATCH (n:$($k.NodeKind)) WHERE NOT (n)--() RETURN n LIMIT 100") } }
$cy.Add('')
$cy.Add('// Largest fan-out node per edge kind')
foreach ($k in ($cur.EdgeKinds | Sort-Object MaxFanOut -Descending | Select-Object -First 5)) { $cy.Add("MATCH p=(n)-[:$($k.EdgeKind)]->() WHERE toUpper(n.name) = '$(($k.MaxFanOutNode -replace "'", "\'").ToUpper())' RETURN p LIMIT 300") }
$hk = @($cur.Hybrid | Select-Object -ExpandProperty EdgeKind -Unique | Select-Object -First 5)
if ($hk) { $cy.Add(''); $cy.Add('// Hybrid edges into existing graph nodes'); foreach ($k in $hk) { $cy.Add("MATCH p=()-[:$k]->(t) WHERE NOT t:$(if ($cur.SourceKind) { $cur.SourceKind } else { 'Base' }) RETURN p LIMIT 200") } }
if ($PathRes) {
    $cy.Add(''); $cy.Add('// Outbound paths from the top origins')
    foreach ($o in ($PathRes.OriginRows | Select-Object -First 5)) { if ($o.Type -eq 'principal') { $cy.Add("MATCH p=(n)-[*1..3]->() WHERE n.objectid = '$(($o.Id -replace "'", "\'"))' RETURN p LIMIT 300") } }
    $cy.Add(''); $cy.Add('// Chokepoint nodes: inbound and outbound')
    foreach ($t in ($PathRes.TopNodes | Select-Object -First 5)) { $sid = $t.Id -replace "'", "\'"; $cy.Add("MATCH p=()-[]->(n) WHERE n.objectid = '$sid' RETURN p LIMIT 300"); $cy.Add("MATCH p=(n)-[]->() WHERE n.objectid = '$sid' RETURN p LIMIT 300") }
}
$cy.Add(''); $cy.Add('// Tier Zero reached from this source (newer BHE label; older tenants: system_tags CONTAINS ''admin_tier_0'')')
if ($cur.SourceKind) { $cy.Add("MATCH p=(s:$($cur.SourceKind))-[*1..4]->(t:Tag_Tier_Zero) RETURN p LIMIT 100") }
$cy | Set-Content -Path (Join-Path $OutputFolder 'cypher_queries.txt') -Encoding UTF8
$script:Report | Set-Content -Path (Join-Path $OutputFolder 'Report.txt') -Encoding UTF8
Write-Host ''
Write-Host "Report, CSVs and Cypher queries written to: $OutputFolder" -ForegroundColor Green
#endregion
