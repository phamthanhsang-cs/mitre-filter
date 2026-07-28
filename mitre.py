from __future__ import annotations
import json
import argparse
import csv
import os
from collections import defaultdict
from typing import List, Tuple, Dict, Any


def load_technique_lookup(path: str) -> Dict[str, str]:
    lookup = {}
    with open(path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            lookup[row["ID"]] = row["name"]
    return lookup


def load_detection_rules(path: str) -> List[Dict[str, str]]:
    rules = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            technique_id = (row.get("Technique ID") or "").strip()
            if not technique_id or technique_id.upper() == "N/A":
                continue
            rules.append(row)
    return rules


def load_groups(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("techniques"), list):
        pseudo_group = {
            "name": data.get("name") or data.get("description") or "Navigator Layer",
            "metadata": data.get("metadata", []),
            "techniques": data.get("techniques", []),
            "description": data.get("description", "")
        }
        return [pseudo_group]
    raise ValueError(f"Expected top-level JSON list in {path}")

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_TACTIC_INDEX = {t: i for i, t in enumerate(TACTIC_ORDER)}

def _tactic_sort_key(tactic: str) -> Tuple[int, str]:
    return (_TACTIC_INDEX.get(tactic, 999), tactic)


def parse_filter(s: str) -> Tuple[str, str]:
    if "=" in s:
        k, v = s.split("=", 1)
    elif ":" in s:
        k, v = s.split(":", 1)
    else:
        raise argparse.ArgumentTypeError("filter must be in format Key=Value or Key:Value")
    return k.strip(), v.strip()


def group_has_metadata(group: Dict[str, Any], key: str, val: str) -> bool:
    for m in group.get("metadata", []):
        if m.get("name") == key and str(m.get("value")) == val:
            return True
    return False


def filter_groups(groups: List[Dict[str, Any]], filters: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    if not filters:
        return groups[:]
    out = []
    for g in groups:
        ok = True
        for k, v in filters:
            if not group_has_metadata(g, k, v):
                ok = False
                break
        if ok:
            out.append(g)
    return out


def filter_groups_by_names(groups: List[Dict[str, Any]], names: List[str]) -> List[Dict[str, Any]]:
    if not names:
        return groups[:]
    name_set = set(names)
    return [g for g in groups if g.get("name") in name_set]


def write_csv(path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    """Write report data to a UTF-8 CSV file with a header row."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def format_metadata(metadata: List[Dict[str, Any]]) -> str:
    return "; ".join(f"{m.get('name')}={m.get('value')}" for m in metadata)


def merge_groups_to_layer(selected_groups: List[Dict[str, Any]], layer_name: str = "Merged Layer") -> Dict[str, Any]:
    technique_counts: Dict[str, int] = defaultdict(int)
    technique_details: Dict[str, Dict[str, Any]] = {}

    for group in selected_groups:
        for tech in group.get("techniques", []):
            tid = tech.get("techniqueID") or tech.get("id") or tech.get("technique_id")
            if not tid:
                continue
            technique_counts[tid] += 1
            technique_details[tid] = {k: v for k, v in tech.items() if k != "score"}

    max_val = max(technique_counts.values()) if technique_counts else 1
    merged_layer = {
        "name": f"Merged Layer - {layer_name}",
        "versions": {"attack": "18", "navigator": "5.1.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques aggregated across {len(selected_groups)} groups. Filters: {layer_name}",
        "techniques": [],
        "gradient": {
            "colors": ["#00ff00", "#ffff00", "#ff0000",],
            "minValue": 1,
            "maxValue": max_val
        }
    }

    for tid, count in sorted(technique_counts.items(), key=lambda x: (-x[1], x[0])):
        entry = {
            "techniqueID": tid,
            "score": count,
            "comment": f"Used by {count} groups",
            "enabled": True
        }
        if tid in technique_details:
            entry.update(technique_details[tid])
        merged_layer["techniques"].append(entry)

    return merged_layer


def discover_metadata_keys_values(groups: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for g in groups:
        for m in g.get("metadata", []):
            k = m.get("name")
            v = str(m.get("value"))
            if k not in out:
                out[k] = {}
            out[k][v] = out[k].get(v, 0) + 1
    return out


def _iter_group_techniques(group: Dict[str, Any]):
    for tech in group.get("techniques", []):
        tid = tech.get("techniqueID") or tech.get("id") or tech.get("technique_id")
        if not tid:
            continue
        tactic = tech.get("tactic")
        score = tech.get("score", 1)
        yield tid, tactic, score


def aggregate_top_techniques(groups: List[Dict[str, Any]], tactic: str | None = None) -> Dict[str, float]:
    counts: Dict[str, float] = defaultdict(float)
    for group in groups:
        per_group_max: Dict[str, float] = {}
        for tid, ttc, score in _iter_group_techniques(group):
            if tactic and ttc != tactic:
                continue
            prev = per_group_max.get(tid, 0)
            if score > prev:
                per_group_max[tid] = score
        for tid, sc in per_group_max.items():
            counts[tid] += sc
    return counts


def aggregate_top_per_tactic(groups: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    per_tactic: Dict[str, Dict[str, float]] = {}
    for group in groups:
        group_maps: Dict[str, Dict[str, float]] = defaultdict(dict)
        for tid, tactic, score in _iter_group_techniques(group):
            if not tactic:
                continue
            prev = group_maps[tactic].get(tid, 0)
            if score > prev:
                group_maps[tactic][tid] = score
        for tactic, tid_to_score in group_maps.items():
            if tactic not in per_tactic:
                per_tactic[tactic] = {}
            for tid, sc in tid_to_score.items():
                per_tactic[tactic][tid] = per_tactic[tactic].get(tid, 0) + sc
    return per_tactic


def _technique_parent(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


def _confidence_sort_value(confidence: str) -> int:
    order = {"high": 3, "medium": 2, "low": 1}
    return order.get((confidence or "").strip().lower(), 0)


def map_rules_to_techniques(
    technique_rows: List[Dict[str, Any]],
    rules: List[Dict[str, str]],
    include_parent: bool = True,
) -> List[Dict[str, Any]]:
    rules_by_tid: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for rule in rules:
        tid = (rule.get("Technique ID") or "").strip()
        if tid:
            rules_by_tid[tid].append(rule)

    mapped_rows = []
    for technique in technique_rows:
        tid = technique["technique_id"]
        candidates = [(tid, "exact")]
        parent_tid = _technique_parent(tid)
        if include_parent and parent_tid != tid:
            candidates.append((parent_tid, "parent"))

        matched = False
        for match_tid, match_type in candidates:
            for rule in rules_by_tid.get(match_tid, []):
                matched = True
                mapped_rows.append({
                    "tactic": technique.get("tactic", ""),
                    "rank": technique.get("rank", ""),
                    "technique_id": tid,
                    "technique_name": technique.get("technique_name", ""),
                    "aggregated_score": technique.get("aggregated_score", ""),
                    "match_type": match_type,
                    "rule": rule.get("Rule", ""),
                    "rule_tactic": rule.get("Tactic", ""),
                    "rule_technique": rule.get("Technique", ""),
                    "rule_technique_id": match_tid,
                    "confidence": rule.get("Confidence", ""),
                    "notes": rule.get("Notes", ""),
                })
        if not matched:
            mapped_rows.append({
                "tactic": technique.get("tactic", ""),
                "rank": technique.get("rank", ""),
                "technique_id": tid,
                "technique_name": technique.get("technique_name", ""),
                "aggregated_score": technique.get("aggregated_score", ""),
                "match_type": "unmatched",
                "rule": "",
                "rule_tactic": "",
                "rule_technique": "",
                "rule_technique_id": "",
                "confidence": "",
                "notes": "",
            })

    return sorted(
        mapped_rows,
        key=lambda row: (
            row.get("match_type") == "unmatched",
            -float(row.get("aggregated_score") or 0),
            str(row.get("tactic") or ""),
            int(row.get("rank") or 999999),
            -_confidence_sort_value(str(row.get("confidence") or "")),
            str(row.get("rule") or ""),
        ),
    )


def build_top_technique_rows(
    groups: List[Dict[str, Any]],
    limit: int,
    min_score: float,
    per_tactic: bool = False,
    tactic: str | None = None,
    lookup: Dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    lookup = lookup or {}
    rows = []
    if per_tactic:
        per_tactic_counts = aggregate_top_per_tactic(groups)
        tactics = [tactic] if tactic and tactic in per_tactic_counts else sorted(per_tactic_counts.keys(), key=_tactic_sort_key)
        for tactic_name in tactics:
            filtered_items = [(tid, cnt) for tid, cnt in per_tactic_counts[tactic_name].items() if cnt >= min_score]
            sorted_items = sorted(filtered_items, key=lambda x: (-x[1], x[0]))
            for idx, (tid, cnt) in enumerate(sorted_items[:limit], 1):
                rows.append({
                    "tactic": tactic_name,
                    "rank": idx,
                    "technique_id": tid,
                    "technique_name": lookup.get(tid, ""),
                    "aggregated_score": cnt,
                })
        return rows

    counts = aggregate_top_techniques(groups, tactic=tactic)
    filtered_items = [(tid, cnt) for tid, cnt in counts.items() if cnt >= min_score]
    sorted_items = sorted(filtered_items, key=lambda x: (-x[1], x[0]))
    for idx, (tid, cnt) in enumerate(sorted_items[:limit], 1):
        rows.append({
            "tactic": tactic or "",
            "rank": idx,
            "technique_id": tid,
            "technique_name": lookup.get(tid, ""),
            "aggregated_score": cnt,
        })
    return rows


def cmd_top(args: argparse.Namespace):
    groups = load_groups(args.input)
    filters = [parse_filter(f) for f in (args.filter or [])]
    matched = filter_groups(groups, filters)
    matched = filter_groups_by_names(matched, args.name or [])

    if not matched:
        print("No groups matched the provided filter(s).")
        return

    limit = max(1, args.limit or 10)

    # Load technique lookup if provided and exists
    lookup = {}
    if args.technique_lookup and os.path.exists(args.technique_lookup):
        try:
            lookup = load_technique_lookup(args.technique_lookup)
        except Exception as e:
            print(f"Warning: Could not load technique lookup from {args.technique_lookup}: {e}")

    if args.per_tactic:
        per_tactic_counts = aggregate_top_per_tactic(matched)
        if args.tactic:
            tactics = [args.tactic] if args.tactic in per_tactic_counts else []
        else:
            tactics = sorted(per_tactic_counts.keys(), key=_tactic_sort_key)

        if args.tactic and not tactics:
            print(f"No techniques found for tactic '{args.tactic}'.")
            return

        shown_any = False
        csv_rows = []
        for tactic in tactics:
            filtered_items = [(tid, cnt) for tid, cnt in per_tactic_counts[tactic].items() if cnt >= args.min_score]
            if not filtered_items:
                continue
            shown_any = True
            print(f"Tactic: {tactic}")
            sorted_items = sorted(filtered_items, key=lambda x: (-x[1], x[0]))
            for idx, (tid, cnt) in enumerate(sorted_items[:limit], 1):
                name = lookup.get(tid, "")
                csv_rows.append({
                    "tactic": tactic,
                    "rank": idx,
                    "technique_id": tid,
                    "technique_name": name,
                    "aggregated_score": cnt,
                })
                if name:
                    print(f"  {idx:2d}. {tid} ({name}) - {cnt}")
                else:
                    print(f"  {idx:2d}. {tid} - {cnt}")
        if not shown_any:
            print("No tactics have techniques meeting the score threshold.")
        if args.csv:
            write_csv(args.csv, ["tactic", "rank", "technique_id", "technique_name", "aggregated_score"], csv_rows)
            print(f"Wrote top-techniques CSV to: {args.csv}")
        return

    counts = aggregate_top_techniques(matched, tactic=args.tactic)
    if args.tactic and not counts:
        print(f"No techniques found for tactic '{args.tactic}'.")
        return
    filtered_items = [(tid, cnt) for tid, cnt in counts.items() if cnt >= args.min_score]
    sorted_items = sorted(filtered_items, key=lambda x: (-x[1], x[0]))
    print("Top techniques" + (f" for tactic '{args.tactic}'" if args.tactic else "") + ":")
    csv_rows = []
    for idx, (tid, cnt) in enumerate(sorted_items[:limit], 1):
        name = lookup.get(tid, "")
        csv_rows.append({
            "tactic": args.tactic or "",
            "rank": idx,
            "technique_id": tid,
            "technique_name": name,
            "aggregated_score": cnt,
        })
        if name:
            print(f"  {idx:2d}. {tid} ({name}) - {cnt}")
        else:
            print(f"  {idx:2d}. {tid} - {cnt}")
    if args.csv:
        write_csv(args.csv, ["tactic", "rank", "technique_id", "technique_name", "aggregated_score"], csv_rows)
        print(f"Wrote top-techniques CSV to: {args.csv}")


def cmd_map_rules(args: argparse.Namespace):
    groups = load_groups(args.input)
    filters = [parse_filter(f) for f in (args.filter or [])]
    matched = filter_groups(groups, filters)
    matched = filter_groups_by_names(matched, args.name or [])

    if not matched:
        print("No groups matched the provided filter(s).")
        return

    lookup = {}
    if args.technique_lookup and os.path.exists(args.technique_lookup):
        try:
            lookup = load_technique_lookup(args.technique_lookup)
        except Exception as e:
            print(f"Warning: Could not load technique lookup from {args.technique_lookup}: {e}")

    rules = load_detection_rules(args.rules)
    limit = max(1, args.limit or 10)
    technique_rows = build_top_technique_rows(
        matched,
        limit=limit,
        min_score=args.min_score,
        per_tactic=args.per_tactic,
        tactic=args.tactic,
        lookup=lookup,
    )
    mapped_rows = map_rules_to_techniques(technique_rows, rules, include_parent=not args.exact_only)
    if args.per_tactic:
        mapped_rows = sorted(
            mapped_rows,
            key=lambda row: (
                _tactic_sort_key(str(row.get("tactic") or "")),
                int(row.get("rank") or 999999),
                row.get("match_type") == "unmatched",
                -_confidence_sort_value(str(row.get("confidence") or "")),
                str(row.get("rule") or ""),
            ),
        )
    matched_rule_rows = [row for row in mapped_rows if row["match_type"] != "unmatched"]
    unmatched_rows = [row for row in mapped_rows if row["match_type"] == "unmatched"]

    if not mapped_rows:
        print("No techniques found for the selected groups and filters.")
        return

    print("SolarWinds rule mapping:")
    current_tactic = None
    shown = 0
    for row in matched_rule_rows:
        if args.per_tactic and row["tactic"] != current_tactic:
            current_tactic = row["tactic"]
            print(f"Tactic: {current_tactic}")
        prefix = "  " if args.per_tactic else ""
        print(
            f"{prefix}{row['technique_id']} score={row['aggregated_score']} "
            f"-> {row['rule']} ({row['confidence']}, {row['match_type']})"
        )
        shown += 1

    if not matched_rule_rows:
        print("  No SolarWinds rules matched the selected techniques.")
    if unmatched_rows:
        print(f"Unmatched techniques: {len(unmatched_rows)}")
        for row in unmatched_rows[:args.show_unmatched]:
            name_part = f" ({row['technique_name']})" if row["technique_name"] else ""
            print(f"  {row['technique_id']}{name_part} score={row['aggregated_score']}")
        if len(unmatched_rows) > args.show_unmatched:
            print(f"  ... and {len(unmatched_rows) - args.show_unmatched} more")

    if args.csv:
        fields = [
            "tactic",
            "rank",
            "technique_id",
            "technique_name",
            "aggregated_score",
            "match_type",
            "rule",
            "rule_tactic",
            "rule_technique",
            "rule_technique_id",
            "confidence",
            "notes",
        ]
        write_csv(args.csv, fields, mapped_rows)
        print(f"Wrote SolarWinds rule mapping CSV to: {args.csv}")


def cmd_list(args: argparse.Namespace):
    groups = load_groups(args.input)
    filters = [parse_filter(f) for f in (args.filter or [])]
    matched = filter_groups(groups, filters)
    matched = filter_groups_by_names(matched, args.name or [])
    if not matched:
        print("No groups matched the provided filter(s).")
        return

    sorted_groups = sorted(matched, key=lambda x: x.get("name", ""))
    for idx, g in enumerate(sorted_groups, 1):
        name = g.get("name", "<unnamed>")
        desc = g.get("description", "")
        print(f"{idx:3d}. {name}")
        if args.verbose:
            meta = g.get("metadata", [])
            if meta:
                meta_str = format_metadata(meta)
                print(f"      metadata: {meta_str}")
            if desc:
                print(f"      description: {desc}")
    if args.csv:
        rows = [
            {
                "rank": idx,
                "name": g.get("name", "<unnamed>"),
                "description": g.get("description", ""),
                "metadata": format_metadata(g.get("metadata", [])),
                "technique_count": len(g.get("techniques", [])),
            }
            for idx, g in enumerate(sorted_groups, 1)
        ]
        write_csv(args.csv, ["rank", "name", "description", "metadata", "technique_count"], rows)
        print(f"Wrote group-list CSV to: {args.csv}")


def cmd_merge(args: argparse.Namespace):
    groups = load_groups(args.input)
    filters = [parse_filter(f) for f in (args.filter or [])]
    matched = filter_groups(groups, filters)
    matched = filter_groups_by_names(matched, args.name or [])

    if not matched:
        print("No groups matched the provided filter(s). Nothing to merge.")
        return

    name_part = ", ".join(args.name) if args.name else None
    filter_part = ", ".join(f"{k}={v}" for k, v in filters) if filters else None
    if name_part and filter_part:
        layer_name = f"names:[{name_part}] AND {filter_part}"
    elif name_part:
        layer_name = f"names:[{name_part}]"
    elif filter_part:
        layer_name = filter_part
    else:
        layer_name = "all-groups"
    merged = merge_groups_to_layer(matched, layer_name=layer_name)

    out_path = args.output or f"merged_{layer_name.replace(' ', '_').replace('=', '-')}.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4)
    print(f"Wrote merged layer ({len(merged['techniques'])} techniques) to: {out_path}")


def cmd_keys(args: argparse.Namespace):
    groups = load_groups(args.input)
    kv = discover_metadata_keys_values(groups)
    if not kv:
        print("No metadata keys found in input data.")
        return
    csv_rows = []
    for key in sorted(kv.keys()):
        print(f"{key}:")
        entries = sorted(kv[key].items(), key=lambda x: (-x[1], x[0]))
        for val, cnt in entries[:50]:
            print(f"  - {val} ({cnt})")
            csv_rows.append({"metadata_key": key, "metadata_value": val, "group_count": cnt})
        if len(entries) > 50:
            print(f"  ... and {len(entries) - 50} more")
    if args.csv:
        write_csv(args.csv, ["metadata_key", "metadata_value", "group_count"], csv_rows)
        print(f"Wrote metadata-keys CSV to: {args.csv}")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mitre.py", description="List and merge MITRE ATT&CK group JSON by metadata tags.")
    p.add_argument("--input", "-i", default="all-groups.json", help="Path to groups JSON export (default: all-groups.json)")
    p.add_argument("--technique-lookup", default="attack_techniques_lookup.csv", help="Path to CSV file with technique ID to name mapping (default: attack_techniques_lookup.csv)")

    sub = p.add_subparsers(title="commands", dest="command", required=True)

    # list
    sl = sub.add_parser("list", help="List group names matching filters")
    sl.add_argument("--filter", "-f", action="append", help="Filter in form Key=Value (can be repeated; combined with AND)")
    sl.add_argument("--name", "-n", action="append", help="Group name (exact match). Can be repeated.")
    sl.add_argument("--verbose", "-v", action="store_true", help="Show metadata and description for each group")
    sl.add_argument("--csv", metavar="PATH", help="Write matching groups to a CSV file")
    sl.set_defaults(func=cmd_list)

    # merge
    sm = sub.add_parser("merge", help="Merge groups matching filters into a Mitre Navigator layer JSON")
    sm.add_argument("--filter", "-f", action="append", help="Filter in form Key=Value (can be repeated; combined with AND)")
    sm.add_argument("--name", "-n", action="append", help="Group name (exact match). Can be repeated.")
    sm.add_argument("--output", "-o", help="Output file path for merged layer JSON (default: generated from filters)")
    sm.set_defaults(func=cmd_merge)

    sk = sub.add_parser("keys", help="List discovered metadata keys and sample values")
    sk.add_argument("--csv", metavar="PATH", help="Write discovered metadata values to a CSV file")
    sk.set_defaults(func=cmd_keys)

    st = sub.add_parser("top", help="Show top techniques overall, per tactic, or per all tactics")
    st.add_argument("--filter", "-f", action="append", help="Filter in form Key=Value (can be repeated; AND)")
    st.add_argument("--name", "-n", action="append", help="Group name (exact match). Can be repeated.")
    st.add_argument("--limit", "-l", type=int, default=10, help="How many techniques to show (default: 10)")
    st.add_argument("--tactic", "-t", help="Limit to a specific tactic (e.g., persistence, execution)")
    st.add_argument("--min-score", type=float, default=0, help="Minimum aggregated score to include (default: 0)")
    st.add_argument("--per-tactic", action="store_true", help="Show top techniques per tactic")
    st.add_argument("--csv", metavar="PATH", help="Write displayed top techniques to a CSV file")
    st.set_defaults(func=cmd_top)

    sr = sub.add_parser("map-rules", help="Map top MITRE techniques to SolarWinds detection rules")
    sr.add_argument("--rules", "-r", default="Solar-Wind-DetectionList-csv.csv", help="SolarWinds rule CSV path")
    sr.add_argument("--filter", "-f", action="append", help="Filter in form Key=Value (can be repeated; AND)")
    sr.add_argument("--name", "-n", action="append", help="Group name (exact match). Can be repeated.")
    sr.add_argument("--limit", "-l", type=int, default=10, help="How many techniques to evaluate (default: 10)")
    sr.add_argument("--tactic", "-t", help="Limit to a specific tactic (e.g., persistence, execution)")
    sr.add_argument("--min-score", type=float, default=0, help="Minimum aggregated score to include (default: 0)")
    sr.add_argument("--per-tactic", action="store_true", help="Map top techniques per tactic")
    sr.add_argument("--exact-only", action="store_true", help="Only match exact technique IDs, not parent IDs")
    sr.add_argument("--show-unmatched", type=int, default=20, help="How many unmatched techniques to print (default: 20)")
    sr.add_argument("--csv", metavar="PATH", help="Write rule mapping to a CSV file")
    sr.set_defaults(func=cmd_map_rules)

    return p


def main():
    parser = build_argparser()
    args = parser.parse_args()
    try:
        args.func(args)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
    except json.JSONDecodeError as e:
        print(f"ERROR: Could not parse JSON file {args.input}: {e}")
    except Exception as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
