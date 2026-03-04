from typing import List, Dict, Any
from collections import Counter

def build_user_host_edges(events: List[Dict[str, Any]], top_n: int = 30) -> Dict[str, Any]:
    edges = []
    for e in events:
        u = e.get("user") or "unknown"
        h = e.get("host") or "unknown"
        if u != "unknown" and h != "unknown":
            edges.append((u, h))

    counts = Counter(edges).most_common(top_n)
    return {
        "edges": [{"user": u, "host": h, "count": c} for ((u, h), c) in counts],
        "unique_users": len({u for (u, _) in edges}),
        "unique_hosts": len({h for (_, h) in edges}),
    }