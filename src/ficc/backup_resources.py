# SPDX-License-Identifier: Apache-2.0
"""Validate project resource references and retained operation ownership."""

import json

from .resource_store import OWNED_TABLES


def records(db):
    users = {row[0] for row in db.execute("SELECT id FROM identities")}
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    nodes = {row[0] for row in db.execute("SELECT id FROM nodes")} | {
        row[0] for row in db.execute("SELECT id FROM module_windows_endpoints")}
    roots = {row[0]: json.loads(row[1]).get("node_id") for row in db.execute("SELECT id,value FROM file_roots")}
    for project, raw_nodes, raw_roots, revision in db.execute("SELECT project_id,nodes,roots,revision FROM project_resources"):
        assigned_nodes, assigned_roots = json.loads(raw_nodes), json.loads(raw_roots)
        if (project not in projects or type(revision) is not int or not 1 <= revision <= 2**53 - 1
                or not isinstance(assigned_nodes, list) or not isinstance(assigned_roots, list)
                or any(not isinstance(item, str) for item in assigned_nodes + assigned_roots)
                or len(assigned_nodes) != len(set(assigned_nodes)) or len(assigned_roots) != len(set(assigned_roots))
                or set(assigned_nodes) - nodes or set(assigned_roots) - roots.keys()
                or any(roots[root] is not None and roots[root] not in assigned_nodes for root in assigned_roots)):
            raise ValueError("A project resource assignment is invalid.")
    for table in sorted(OWNED_TABLES):
        for subject, project in db.execute(f"SELECT subject_id,project_id FROM {table}"):
            if subject not in users or project not in projects:
                raise ValueError("A retained operation has an invalid identity or project.")
