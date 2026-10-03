# SPDX-License-Identifier: Apache-2.0
"""Read large declared outputs without allowing path, link, or file-type substitutions."""

import base64
import os

import pytest
from test_execution_ledger import fence, plan

from ficc.execution.outputs import collect
from ficc.execution.protocol import Read


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_large_sparse_outputs_use_bounded_offsets_with_distinct_files(tmp_path, count):
    for index in range(count):
        root = tmp_path / str(index)
        work = root / "runtime/work"
        work.mkdir(parents=True)
        data = f"row-{index}".encode()
        offset = (20 + index) * 1024**3
        path = work / "result.bin"
        with path.open("wb") as stream:
            stream.seek(offset)
            stream.write(data)
        item = plan(index)
        value = item.model_dump()
        value["job"]["outputs"] = [{"name": "result", "path": "result.bin"}]
        ctx = {"directory": str(root), "binding": {"device": root.stat().st_dev}, "plan": value}
        request = Read(**fence(item).model_dump(), object="output:result", offset=offset, length=1024)
        result = collect(ctx, request, True)
        assert base64.b64decode(result["data"]) == data and result["total_bytes"] == offset + len(data)
        assert result["next_offset"] == result["total_bytes"] and result["eof"] and result["complete"]
        with pytest.raises(ValueError, match="confirmed workload cleanup"):
            collect(ctx, request, False)
        path.unlink()


@pytest.mark.parametrize("change", ["symlink", "parent_symlink", "hardlink", "fifo", "directory", "other_device"])
def test_output_substitutions_are_refused_before_read(tmp_path, change):
    root = tmp_path / "attempt"
    work = root / "runtime/work"
    work.mkdir(parents=True)
    (work / "nested").mkdir()
    path = work / "nested/result"
    path.write_bytes(b"owned result")
    item = plan(0)
    value = item.model_dump()
    value["job"]["outputs"] = [{"name": "result", "path": "nested/result"}]
    ctx = {"directory": str(root), "binding": {"device": root.stat().st_dev}, "plan": value}
    request = Read(**fence(item).model_dump(), object="output:result", offset=0, length=64)
    assert collect(ctx, request, True)["total_bytes"] == 12
    if change == "symlink":
        path.unlink()
        path.symlink_to("/etc/passwd")
    elif change == "parent_symlink":
        path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to("/etc", target_is_directory=True)
    elif change == "hardlink":
        os.link(path, work / "alias")
    elif change in {"fifo", "directory"}:
        path.unlink()
        if change == "fifo":
            os.mkfifo(path)
        else:
            path.mkdir()
    else:
        ctx["binding"]["device"] += 1
    with pytest.raises((ValueError, OSError)):
        collect(ctx, request, True)
