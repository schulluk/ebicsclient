"""Guard the README's links so they never break on PyPI.

PyPI renders the README as a package's ``long_description`` in isolation and resolves any
repo-relative link (``docs/13-...md``, ``LICENSE.md``) against ``https://pypi.org/project/…``,
which 404s. The links only resolve on GitHub, where the repo supplies the base. So every
in-repo reference in the README must be an **absolute** ``https://github.com/.../blob/main/…``
URL. These tests fail closed if a relative link creeps back in, and verify each absolute repo
link points to a file that actually exists.
"""

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_README = _REPO_ROOT / "README.md"
_BLOB_PREFIX = "https://github.com/schulluk/ebicsclient/blob/main/"

# Markdown inline links: the "(target)" of a "[text](target)". Bare, un-bracketed URLs in prose
# are not links a reader clicks through the rendered page, so we only police the [](…) form.
_LINK = re.compile(r"\]\(([^)]+)\)")


def _readme_link_targets() -> list[str]:
    return _LINK.findall(_README.read_text(encoding="utf-8"))


def test_readme_has_no_repo_relative_links() -> None:
    # A relative link is anything that is not an absolute URL or a pure in-page anchor. Those are
    # exactly the ones PyPI cannot resolve.
    relative = [
        target
        for target in _readme_link_targets()
        if not target.startswith(("http://", "https://", "mailto:", "#"))
    ]
    assert not relative, (
        f"README contains repo-relative link(s) that break on PyPI: {relative}. "
        f"Use an absolute {_BLOB_PREFIX}… URL instead."
    )


@pytest.mark.parametrize(
    "target",
    [t for t in _readme_link_targets() if t.startswith(_BLOB_PREFIX)],
)
def test_readme_repo_links_point_at_existing_files(target: str) -> None:
    relative_path = target[len(_BLOB_PREFIX) :]
    assert (_REPO_ROOT / relative_path).is_file(), (
        f"README links to {target!r}, but {relative_path!r} does not exist in the repo — "
        f"a dead link or a typo."
    )
