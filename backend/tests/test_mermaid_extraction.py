from app.services.mermaid_extraction import extract_mermaid_blocks, strip_mermaid_blocks

MULTI_BLOCK_DOC = """\
# Design

Some prose here.

```mermaid
graph TD
    A --> B
```

More prose in between.

```mmd
flowchart LR
    C --> D
```

Trailing prose.
"""


def test_extracts_multiple_blocks_in_order():
    blocks = extract_mermaid_blocks(MULTI_BLOCK_DOC)
    assert len(blocks) == 2
    assert blocks[0].index == 0
    assert "A --> B" in blocks[0].source
    assert blocks[1].index == 1
    assert "C --> D" in blocks[1].source


def test_ignores_non_mermaid_fences():
    doc = """\
```python
print("not mermaid")
```

```mermaid
graph TD; A-->B
```
"""
    blocks = extract_mermaid_blocks(doc)
    assert len(blocks) == 1
    assert "A-->B" in blocks[0].source


NESTED_FENCE_DOC = """\
The outer block below is a 4-backtick "text" fence documenting how to write
a mermaid diagram; the 3-backtick mermaid fence quoted inside it is literal
content of the outer fence and must not be treated as a real block.

````text
Example of writing a mermaid block:
```mermaid
graph TD; FAKE-->BLOCK
```
````

```mermaid
graph TD; REAL-->BLOCK
```
"""


def test_nested_fence_inside_longer_wrapper_is_not_extracted():
    blocks = extract_mermaid_blocks(NESTED_FENCE_DOC)
    assert len(blocks) == 1
    assert "REAL-->BLOCK" in blocks[0].source
    assert "FAKE" not in blocks[0].source


def test_unterminated_fence_at_eof_is_still_captured():
    doc = "prose\n```mermaid\ngraph TD; A-->B"
    blocks = extract_mermaid_blocks(doc)
    assert len(blocks) == 1
    assert "A-->B" in blocks[0].source


def test_strip_mermaid_blocks_removes_only_mermaid_fences():
    stripped = strip_mermaid_blocks(MULTI_BLOCK_DOC)
    assert "graph TD" not in stripped
    assert "flowchart LR" not in stripped
    assert "Some prose here." in stripped
    assert "More prose in between." in stripped
    assert "Trailing prose." in stripped


def test_strip_mermaid_blocks_keeps_other_fenced_code():
    doc = """\
```python
print("keep me")
```

```mermaid
graph TD; A-->B
```
"""
    stripped = strip_mermaid_blocks(doc)
    assert 'print("keep me")' in stripped
    assert "A-->B" not in stripped
