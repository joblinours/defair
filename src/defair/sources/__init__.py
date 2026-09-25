"""Evidence sources: detect collection / image formats, prepare them for tools.

- ``detect``  — what is this evidence (KAPE, Velociraptor, image, ZIP, ORC…)?
- ``prepare`` — make it usable: in place, extracted, decrypted or carved by Dissect
- ``locate``  — where are the artifacts each tool needs?
"""

from defair.sources.detect import SourceInfo, detect_source

__all__ = ["SourceInfo", "detect_source"]
