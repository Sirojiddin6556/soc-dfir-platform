# PCAPNG multi-section interface fixture

Purpose: validate section-local interfaces, default/decimal/binary `if_tsresol`, signed `if_tsoffset`, and packet provenance.

Origin: synthetic deterministic fixture generated for Phase 3 acceptance. It contains no production or user traffic.

The `.pcapng.hex` file is the immutable text representation used by the acceptance test. The test decodes it into the exact on-disk bytes before invoking the streaming parser.

Expected semantic results are recorded in `pcapng_multi_section_interfaces.expected.json`.

Immutable fixture BLAKE3:

```text
b39fc9fbfbe5390d8beebc2061d936c3dab60be2892a03274aa1d43729a03f16
```

Immutable fixture SHA-256:

```text
c3947a669adbe26137b08c0fe8a31dbea2c1143ec2b114c04a3185ea716899cb
```
