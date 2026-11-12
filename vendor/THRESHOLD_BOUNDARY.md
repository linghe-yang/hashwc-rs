# Integer-weight threshold overlay

`sdc-types` and `sdc-config` are copied from
https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols
at commit `731e0b81166125ea756c5a047ab813ccb8af7111`.
They are source patches for the upstream packages `types` and `config`.
Version 0.1.1 distinguishes these local copies from this repository's existing
packages of the same names. The Cargo Git cache is never modified.

The membership convention is corrupt weight B < T and 3(T-1) < W for integer
weights. Default maximal resilience uses T=ceil(W/3), so the fault bound is
ceil(W/3)-1=floor((W-1)/3). The membership quorum field W-T is EXCLUSIVE:
RA, Gather, RBC, AVID and both BinAA certificate stages require weight > W-T.
Relay and reconstruction thresholds remain inclusive >= T.

Source changes in types are confined to weighted membership and its boundary
regressions. Config retains its upstream behavior and uses the patched types.
Manifest changes resolve local types/config without pulling a second, unpatched
weighted membership into the shared primitives.

Explicit smaller T remains supported and provides the explicitly smaller fault
budget T-1; it does not claim maximal resilience for the given weights.
Previously reduced inputs and frozen benchmark plans must be regenerated from
their ORIGINAL weights and the corrected threshold, together with any access
structure preservation certificates. Merely incrementing a reduced threshold
does not prove equivalence to the original real-world policy.
