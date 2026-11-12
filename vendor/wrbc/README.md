# Local WRBC overlay

Source: `broadcast/wrbc` from
<https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols/tree/731e0b81166125ea756c5a047ab813ccb8af7111/broadcast/wrbc>.
Dependencies remain pinned to the same revision, with this workspace's existing
WAVID/util overlays. Existing constructors retain their original behavior.

The optional `*_and_local_reuse` constructors keep the dealer's canonical
public encoding. Only the original storage completion quorum, naming the same
root, can deliver it. The dealer's start may be arbitrarily delayed: completion
alone cannot deliver or trigger a self download. No network payload can fill
the local file slot. Receivers still retrieve normally. Output does not stop
ACK/READY processing, local storage, or service of late retrieval requests.

This feature changes neither wire messages nor CSS validation/reconstruction.
The coin caller binds its explicit reuse option in the session configuration.
