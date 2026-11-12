# Weighted BinAA selected-coordinate overlay

Source: linghe-yang/Secure-Distributed-Computing-Protocols,
revision 731e0b81166125ea756c5a047ab813ccb8af7111, consensus/wbinaa.

The existing Start interface and full-vector wire format are unchanged.
StartSelected / State::start_selected run only agreed physical-dealer
coordinates. Inactive outputs are zero and no messages are generated for those
coordinates. Voting membership, thresholds, precision, and relaying rules are
unchanged. Messages arriving before local start remain buffered as before.

The caller must use an identical selected set at honest nodes; HashRand derives
it from the previous pool word after its target Gather release gate. This
overlay does not turn selected coordinates into a smaller voter committee.

Tests retain all upstream protocol cases and add a selected-coordinate case
with a silent weighted participant.
