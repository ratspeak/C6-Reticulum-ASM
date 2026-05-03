---- MODULE announce_tx ----
\* Tier D trace model for milestone-3 announce transmission.
\*
\* The model is intentionally small: it specifies the observable trace shape
\* that the qemu harness should accept from the asm announce path.
\*
\* Successful path:
\*   identity.ready -> announce.built -> kiss.tx_frame
\*
\* Build-error paths:
\*   identity.ready -> announce.overflow
\*   identity.ready -> announce.error
\*
\* There is no transition that can emit kiss.tx_frame before announce.built.

EXTENDS Naturals, Sequences

VARIABLES phase, trace, build_status, error_kind

vars == <<phase, trace, build_status, error_kind>>

IdentityReadyEvent == "identity.ready"
AnnounceBuiltEvent == "announce.built"
KissTxFrameEvent == "kiss.tx_frame"
AnnounceOverflowEvent == "announce.overflow"
AnnounceErrorEvent == "announce.error"

Phases == {"start", "identity_ready", "built", "build_error", "sent"}
BuildStatuses == {"none", "ok", "overflow", "invalid"}
ErrorKinds == {"none", "overflow", "invalid"}
Events ==
    { IdentityReadyEvent
    , AnnounceBuiltEvent
    , KissTxFrameEvent
    , AnnounceOverflowEvent
    , AnnounceErrorEvent
    }

AllowedTraces ==
    { <<>>
    , <<IdentityReadyEvent>>
    , <<IdentityReadyEvent, AnnounceBuiltEvent>>
    , <<IdentityReadyEvent, AnnounceBuiltEvent, KissTxFrameEvent>>
    , <<IdentityReadyEvent, AnnounceOverflowEvent>>
    , <<IdentityReadyEvent, AnnounceErrorEvent>>
    }

Init ==
    /\ phase = "start"
    /\ trace = <<>>
    /\ build_status = "none"
    /\ error_kind = "none"

IdentityReady ==
    /\ phase = "start"
    /\ phase' = "identity_ready"
    /\ trace' = Append(trace, IdentityReadyEvent)
    /\ build_status' = build_status
    /\ error_kind' = error_kind

BuildOk ==
    /\ phase = "identity_ready"
    /\ phase' = "built"
    /\ trace' = Append(trace, AnnounceBuiltEvent)
    /\ build_status' = "ok"
    /\ error_kind' = "none"

\* announce_build returns a negative overflow errno when the caller-provided
\* raw packet capacity cannot hold the HEADER_1 announce wire image.
BuildOverflow ==
    /\ phase = "identity_ready"
    /\ phase' = "build_error"
    /\ trace' = Append(trace, AnnounceOverflowEvent)
    /\ build_status' = "overflow"
    /\ error_kind' = "overflow"

\* announce_build may also reject invalid public inputs, such as a null app_data
\* pointer paired with a non-zero app_data_len.
BuildInvalid ==
    /\ phase = "identity_ready"
    /\ phase' = "build_error"
    /\ trace' = Append(trace, AnnounceErrorEvent)
    /\ build_status' = "invalid"
    /\ error_kind' = "invalid"

KissTxFrame ==
    /\ phase = "built"
    /\ build_status = "ok"
    /\ phase' = "sent"
    /\ trace' = Append(trace, KissTxFrameEvent)
    /\ build_status' = build_status
    /\ error_kind' = error_kind

TerminalStutter ==
    /\ phase \in {"build_error", "sent"}
    /\ UNCHANGED vars

Next ==
    \/ IdentityReady
    \/ BuildOk
    \/ BuildOverflow
    \/ BuildInvalid
    \/ KissTxFrame
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ trace \in Seq(Events)
    /\ trace \in AllowedTraces
    /\ build_status \in BuildStatuses
    /\ error_kind \in ErrorKinds

PhaseTraceOK ==
    /\ phase = "start" =>
        /\ trace = <<>>
        /\ build_status = "none"
        /\ error_kind = "none"
    /\ phase = "identity_ready" =>
        /\ trace = <<IdentityReadyEvent>>
        /\ build_status = "none"
        /\ error_kind = "none"
    /\ phase = "built" =>
        /\ trace = <<IdentityReadyEvent, AnnounceBuiltEvent>>
        /\ build_status = "ok"
        /\ error_kind = "none"
    /\ phase = "sent" =>
        /\ trace = <<IdentityReadyEvent, AnnounceBuiltEvent, KissTxFrameEvent>>
        /\ build_status = "ok"
        /\ error_kind = "none"
    /\ phase = "build_error" =>
        /\ trace \in
            { <<IdentityReadyEvent, AnnounceOverflowEvent>>
            , <<IdentityReadyEvent, AnnounceErrorEvent>>
            }
        /\ build_status \in {"overflow", "invalid"}
        /\ error_kind = build_status

TraceStartsWithIdentity ==
    Len(trace) = 0 \/ trace[1] = IdentityReadyEvent

TxRequiresPriorBuild ==
    \A i \in DOMAIN trace :
        trace[i] = KissTxFrameEvent =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = AnnounceBuiltEvent

SentRequiresSuccessfulBuild ==
    phase = "sent" =>
        /\ build_status = "ok"
        /\ error_kind = "none"

BuildErrorStopsBeforeTx ==
    phase = "build_error" =>
        /\ build_status \in {"overflow", "invalid"}
        /\ \A i \in DOMAIN trace : trace[i] # KissTxFrameEvent

====
