---- MODULE link_state ----
\* Tier D state model for milestone-6 link establishment and one encrypted
\* session packet.
\*
\* Covered traces:
\*   request -> accept
\*   request -> duplicate
\*   request -> timeout
\*   reject
\*   established -> encrypted packet accept
\*   established -> encrypted packet reject

EXTENDS Naturals, Sequences

VARIABLES phase, trace, scenario

vars == <<phase, trace, scenario>>

RequestEvent == "link.request"
AcceptedEvent == "link.accepted"
DuplicateEvent == "link.duplicate"
RejectedEvent == "link.rejected"
TimeoutEvent == "link.timeout"
EncryptedAcceptedEvent == "link.encrypted.accepted"
EncryptedRejectedEvent == "link.encrypted.rejected"

Phases ==
    { "start"
    , "pending"
    , "established"
    , "duplicate"
    , "rejected"
    , "timed_out"
    , "packet_accepted"
    , "packet_rejected"
    }

Scenarios ==
    { "request_accept"
    , "request_duplicate"
    , "request_reject"
    , "request_timeout"
    , "encrypted_accept"
    , "encrypted_reject"
    }

Events ==
    { RequestEvent
    , AcceptedEvent
    , DuplicateEvent
    , RejectedEvent
    , TimeoutEvent
    , EncryptedAcceptedEvent
    , EncryptedRejectedEvent
    }

AllowedTraces ==
    { <<>>
    , <<RequestEvent>>
    , <<RequestEvent, AcceptedEvent>>
    , <<RequestEvent, DuplicateEvent>>
    , <<RequestEvent, TimeoutEvent>>
    , <<RejectedEvent>>
    , <<AcceptedEvent>>
    , <<AcceptedEvent, EncryptedAcceptedEvent>>
    , <<AcceptedEvent, EncryptedRejectedEvent>>
    }

Init ==
    /\ scenario \in Scenarios
    /\ IF scenario \in {"encrypted_accept", "encrypted_reject"}
       THEN
           /\ phase = "established"
           /\ trace = <<AcceptedEvent>>
       ELSE
           /\ phase = "start"
           /\ trace = <<>>

RequestStart ==
    /\ phase = "start"
    /\ scenario \in {"request_accept", "request_duplicate", "request_timeout"}
    /\ phase' = "pending"
    /\ trace' = Append(trace, RequestEvent)
    /\ scenario' = scenario

RequestReject ==
    /\ phase = "start"
    /\ scenario = "request_reject"
    /\ phase' = "rejected"
    /\ trace' = Append(trace, RejectedEvent)
    /\ scenario' = scenario

AcceptRequest ==
    /\ phase = "pending"
    /\ scenario = "request_accept"
    /\ phase' = "established"
    /\ trace' = Append(trace, AcceptedEvent)
    /\ scenario' = scenario

DuplicateRequest ==
    /\ phase = "pending"
    /\ scenario = "request_duplicate"
    /\ phase' = "duplicate"
    /\ trace' = Append(trace, DuplicateEvent)
    /\ scenario' = scenario

TimeoutRequest ==
    /\ phase = "pending"
    /\ scenario = "request_timeout"
    /\ phase' = "timed_out"
    /\ trace' = Append(trace, TimeoutEvent)
    /\ scenario' = scenario

EncryptedPacketAccept ==
    /\ phase = "established"
    /\ scenario = "encrypted_accept"
    /\ phase' = "packet_accepted"
    /\ trace' = Append(trace, EncryptedAcceptedEvent)
    /\ scenario' = scenario

EncryptedPacketReject ==
    /\ phase = "established"
    /\ scenario = "encrypted_reject"
    /\ phase' = "packet_rejected"
    /\ trace' = Append(trace, EncryptedRejectedEvent)
    /\ scenario' = scenario

TerminalStutter ==
    /\ \/ phase \in
            { "duplicate"
            , "rejected"
            , "timed_out"
            , "packet_accepted"
            , "packet_rejected"
            }
       \/ /\ phase = "established"
          /\ scenario = "request_accept"
    /\ UNCHANGED vars

Next ==
    \/ RequestStart
    \/ RequestReject
    \/ AcceptRequest
    \/ DuplicateRequest
    \/ TimeoutRequest
    \/ EncryptedPacketAccept
    \/ EncryptedPacketReject
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ trace \in Seq(Events)
    /\ trace \in AllowedTraces
    /\ scenario \in Scenarios

PhaseTraceOK ==
    /\ phase = "start" =>
        /\ trace = <<>>
    /\ phase = "pending" =>
        /\ trace = <<RequestEvent>>
    /\ phase = "established" =>
        /\ trace \in {<<AcceptedEvent>>, <<RequestEvent, AcceptedEvent>>}
    /\ phase = "duplicate" =>
        /\ trace = <<RequestEvent, DuplicateEvent>>
    /\ phase = "rejected" =>
        /\ trace = <<RejectedEvent>>
    /\ phase = "timed_out" =>
        /\ trace = <<RequestEvent, TimeoutEvent>>
    /\ phase = "packet_accepted" =>
        /\ trace = <<AcceptedEvent, EncryptedAcceptedEvent>>
    /\ phase = "packet_rejected" =>
        /\ trace = <<AcceptedEvent, EncryptedRejectedEvent>>

RejectNeverEstablishes ==
    phase = "rejected" =>
        \A i \in DOMAIN trace : trace[i] # AcceptedEvent

TimeoutOnlyAfterRequest ==
    phase = "timed_out" =>
        /\ trace = <<RequestEvent, TimeoutEvent>>
        /\ scenario = "request_timeout"

DuplicateOnlyAfterRequest ==
    phase = "duplicate" =>
        /\ trace = <<RequestEvent, DuplicateEvent>>
        /\ scenario = "request_duplicate"

EncryptedPacketRequiresEstablished ==
    \A i \in DOMAIN trace :
        trace[i] \in {EncryptedAcceptedEvent, EncryptedRejectedEvent} =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = AcceptedEvent

EncryptedAcceptAndRejectExclusive ==
    ~(
        /\ \E i \in DOMAIN trace : trace[i] = EncryptedAcceptedEvent
        /\ \E j \in DOMAIN trace : trace[j] = EncryptedRejectedEvent
    )

====
