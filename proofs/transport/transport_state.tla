---- MODULE transport_state ----
\* Tier D state model for milestone-5 inbound announce processing.
\*
\* The observable transport log traces are intentionally status-only:
\*   valid new/update/evict: transport.announce_valid -> transport.path_updated
\*   invalid parse/validate: transport.announce_invalid
\*
\* Duplicate and eviction cases share the same runtime logs as a new accepted
\* path, but the model tracks the selected path_case state so TLC explores
\* all three update paths.

EXTENDS Naturals, Sequences

VARIABLES phase, trace, scenario, path_case

vars == <<phase, trace, scenario, path_case>>

AnnounceValidEvent == "transport.announce_valid"
AnnounceInvalidEvent == "transport.announce_invalid"
PathUpdatedEvent == "transport.path_updated"

Phases == {"start", "parsed", "validated", "looked_up", "accepted", "rejected"}
Scenarios == {"new", "duplicate", "evict", "invalid_parse", "invalid_validate"}
PathCases == {"none", "new", "duplicate", "evict"}
Events == {AnnounceValidEvent, AnnounceInvalidEvent, PathUpdatedEvent}

AllowedTraces ==
    { <<>>
    , <<AnnounceInvalidEvent>>
    , <<AnnounceValidEvent>>
    , <<AnnounceValidEvent, PathUpdatedEvent>>
    }

Init ==
    /\ phase = "start"
    /\ trace = <<>>
    /\ scenario \in Scenarios
    /\ path_case = "none"

ParseReject ==
    /\ phase = "start"
    /\ scenario = "invalid_parse"
    /\ phase' = "rejected"
    /\ trace' = Append(trace, AnnounceInvalidEvent)
    /\ path_case' = path_case
    /\ scenario' = scenario

ParseOk ==
    /\ phase = "start"
    /\ scenario # "invalid_parse"
    /\ phase' = "parsed"
    /\ UNCHANGED <<trace, scenario, path_case>>

ValidateReject ==
    /\ phase = "parsed"
    /\ scenario = "invalid_validate"
    /\ phase' = "rejected"
    /\ trace' = Append(trace, AnnounceInvalidEvent)
    /\ path_case' = path_case
    /\ scenario' = scenario

ValidateOk ==
    /\ phase = "parsed"
    /\ scenario \in {"new", "duplicate", "evict"}
    /\ phase' = "validated"
    /\ trace' = Append(trace, AnnounceValidEvent)
    /\ path_case' = path_case
    /\ scenario' = scenario

LookupNew ==
    /\ phase = "validated"
    /\ scenario = "new"
    /\ phase' = "looked_up"
    /\ path_case' = "new"
    /\ UNCHANGED <<trace, scenario>>

LookupDuplicate ==
    /\ phase = "validated"
    /\ scenario = "duplicate"
    /\ phase' = "looked_up"
    /\ path_case' = "duplicate"
    /\ UNCHANGED <<trace, scenario>>

LookupEvict ==
    /\ phase = "validated"
    /\ scenario = "evict"
    /\ phase' = "looked_up"
    /\ path_case' = "evict"
    /\ UNCHANGED <<trace, scenario>>

UpdatePath ==
    /\ phase = "looked_up"
    /\ path_case \in {"new", "duplicate", "evict"}
    /\ phase' = "accepted"
    /\ trace' = Append(trace, PathUpdatedEvent)
    /\ UNCHANGED <<scenario, path_case>>

TerminalStutter ==
    /\ phase \in {"accepted", "rejected"}
    /\ UNCHANGED vars

Next ==
    \/ ParseReject
    \/ ParseOk
    \/ ValidateReject
    \/ ValidateOk
    \/ LookupNew
    \/ LookupDuplicate
    \/ LookupEvict
    \/ UpdatePath
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ trace \in Seq(Events)
    /\ trace \in AllowedTraces
    /\ scenario \in Scenarios
    /\ path_case \in PathCases

RejectStopsBeforePathUpdate ==
    phase = "rejected" =>
        /\ trace = <<AnnounceInvalidEvent>>
        /\ \A i \in DOMAIN trace : trace[i] # PathUpdatedEvent

PathUpdateRequiresValidAnnounce ==
    \A i \in DOMAIN trace :
        trace[i] = PathUpdatedEvent =>
            /\ \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = AnnounceValidEvent
            /\ phase = "accepted"

AcceptedHasPathCase ==
    phase = "accepted" => path_case \in {"new", "duplicate", "evict"}

DuplicateCaseCovered ==
    scenario = "duplicate" /\ phase = "accepted" =>
        /\ path_case = "duplicate"
        /\ trace = <<AnnounceValidEvent, PathUpdatedEvent>>

EvictCaseCovered ==
    scenario = "evict" /\ phase = "accepted" =>
        /\ path_case = "evict"
        /\ trace = <<AnnounceValidEvent, PathUpdatedEvent>>

NewCaseCovered ==
    scenario = "new" /\ phase = "accepted" =>
        /\ path_case = "new"
        /\ trace = <<AnnounceValidEvent, PathUpdatedEvent>>

====
