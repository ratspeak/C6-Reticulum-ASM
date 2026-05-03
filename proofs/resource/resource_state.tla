---- MODULE resource_state ----
\* Tier D state model for milestone-7 resource/channel plaintext dispatch.
\*
\* Covered traces:
\*   resource.advertised
\*   resource.advertised -> resource.part_accepted
\*   resource.advertised -> resource.part_accepted -> resource.part_duplicate
\*   resource.advertised -> resource.part_accepted -> resource.complete
\*   resource.rejected
\*   channel.accepted

EXTENDS Naturals, Sequences

VARIABLES phase, trace, scenario, received_count

vars == <<phase, trace, scenario, received_count>>

ResourceAdvertisedEvent == "resource.advertised"
PartAcceptedEvent == "resource.part_accepted"
PartDuplicateEvent == "resource.part_duplicate"
ResourceCompleteEvent == "resource.complete"
ResourceRejectedEvent == "resource.rejected"
ChannelAcceptedEvent == "channel.accepted"

Phases ==
    { "start"
    , "advertised"
    , "part_received"
    , "duplicate"
    , "complete"
    , "rejected"
    , "channel_accepted"
    }

ResourceScenarios ==
    { "advertise_only"
    , "advertise_accept"
    , "advertise_duplicate"
    , "advertise_complete"
    }

RejectScenarios ==
    { "reject_advertisement"
    , "reject_part"
    , "reject_channel"
    }

Scenarios == ResourceScenarios \cup RejectScenarios \cup {"channel_accept"}

Events ==
    { ResourceAdvertisedEvent
    , PartAcceptedEvent
    , PartDuplicateEvent
    , ResourceCompleteEvent
    , ResourceRejectedEvent
    , ChannelAcceptedEvent
    }

AllowedTraces ==
    { <<>>
    , <<ResourceAdvertisedEvent>>
    , <<ResourceAdvertisedEvent, PartAcceptedEvent>>
    , <<ResourceAdvertisedEvent, PartAcceptedEvent, PartDuplicateEvent>>
    , <<ResourceAdvertisedEvent, PartAcceptedEvent, ResourceCompleteEvent>>
    , <<ResourceRejectedEvent>>
    , <<ChannelAcceptedEvent>>
    }

Init ==
    /\ phase = "start"
    /\ trace = <<>>
    /\ scenario \in Scenarios
    /\ received_count = 0

Advertise ==
    /\ phase = "start"
    /\ scenario \in ResourceScenarios
    /\ phase' = "advertised"
    /\ trace' = Append(trace, ResourceAdvertisedEvent)
    /\ received_count' = 0
    /\ scenario' = scenario

AcceptPart ==
    /\ phase = "advertised"
    /\ scenario \in
        { "advertise_accept"
        , "advertise_duplicate"
        , "advertise_complete"
        }
    /\ phase' = "part_received"
    /\ trace' = Append(trace, PartAcceptedEvent)
    /\ received_count' = 1
    /\ scenario' = scenario

DuplicatePart ==
    /\ phase = "part_received"
    /\ scenario = "advertise_duplicate"
    /\ phase' = "duplicate"
    /\ trace' = Append(trace, PartDuplicateEvent)
    /\ received_count' = received_count
    /\ scenario' = scenario

CompleteTransfer ==
    /\ phase = "part_received"
    /\ scenario = "advertise_complete"
    /\ phase' = "complete"
    /\ trace' = Append(trace, ResourceCompleteEvent)
    /\ received_count' = 2
    /\ scenario' = scenario

RejectPlaintext ==
    /\ phase = "start"
    /\ scenario \in RejectScenarios
    /\ phase' = "rejected"
    /\ trace' = Append(trace, ResourceRejectedEvent)
    /\ received_count' = 0
    /\ scenario' = scenario

AcceptChannel ==
    /\ phase = "start"
    /\ scenario = "channel_accept"
    /\ phase' = "channel_accepted"
    /\ trace' = Append(trace, ChannelAcceptedEvent)
    /\ received_count' = 0
    /\ scenario' = scenario

TerminalStutter ==
    /\ \/ phase \in {"duplicate", "complete", "rejected", "channel_accepted"}
       \/ /\ phase = "advertised"
          /\ scenario = "advertise_only"
       \/ /\ phase = "part_received"
          /\ scenario = "advertise_accept"
    /\ UNCHANGED vars

Next ==
    \/ Advertise
    \/ AcceptPart
    \/ DuplicatePart
    \/ CompleteTransfer
    \/ RejectPlaintext
    \/ AcceptChannel
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ trace \in Seq(Events)
    /\ trace \in AllowedTraces
    /\ scenario \in Scenarios
    /\ received_count \in 0..2

PhaseTraceOK ==
    /\ phase = "start" =>
        /\ trace = <<>>
        /\ received_count = 0
    /\ phase = "advertised" =>
        /\ trace = <<ResourceAdvertisedEvent>>
        /\ received_count = 0
    /\ phase = "part_received" =>
        /\ trace = <<ResourceAdvertisedEvent, PartAcceptedEvent>>
        /\ received_count = 1
    /\ phase = "duplicate" =>
        /\ trace = <<ResourceAdvertisedEvent, PartAcceptedEvent, PartDuplicateEvent>>
        /\ received_count = 1
    /\ phase = "complete" =>
        /\ trace = <<ResourceAdvertisedEvent, PartAcceptedEvent, ResourceCompleteEvent>>
        /\ received_count = 2
    /\ phase = "rejected" =>
        /\ trace = <<ResourceRejectedEvent>>
        /\ received_count = 0
    /\ phase = "channel_accepted" =>
        /\ trace = <<ChannelAcceptedEvent>>
        /\ received_count = 0

RejectNeverAdvances ==
    phase = "rejected" =>
        /\ trace = <<ResourceRejectedEvent>>
        /\ received_count = 0
        /\ \A i \in DOMAIN trace :
            trace[i] \notin {ResourceAdvertisedEvent, PartAcceptedEvent, ResourceCompleteEvent}

ResourceProgressRequiresAdvertise ==
    \A i \in DOMAIN trace :
        trace[i] \in {PartAcceptedEvent, PartDuplicateEvent, ResourceCompleteEvent} =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = ResourceAdvertisedEvent

DuplicateRequiresAcceptedPart ==
    \A i \in DOMAIN trace :
        trace[i] = PartDuplicateEvent =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = PartAcceptedEvent

CompleteRequiresAcceptedPart ==
    phase = "complete" =>
        /\ received_count = 2
        /\ \E i \in DOMAIN trace :
            /\ trace[i] = PartAcceptedEvent
        /\ \E j \in DOMAIN trace :
            /\ trace[j] = ResourceCompleteEvent

DuplicateAndCompleteExclusive ==
    ~(
        /\ \E i \in DOMAIN trace : trace[i] = PartDuplicateEvent
        /\ \E j \in DOMAIN trace : trace[j] = ResourceCompleteEvent
    )

ChannelExclusiveWithResource ==
    phase = "channel_accepted" =>
        /\ trace = <<ChannelAcceptedEvent>>
        /\ \A i \in DOMAIN trace :
            trace[i] \notin
                { ResourceAdvertisedEvent
                , PartAcceptedEvent
                , PartDuplicateEvent
                , ResourceCompleteEvent
                , ResourceRejectedEvent
                }

====
