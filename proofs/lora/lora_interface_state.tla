---- MODULE lora_interface_state ----
\* Tier D state model for milestone-8 native LoRa interface bring-up and
\* one packet-level TX/RX action.
\*
\* Covered traces:
\*   reset -> configure -> idle
\*   reset -> init_error
\*   reset -> configure -> idle -> tx_start -> tx_done
\*   reset -> configure -> idle -> tx_start -> tx_timeout -> recovery
\*   reset -> configure -> idle -> rx_frame
\*   reset -> configure -> idle -> rx_error -> recovery

EXTENDS Naturals, Sequences

VARIABLES phase, trace, scenario, rx_armed

vars == <<phase, trace, scenario, rx_armed>>

ResetEvent == "lora.reset"
ConfiguredEvent == "lora.configured"
InitErrorEvent == "lora.init_error"
IdleEvent == "lora.idle"
TxStartEvent == "lora.tx_start"
TxDoneEvent == "lora.tx_done"
TxTimeoutEvent == "lora.tx_timeout"
RxFrameEvent == "lora.rx_frame"
RxErrorEvent == "lora.rx_error"
RecoveryEvent == "lora.recovery"

Phases ==
    { "start"
    , "reset"
    , "configured"
    , "idle"
    , "init_failed"
    , "tx_active"
    , "tx_done"
    , "tx_timeout"
    , "rx_frame"
    , "rx_error"
    , "recovered"
    }

Scenarios ==
    { "configure_success"
    , "configure_error"
    , "tx_done"
    , "tx_timeout"
    , "rx_packet"
    , "rx_error"
    , "idle_no_packet"
    }

Events ==
    { ResetEvent
    , ConfiguredEvent
    , InitErrorEvent
    , IdleEvent
    , TxStartEvent
    , TxDoneEvent
    , TxTimeoutEvent
    , RxFrameEvent
    , RxErrorEvent
    , RecoveryEvent
    }

TrafficEvents ==
    { TxStartEvent
    , TxDoneEvent
    , TxTimeoutEvent
    , RxFrameEvent
    , RxErrorEvent
    }

AllowedTraces ==
    { <<>>
    , <<ResetEvent>>
    , <<ResetEvent, InitErrorEvent>>
    , <<ResetEvent, ConfiguredEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxDoneEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxTimeoutEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxTimeoutEvent, RecoveryEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, RxFrameEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, RxErrorEvent>>
    , <<ResetEvent, ConfiguredEvent, IdleEvent, RxErrorEvent, RecoveryEvent>>
    }

Init ==
    /\ phase = "start"
    /\ trace = <<>>
    /\ scenario \in Scenarios
    /\ rx_armed = FALSE

ResetRadio ==
    /\ phase = "start"
    /\ phase' = "reset"
    /\ trace' = Append(trace, ResetEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

ConfigureOk ==
    /\ phase = "reset"
    /\ scenario # "configure_error"
    /\ phase' = "configured"
    /\ trace' = Append(trace, ConfiguredEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

ConfigureError ==
    /\ phase = "reset"
    /\ scenario = "configure_error"
    /\ phase' = "init_failed"
    /\ trace' = Append(trace, InitErrorEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

EnterIdle ==
    /\ phase = "configured"
    /\ phase' = "idle"
    /\ trace' = Append(trace, IdleEvent)
    /\ rx_armed' = TRUE
    /\ scenario' = scenario

StartTx ==
    /\ phase = "idle"
    /\ scenario \in {"tx_done", "tx_timeout"}
    /\ phase' = "tx_active"
    /\ trace' = Append(trace, TxStartEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

CompleteTx ==
    /\ phase = "tx_active"
    /\ scenario = "tx_done"
    /\ phase' = "tx_done"
    /\ trace' = Append(trace, TxDoneEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

TimeoutTx ==
    /\ phase = "tx_active"
    /\ scenario = "tx_timeout"
    /\ phase' = "tx_timeout"
    /\ trace' = Append(trace, TxTimeoutEvent)
    /\ rx_armed' = FALSE
    /\ scenario' = scenario

ReceiveFrame ==
    /\ phase = "idle"
    /\ scenario = "rx_packet"
    /\ phase' = "rx_frame"
    /\ trace' = Append(trace, RxFrameEvent)
    /\ rx_armed' = TRUE
    /\ scenario' = scenario

ReceiveError ==
    /\ phase = "idle"
    /\ scenario = "rx_error"
    /\ phase' = "rx_error"
    /\ trace' = Append(trace, RxErrorEvent)
    /\ rx_armed' = TRUE
    /\ scenario' = scenario

RecoverFromError ==
    /\ \/ /\ phase = "tx_timeout"
          /\ scenario = "tx_timeout"
       \/ /\ phase = "rx_error"
          /\ scenario = "rx_error"
    /\ phase' = "recovered"
    /\ trace' = Append(trace, RecoveryEvent)
    /\ rx_armed' = TRUE
    /\ scenario' = scenario

TerminalStutter ==
    /\ \/ phase \in {"init_failed", "tx_done", "rx_frame", "recovered"}
       \/ /\ phase = "idle"
          /\ scenario \in {"configure_success", "idle_no_packet"}
    /\ UNCHANGED vars

Next ==
    \/ ResetRadio
    \/ ConfigureOk
    \/ ConfigureError
    \/ EnterIdle
    \/ StartTx
    \/ CompleteTx
    \/ TimeoutTx
    \/ ReceiveFrame
    \/ ReceiveError
    \/ RecoverFromError
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ trace \in Seq(Events)
    /\ trace \in AllowedTraces
    /\ scenario \in Scenarios
    /\ rx_armed \in BOOLEAN

PhaseTraceOK ==
    /\ phase = "start" =>
        /\ trace = <<>>
        /\ rx_armed = FALSE
    /\ phase = "reset" =>
        /\ trace = <<ResetEvent>>
        /\ rx_armed = FALSE
    /\ phase = "configured" =>
        /\ trace = <<ResetEvent, ConfiguredEvent>>
        /\ rx_armed = FALSE
    /\ phase = "idle" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent>>
        /\ rx_armed = TRUE
    /\ phase = "init_failed" =>
        /\ trace = <<ResetEvent, InitErrorEvent>>
        /\ rx_armed = FALSE
    /\ phase = "tx_active" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent>>
        /\ rx_armed = FALSE
    /\ phase = "tx_done" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxDoneEvent>>
        /\ rx_armed = FALSE
    /\ phase = "tx_timeout" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxTimeoutEvent>>
        /\ rx_armed = FALSE
    /\ phase = "rx_frame" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent, RxFrameEvent>>
        /\ rx_armed = TRUE
    /\ phase = "rx_error" =>
        /\ trace = <<ResetEvent, ConfiguredEvent, IdleEvent, RxErrorEvent>>
        /\ rx_armed = TRUE
    /\ phase = "recovered" =>
        /\ trace \in
            { <<ResetEvent, ConfiguredEvent, IdleEvent, TxStartEvent, TxTimeoutEvent, RecoveryEvent>>
            , <<ResetEvent, ConfiguredEvent, IdleEvent, RxErrorEvent, RecoveryEvent>>
            }
        /\ rx_armed = TRUE

TrafficRequiresConfigured ==
    \A i \in DOMAIN trace :
        trace[i] \in TrafficEvents =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = ConfiguredEvent

TxDoneAndTimeoutExclusive ==
    ~(
        /\ \E i \in DOMAIN trace : trace[i] = TxDoneEvent
        /\ \E j \in DOMAIN trace : trace[j] = TxTimeoutEvent
    )

TxCompletionRequiresTxStart ==
    \A i \in DOMAIN trace :
        trace[i] \in {TxDoneEvent, TxTimeoutEvent} =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] = TxStartEvent

RxFrameAndErrorExclusive ==
    ~(
        /\ \E i \in DOMAIN trace : trace[i] = RxFrameEvent
        /\ \E j \in DOMAIN trace : trace[j] = RxErrorEvent
    )

RecoveryOnlyAfterErrorOrTimeout ==
    \A i \in DOMAIN trace :
        trace[i] = RecoveryEvent =>
            \E j \in DOMAIN trace :
                /\ j < i
                /\ trace[j] \in {TxTimeoutEvent, RxErrorEvent}

InitFailureStopsTraffic ==
    phase = "init_failed" =>
        /\ trace = <<ResetEvent, InitErrorEvent>>
        /\ \A i \in DOMAIN trace :
            trace[i] \notin TrafficEvents

====
SPECIFICATION Spec

INVARIANT TypeOK
INVARIANT PhaseTraceOK
INVARIANT TrafficRequiresConfigured
INVARIANT TxDoneAndTimeoutExclusive
INVARIANT TxCompletionRequiresTxStart
INVARIANT RxFrameAndErrorExclusive
INVARIANT RecoveryOnlyAfterErrorOrTimeout
INVARIANT InitFailureStopsTraffic
