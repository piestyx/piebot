# Controller: Coordination for GSAMA Orchestration

> The router, orchestrator, and contract enforcer

The Controller is the **coordination layer** that sits between:

- the **Encoder** (state vector producer),
- the **GSAMA Core** (memory substrate),
- and the **Modules** (LLM-driven behaviour pieces).

It does not “think”.  
It does not generate language.  
It does not transform memory.  
It does not rewrite vectors.

It just **routes**, **packages**, **retrieves**, and **delegates**.

This layer is crucial but kept intentionally boring because it enforces the entire architecture’s invariants.

---

## **Contents**

1. [**Controller**](#controller)  
	a. [**Purpose**](#purpose)  
	b. [**Responsibilities**](#responsibilities)  
	c. [**Architecture Invariants**](#architecture-invariants)  
	d. [**Exhibited Behaviours**](#exhibited-behaviours)  
	e. [**Interpretation**|Interpretation](#exhibited-behaviours)  
2. [**Summary**](#summary)  
3. [**Future Extensions**](#future-extensions)  

---

# **Controller**

## **Purpose**

The Controller is responsible for:

1. **Turning raw inputs into an encoded state**
2. **Writing that state to GSAMA with tags + entropy**
3. **Retrieving the top-k memories with filters**
4. **Constructing a unified task input for the module**
5. **Delegating the actual behaviour to the module**
6. **Returning the module’s output**

The controller defines **what GSAMA _is allowed_ to be used for** and **keeps all modules honest**.

---

## **Responsibilities**

### **State Encoding**

Inputs:

- raw text (`text`)
- or structured dicts (`state_encoder_inputs` containing `perception_vec`)

The controller delegates encoding to the **Encoder** (not part of the core).  
The Encoder generates a single vector `z`.

The Controller’s job:

- Guarantee the vector is L2-normalised
- Pass it consistently to GSAMA

No semantic decisions.  
No branching logic.

### **Memory Write**

Once the Controller has `z`, it writes it into GSAMA:

```
gsama.write(
  vector=z,
  tags=tags,        # agent, conversation_id, etc.
  entropy=entropy,  # scalar for eviction
)
```

**Tags** are the key mechanism for:

- conversation isolation,
- agent-filtered recall,
- phase separation.

The Controller ensures tags are **flat**, **serialisable**, and **consistent**.

### **Memory Retrieval**

The Controller handles retrieval like this:

```
memories = gsama.retrieve(
    query_vector = z,
    k = self.top_k,
    filters = tags,   # dict — must match exactly
)
```

Only the Controller knows:

- how big k should be,
- which filters apply,
- what context is active.

GSAMA Core never sees 

- tasks
- roles
- phases
- agents 

these are controller-level inputs.

### **Task Delegation**

The Controller selects the module based on `task`:

```
module = self.modules[task]
return module.forward(
    query=z,
    memories=memories,
    context=context
)
```

Key principles:

- Controller never builds prompts
- Controller never touches memory strings
- Controller never interprets memory content
- Controller only hands structured objects to modules

This keeps the system modular and allows swapping modules without touching the core.

---

## **Architecture Invariants**

The Controller guarantees:

- **The core is never passed unnormalised vectors**
	- L2-normalisation is required for cosine correctness.
- **All memory operations follow the same pattern**
	- No module gets to choose how retrieval works.
- **No direct LLM calls bypass memory**
	- All behaviour is mediated through state + memory.
- **Memory ownership is explicit via tags**
	- Isolation remains airtight.
- **Modules cannot mutate GSAMA**
	- They only receive structured data.

These invariants were validated in all experiments:

- zero cross-conversation leakage
- perfect determinism in retrieval
- clear attractor formation
- phase-shift signatures
- contradiction storage and coexistence

All because the controller consistently enforces the usage pattern.

---

## **Exhibited Behaviours**

Across four test types, the Controller’s routing produced:

### **Stable State Trajectories**

Vectors evolved slowly except during intentional topic switches.

The Controller never introduced noise or drift.

### **Consistent Recall**

Retrieval was always:

- stable (20 items),
- filtered correctly,
- delivered in a structured format to modules.

### **Predictable Module Behaviour**

Because the Controller always delivers the _same shape_ of input:

- Modules respond consistently.
- Tests produce reproducible cosine curves.
- Contradictions accumulate predictably.

### **Zero Contamination**

The multi-conversation test proved the Controller’s tag enforcement works:

- 0 mismatched IDs.
- Perfect isolation.

### **Full Stability Under Load**

The controller ran for:

- Hours,
- Hundreds of turns per test,
- Tens of thousands of llama-server requests,

With no corruption or performance collapse.

---

## **Interpretation**

Because it is:

- **Thin:** almost no logic.
- **Predictable:** deterministic, no randomness.
- **Boring:** does exactly what it says, nothing more.
- **Strict:** enforces the architecture’s contracts.

This allows:

- modularity (swap modules anytime),
- testability (you can isolate any layer),
- cognitive analysis (clean separation of roles),
- long-term stability (no hidden state),
- and perfect observability (every step is logged deterministically).

---

# **Summary**

The Controller is the:

- **router**
- **supervisor**
- **integration layer**
- **safety boundary**
- **contract enforcer**

Its job is not to think — its job is to guarantee that **the system behaves like a system**, not like a pile of loosely coupled functions.

In essence:

The Controller is the reason GSAMA core can be simple, deterministic, and yet still support emergent cognitive structure.

---

# **Future Extensions**

- Add role hints
- Add phase metadata
- Inject contradiction signals
- Introduce multiple agents
- Supply new structured context    
- Add more modules (summarisation, planning, tool-use)
- A/B test retrieval sizes or entropy rules

All these can be done by changing only:

- context dicts
- module selection
- tags
- top-k

Without modifying the core or breaking invariants.

This is exactly why your experiments worked on the first attempt — the controller provides a stable interface surface.