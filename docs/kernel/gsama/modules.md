# **Modules**

> The behavioural layer where LLMs interface with memory and context

Modules are the **only** components in GSAMA allowed to:

- call an LLM,
- generate text,
- interpret memory tags,
- shape prompts,
- and produce behavioural output.

Everything else in the system (core, controller, encoder) is mechanistic, deterministic, and context-free.

Modules are where “mind-like” behaviour emerges _because_ they sit on top of a clean, predictable substrate.

---

## **Contents**

1. [**Modules**](#modules)  
	a. [**Purpose**](#purpose)  
	b. [**Responsibilities**](#responsibilities)  
	c. [**Interactions**](#interactions)  
	d. [**Exhibited Behaviours**](#exhibited-behaviours)  
	e. [**What the Modules are not**](#what-the-modules-are-not)  
	f. [**Interpretation**](#interpretation)  
2. [**Summary**](#summary)  
3. [**Future Extensions**](#future-extensions)  
 
---

# **Modules**

## **Purpose**

A Module takes three inputs:

```
forward(
    query: np.ndarray,
    memories: list[MemoryEntry],
    context: dict
) -> dict
```

Its job is to:

1. **Summarise retrieved memories** using only metadata, never content.
2. **Build a role-appropriate prompt** using memory summaries + context.
3. **Call the LLM** with that prompt.
4. **Return a structured dict** containing the output (`{"reply": ...}` in v1).

Modules do not:

- write to GSAMA,
- retrieve from GSAMA directly,
- normalise vectors,
- manage eviction,
- hold their own state.

This strict containment is why the experiments produce clean signals.

---

## **Responsibilities**

There is currently only one module implemented in GSAMA.

It provides a stable baseline testbed for:

- long-term memory usage,
- phase shifts,
- contradictions,
- multi-conversation isolation,
- emergent attractors.

### **Memory formatting**

It takes each `MemoryEntry`:

```
id, tags, entropy, time
```

and converts them into bullet-point summaries such as:

```
- mem_30 (agent=B, text="CPU threshold discussion", entropy=1.0)
```

Only ID + tag metadata is shown.  
No content is ever revealed.  
The LLM only receives descriptions of what the memories _represent_.

This is why the system cleanly reuses concepts like “70% CPU” even when the embedding has long since passed out of context.

### **Prompt construction**

The module:

- embeds role identity (“You are Agent B…”)
- includes memory summaries,
- places context dicts directly into the system message,
- instructs the LLM to reference memory as needed,
- anchors behaviour with `role_hint`.

The structure ensures the LLM uses GSAMA information consistently.

### **Delegation**

It calls:

```
llm_client.generate(prompt)
```

and returns:

```
{"reply": generated_text}
```

No other side effects.  
No writes to memory.  
No cross-layer behaviour.

---

## **Interactions**

Modules never touch:

- vector similarity,
- time ordering,
- entropy sorting,
- normalization,
- indexing.

Instead, GSAMA Core → Controller → Module produces a **strict data pipeline**:

1. GSAMA returns the top-k `MemoryEntry` objects.
2. The Controller passes them unmodified into the module.
3. The module formats metadata into a list of bullet points.
4. The module embeds these into a text prompt.
5. The LLM responds based on this structured, metadata-driven context.

This is why your four experiments show such clean separability:

- contradiction handling,
- topic shifts,
- multi-conversation isolation,
- attractor formation.

The module receives _only_ what the controller tells it to receive and nothing more.

---

## **Exhibited Behaviours**

Across all tests, `DefaultDialogueModule` produced predictable, interpretable behaviour:

### **Memory Referencing**

LLMs repeatedly used memory metadata to:

- refer to earlier turns,
- reference IDs,
- track facts introduced early,
- maintain stable thematic consistency.

The module _explicitly conditions_ responses on structured summaries of historical states and not on any learned memory.

### **Phase Shift Sensitivity**

In the topic-switch experiment:

- a single injection of a new role/context changed the module's output structure,
- cosine geometry showed the system rotating into a new attractor before returning,
- behaviour remained consistent because prompt structure remained consistent.

Modules respond _exactly_ to context dicts and nothing more.

### **Contradiction Handling**

During the contradiction test:

- Modules never “forgot” the old facts.
- They incorporated both old and new memories into the prompt.
- The LLM made the phase-dependent decision to prioritise the new facts during the probe phase.

This shows:

- Modules reliably reflect the entire memory substrate,
- while LLM behaviour resolves contradictions at the behavioural layer.

### **Multi-Conversation Isolation**

Modules only see:

- memories filtered by conversation ID,
- role hints per agent per conversation,
- isolated contexts.

Retrieval isolation → prompt isolation → behavioural isolation.

This is why the dual conversation test had:

- **zero leakage**,
- clean topical separation,
- zero cross-conversation references over hundreds of turns.

---

## **What the Modules are not** 

Modules must _not_:

- Update GSAMA
- Filter GSAMA
- Read vector contents
- Use memory content directly
- Implement their own memory
- Access the LLM outside `generate()`

This strictness:

- kept all experiments stable,
- preserved all invariants,
- prevented leakage,
- made every layer interpretable.

---

## **Interpretation**

Modules are where you get:

- behavioural richness,
- role shaping,
- meta-cognition via context,
- task-specific logic,
- expressive interpretation of memory.

Modules provide the **semantic interface**, while GSAMA provides the **mechanistic substrate**.

---

# **Summary** 

Modules are:

- the interpretive layer,
- the behavioural API,
- the semantic glue between LLM reasoning and GSAMA’s vector substrate.

Experiments validated all the intended behaviours:

- **Memory-consistent reasoning**
- **Phase shifts under contextual pressure**
- **Contradiction coexistence**
- **Impeccable isolation and task routing**
- **Emergent attractors from prompt+state geometry**

The module layer is adding “mind-like” behaviour while staying strictly within the allowed architectural boundaries.

---

# **Future Extensions**

- **Planning Module**
	- Uses memory summaries to build plans, multi-step actions, etc.
- **Summarisation Module**
	- Periodically writes compressed “epoch summaries” into GSAMA.
- **Tool-Use Module**
	- Wraps external APIs/tools with structured reasoning.
- **Self-Reflection Module**
	- Analyses memory metadata and rewrites role/context hints.

All of these remain safe because the Controller would restrict their interactions.

---