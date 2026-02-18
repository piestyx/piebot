# **GSAMA: Geometric State Associative Memory Architecture**

> _Deterministic, Non-Learned, Mechanistic Memory Substrate_

The GSAMA Core is the **heart of the system**, the substrate that stores and retrieves state vectors. It is intentionally primitive, brutally simple, and absolutely deterministic.

It does **one job**:

> Store L2-normalised vectors and return the most similar ones.

No learning.  
No semantic processing.  
No internal models.  
Just geometry.

---

## **Contents**

1. [**Core**](#core)  
	a. [**Purpose**](#purpose)  
	b. [**Responsibilities**](#responsibilities)  
	c. [**Data Structure**](#data-structure)  
	d. [**Properties**](#properties)  
	e. [**What it is not**](#what-it-is-not)  
	f. [**Exhibited Behaviours**](#exhibited-behaviours)  
	g. [**Interpretation**](#interpretation)  
2. [**Summary**](#summary)  
3. [**Future Extensions**](#future-extensions)  

---

# **Core**

## **Purpose**

The core provides:

- **Long-term storage** for state vectors.
- **Similarity-based retrieval** (cosine similarity).
- **Eviction** when capacity is exceeded.
- **Tagged indexing**, allowing isolation between tasks, agents, and conversations.

The result is a memory system that behaves like:

- an append-only,
- bounded-capacity,
- lattice-like geometric substrate.

This forms the basis for all emergent behaviour.

---

## **Responsibilities**

The core handles exactly three operations:

### **Write**

Input:

- `vector: np.ndarray` (L2-normalised) 
- `tags: Dict[str, Any]`
- `entropy: float` (scalar)
- `time: float` (timestamp)

Output:

- `memory_id: str`

Procedure:

1. Assign next memory ID (`mem_n`).
2. Insert entry into `entries` list.
3. If capacity exceeded → run eviction.

### **Retrieve**

Input:

- `query_vector: np.ndarray`
- `k: int`
- `filters: Dict[str, Any]`

Output:

- List of `MemoryEntry` sorted by decreasing cosine similarity.

Procedure:

1. Apply filters: keep only entries whose tags match all filter key/values.
2. Compute cosine similarity between query and entry.vector for all filtered entries.
3. Return top-k.

### **Eviction**

Triggered automatically when `len(entries) > max_entries`.

Eviction policy:

- Remove entry with **lowest (entropy, time)** pair.
    - Lower entropy → evicted first.
    - If entropy equal → evict oldest.

This makes GSAMA:

- deterministic,
- tunable via entropy channels,
- and capable of forming a “retention horizon”.

---

## **Data Structure**

Each memory slot is a simple dictionary:

```
MemoryEntry = {
  "id": str,
  "vector": np.ndarray,
  "tags": Dict[str, Any],
  "entropy": float,
  "time": float,
}
```

The entire memory substrate is:

```
self._entries : list[MemoryEntry]
self._max_entries : int
self._next_id : int
```

There is no index structure (e.g., no HNSW, no ANN).  
Retrieval is brute-force, full-scan.

This ensures **absolute correctness** and **predictable behaviour**.

---

## **Properties**

### **Mechanistic**

Vectors have no meaning internally.  
Meaning only emerges at the LLM layer.

### **Deterministic**

Same input → same output.  
Eviction order is fixed.  
IDs are sequential.

### **Inspectable**

Every entry is fully traceable:

- tags 
- time
- entropy
- vector

This is crucial for debugging and cognitive interpretation.

### **Unbounded time**

GSAMA does not use “context windows”.  
Old memories remain indefinitely (until eviction).

### **Stable across tests**

All tests (dual-agent, long-run, topic-switch, contradiction, multi-conversation) showed:

- no contamination
- no mutation
- no drift
- no corruption
- no collapse under sustained load

---

## **What it is not**

It is NOT:

- a database
- a RAG system
- a neural network
- a learned memory
- a semantic index
- a knowledge base

It is purely a **geometric store**.

---

## **Exhibited Behaviours**

Based on the experimental runs:

### **Long-Run Stability**

- Survived 3+ hours of continuous embeddings + retrievals.
- No memory degradation or runaway state.

### **Topic Switch**

- Abrupt cosine change at turn 100.
- Recovery to new attractor within ~5 turns.
- Demonstrates phase rotation in the latent geometry.

### **Contradiction**

- Maintained both versions of facts (70/80/2 and 60/75/3).
- Never overwrote or mutated earlier entries.
- LLM behaviour moved from:
    - Only old → Mixed → Mostly new  
        despite both memory sets coexisting.

This shows GSAMA behaves like a **non-mutable episodic store**.

### **Eviction Stress**

- `current_entries` plateaued at capacity.
- `total_writes` continued increasing.
- Eviction happened exactly as expected.
- `estimated_evictions` grew linearly.

The expected retention horizon behaviour was partially visible (older memories persisted due to uniform entropy).

### **Multi-Conversation Isolation**

- ZERO cross-conversation retrievals across ~330 turns.
- No topical bleed in logs.
- Perfect isolation via filtering.

Demonstrates GSAMA can act as a **multi-agent, multi-context memory substrate** safely.

---

## **Interpretation**

GSAMA Core provides:

- **A probeable internal geometry**
- **A stable attractor landscape**
- **A memory substrate that supports emergent long-term behaviour**
- **Metrics that read like cognitive diagnostics**

It functions analogously to:

- hippocampal episodic storage,
- pattern-completion retrieval,
- drift-based narrative evolution,
- phase transitions under semantic shock.

It is not biological but the geometric behaviour is interpretable in similar ways.

---

# **Summary**

GSAMA Core is:

- A deterministic, bounded memory substrate
- With brute-force cosine retrieval
- Zero learning
- Perfectly inspectable
- Proven stable in long runs
- Proven isolating between conversations
- Proven to maintain contradictory episodes
- Proven to express latent phase transitions

This is the **foundation** of GSAMA’s cognitive architecture.

Attractors, drift, convergence, contradictions, stability, emerges from:

- The encoder mapping,
- The LLM interpreting memory snippets,
- and the core’s deterministic vector substrate.

The core is complete, solid, and validated.

---

# **Future Extensions**

The core is STRICTLY locked but experiments can be expanded around it:

- **New entropy heuristics**
	- (lexical novelty, embedding variance, time-decay)
- **More retrieval filters**
	- (agent role, phase, task type)
- **Alternative write policies**
	- (write only on non-empty text, or per-turn summaries)
- **More metrics**
	 -(vector norm drift, cluster density, retrieval overlap)
- **Multi-agent simulations**
	 -(100+ agents with filtered memory slices)
- **Story rewriting experiments**
	- (long-form narratives stored + reinterpreted)

If experiments suggest that core mechanics need to be revised then it will be reviewed.

---