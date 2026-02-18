# Encoder: State Construction for Long-Term memory 

> Mechanistic State Construction for Long-Term Memory

The encoder is the **first real computational layer** in GSAMA, the point where raw perception (incoming text, embeddings) is transformed into the **state vector `z`** that GSAMA stores, retrieves, and reasons over.

It is intentionally simple, deterministic, and entirely non-learned.

---

## **Contents**

1. [**Encoder**](#encoder)  
	a. [**Purpose**](#purpose)  
	b. [**Inputs**](#inputs)  
	c. [**Architecture**](#architecture)  
	d. [**Properties**](#properties)  
	e. [**What the Encoder is not**](#what-the-encoder-is-not)  
    f. [**Interpretation**](#interpretation)  
2. [**Summary**](#summary)
3. [**Future Extensions**](#future-extensions)

---

# **Encoder**

## **Purpose**

The encoder exists to:

- produce a **stable, comparable representation** of each turn;
- ensure all states live in the **same geometric manifold**;
- act as the **interface** between semantic space (LLM/embeddings) and GSAMA’s geometric substrate;
- enable **drift, attractors, and phase transitions** to be observable in cosine-based metrics.

It is not intended to understand concepts.  
It is not intended to produce meaning.  
It only produces **state geometry**.

This simplicity is deliberate.

---

## **Inputs**

The encoder receives two ingredients:

1. **Perception Vector**
    - Produced by the Nomic embedder (`nomic-embed-text-v2-moe.Q6_K.gguf`).
    - Shape: `(embedding_dim,)` — usually 768 or 1024.
2. **Context Vector**
    - Flattened metadata (e.g. agent name, conversation ID, phase flags).
    - Shape: small (e.g. 32–64 dims).
    - Encoded deterministically (string → hash → float vector).

Both streams are **concatenated** into a single pre-projection vector.

---

## **Architecture**

The encoder pipeline is:

```
Embed(text) → `e`
Encode(context) → `c`
Concatenate(`e`, `c`) → `u`
Project(`u`) → `z_raw`
L2-normalise(`z_raw`) → `z`
```

Where:

- **No weights are learned**.
- The projection matrix is randomly initialised once at startup.
- The dimension reduction compresses the concatenated input into a smaller, fixed-dim latent (e.g. 256 dims).

This produces a **stable geometric substrate** that can be probed with cosine similarity.

---

## **Properties**

### **Non-learned**

No training.  
No backprop.  
Nothing adapts.

This is what makes GSAMA purely mechanistic.

### **Deterministic**

Given the same embedder, context, and text, the encoder always produces the same `z`.

### **Non-linear (mildly)**

The only non-linearity is within the LLM embedder.  
GSAMA adds no learned non-linearity.

### **Stable under long runs**

Your 3-hour test validated:

- no drift in vector norms,
- no accumulation error,
- no memory contamination.

### **Compatible with any embedding model**

The encoder doesn’t care which models is used, I used Nomic 1024-dim embeddings with no significant issues.

It will work with:

- BERT,
- sentence transformers,
- custom embedding LLMs,
- multimodal vectors,
- etc.

---

## **What the Encoder is not**

It is NOT:

- a feature extractor
- a semantic reasoner
- a learned memory model
- a time-aware module
- a concept combiner
- a modelling layer

It only provides **geometric representation for GSAMA to operate on**.

---

## **Interpretation**

Despite its simplicity, the encoder gives GSAMA:

### **Consistent state geometry**

Each memory is in the same latent space, so retrieval becomes a simple geometric comparison.

### **Drift and phase transitions**

Because the L2-normalised latent moves gradually (or abruptly) with changes in input, cosine similarity becomes a readable “motion detector.”

This is why in the Topic Switch test:

- 99 turns → state vectors orbit one attractor
- Turn 100 → drop in `self_state_shift_cosine` from ~0.9 to ~0.26  
    **(phase rotation caused by external forcing)**
- Turns 101+ → convergence to a new attractor

The encoder is responsible for producing a manifold where these transitions become obvious.

### **Cross-agent comparability**

Agent A and Agent B both use:

- the same encoder weights,
- the same projective mapping,
- the same L2 manifold.

This is why:

- A’s and B’s state spaces can be compared directly,
- `cross_agent_state_cosine` shows meaningful coupling.

### Latent Space

The encoder produces the latent space where GSAMA’s “cognitive geometry” emerges.

This is why:

- Topic shifts → vector rotations
- Contradictions → two coexisting attractors
- Multi-conversation → disjoint manifolds under filtered retrieval
- Eviction → changes in the distribution of retrieved vectors
- Agent coupling → cross-agent cosine synchronisation
- Memory buildup → cluster densification

Whenever you see structure in the metrics, the encoder is what made that space measurable.

---

# **Summary**

The GSAMA encoder is the **bridge** between semantic text and geometric memory.  
It is deliberately simple, deterministic, and non-phenomenological.

Its role is not to “understand” —  
its role is to **place each moment into the global manifold** so GSAMA can operate on it.

This simplicity is why we can measure, test, and map the cognitive geometry of the system.

---

# **Future Extensions**

- **Alternative projection matrices**
	- different random seeds
	- different output dims (128, 256, 512)
- **Alternative context encodings**
	- phase flags
	- agent roles
	- multi-modal indicators
- **Non-text embeddings**
	- audio
	- symbolic sequences
	- structured states
- **Multi-layer concatenations**

Still no learning — just more concatenated channels.