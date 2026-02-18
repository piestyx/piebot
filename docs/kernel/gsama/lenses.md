# Lenses: Post-Retrieval Ranking Operators**

> Retrieval bias on returned vectors for the best candidate

A Lens takes (query_vector, retrieved_candidates) → returns (ranked_candidates, scores, debug). They are _pure functions_.

---

## **Contents**

1. [**Role of Lenses**](#role-of-lenses)  
2. [**Why Lenses Exist**](#why-lenses-exist)  
3. [**Core Lens Types**](#core-lens-types)  
    a. [**CausalLens**](#1-causallens)  
    b. [**SalienceLens**](#2-saliencelens)  
    c. [**AbstractionLens**](#3-abstractionlens)  
    d. [**RobustnessLens**](#4-robustnesslens)  
4. [**Lens Composition**](#lens-composition-combinedlens)  
5. [**Properties of the Lens Layer**](#properties-of-the-lens-layer)  
6. [**Lens Debugging and Metrics**](#lens-debugging--metrics)  
7. [**Interpretation**](#interpretation)  

---

## **Role of Lenses**

Lenses are **post-retrieval ranking operators** that reorder GSAMA’s retrieved memory entries before they reach any LM module.

They do not store memory.  
They do not modify GSAMA.  
They do not perform semantic operations.  
They impose **geometric or structural biases** on the retrieved set.

---

## **Why Lenses Exist**

- GSAMA retrieval is geometry-only (cosine similarity).
- Multiple memory entries may be equally similar.
- Some entries should matter more than others depending on:
    - time
    - entropy
    - novelty
    - cluster structure
    - robustness under noise

Lenses inject **behavioural priors** without touching the core.

In other words:

> GSAMA retrieves what is nearby;  
> Lenses decide what is _important_.

---

## **Core Lens Types**

### a. **CausalLens**

Adds a temporal bias:

- newer memories get slightly higher weight,
- older memories decay proportionally to turn distance.

Effect:

- supports sequential reasoning,
- prevents stale memories from dominating.

### b. **SalienceLens**

Uses entropy and system-level metadata:

- high-entropy writes (novel or surprising states) get boosted,
- low-entropy, repetitive states diminish.

Effect:

- emphasises turning points in the state trajectory,
- filters out dull, repetitive states.

### c. **AbstractionLens**

Cluster-based weighting:

- groups memories by similarity,
- lifts representative cluster centres,
- suppresses redundant neighbours.

Effect:

- compresses noise,
- reveals latent structure,
- acts like a "concept selector".

### d. **RobustnessLens**

Perturbation-based scoring:

- injects noise into the query vector,
- re-runs similarity,
- scores entries based on stability under perturbation.

Effect:

- selects memories that lie in stable basins,
- reduces reactivity to accidental spikes,
- provides consistency over multiple turns.

---

## **Lens Composition: CombinedLens**

The project uses a **weighted sum** lens ():

- apply each lens independently,
- scale by its configured weight,
- aggregate ranked scores,
- sort candidates by combined rank.

This turns distinct geometric biases into a single, unified ranking.

It is fully modular:

- any lens can be toggled or weighted,
- new lenses can be added without breaking the system.

---

## **Properties of the Lens Layer**

- **Deterministic** — all randomness is controlled or seeded.
- **Non-learning** — no weights are trained; behaviour is rule-based.
- **Composable** — arbitrarily complex pipelines from simple primitives.
- **Non-invasive** — lenses reorder, never modify state vectors.

---

## **Lens Debugging & Metrics**

Each lens returns:

- ranked_ids
- raw candidate ids
- score vector
- internal debug (e.g., causal decay factors, cluster assignments, perturbation samples)

This is what powers:

- HF visualisations,
- interpretability tools,
- memory activation graphs.

---

## **Interpretation**

Lenses are the **attentional geometry** of GSAMA —  
a lightweight, rule-based analogue to transformer attention, but over _memory_ not _text_.

They are the layer that transforms “nearby vectors” into “relevant moments”.

---
