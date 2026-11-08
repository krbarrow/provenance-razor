# The Provenance Razor and related principles

The Provenance Razor does not compete with existing razors and maxims. It governs a different question: not how an assertion is produced, but whether action or inaction based upon it is justified. This document tests the razor against established heuristics by the evidence standard in the README: the razor is supported only insofar as it reproduces their useful conclusions, predicts their failure conditions, and identifies domains where they remain superior.

## Method

Each case records:

- **the heuristic** and what the razor sees in it;
- **borrowed premises**: inputs the razor takes from outside itself, each needing its own provenance;
- **reproduces**: situations where the razor reaches the heuristic's conclusion;
- **predicted failures**: situations where the razor predicts the heuristic goes wrong, each with an example;
- **heuristic superior**: ground the heuristic keeps.

Examples are judged by what was **knowable at the time** reliance was requested, recorded before the outcome. The razor does not reward explanations for eventually being correct; a justified reliance that turned out wrong does not count against it, and an unjustified one that turned out right does not count for it.

---

## Case 1: Hanlon's razor

**Heuristic.** Never attribute to malice that which is adequately explained by incompetence.

**What the razor sees.** Two competing assertions, "this was a mistake" and "this was deliberate". Each needs provenance proportional to the consequences of relying on it wrongly.

**Borrowed premises.** The base rate of error versus malice in the domain; whether an adversary is present; the cost of each error (missed malice, false accusation).

### Reproduces

Low stakes, no adversary: a broken script, a misrouted email, a configuration typo. Wrongly assuming a mistake costs little; wrongly assuming malice damages trust. "Mistake" needs only modest provenance, and the base rate supplies it.

Large outages fit the same pattern once a root-cause analysis exists. The CrowdStrike content update (July 2024) and the Facebook BGP configuration error (October 2021) both drew early speculation about attacks. Before the root-cause analyses, both "it was an attack" and "it was a mistake" were unjustified; the second turned out right, but at that moment it was a guess. After the analyses, which others could check, "mistake" had strong provenance.

### Predicted failures

High stakes with an adversary present: wrongly accepting "mistake" becomes expensive, so that assertion also needs strong provenance. The razor's conclusion is not "assume malice" but **neither explanation is justified yet; investigate**. It predicts four signs that Hanlon's razor is being exploited:

1. **Malice designed to look like a mistake.** An adversary who knows the base rate disguises the attack as error, turning the defender's heuristic into cover. *The University of Minnesota "hypocrite commits" (2021)* submitted deliberately flawed patches to the Linux kernel that looked like honest mistakes.
2. **The innocent explanation comes from the suspect.** *The xz utils backdoor (2024, CVE-2024-3094):* anomalous behaviour received benign explanations and "fixes" from the contributor who planted the backdoor, and apparently independent accounts pressured the original maintainer to hand over control. The check Hanlon's razor cannot make: who supplied the innocent explanation, and are they independent of the outcome?
3. **"Mistakes" that all point the same way.** Genuine errors are random; deliberate ones consistently benefit someone. A run of errors with one beneficiary behaves like one lineage, not several independent ones.
4. **Missed malice costs far more than a false accusation.** *Stuxnet:* centrifuge failures at Natanz were reportedly attributed to faulty equipment and operator error before sabotage was understood. Knowable at the time: a sanctioned nuclear programme with capable, known adversaries, a knowably adversarial setting in which the cost of missed sabotage was foreseeable. "Equipment failure" therefore needed strong provenance, such as verified root causes for repeated failures, not a plausible account.

### Heuristic superior

Everyday interpersonal judgement. Hanlon's razor costs a second; a provenance analysis costs far more, and false accusations of malice do lasting damage regardless of the truth. The heuristic wins on cost of analysis, which the razor does not measure.

---

## Case 2: Occam's razor

**Heuristic.** Entities should not be multiplied beyond necessity.

**What the razor sees.** Each assumption is an assertion needing provenance, and a conjunction of assumptions cannot be better supported than its weakest member. Confidence falls with each *unsupported* assumption, not with each assumption.

**Borrowed premises.** What counts as one assumption; the provenance of each.

### Reproduces

Two explanations fit the facts, and the larger one's extra assumptions have no independent support. The razor gives the larger one less confidence. This covers most legitimate uses of Occam's razor.

### Predicted failures

1. **Several causes, each well supported.** Hickam's dictum in medicine: a patient can have several diseases at once. Knowable at the time: age, existing diagnoses, and the base rate of co-occurring conditions. The razor accepts two diagnoses if each has its own provenance, and judges a single unifying diagnosis on its provenance, not its tidiness. Occam's razor fails wherever independent causes are common and each is checkable.

2. **An added entity can inherit strong provenance.**

   | | Neptune (1846) | Vulcan (from 1859) |
   |---|---|---|
   | Anomaly | Uranus's orbit | Mercury's perihelion |
   | Added entity | an unseen planet | an unseen planet |
   | Knowable at the time | Newtonian mechanics' track record; a specific, testable prediction | the same track record; claimed sightings unreplicated; repeated searches empty |
   | Razor at the time | justified as a working hypothesis, then strongly justified once observed | justified at first; increasingly unjustified as independent searches failed |
   | Outcome | found | nonexistent; general relativity explained the perihelion |

   Occam's razor objects to both. The razor allows both at first, because each added entity inherits provenance from a well-tested theory, and then separates them by provenance as it accumulated, not by outcome. Early reliance on Vulcan was justified; continued reliance after repeated null searches was not. Pauli's neutrino (1930), proposed to preserve conservation of energy and detected in 1956, follows the same pattern.

3. **Simplicity claimed through a single overpowered root.** "One actor explains everything" sounds simpler than many separate causes. The razor asks for provenance of that actor's capabilities, access and coordination. One root that needs unsupported powers is weaker, not simpler. Occam's razor can be invoked for such explanations; the razor cannot.

### Heuristic superior

- **Equally well-supported explanations.** The razor is silent; parsimony breaks the tie.
- **Statistical model selection.** Among models fitted to the same data, simpler models tend to generalise better. This is a property of estimation, not provenance.
- **Choosing what to test first.** Simpler hypotheses are often cheaper to test. That is the production of assertions, outside the razor's scope.

---

## Case 3: Extraordinary claims require extraordinary evidence

**Heuristic.** The more surprising a claim, the stronger the evidence needed to accept it.

**What the razor sees.** Extraordinary consequences can require extraordinary provenance even when the claim itself is mundane. Surprise and consequence are orthogonal variables: the heuristic tracks surprise, the razor tracks consequences. When both are high they agree; where they diverge, their recommendations diverge predictably.

The variables are separable, not uncorrelated. Surprising claims are often consequential because they overturn what people rely on, which is why the heuristic usually appears to work. The off-diagonal cells are the test.

| | Low consequence | High consequence |
|---|---|---|
| **High surprise** | Diverge: the razor is more permissive (rely enough to pursue or trial) | Agree: extraordinary support required |
| **Low surprise** | Agree: ordinary support suffices | Diverge: the razor is stricter (extraordinary provenance for a mundane claim) |

**Borrowed premises.** The claim's prior improbability, from the method that produced it; the cost of wrongly relying and of wrongly refusing; the independence of the support.

### Reproduces (high surprise, high consequence)

- **Cold fusion (1989).** Knowable at the time: announced at a press conference before peer review, from one laboratory, with replications failing within weeks, and funding and policy at stake. One unreplicated line of support against high consequences: reliance not justified.
- **Faster-than-light neutrinos (OPERA, 2011).** Knowable at the time: a single experiment contradicting a well-tested theory, published with an explicit request for independent scrutiny. No reliance until independent support existed. The anomaly was later traced to equipment faults.

### Predicted failures

1. **Low surprise, high consequence: the razor is stricter.**
   - *GitLab database outage (2017).* Knowable at the time: several backup mechanisms, none verified by regular restore tests. "The backups work" is unsurprising, so the heuristic is satisfied; the razor requires verified provenance, a tested restore, for a claim whose failure means losing production data.
   - *Therac-25 (1985–1987).* Knowable at the time: hardware interlocks from earlier models had been removed, leaving reused software to carry the safety function alone. "The software is correct" was an ordinary assumption with a lethal consequence if wrong.

2. **High surprise, low consequence: the razor is more permissive.**
   - *Helicobacter pylori and ulcers (from 1982).* Knowable at the time: a claim against medical consensus, supported by culture evidence, a self-infection experiment and early treatment results. Acting on it meant a course of antibiotics: modest cost, low risk, reversible. The evidence did not yet justify rewriting textbooks, but it justified relying on it for a treatment trial, years before the evidence counted as extraordinary.
   - *Continental drift (from 1912).* Knowable at the time: strong evidence of fit, no known mechanism. Treating drift as settled geology was not justified, so its rejection was a justified judgement at the time. Investigating it was cheap and was justified. The razor separates relying on a claim as established from relying on it enough to pursue it; the heuristic applies one standard to both.

3. **Support that looks extraordinary but has one origin.** Independence is a property of the support, not the claim, so it applies in every cell. *Iraq WMD assessments (2002–2003):* key biological-weapons claims rested on a single defector, "Curveball", whom US analysts had not interviewed directly and whose handling service had warned of his unreliability. Repetition across agencies and reports made the claims look corroborated. The claim was unsurprising to its audience, so the heuristic set a low bar, and repetition appeared to clear it. The razor collapses the repetitions to one weak root against extreme consequences.

### Heuristic superior

- **Quantified discovery claims.** Where priors and likelihoods can be stated, as in particle physics' five-sigma convention, the heuristic's Bayesian form says how much evidence is needed. The razor says only whether the reliance threshold is met.
- **Surprise as a cheap error signal.** A result contradicting strong prior knowledge is more likely a measurement error than a discovery. The heuristic encodes that at almost no cost; the razor sees it only if the error rate is expressed as provenance.

---

## Case 4: Hitchens's razor

**Heuristic.** What can be asserted without evidence can also be dismissed without evidence.

**What the razor sees.** The zero-provenance boundary. "Dismiss" covers two acts the razor separates: **declining to rely on the claim**, always justified at zero provenance, and **relying on the claim being false**, a reliance of its own that needs provenance proportional to the cost of being wrong. Absence of evidence for a claim is not provenance for its negation.

**Borrowed premises.** What counts as evidence (presented evidence only, or also a source's track record); the cost of wrongful dismissal.

### Reproduces

Unsourced claims whose wrongful dismissal costs little: rumours, spam, unsupported assertions in argument. Declining to rely and treating as false come to the same thing.

### Predicted failures

1. **Wrongful dismissal is costly.** An unverified warning of serious harm: an anonymous bomb threat, a reported gas smell, an unconfirmed breach report. Knowable at the time: nothing supports the claim, and nothing supports its negation. Dismissal relies on "this is false", which has no provenance and severe consequences if wrong. Neither belief nor dismissal is justified; cheap verification or precaution is. Established threat-response and gas-leak procedures already act this way.
2. **Provenance without presented evidence.** A source with a strong track record warns without supplying evidence. Read narrowly, the heuristic permits dismissal; the razor counts the track record as provenance, which can justify at least a check. If "evidence" includes track record, the two agree; the case turns on that definition.

### Heuristic superior

Debate and the burden of proof. The heuristic places the burden on the claimant at almost no cost, and protects against unsupported claims arriving faster than they can be refuted and against demands to disprove the undisprovable. In low-stakes discussion it wins on cost of analysis.

---

## Synthesis

Across the four cases, the heuristics' failures were not caused by lack of evidence. Where they broke, evidence existed but was mis-accounted: its consequence ignored, its independence assumed, its source unexamined, or its assumptions unsupported.

| Dimension | Side of the razor | Cases |
|---|---|---|
| Consequence | provenance **required** ("proportional to the consequences of its being wrong") | Hanlon 4; extraordinary claims, low surprise and high consequence; Hitchens 1 |
| Independence | provenance **available** | Hanlon 3; Curveball |
| Source lineage (who supplied it, and their interest in it) | provenance **available** | Hanlon 2 |
| Unsupported assumptions | provenance **available** | Occam 3 |

The four dimensions are not an extra rule; they unpack the razor's own sentence into the provenance required and three measures of the provenance available. The Provenance Razor then becomes the operational test:

> Before relying on an assertion, examine its provenance through those dimensions and calibrate confidence to the consequences of error.

The underlying theory is the repeated appearance of the same provenance failures across otherwise unrelated heuristics.

## Open questions

- **Freshness.** Time appears in Occam 2 (Vulcan's provenance decaying as searches failed), in Hanlon 4 (judgement reconstructed at the moment of reliance), and in the specification's expiry and clock-skew vectors. Whether freshness is a fifth dimension or is covered by the other four is undecided.
- **Selection.** The four heuristics were chosen as supporting principles, not sampled. The dimensions should be tested against heuristics not chosen to fit them, with predictions recorded before each analysis. Candidates: Chesterton's fence, the precautionary principle, the Lindy effect, "if it ain't broke, don't fix it", and the wisdom of crowds.
- **Recorded prediction, wisdom of crowds.** The heuristic holds only when the crowd's judgements are independent. Mass media and shared information sources erode that independence, so the razor predicts the heuristic fails where a crowd's judgements trace to common sources, and holds where they are formed separately.
