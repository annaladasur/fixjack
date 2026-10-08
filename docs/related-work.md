# Related work

How fixjack relates to earlier work, and what it does and does not add. Bibliographic details for the papers below were checked on October 3, 2026, against search results that point to each publisher's or proceedings page. The publisher pages themselves could not be opened from the environment used for the check. The two OWASP standards were checked first-hand in their repositories.

## The design rule

The Write-Access Test is the remediation-specific case of a known rule: untrusted data may inform a decision, but it must not authorize one.

- Greshake, K., et al. "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." AISec '23 (ACM Workshop on Artificial Intelligence and Security), 2023. DOI 10.1145/3605764.3623985. It framed indirect prompt injection: data the application retrieves acquires instruction authority.
- Debenedetti, E., et al. "Defeating Prompt Injections by Design." arXiv:2503.18813, 2025; also listed in the IEEE SaTML 2026 proceedings. CaMeL takes control and data flow from the trusted query, so untrusted data cannot change program flow, and it enforces policies on tool calls. Its headline task-success figure differs between arXiv versions, so cite the version you use.

fixjack applies that rule outside the agent, at merge. It does not change how the agent reasons. It re-derives the version decision from sources the attacker cannot write.

## Measuring injection against agents

- Debenedetti, E., Zhang, J., Balunovic, M., Beurer-Kellner, L., Fischer, M., Tramer, F. "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents." NeurIPS 2024 Datasets and Benchmarks Track. It measures task success and attack success together. fixjack's counterpart is reporting the false-block rate on real bot PRs next to the attack results.
- Spracklen, J., et al. "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs." USENIX Security 2025. It shows models suggesting packages that do not exist, which is the precedent for agents choosing package names and versions no authority backs.

## Dependency bots and the npm ecosystem

These ground the premise that automated dependency PRs are common and often merged, and that the npm dependency network spreads both vulnerabilities and fixes unevenly.

- Mirhosseini, S., Parnin, C. "Can automated pull requests encourage software developers to upgrade out-of-date dependencies?" ASE 2017. Projects that received automated update PRs upgraded more often than projects with no such tooling. Notification fatigue limited the effect.
- Alfadel, M., Costa, D. E., Shihab, E., Mkhallalati, M. "On the Use of Dependabot Security Pull Requests." MSR 2021. DOI 10.1109/MSR52588.2021.00037. Most Dependabot security PRs in the JavaScript projects studied were merged, often within a day.
- Decan, A., Mens, T., Constantinou, E. "On the impact of security vulnerabilities in the npm package dependency network." MSR 2018. DOI 10.1145/3196398.3196401.
- Zerouali, A., Constantinou, E., Mens, T., Robles, G., Gonzalez-Barahona, J. "An Empirical Analysis of Technical Lag in npm Package Dependencies." ICSR 2018 (International Conference on Software Reuse). DOI 10.1007/978-3-319-90421-4_6.
- Zimmermann, M., Staicu, C.-A., Tenny, C., Pradel, M. "Small World with High Risks: A Study of Security Threats in the npm Ecosystem." USENIX Security 2019.

## Supply-chain attack taxonomies

- Ladisa, P., Plate, H., Martinez, M., Barais, O. "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains." IEEE S&P 2023. DOI 10.1109/SP46215.2023.10179304.
- Ohm, M., Plate, H., Sykosch, A., Meier, M. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA 2020. DOI 10.1007/978-3-030-52683-2_2.

## 2026 work on agents and untrusted text

Recent work reports untrusted text steering coding agents, including into a known-vulnerable version pin. So "untrusted text steers version selection" is not new. fixjack adds four narrower things:

- the security fix itself as the target;
- six remediation-specific channels;
- which existing gate misses each hijack;
- a deployable verifier whose false-block rate will be measured on real bot PRs.

Verify the scope of each 2026 work before saying that none of it covers remediation inputs.

## Standards

- OWASP AISVS 1.0 (June 2026), chapter C9, section C9.3 "Component Isolation and Tool Authorization":
  - fixjack implements 9.3.7: external resources named in model output are verified against an approved allow-list or registry before the agent installs or invokes them.
  - It enforces 9.3.5 and 9.3.6, which ask for isolation and separation inside the agent, outside the agent, at merge.
  - The `1.01-dev` draft keeps the same numbering. Re-check before citing it in a talk.
- OWASP SCVS 1.0 (still the latest release), V4 "Package Management Requirements". The closest controls are 4.13 (the package manager verifies integrity on retrieval) and 4.2 (repository contents match an authoritative origin). No SCVS control names lockfiles.
- SLSA: build provenance. It has no lockfile track.

## The author's other project

`agent-trust-plane` gates an agent's write actions on where its context came from: a taint ledger and a signed decision record. fixjack ignores the agent's process and judges the outcome: what the chosen version is, according to external authorities. The two are layers that compose, not one tool built twice.
