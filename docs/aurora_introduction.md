# Aurora: An Automated Cyberattack Emulation System

<p><a href="https://arxiv.org/pdf/2407.16928"><img src="../images/First_page.png" alt="Paper thumbnail" align="right" width="160"/></a></p>

-   Introduces AURORA, a cyberattack emulation system that leverages classical planning (PDDL) and Large Language Models (LLMs).
-   Constructs an extensive attack space containing over 5,000 attack actions and 1,000 attack chains.
-   Generates high-quality attack plans with comprehensive TTP (Tactics, Techniques, and Procedures) coverage.
-   Automatically sets up the attack emulation environments and semi-automatically executes the attacks.

Our paper: [From Sands to Mansions: Towards Automated Cyberattack Emulation with Classical Planning and Large Language Models](https://arxiv.org/pdf/2407.16928)

## Resources & Socials

-   📜 [Documentation, training, and use-cases]()(Coming Soon)
-   ✍️ [aurora's blog]()(Coming Soon)
-   🌐 [Homepage](https://auroraattack.github.io/)

## System Overview

<p align="center">

<img src="../images/framework.png" alt="cli output" width="1000"/>

</p>

Aurora’s architecture comprises five components:
- `Attack Tool Analysis`: Converts third-party tool documentation into structured attack actions using rule-based and LLM-assisted predicate extraction.
- `Attack Report Analysis`: Extracts Tactics, Techniques, and Procedures (TTPs) from CTI reports via LLMs to guide attack planning.
- `Attack Planning`: Uses PDDL and reward functions (aligned with CTI-derived TTPs) to generate attack chains.
- `Attack Environment Builder`: Deploys pre-configured virtual machines to replicate vulnerable environments.
- `Attack Execution`: Semi-automatically runs attack scripts and collects traces for dataset construction.