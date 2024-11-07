# Nautilus
NIST-compliant Security solutions

https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards

# How to stay updated

To get updates once this on your computer, you have two options:

1. [**Using HTTPS (Most Common)**](#using-https-most-common)
2. [**Using SSH (Advanced)**](#using-ssh-advanced)

- **Either** option requires[git](#how-to-install-git) to be installed:

### Using HTTPS (Most Common)

This option is best if:

    * You’re new to GitHub
    * You like to keep things simple.
    * You haven't set up SSH/GPG keys for Github.
    * You don't have the Github CLI

- MacOS | Linux | Microsoft WSL

```bash
git clone --depth 1 https://github.com/qompassai/Equator.git
git remote add upstream https://github.com/qompassai/Equator.git
git fetch upstream
git checkout main
git merge upstream/main
```

Note: You only need to run the clone command **once**. After that, go to [3. Getting Updates](#getting-updates) to keep your local repository up-to-date.

2. **Using SSH(Advanced)**:

-  MacOS | Linux | Microsoft WSL **with** [GitHub CLI (gh)](https://github.com/cli/cli#installation)

```bash
gh repo clone qompassai/Equator
git remote add upstream https://github.com/qompassai/Equator.git
git fetch upstream
git checkout main
git merge upstream/main
```

This option is best if you:

    * are not new to Github
    * You want to add a new technical skill
    * You're comfortable with the terminal/CLI, or want to be
    * You have SSH/GPG set up
    * You're

Note: You only need to run the clone command **once**. After that, go to [3. Getting Updates](#getting-updates) to keep your local repository up-to-date.

3. Getting updates

- **After** cloning locally, use the following snippet below to get the latest updates:

- MacOS | Linux | Microsoft WSL

- Option 1:
**This will **overwrite** any local changes you've made**

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

-Option 2:
**To keep your local changes and still get the updates**

```bash
git stash
git fetch upstream
git checkout main
git merge upstream/main
git stash pop
```

## Dual-License Notice
This repository and all applications within it are dual-licensed under the terms of the [Qompass Commercial Distribution Agreement (CDA)](LICENSE) and [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE-AGPL) licenses.

## What a Dual-License means

### Protection for Vulnerable Populations

The dual licensing aims to address the cybersecurity gap that disproportionately affects underserved populations. As highlighted by recent attacks[^1], low-income residents, seniors, and foreign language speakers face higher-than-average risks of being victims of cyber attacks. By offering both open-source and commercial licensing options, we encourage the development of cybersecurity solutions that can reach these vulnerable groups while also enabling sustainable development and support.

### Preventing Malicious Use

The AGPL-3.0 license ensures that any modifications to the software remain open source, preventing bad actors from creating closed-source variants that could be used for exploitation. This is especially crucial given the rising threats to vulnerable communities, including children in educational settings. The attack on Minneapolis Public Schools, which resulted in the leak of 300,000 files and a $1 million ransom demand, highlights the importance of transparency and security[^6]).

### Addressing Cybersecurity in Critical Sectors

The commercial license option allows for tailored solutions in critical sectors such as healthcare, which has seen significant impacts from cyberattacks. For example, the recent Change Healthcare attack[^2] affected millions of Americans and caused widespread disruption for hospitals and other providers.

### Supporting Cybersecurity Awareness

The dual licensing model supports initiatives like theCybersecurity and Infrastructure Security Agency (CISA) efforts to improve cybersecurity awareness[^3] in "target rich" sectors, including K-12 education. By allowing both open-source and commercial use, we aim to facilitate the development of tools that support these critical awareness and protection efforts.

### Bridging the Digital Divide

The unfortunate reality is that a number of individuals and organizations have gone into a frenzy in every facet of our daily lives[^4]. These unfortunate folks identify themselves with their talk of "10X" returns and building towards Artificial General Intelligence aka "AGI". Our dual licensing approach aims to acknkowledge this deeply concerning predatory paradigm witih clear eyes while still doing operating to bring the best parts of the open-source community with our services and solutions.

### Recent Cybersecurity Attacks

Recent attacks underscore the importance of robust cybersecurity measures:

- The Change Healthcare cyberattack in February 2024[^2] affected millions of Americans and caused significant disruption to healthcare providers.
- The White House and Congress jointly designated October as Cybersecurity Awareness Month[^5]. This designation comes with over 100 actions that align the Federal government and public/private sector partners are taking to help every man, woman, and child to safely navigate the age of AI. 
### Conclusion

By offering both open-source and commercial licensing options, we strive to create a balance that promotes innovation and accessibility while also providing the necessary resources and flexibility to address the complex cybersecurity challenges faced by vulnerable populations and critical infrastructure sectors.

[^1]: [International Counter Ransomware Initiative 2024 Joint Statement](https://www.whitehouse.gov/briefing-room/statements-releases/2024/10/02/international-counter-ransomware-initiative-2024-joint-statement/)
[^2]: [The Top 10 Health Data Breaches of the First Half of 2024](https://www.chiefhealthcareexecutive.com/view/the-top-10-health-data-breaches-of-the-first-half-of-2024)
[^3]: [CISA's K-12 Cybersecurity Initiatives](https://www.cisa.gov/K12Cybersecurity)
[^4]: [Federal Trade Commission Operation AI Comply: continuing the crackdown on overpromises and AI-related lies](https://www.ftc.gov/business-guidance/blog/2024/09/operation-ai-comply-continuing-crackdown-overpromises-ai-related-lies)
[^5]: [A Proclamation on Cybersecurity Awareness Month, 2024 ](https://www.whitehouse.gov/briefing-room/presidential-actions/2024/09/30/a-proclamation-on-cybersecurity-awareness-month-2024/)
[^6]: [Minneapolis school district says data breach affected more than 100,000 people](https://therecord.media/minneapolis-schools-say-data-breach-affected-100000/)
