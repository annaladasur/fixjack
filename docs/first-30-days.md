# Your first 30 days

**Day 1.** Write down every bot and agent that can change a dependency, and what each one reads.

**Week 1.**
1. Run `fixjack-baseline` on 90 days of history to get the non-human change share and provenance coverage.
2. Replay the last 50 non-human dependency PRs with `fixjack-replay`, in report-only mode.
3. Bring the table of what would have been blocked, and why, to whoever owns branch protection.

The commands are in `checklist.md`.

**Week 2.** Add the verifier as a CI job on one busy repository, in report-only mode, posting verdicts as comments.

**Week 3.** Send block events to ticketing. Review every would-be block with the owning team.

**Week 4.** Compute the false-block rate. Decide, with that number, whether the repository goes to Level 3.

**Monday morning test.** You should be able to do Day 1 and Week 1 with git, a spreadsheet, a read token and this repository, without asking anyone.

Then open a commitment in `CHALLENGE.md`. Thirty days later, say what happened, including what did not work.
