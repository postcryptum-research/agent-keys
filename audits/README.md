# Audits

The audits of this repository: each report with the commit it covers, its
findings, and the issue and the pull request of each finding.

**None of these is an external, third-party audit.** They are internal
audits, made apart from the sessions that write the code. The project runs
on test networks and holds no real funds
([`docs/FAQ.md`](../docs/FAQ.md#is-it-audited)).

## Internal audits

| Audit | Covers | Findings | State |
|---|---|---|---|
| [`audit1`](audit1/README.md), 2026-11-24 | `73a707ca2cc573b85f117bab929f4528f61c2be2`: the contracts, the Rust signer, the phone's core, the ERC-7562 checker | 1 High, 1 Medium, 5 Low, 8 notes | every finding resolved and its issue closed (#147 to #154) |
| [`audit2`](audit2/README.md), 2026-11-27 | `4295e00bcf7ef19a2cde92b191d6ad40604a543b`: the same, with the native phone apps and the integrations of `examples/` | 2 High, 1 Medium, 1 Low | the findings filed (#244 to #247); #244 and #247 answered in #249, #245 and #246 in #252; the fixes confirmed in the source by audit3, in review |
| [`audit3`](audit3/README.md), 2026-11-28 | a re-audit of #252, #255, #257 and #258 at their heads, then of #259, #260 and #261: the division of `AgentPolicy`, the Jinn fixes, a venue's pause over registered orders, one budget on Arc | 1 Medium | filed as #262, fixed in #260 (in review); the delta of #259 and #261 has no finding, and its head is cleared for the test networks |

Earlier internal reviews, kept where they were written:
[`docs/AUDIT-2026-10-20.md`](../docs/AUDIT-2026-10-20.md) (the first
contracts and the signer) and
[`docs/audit/REVIEW-SCOPE-2026-11-19.md`](../docs/audit/REVIEW-SCOPE-2026-11-19.md)
(what the internal review covered by that date).

## External audits

None yet. An external audit comes before any deployment to a mainnet: a
release is tagged for it and its report is kept here with that tag
([`CONTRIBUTING.md`](../CONTRIBUTING.md), versions and releases).

## How a report is kept

- A report names the commit it read. A finding names the file and what an
  attacker or a mistake can do with it; a person is never named.
- Each finding gets an issue. The pull request that fixes it comes with a
  test that fails without the fix, and the report is updated with both.
- A finding that is accepted and not fixed says so, with the reason and
  where an owner reads about it.
- Dates are UTC.
