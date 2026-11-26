#!/usr/bin/env python3
"""Breaks one rule of AgentPolicy, in a copy, for the proof that must catch it.

    scripts/kontrol-break.py <break> <path to AgentPolicy.sol>   # prints the proof, as Contract.name
    scripts/kontrol-break.py --list                               # the breaks, one per line

Each rule that contracts/test/BudgetProof.t.sol proves of the budget, and
that contracts/test/VenueCallProof.t.sol proves of a call a venue's decoder
judged (issue #225), is broken here alone, and
.github/workflows/kontrol.yml requires its proof to fail (issue #130, item
3): a proof that still passed with its rule broken would prove nothing
about that rule.

A break is a text replacement inside one function, found by its signature,
so that comments added around the code do not move it. The replacement must
match exactly once in that function; anything else is an error, not a pass.
"""
import re
import sys

# name, the proof that must fail, the function, the code, the broken code
BREAKS = [
    ("token-cap", "BudgetProof.check_tokenTransfer_oneOp", "_chargeToken",
     "_movedThisOperation(token, amount) > t.maxPerOp", "_movedThisOperation(token, amount) > t.maxPerOp + 1"),
    ("token-budget", "BudgetProof.check_tokenTransfer_twoOps", "_chargeToken",
     "if (spent > t.budget)", "if (spent > t.budget + 1)"),
    ("native-cap", "BudgetProof.check_nativeTransfer_oneOp", "checkUserOpPolicy",
     "value > c.maxValuePerOp)", "value > c.maxValuePerOp + 1)"),
    ("native-budget", "BudgetProof.check_nativeTransfer_twoOps", "checkUserOpPolicy",
     "if (spent > c.budget)", "if (spent > c.budget + 1)"),
    ("token-sum-per-operation", "BudgetProof.check_tokenBatch_twoLegs", "_movedThisOperation",
     "total = before + amount;", "total = amount;"),
    ("batch-legs-summed", "BudgetProof.check_nativeBatch_twoLegs", "_judgeAccountBatch",
     "moved += legMoved;", "moved = legMoved;"),
    ("safe-inner-value", "BudgetProof.check_safe_innerValue", "_judgeSafe",
     "(true, value + moved)", "(true, value)"),
    ("multisend-legs-summed", "BudgetProof.check_safe_multiSend_twoLegs", "_judgeBatch",
     "moved += legMoved;", "moved = legMoved;"),
    ("call-value-counted", "BudgetProof.check_faithful_batch", "_judge",
     "return (true, value);", "return (true, 0);"),
    ("allowance-left-open", "BudgetProof.check_allowance_mustBeWithdrawn", "checkUserOpPolicy",
     "if (_tload(_thisOperation(OPEN_ALLOWANCES)) != 0)", "if (false)"),
    # a call a venue's decoder judged (#225)
    ("venue-call-value-counted", "VenueCallProof.check_venueCall_valueCounted", "_judgeAccountBatch",
     "(ok, legMoved) = (_judgeVenueCall(m, target, value, data), value);",
     "(ok, legMoved) = (_judgeVenueCall(m, target, value, data), 0);"),
    ("venue-call-price-capped", "VenueCallProof.check_venueCall_priced", "_registerOrder",
     "if (_movedThisOperation(j.token, j.mostSold) > t.maxPerOp)", "if (_movedThisOperation(j.token, j.mostSold) > t.maxPerOp + 1)"),
    ("venue-call-is-the-registered-one", "VenueCallProof.check_venueCall_onlyThatCall", "_judgeVenueCall",
     "if (uint256(VenueCalls.bound(target, VenueCalls.digest(value, data))) != _tload(slot))", "if (false)"),
    ("venue-call-registration-alone", "VenueCallProof.check_venueCall_aRegistrationAlone", "checkUserOpPolicy",
     "if (_tload(_thisOperation(EXPECTED_CALL)) != 0)", "if (false)"),
]


def function_body(source, name):
    """The span of `function <name>(` up to the next function or the end."""
    starts = [m.start() for m in re.finditer(r"\n    function " + re.escape(name) + r"\(", source)]
    if len(starts) != 1:
        sys.exit(f"function {name}: found {len(starts)} times, expected once")
    nxt = source.find("\n    function ", starts[0] + 1)
    return starts[0], (len(source) if nxt == -1 else nxt)


def main():
    if sys.argv[1:] == ["--list"]:
        print("\n".join(b[0] for b in BREAKS))
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    name, path = sys.argv[1:]
    match = [b for b in BREAKS if b[0] == name]
    if not match:
        sys.exit(f"no break named {name}")
    _, proof, function, code, broken = match[0]
    source = open(path).read()
    start, end = function_body(source, function)
    body = source[start:end]
    if body.count(code) != 1:
        sys.exit(f"{name}: `{code}` found {body.count(code)} times in {function}, expected once")
    open(path, "w").write(source[:start] + body.replace(code, broken, 1) + source[end:])
    print(proof)


if __name__ == "__main__":
    main()
