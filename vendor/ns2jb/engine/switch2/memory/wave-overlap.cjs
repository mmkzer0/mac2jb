// Qualify the request lifetimes observed in one gap-probe wave.
// Ported from upstream mac2jb `vendor/ns2jb-hosts/cellenseres` (v0.8.0) so the
// overlap predicate can be unit-tested and compared against the inline
// computation in probe-reserved-gap.cjs. Default run behavior is unchanged
// until the retry/qualification change is adopted deliberately.
//
// Divergence to keep in mind before wiring this into the probe: the inline
// predicate still used for `isExtent && hasTmp` requires held roles to stay
// alive past `trigger.endUs`, while this unified predicate only requires
// `trigger.startUs < row.endUs` for held roles. This module is therefore a
// stricter/looser comparison reference, not a drop-in replacement for that case.
const HELD_ROLES = ['canary', 'filler0', 'filler1', 'guard0', 'guard1'];
const THROUGH_ROLES = ['commit', 'tail0', 'tail1', 'tail2', 'tail3'];

function qualifyOverlap(rows) {
  const byRole = new Map(rows.map(row => [row.role, row]));
  const trigger = byRole.get('trigger');
  const held = HELD_ROLES.map(role => byRole.get(role));
  const through = THROUGH_ROLES.map(role => byRole.get(role));
  const mode = 'trigger-entry';
  if (!trigger || held.some(row => !row) || through.some(row => !row))
    return {qualified: false, mode};

  const startedBeforeTrigger = [...held, ...through].every(row => row.startUs < trigger.startUs);
  const throughTriggerEnd = through.every(row => trigger.endUs < row.endUs);
  const heldLongEnough = held.every(row => trigger.startUs < row.endUs);
  return {qualified: startedBeforeTrigger && throughTriggerEnd && heldLongEnough, mode};
}

module.exports = {qualifyOverlap, HELD_ROLES, THROUGH_ROLES};
