export const DEMO = {
  invoiceFace: 110,
  advance: 100,
  originatorProceeds: 90,
  initialBond: 10,
  initialUnits: 100,
  holders: [
    { id: "A", units: 60 },
    { id: "B", units: 40 },
  ],
} as const;

export function requiredBond(outstandingUnits: number): number {
  if (!Number.isInteger(outstandingUnits) || outstandingUnits < 0 || outstandingUnits > DEMO.initialUnits) {
    throw new RangeError("outstandingUnits must be an integer between zero and the issued supply");
  }
  return (DEMO.initialBond * outstandingUnits) / DEMO.initialUnits;
}

export function holderEntitlement(holderUnits: number, snapshotSupply: number, entitlementBond: number): number {
  if (holderUnits < 0 || snapshotSupply <= 0 || holderUnits > snapshotSupply || entitlementBond < 0) {
    throw new RangeError("invalid entitlement inputs");
  }
  return (entitlementBond * holderUnits) / snapshotSupply;
}

export function holderRedemption(holderUnits: number): number {
  if (!Number.isInteger(holderUnits) || holderUnits < 0 || holderUnits > DEMO.initialUnits) {
    throw new RangeError("holderUnits must be an integer between zero and the issued supply");
  }
  return (DEMO.invoiceFace * holderUnits) / DEMO.initialUnits;
}
