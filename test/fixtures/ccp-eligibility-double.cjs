// Test double for the CCP eligibility module.
//
// Re-exports the real compiled implementation so every validation rule under test is the
// real one, and replaces only the reader factory, which is the single seam that would
// otherwise require a network. The route therefore gets its production logic and an
// offline chain, without any test seam in production code.
const real = require("../../.product-test-dist/src/lib/protection/ccp-eligibility.js");

const state = { verdict: true, registered: true, chainId: 10143, blockNumber: 51150000n, failWith: null };
const ELIGIBLE = "0x911f99f424d47f08a15fcc771e94dcc2f7252b02";

function createCcpReader() {
  const boom = () => {
    if (state.failWith !== null) throw new Error(state.failWith);
  };
  return {
    getChainId: async () => { boom(); return state.chainId; },
    getBlockNumber: async () => { boom(); return state.blockNumber; },
    isRegistered: async () => { boom(); return state.registered; },
    complianceVerify: async (_gate, holder) => { boom(); return state.verdict && holder.toLowerCase() === ELIGIBLE; },
  };
}

module.exports = { ...real, state, createCcpReader };
