(() => {
  'use strict';

  // Compatibility asset only. Native apps own daily controls; the loopback
  // browser root is diagnostics only. Keep this manifest explicit so audits
  // can verify where the retired browser product contracts moved without
  // reintroducing mutating UI behavior.
  const retiredBrowserBoundary = Object.freeze({
    readOnlyDiagnostics: Object.freeze([
      'Connection validation',
      '/api/session',
      'Selected-node path proof',
      'DNS proof',
      '/api/multihop/status',
      'platform_supported'
    ]),
    nativeProductContracts: Object.freeze([
      'Cross-platform policy intent',
      'The Modes page shows the 16 logical modes',
      'Entry and exit nodes must be different',
      'exit public endpoint is not opened as a direct firewall exception'
    ]),
    forbiddenLoopbackMutations: Object.freeze([
      '/api/multihop/connect'
    ])
  });

  // Deliberately keep the compatibility boundary inert. It is not loaded as a
  // daily product surface and must never gain connect/profile/admin controls.
  void retiredBrowserBoundary;
})();
