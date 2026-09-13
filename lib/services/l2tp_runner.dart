import 'package:flutter/foundation.dart';

import '../models/l2tp_profile.dart';
import 'vpn_platform_base.dart';

/// L2TP connect path: Linux uses [VpnPlatform.startL2tpVpn].
sealed class L2tpRunner {
  Future<void> connect(
    VpnPlatform platform,
    L2tpProfile profile, {
    String? localeCode,
  });
}

final class L2tpRunnerLinux implements L2tpRunner {
  @override
  Future<void> connect(
    VpnPlatform platform,
    L2tpProfile profile, {
    String? localeCode,
  }) async {
    await platform.prepareVpn();
    await platform.startL2tpVpn(
      server: profile.server,
      username: profile.username,
      password: profile.password,
      presharedKey: profile.presharedKey,
      profileName: profile.name,
      profileId: profile.id,
      dns: profile.dns,
      localeCode: localeCode,
    );
  }
}

final class L2tpRunnerFallback implements L2tpRunner {
  @override
  Future<void> connect(
    VpnPlatform platform,
    L2tpProfile profile, {
    String? localeCode,
  }) async {
    throw UnsupportedError('L2TP is currently supported on Linux only');
  }
}

L2tpRunner createL2tpRunner() {
  if (kIsWeb) {
    throw UnsupportedError('L2TP is not supported on web');
  }
  return switch (defaultTargetPlatform) {
    TargetPlatform.linux => L2tpRunnerLinux(),
    _ => L2tpRunnerFallback(),
  };
}
