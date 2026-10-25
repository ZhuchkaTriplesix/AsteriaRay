import 'amnezia_wg_profile.dart';
import 'l2tp_profile.dart';
import 'vless_profile.dart';
import 'vpn_protocol.dart';

/// Single wrapper for multi-protocol profiles in one list.
sealed class StoredVpnProfile {
  const StoredVpnProfile();

  String get id;
  String get name;
  VpnProtocol get protocol;
}

final class VlessStoredVpnProfile extends StoredVpnProfile {
  VlessStoredVpnProfile(this.profile);

  final VlessProfile profile;

  @override
  String get id => profile.id;

  @override
  String get name => profile.name;

  @override
  VpnProtocol get protocol => VpnProtocol.vless;
}

final class AmneziaWgStoredVpnProfile extends StoredVpnProfile {
  AmneziaWgStoredVpnProfile(this.profile);

  final AmneziaWgProfile profile;

  @override
  String get id => profile.id;

  @override
  String get name => profile.name;

  @override
  VpnProtocol get protocol => VpnProtocol.amneziaWg;
}

final class L2tpStoredVpnProfile extends StoredVpnProfile {
  L2tpStoredVpnProfile(this.profile);

  final L2tpProfile profile;

  @override
  String get id => profile.id;

  @override
  String get name => profile.name;

  @override
  VpnProtocol get protocol => VpnProtocol.l2tp;
}
