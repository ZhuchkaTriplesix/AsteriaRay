import 'package:flutter_test/flutter_test.dart';
import 'package:asteriaray/models/l2tp_profile.dart';
import 'package:asteriaray/models/stored_vpn_profile.dart';
import 'package:asteriaray/models/vpn_protocol.dart';
import 'package:asteriaray/services/stored_profile_codec.dart';

void main() {
  group('L2tpProfile', () {
    test('toJson and fromJson preserves all fields', () {
      final profile = L2tpProfile(
        id: 'l2tp-123',
        name: 'Office VPN',
        server: 'vpn.office.com',
        username: 'alice',
        password: 'secretpassword',
        presharedKey: 'ipsec-psk-123',
      );

      final json = profile.toJson();
      final restored = L2tpProfile.fromJson(json);

      expect(restored.id, 'l2tp-123');
      expect(restored.name, 'Office VPN');
      expect(restored.server, 'vpn.office.com');
      expect(restored.username, 'alice');
      expect(restored.password, 'secretpassword');
      expect(restored.presharedKey, 'ipsec-psk-123');
      expect(restored.endpointHint, 'vpn.office.com');
    });

    test('copyWith works correctly', () {
      final profile = L2tpProfile(
        id: 'l2tp-1',
        name: 'Initial',
        server: '1.2.3.4',
        username: 'user',
        password: 'pwd',
        presharedKey: 'psk',
      );

      final updated = profile.copyWith(
        name: 'Updated',
        server: '5.6.7.8',
      );

      expect(updated.id, 'l2tp-1');
      expect(updated.name, 'Updated');
      expect(updated.server, '5.6.7.8');
      expect(updated.username, 'user');
      expect(updated.password, 'pwd');
      expect(updated.presharedKey, 'psk');
    });
  });

  group('StoredProfileCodec with L2TP', () {
    test('encodes and decodes L2tpStoredVpnProfile', () {
      final profile = L2tpProfile(
        id: 'l2tp-test-id',
        name: 'Production L2TP',
        server: 'l2tp.prod.example',
        username: 'bob',
        password: 'mypassword',
        presharedKey: 'sharedkey',
      );
      final stored = L2tpStoredVpnProfile(profile);

      expect(stored.protocol, VpnProtocol.l2tp);
      expect(stored.id, 'l2tp-test-id');
      expect(stored.name, 'Production L2TP');

      final encoded = StoredProfileCodec.encode(stored);
      expect(encoded.contains('"protocol":"l2tp"'), isTrue);

      final decoded = StoredProfileCodec.decode(encoded);
      expect(decoded, isA<L2tpStoredVpnProfile>());
      final l2tpStored = decoded as L2tpStoredVpnProfile;
      expect(l2tpStored.profile.id, 'l2tp-test-id');
      expect(l2tpStored.profile.name, 'Production L2TP');
      expect(l2tpStored.profile.server, 'l2tp.prod.example');
      expect(l2tpStored.profile.username, 'bob');
      expect(l2tpStored.profile.password, 'mypassword');
      expect(l2tpStored.profile.presharedKey, 'sharedkey');
    });
  });
}
