import 'dart:convert';

/// L2TP / IPsec PSK VPN profile.
class L2tpProfile {
  L2tpProfile({
    required this.id,
    required this.name,
    required this.server,
    required this.username,
    required this.password,
    required this.presharedKey,
    this.dns,
  });

  final String id;
  final String name;
  final String server;
  final String username;
  final String password;
  final String presharedKey;
  final String? dns;

  /// Short subtitle for the list (server address).
  String get endpointHint => server.trim().isNotEmpty ? server.trim() : 'L2TP / IPsec';

  L2tpProfile copyWith({
    String? id,
    String? name,
    String? server,
    String? username,
    String? password,
    String? presharedKey,
    String? dns,
  }) {
    return L2tpProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      server: server ?? this.server,
      username: username ?? this.username,
      password: password ?? this.password,
      presharedKey: presharedKey ?? this.presharedKey,
      dns: dns ?? this.dns,
    );
  }

  Map<String, dynamic> toMap() => {
        'id': id,
        'name': name,
        'server': server,
        'username': username,
        'password': password,
        'presharedKey': presharedKey,
        if (dns != null) 'dns': dns,
      };

  factory L2tpProfile.fromMap(Map<String, dynamic> map) {
    return L2tpProfile(
      id: map['id'] as String? ?? '',
      name: map['name'] as String? ?? 'L2TP',
      server: map['server'] as String? ?? '',
      username: map['username'] as String? ?? '',
      password: map['password'] as String? ?? '',
      presharedKey: map['presharedKey'] as String? ?? '',
      dns: map['dns'] as String?,
    );
  }

  String toJson() => jsonEncode(toMap());

  factory L2tpProfile.fromJson(String source) =>
      L2tpProfile.fromMap(jsonDecode(source) as Map<String, dynamic>);
}
