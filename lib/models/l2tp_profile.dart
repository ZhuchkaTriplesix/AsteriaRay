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
    this.routes = '',
    this.dnsDomains = '',
  });

  final String id;
  final String name;
  final String server;
  final String username;
  final String password;
  final String presharedKey;
  final String? dns;

  /// Networks (CIDR, separated by commas/spaces/newlines) to send through the tunnel; empty = everything.
  final String routes;

  /// Domains resolved by the VPN's DNS (e.g. `npcmr.ru`); empty = all DNS goes through the VPN.
  final String dnsDomains;

  static final _cidr = RegExp(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$');
  static final _splitter = RegExp(r'[\s,;]+');

  static List<String> _tokens(String raw) =>
      raw.split(_splitter).where((e) => e.isNotEmpty).toList();

  List<String> get routeList => _tokens(routes);
  List<String> get dnsDomainList => _tokens(dnsDomains);

  /// First entry that is not a valid IPv4 CIDR, or null when [raw] is fine.
  static String? firstInvalidRoute(String raw) {
    for (final r in _tokens(raw)) {
      final m = _cidr.hasMatch(r);
      final octets = r.split('/').first.split('.').map(int.tryParse);
      final prefix = int.tryParse(r.split('/').last);
      if (!m || octets.any((o) => o == null || o > 255) || prefix == null || prefix > 32) {
        return r;
      }
    }
    return null;
  }

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
    String? routes,
    String? dnsDomains,
  }) {
    return L2tpProfile(
      id: id ?? this.id,
      name: name ?? this.name,
      server: server ?? this.server,
      username: username ?? this.username,
      password: password ?? this.password,
      presharedKey: presharedKey ?? this.presharedKey,
      dns: dns ?? this.dns,
      routes: routes ?? this.routes,
      dnsDomains: dnsDomains ?? this.dnsDomains,
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
        if (routes.isNotEmpty) 'routes': routes,
        if (dnsDomains.isNotEmpty) 'dnsDomains': dnsDomains,
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
      routes: map['routes'] as String? ?? '',
      dnsDomains: map['dnsDomains'] as String? ?? '',
    );
  }

  String toJson() => jsonEncode(toMap());

  factory L2tpProfile.fromJson(String source) =>
      L2tpProfile.fromMap(jsonDecode(source) as Map<String, dynamic>);
}
