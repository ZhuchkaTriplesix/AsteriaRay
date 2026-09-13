import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:uuid/uuid.dart';

import '../l10n/app_localizations.dart';
import '../models/l2tp_profile.dart';
import '../models/stored_vpn_profile.dart';
import '../notifiers/profile_notifier.dart';
import '../widgets/acrylic_toast.dart';

class L2tpFormScreen extends StatefulWidget {
  const L2tpFormScreen({
    super.key,
    this.profile,
    this.embedded = false,
  });

  final L2tpProfile? profile;
  final bool embedded;

  @override
  State<L2tpFormScreen> createState() => L2tpFormScreenState();
}

class L2tpFormScreenState extends State<L2tpFormScreen>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => widget.embedded;
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _name;
  late final TextEditingController _server;
  late final TextEditingController _username;
  late final TextEditingController _password;
  late final TextEditingController _psk;
  bool _obscurePassword = true;
  bool _obscurePsk = true;

  static const _radius = 14.0;
  static const _padding = EdgeInsets.symmetric(horizontal: 16, vertical: 16);

  @override
  void initState() {
    super.initState();
    final p = widget.profile;
    _name = TextEditingController(text: p?.name ?? '');
    _server = TextEditingController(text: p?.server ?? '');
    _username = TextEditingController(text: p?.username ?? '');
    _password = TextEditingController(text: p?.password ?? '');
    _psk = TextEditingController(text: p?.presharedKey ?? '');
  }

  @override
  void dispose() {
    _name.dispose();
    _server.dispose();
    _username.dispose();
    _password.dispose();
    _psk.dispose();
    super.dispose();
  }

  InputDecoration _fieldDecoration(
    BuildContext context, {
    required String labelText,
    IconData? prefixIcon,
    Widget? suffixIcon,
    String? hintText,
    String? helperText,
  }) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final border = OutlineInputBorder(
      borderRadius: BorderRadius.circular(_radius),
      borderSide: BorderSide(
        color: colorScheme.outline.withValues(alpha: 0.35),
        width: 1,
      ),
    );
    final focusedBorder = OutlineInputBorder(
      borderRadius: BorderRadius.circular(_radius),
      borderSide: BorderSide(
        color: colorScheme.primary.withValues(alpha: 0.7),
        width: 1.5,
      ),
    );
    return InputDecoration(
      labelText: labelText,
      hintText: hintText,
      helperText: helperText,
      prefixIcon: prefixIcon != null
          ? Icon(prefixIcon, size: 22, color: colorScheme.onSurface.withValues(alpha: 0.6))
          : null,
      suffixIcon: suffixIcon,
      filled: true,
      fillColor: colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
      contentPadding: _padding,
      border: border,
      enabledBorder: border,
      focusedBorder: focusedBorder,
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(_radius),
        borderSide: BorderSide(color: colorScheme.error.withValues(alpha: 0.8)),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(_radius),
        borderSide: BorderSide(color: colorScheme.error, width: 1.5),
      ),
    );
  }

  Future<void> submit() async {
    if (!_formKey.currentState!.validate()) return;

    final id = widget.profile?.id ?? const Uuid().v4();
    final name = _name.text.trim().isNotEmpty ? _name.text.trim() : _server.text.trim();
    final profile = L2tpProfile(
      id: id,
      name: name,
      server: _server.text.trim(),
      username: _username.text.trim(),
      password: _password.text,
      presharedKey: _psk.text,
    );

    final notifier = context.read<ProfileNotifier>();
    await notifier.addOrUpdate(L2tpStoredVpnProfile(profile));

    if (!mounted) return;
    AcrylicToast.show(
      context,
      'L2TP profile saved',
      icon: Icons.check_circle_rounded,
    );
    if (!widget.embedded) {
      Navigator.of(context).pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final isEditing = widget.profile != null;

    final formBody = Form(
      key: _formKey,
      child: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Text(
            'Configuration Parameters',
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _name,
            decoration: _fieldDecoration(
              context,
              labelText: 'Profile Name',
              prefixIcon: Icons.label_outline_rounded,
              hintText: 'Home L2TP, Office VPN…',
            ),
            textCapitalization: TextCapitalization.sentences,
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _server,
            decoration: _fieldDecoration(
              context,
              labelText: 'Server Host / IP Address',
              prefixIcon: Icons.dns_outlined,
              hintText: 'vpn.example.com or 198.51.100.1',
            ),
            validator: (v) {
              if (v == null || v.trim().isEmpty) {
                return 'Server address is required';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _username,
            decoration: _fieldDecoration(
              context,
              labelText: 'Username',
              prefixIcon: Icons.person_outline_rounded,
            ),
            validator: (v) {
              if (v == null || v.trim().isEmpty) {
                return 'Username is required';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _password,
            obscureText: _obscurePassword,
            decoration: _fieldDecoration(
              context,
              labelText: 'Password',
              prefixIcon: Icons.lock_outline_rounded,
              suffixIcon: IconButton(
                icon: Icon(
                  _obscurePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                ),
                onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
              ),
            ),
            validator: (v) {
              if (v == null || v.isEmpty) {
                return 'Password is required';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _psk,
            obscureText: _obscurePsk,
            decoration: _fieldDecoration(
              context,
              labelText: 'IPsec Pre-Shared Key (PSK)',
              prefixIcon: Icons.key_outlined,
              suffixIcon: IconButton(
                icon: Icon(
                  _obscurePsk ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                ),
                onPressed: () => setState(() => _obscurePsk = !_obscurePsk),
              ),
            ),
            validator: (v) {
              if (v == null || v.isEmpty) {
                return 'Pre-Shared Key is required';
              }
              return null;
            },
          ),
        ],
      ),
    );

    if (widget.embedded) return formBody;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          isEditing ? 'Edit L2TP Profile' : 'New L2TP Profile',
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        actions: [
          TextButton.icon(
            onPressed: submit,
            icon: const Icon(Icons.check_rounded),
            label: const Text('Save'),
            style: TextButton.styleFrom(
              foregroundColor: colorScheme.primary,
            ),
          ),
        ],
      ),
      body: formBody,
    );
  }
}
