import 'package:flutter/material.dart';

import '../models/vpn_protocol.dart';
import '../l10n/app_localizations.dart';
import '../widgets/protocol_slide_tabs.dart';
import 'amnezia_wg_form_screen.dart';
import 'l2tp_form_screen.dart';
import 'profile_form_screen.dart';

/// Manual profile creation: swipe VLESS ↔ AmneziaWG ↔ L2TP, same tabs as home.
class ManualProfileScreen extends StatefulWidget {
  const ManualProfileScreen({
    super.key,
    this.initialProtocol = VpnProtocol.vless,
  });

  final VpnProtocol initialProtocol;

  @override
  State<ManualProfileScreen> createState() => _ManualProfileScreenState();
}

class _ManualProfileScreenState extends State<ManualProfileScreen> {
  late final PageController _pageController;
  final _vlessFormKey = GlobalKey<ProfileFormScreenState>();
  final _awgFormKey = GlobalKey<AmneziaWgFormScreenState>();
  final _l2tpFormKey = GlobalKey<L2tpFormScreenState>();

  @override
  void initState() {
    super.initState();
    final initialPage = switch (widget.initialProtocol) {
      VpnProtocol.amneziaWg => 1,
      VpnProtocol.l2tp => 2,
      _ => 0,
    };
    _pageController = PageController(initialPage: initialPage);
  }

  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }

  void _goToPage(int index) {
    if (!_pageController.hasClients) return;
    final current = _pageController.page?.round() ?? _pageController.initialPage;
    if (current == index) return;
    _pageController.animateToPage(
      index,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeInOutCubic,
    );
  }

  Future<void> _saveCurrent() async {
    final page = _pageController.hasClients
        ? (_pageController.page?.round() ?? _pageController.initialPage)
        : _pageController.initialPage;
    if (page == 0) {
      await _vlessFormKey.currentState?.submit();
    } else if (page == 1) {
      await _awgFormKey.currentState?.submit();
    } else {
      await _l2tpFormKey.currentState?.submit();
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final l10n = context.l10n;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          l10n.newConfig,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        actions: [
          TextButton.icon(
            onPressed: _saveCurrent,
            icon: const Icon(Icons.check_rounded),
            label: Text(l10n.save),
            style: TextButton.styleFrom(
              foregroundColor: colorScheme.primary,
            ),
          ),
        ],
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          RepaintBoundary(
            child: AnimatedBuilder(
              animation: _pageController,
              builder: (context, _) {
                final page = _pageController.hasClients
                    ? (_pageController.page ??
                        _pageController.initialPage.toDouble())
                    : _pageController.initialPage.toDouble();
                return ProtocolSlideTabs(
                  page: page.clamp(0.0, 2.0),
                  onSelect: _goToPage,
                );
              },
            ),
          ),
          Expanded(
            child: PageView(
              controller: _pageController,
              physics: const PageScrollPhysics(
                parent: ClampingScrollPhysics(),
              ),
              children: [
                ProfileFormScreen(
                  key: _vlessFormKey,
                  embedded: true,
                ),
                AmneziaWgFormScreen(
                  key: _awgFormKey,
                  embedded: true,
                ),
                L2tpFormScreen(
                  key: _l2tpFormKey,
                  embedded: true,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
