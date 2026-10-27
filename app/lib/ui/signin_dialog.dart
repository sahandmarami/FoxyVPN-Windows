import 'package:flutter/material.dart';

import '../core/core_api.dart';
import '../core/core_controller.dart';
import '../l10n/app_localizations.dart';
import 'widgets.dart';

/// Adds an account from a FoxyVPN key: no email, no password — the key
/// itself carries the account. This is the only way to sign in.
Future<void> showSignInDialog(BuildContext context, CoreController core) =>
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _SignInDialog(core: core),
    );

class _SignInDialog extends StatefulWidget {
  const _SignInDialog({required this.core});

  final CoreController core;

  @override
  State<_SignInDialog> createState() => _SignInDialogState();
}

class _SignInDialogState extends State<_SignInDialog> {
  final _key = TextEditingController();

  /// Set once the core accepted a pasted key and added the account.
  bool _done = false;
  bool _sending = false;
  String? _error;

  /// The core's own technical detail under a key error (an FxA errno, an
  /// HTTP status): the localized message explains, this proves.
  String _errorDetail = '';

  CoreApi? get _api => widget.core.api;

  @override
  void dispose() {
    _key.dispose();
    super.dispose();
  }

  /// Sends the pasted key to the core; the answer comes in this one call
  /// (no codes, no CAPTCHA), so there is no sign-in session to follow.
  Future<void> _start() async {
    final api = _api;
    if (api == null || _sending) return;
    final key = _key.text.trim();
    if (key.isEmpty) {
      setState(() => _error = AppLocalizations.of(context).keyInvalid);
      return;
    }
    setState(() {
      _sending = true;
      _error = null;
      _errorDetail = '';
    });
    try {
      await api.signInWithKey(key);
      if (!mounted) return;
      await widget.core.refresh(accountsToo: true);
      if (mounted) setState(() => _done = true);
    } on CoreApiException catch (e) {
      if (mounted) {
        final l = AppLocalizations.of(context);
        final localized = switch (e.code) {
          'key_invalid' => l.keyInvalid,
          'key_expired' => l.keyExpired,
          'key_rejected' => l.keyRejected,
          'key_network' => l.keyNetwork,
          _ => null,
        };
        setState(() {
          if (localized != null) {
            _error = localized;
            // the default text carries no detail; anything else does
            _errorDetail =
                e.message.isEmpty ||
                    e.message == 'the FoxyVPN key was not accepted'
                ? ''
                : e.message;
          } else {
            _error = e.message;
            _errorDetail = '';
          }
        });
      }
    } on CoreUnavailable catch (e) {
      if (mounted) {
        setState(
          () => _error = describeProblem(AppLocalizations.of(context), e),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _close() => Navigator.of(context).pop();

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l.addAccount),
      content: SizedBox(
        width: 400,
        child: AnimatedSize(
          duration: const Duration(milliseconds: 200),
          alignment: Alignment.topCenter,
          child: _done ? _success(l) : _keyForm(l),
        ),
      ),
      actions: [
        TextButton(onPressed: _close, child: Text(l.cancel)),
        if (_done)
          FilledButton(onPressed: _close, child: Text(l.done))
        else
          FilledButton(
            onPressed: _sending ? null : _start,
            child: _sending
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : Text(l.signIn),
          ),
      ],
    );
  }

  Widget _success(AppLocalizations l) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: const Icon(
        Icons.check_circle_rounded,
        color: StatusColors.good,
        size: 32,
      ),
      title: Text(l.accountReady),
      subtitle: Text(l.accountReadyHint),
    );
  }

  Widget _keyForm(AppLocalizations l) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(l.keyIntro, style: Theme.of(context).textTheme.bodyMedium),
        const SizedBox(height: 16),
        TextFormField(
          controller: _key,
          autofocus: true,
          minLines: 2,
          maxLines: 3,
          enableSuggestions: false,
          autocorrect: false,
          // Keys are typed and shared left to right, also in Persian.
          textDirection: TextDirection.ltr,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5),
          decoration: InputDecoration(
            labelText: l.keyLabel,
            border: const OutlineInputBorder(),
            prefixIcon: const Icon(Icons.vpn_key_rounded),
          ),
          onFieldSubmitted: (_) => _start(),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          _ErrorBox(_error!),
          if (_errorDetail.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              _errorDetail,
              textDirection: TextDirection.ltr,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ],
      ],
    );
  }
}

class _ErrorBox extends StatelessWidget {
  const _ErrorBox(this.message);

  final String message;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: StatusColors.bad.withValues(alpha: 0.12),
      borderRadius: BorderRadius.circular(8),
    ),
    child: Text(
      message,
      style: Theme.of(
        context,
      ).textTheme.bodyMedium?.copyWith(color: StatusColors.bad),
    ),
  );
}
