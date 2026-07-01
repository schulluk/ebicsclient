# PHP parity tool (dev-only)

Generates golden EBICS request vectors from
[ebics-client-php](https://github.com/ebics-api/ebics-client-php) so the Python
`ebicsclient` can be cross-checked against an independent implementation offline. This
tool is **not** part of the distributed package.

## Regenerate the fixtures

Requires PHP 8+ and Composer.

```bash
composer install --working-dir=tools/php-parity
php tools/php-parity/generate.php
```

This writes `tests/fixtures/parity/{ini,hia,hpb}.xml` and `meta.json` (the fixed keyring,
as PEM). Commit the regenerated fixtures as one internally-consistent snapshot. The
`vendor/` directory (the fetched library) is gitignored; `composer.json`/`composer.lock`
pin the exact version and are committed.

The parity assertions live in `tests/test_php_parity.py` and run in CI **without** PHP —
they read the committed fixtures. See [docs/08](../../docs/08-parity-and-xsd-findings.md).
