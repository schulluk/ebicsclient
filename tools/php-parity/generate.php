<?php

/**
 * Generate golden EBICS request vectors from ebics-client-php.
 *
 * Dev-only tool. Builds INI, HIA, and HPB requests with a fixed keyring and captures the
 * exact request XML that ebics-client-php produces (without sending it anywhere), then
 * writes them plus the keys as fixtures under tests/fixtures/parity/. The Python parity
 * test (tests/test_php_parity.py) cross-checks our output against these.
 *
 * Regenerate with:  php tools/php-parity/generate.php
 * (fixtures are regenerated as one internally-consistent snapshot; commit the result.)
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\EbicsClient;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\EbicsClientOptions;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\User;
use EbicsApi\Ebics\Orders\HIA;
use EbicsApi\Ebics\Orders\HPB;
use EbicsApi\Ebics\Orders\INI;

/** Thrown to grab the fully-built request XML before it is sent anywhere. */
final class CaptureException extends Exception
{
    public function __construct(public string $content)
    {
        parent::__construct('request captured');
    }
}

/** Captures the request instead of performing any network call. */
final class CapturingHttpClient implements HttpClientInterface
{
    public function post(string $url, Request $request): Response
    {
        throw new CaptureException($request->getContent());
    }
}

function capture(callable $build): string
{
    try {
        $build();
    } catch (CaptureException $exception) {
        return $exception->content;
    }
    throw new RuntimeException('no request was captured');
}

$outputDir = __DIR__ . '/../../tests/fixtures/parity';
if (!is_dir($outputDir)) {
    mkdir($outputDir, 0o777, true);
}

$password = 'parity-test-password';
$bank = new Bank('EBICSHOST', 'https://example.com/ebicsweb');
$user = new User('PARTNERPARITY', 'USERPARITY');
$keyring = new Keyring(Keyring::VERSION_30);
$keyring->setPassword($password);

$options = new EbicsClientOptions();
$options->setHttpClient(new CapturingHttpClient());

$client = new EbicsClient($bank, $user, $keyring, $options);
$client->createUserSignatures();

file_put_contents($outputDir . '/ini.xml', capture(fn () => $client->executeStandardOrder(new INI())));
file_put_contents($outputDir . '/hia.xml', capture(fn () => $client->executeStandardOrder(new HIA())));
file_put_contents(
    $outputDir . '/hpb.xml',
    capture(fn () => $client->executeInitializationOrder(new HPB()))
);

$signatureA = $keyring->getUserSignatureA();
$signatureX = $keyring->getUserSignatureX();
$signatureE = $keyring->getUserSignatureE();

$meta = [
    'source' => 'ebics-api/ebics-client-php ' .
        (\Composer\InstalledVersions::getPrettyVersion('ebics-api/ebics-client-php') ?? '?'),
    'password' => $password,
    'host_id' => $bank->getHostId(),
    'partner_id' => $user->getPartnerId(),
    'user_id' => $user->getUserId(),
    'keys' => [
        'signature' => [
            'public' => $signatureA->getPublicKey()->getKey(),
            'private' => $signatureA->getPrivateKey()->getKey(),
        ],
        'authentication' => [
            'public' => $signatureX->getPublicKey()->getKey(),
            'private' => $signatureX->getPrivateKey()->getKey(),
        ],
        'encryption' => [
            'public' => $signatureE->getPublicKey()->getKey(),
            'private' => $signatureE->getPrivateKey()->getKey(),
        ],
    ],
];

file_put_contents(
    $outputDir . '/meta.json',
    json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
);

echo "Wrote INI/HIA/HPB fixtures and meta.json to $outputDir\n";
