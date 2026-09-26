<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Mail\ScalpelsTransport;
use ArtisanBuild\BuiltForCloudContracts\Mail\ManagedMail;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Mail\MailManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\TextPart;
use Symfony\Component\Mime\RawMessage;

uses(RefreshDatabase::class);

const SCALPELS_MESSAGE_ID = '01999f54-8e7d-7110-8c1b-9f261919f68f';

/** @return array{base_url: string, bearer: string, connection_id: string, installation_id: string, ca_bundle: string} */
function configureManagedMailConnection(): array
{
    $connection = [
        'base_url' => 'https://managed-mail-authority.example.test',
        'bearer' => 'managed-mail-private-bearer',
        'connection_id' => '01999f54-1111-7110-8c1b-9f261919f68f',
        'installation_id' => '01999f54-2222-7110-8c1b-9f261919f68f',
        'ca_bundle' => '/test-created/managed-mail-ca.pem',
    ];

    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => $connection['connection_id'],
        'organization_id' => '01999f54-3333-7110-8c1b-9f261919f68f',
        'installation_id' => $connection['installation_id'],
        'authority_base_url' => $connection['base_url'],
    ]);
    config([
        'built-for-cloud.managed.client_secret' => $connection['bearer'],
        'built-for-cloud.managed.ca_bundle' => $connection['ca_bundle'],
    ]);

    return $connection;
}

function managedMailEmail(string $messageId = 'managed-mail-message@example.test'): Email
{
    $email = (new Email)
        ->from(new Address('private-sender@example.test', 'Private Sender'))
        ->replyTo(new Address('private-reply@example.test', 'Private Reply'))
        ->to(new Address('to@example.test', 'Tō Recipient'))
        ->subject('Managed subject')
        ->text('Managed text body');
    $email->getHeaders()->addIdHeader('Message-ID', $messageId);

    return $email;
}

/** @param Closure(int): void|null $sleep */
function resolvedScalpelsTransport(?Closure $sleep = null): ScalpelsTransport
{
    return new ScalpelsTransport(
        app(Factory::class),
        app(),
        static fn (): TransportInterface => Mail::mailer('log')->getSymfonyTransport(),
        $sleep,
    );
}

it('registers through Laravel without replacing host mailers or the explicit default', function (): void {
    $manager = app(MailManager::class);
    $transport = $manager->mailer('scalpels')->getSymfonyTransport();

    expect(config('mail.mailers.array'))->toBe(['transport' => 'array'])
        ->and(config('mail.mailers.log'))->toBeArray()
        ->and(config('mail.mailers.scalpels'))->toBe(['transport' => 'scalpels'])
        ->and(config('mail.default'))->toBe('log')
        ->and($transport)->toBeInstanceOf(ScalpelsTransport::class);

    config(['mail.default' => 'array']);

    expect($manager->getDefaultDriver())->toBe('array');
});

it('maps structured content exactly and sends the managed authority envelope and transport options', function (): void {
    $connection = configureManagedMailConnection();
    $binary = "\x00\xFFattachment\x10bytes";
    $captured = null;
    $capturedOptions = null;
    Http::fake(function (ClientRequest $request, array $options) use (&$captured, &$capturedOptions) {
        $captured = $request;
        $capturedOptions = $options;

        return Http::response(['message_id' => SCALPELS_MESSAGE_ID], 202);
    });
    $email = managedMailEmail();
    $email
        ->cc(new Address('cc@example.test', 'Céline Copy'))
        ->bcc(new Address('bcc@example.test'))
        ->subject('Unicode snowman ☃ subject')
        ->html('<p>Héllo HTML ☃</p>')
        ->text('Héllo text ☃')
        ->attach($binary, 'résumé.bin', 'application/octet-stream');
    $email->getHeaders()->addTextHeader('X-Private-Custom', 'must-be-dropped');

    $sent = resolvedScalpelsTransport()->send($email);

    expect($sent?->getMessageId())->toBe(SCALPELS_MESSAGE_ID)
        ->and($captured)->toBeInstanceOf(ClientRequest::class)
        ->and($captured->method())->toBe('POST')
        ->and($captured->url())->toBe($connection['base_url'].ManagedMail::PATH)
        ->and($captured->hasHeader('Authorization', 'Bearer '.$connection['bearer']))->toBeTrue()
        ->and($captured->hasHeader('Bfc-Contract-Version', ManagedMail::CONTRACT_VERSION))->toBeTrue()
        ->and($captured->hasHeader('Idempotency-Key', hash('sha256', 'managed-mail-message@example.test')))->toBeTrue()
        ->and($captured->hasHeader('Accept', 'application/json'))->toBeTrue()
        ->and($captured->hasHeader('Content-Type', 'application/json'))->toBeTrue()
        ->and($capturedOptions['verify'] ?? null)->toBe($connection['ca_bundle'])
        ->and($capturedOptions['timeout'] ?? null)->toBe(8);

    $payload = json_decode($captured->body(), true, flags: JSON_THROW_ON_ERROR);

    expect($payload)->toBe([
        'connection_id' => $connection['connection_id'],
        'installation_id' => $connection['installation_id'],
        'to' => [['address' => 'to@example.test', 'name' => 'Tō Recipient']],
        'cc' => [['address' => 'cc@example.test', 'name' => 'Céline Copy']],
        'bcc' => [['address' => 'bcc@example.test']],
        'subject' => 'Unicode snowman ☃ subject',
        'html' => '<p>Héllo HTML ☃</p>',
        'text' => 'Héllo text ☃',
        'attachments' => [[
            'filename' => 'résumé.bin',
            'content_type' => 'application/octet-stream',
            'content' => base64_encode($binary),
        ]],
    ])->and(array_keys($payload))->not->toContain('from', 'reply_to', 'sender', 'headers', 'X-Private-Custom');
    expect(base64_decode($payload['attachments'][0]['content'], true))->toBe($binary);
});

it('replays retryable HTTP outcomes once with the same idempotency key and bounded retry after', function (int $status): void {
    configureManagedMailConnection();
    $sleeps = [];
    Http::fakeSequence()
        ->push(['error' => 'retryable'], $status, ['Retry-After' => '30'])
        ->push(['message_id' => SCALPELS_MESSAGE_ID], 202);

    $sent = resolvedScalpelsTransport(function (int $seconds) use (&$sleeps): void {
        $sleeps[] = $seconds;
    })->send(managedMailEmail('retryable-message@example.test'));
    $requests = Http::recorded()->map(fn (array $pair): ClientRequest => $pair[0]);

    expect($sent?->getMessageId())->toBe(SCALPELS_MESSAGE_ID)
        ->and($requests)->toHaveCount(2)
        ->and($requests[0]->header('Idempotency-Key'))->toBe($requests[1]->header('Idempotency-Key'))
        ->and($requests[0]->header('Idempotency-Key'))->toBe([hash('sha256', 'retryable-message@example.test')])
        ->and($sleeps)->toBe([5]);
})->with(['rate limited' => 429, 'provider unavailable' => 503]);

it('replays a network failure once with the same idempotency key', function (): void {
    configureManagedMailConnection();
    Http::fakeSequence()
        ->pushFailedConnection('network-private-provider-detail')
        ->push(['message_id' => SCALPELS_MESSAGE_ID], 202);

    $sent = resolvedScalpelsTransport()->send(managedMailEmail('network-retry@example.test'));
    $requests = Http::recorded()->map(fn (array $pair): ClientRequest => $pair[0]);

    expect($sent?->getMessageId())->toBe(SCALPELS_MESSAGE_ID)
        ->and($requests)->toHaveCount(2)
        ->and($requests[0]->header('Idempotency-Key'))->toBe($requests[1]->header('Idempotency-Key'));
});

it('attempts permanent client failures once and rejects malformed success generically', function (mixed $response, int $status): void {
    configureManagedMailConnection();
    Http::fakeSequence()->push($response, $status);

    $failure = null;

    try {
        resolvedScalpelsTransport()->send(managedMailEmail());
    } catch (Throwable $caught) {
        $failure = $caught;
    }

    expect($failure)->toBeInstanceOf(TransportException::class)
        ->and($failure?->getMessage())->toBe('Managed mail delivery failed.')
        ->and($failure?->getPrevious())->toBeNull();
    Http::assertSentCount(1);
})->with([
    'permanent validation response' => [['error' => 'private-validation-detail'], 422],
    'missing message id' => [[], 202],
    'malformed message id' => [['message_id' => 'not-a-uuid'], 202],
    'malformed JSON' => ['{not-json', 202],
]);

it('delegates a missing local managed connection to log without egress', function (): void {
    app()->detectEnvironment(static fn (): string => 'local');
    $logs = [];
    Log::listen(function ($entry) use (&$logs): void {
        $logs[] = $entry->message;
    });
    Http::fake();

    $sent = app(MailManager::class)->mailer('scalpels')->getSymfonyTransport()
        ->send(managedMailEmail()->text('local-log-body-sentinel'));

    expect($sent)->not->toBeNull()
        ->and(implode("\n", $logs))->toContain('local-log-body-sentinel');
    Http::assertNothingSent();
});

it('refuses a missing managed connection outside local without logging or egress', function (string $environment): void {
    app()->detectEnvironment(static fn (): string => $environment);
    $logs = [];
    Log::listen(function ($entry) use (&$logs): void {
        $logs[] = $entry->message;
    });
    Http::fake();

    expect(fn () => resolvedScalpelsTransport()->send(managedMailEmail()))
        ->toThrow(
            TransportException::class,
            'The scalpels mailer needs a Scalpels-managed installation. Standalone apps must configure their own mailer via MAIL_MAILER.',
        )
        ->and($logs)->toBe([]);
    Http::assertNothingSent();
})->with(['testing', 'production', '']);

it('refuses contract cap violations and unsupported raw or custom message parts before egress', function (): void {
    configureManagedMailConnection();
    Http::fake();
    $transport = resolvedScalpelsTransport();
    $tooManyRecipients = managedMailEmail()->to(...array_map(
        static fn (int $index): Address => new Address("recipient{$index}@example.test"),
        range(1, ManagedMail::MAX_RECIPIENTS + 1),
    ));
    $tooLarge = managedMailEmail()->text(str_repeat('x', ManagedMail::MAX_MESSAGE_BYTES));
    $customPart = managedMailEmail();
    $customPart->setBody(new TextPart('custom-message-part-sentinel'));

    foreach ([$tooManyRecipients, $tooLarge, $customPart, new RawMessage('raw-message-sentinel')] as $message) {
        expect(fn () => $transport->send($message))->toThrow(TransportException::class, 'Managed mail delivery failed.');
    }

    Http::assertNothingSent();
});

it('removes bearer and message content from failures chains reports logs and trace arguments', function (): void {
    $connection = configureManagedMailConnection();
    $sentinels = [
        $connection['bearer'],
        'private-recipient@example.test',
        'private-subject-sentinel',
        'private-body-sentinel',
        'private-attachment-sentinel',
    ];
    $logs = [];
    $attempts = 0;
    Log::listen(function ($entry) use (&$logs): void {
        $logs[] = $entry->message.' '.json_encode($entry->context);
    });
    Exceptions::fake();
    Http::fake(static function () use (&$attempts): never {
        $attempts++;

        throw new RuntimeException('provider exposed '.implode('|', [
            'managed-mail-private-bearer',
            'private-recipient@example.test',
            'private-subject-sentinel',
            'private-body-sentinel',
            'private-attachment-sentinel',
        ]));
    });
    $email = managedMailEmail()
        ->to($sentinels[1])
        ->subject($sentinels[2])
        ->text($sentinels[3])
        ->attach($sentinels[4], 'private-file.bin', 'application/octet-stream');
    $failure = null;

    try {
        resolvedScalpelsTransport()->send($email);
    } catch (Throwable $caught) {
        $failure = $caught;
    }

    expect($failure)->toBeInstanceOf(TransportException::class)
        ->and($failure?->getPrevious())->toBeNull();
    report($failure);
    $reported = collect(Exceptions::reported())->map(static fn (Throwable $exception): string => json_encode([
        'exception' => (string) $exception,
        'trace' => $exception->getTrace(),
        'previous' => $exception->getPrevious(),
    ], JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_THROW_ON_ERROR))->implode("\n");
    $observable = (string) $failure."\n"
        .json_encode($failure?->getTrace(), JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_THROW_ON_ERROR)."\n"
        .$reported."\n".implode("\n", $logs);

    foreach ($sentinels as $sentinel) {
        expect($observable)->not->toContain($sentinel);
    }

    expect($attempts)->toBe(2);
    Exceptions::assertReported(TransportException::class);
});
