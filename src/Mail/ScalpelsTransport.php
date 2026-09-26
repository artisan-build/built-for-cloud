<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mail;

use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloudContracts\Mail\ManagedMail;
use Closure;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Override;
use ReflectionProperty;
use SensitiveParameter;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\AbstractTransport;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Message;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\TextPart;
use Symfony\Component\Mime\RawMessage;
use Throwable;

final class ScalpelsTransport extends AbstractTransport
{
    private const int REQUEST_TIMEOUT_SECONDS = 8;

    private const int MAX_ATTEMPTS = 2;

    private const int MAX_RETRY_AFTER_SECONDS = 5;

    /**
     * @param  Closure(): TransportInterface  $logTransport
     * @param  Closure(int): void|null  $sleep
     */
    public function __construct(
        private readonly Factory $http,
        private readonly Application $app,
        private readonly Closure $logTransport,
        private readonly QueuedMailIdentity $queuedMailIdentity,
        ?Closure $sleep = null,
    ) {
        parent::__construct();

        $this->sleep = $sleep ?? static function (int $seconds): void {
            sleep($seconds);
        };
    }

    /** @var Closure(int): void */
    private readonly Closure $sleep;

    #[Override]
    public function send(
        #[SensitiveParameter] RawMessage $message,
        #[SensitiveParameter] ?Envelope $envelope = null,
    ): ?SentMessage {
        try {
            if ($message instanceof Email) {
                $this->queuedMailIdentity->apply($message);
            }

            return parent::send($message, $envelope);
        } catch (TransportException $failure) {
            throw new TransportException($failure->getMessage(), $failure->getCode());
        } catch (Throwable) {
            throw new TransportException('Managed mail delivery failed.');
        }
    }

    #[Override]
    public function __toString(): string
    {
        return 'scalpels';
    }

    #[Override]
    protected function doSend(#[SensitiveParameter] SentMessage $message): void
    {
        try {
            $connection = ManagedAuthConnection::current();
        } catch (Throwable) {
            if ($this->app->environment('local')) {
                $this->sendToLog($message);

                return;
            }

            throw new TransportException(
                'The scalpels mailer needs a Scalpels-managed installation. Standalone apps must configure their own mailer via MAIL_MAILER.',
            );
        }

        try {
            $encoded = $this->encodedPayload($message, $connection);
            $idempotencyKey = hash('sha256', $message->getMessageId());
            $request = $this->request($connection, $idempotencyKey, $encoded);

            for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
                try {
                    $response = $request->post($connection->baseUrl.ManagedMail::PATH);
                } catch (Throwable) {
                    if ($attempt < self::MAX_ATTEMPTS) {
                        continue;
                    }

                    throw new TransportException('Managed mail delivery failed.');
                }

                if ($response->status() === 202) {
                    $message->setMessageId($this->responseMessageId($response));

                    return;
                }

                if ($attempt < self::MAX_ATTEMPTS && $this->isRetryable($response->status())) {
                    $retryAfter = $this->retryAfter($response);

                    if ($retryAfter > 0) {
                        ($this->sleep)($retryAfter);
                    }

                    continue;
                }

                throw new TransportException('Managed mail delivery failed.', $response->status());
            }
        } catch (TransportException $failure) {
            throw new TransportException($failure->getMessage(), $failure->getCode());
        } catch (Throwable) {
            throw new TransportException('Managed mail delivery failed.');
        }
    }

    private function sendToLog(#[SensitiveParameter] SentMessage $message): void
    {
        try {
            $logged = ($this->logTransport)()->send($message->getOriginalMessage(), $message->getEnvelope());

            if ($logged !== null) {
                $message->setMessageId($logged->getMessageId());
            }
        } catch (Throwable) {
            throw new TransportException('Managed mail delivery failed.');
        }
    }

    private function request(
        #[SensitiveParameter] ManagedAuthConnection $connection,
        string $idempotencyKey,
        #[SensitiveParameter] string $encoded,
    ): PendingRequest {
        $request = $this->http
            ->acceptJson()
            ->withToken($connection->clientSecret)
            ->withHeaders([
                'Bfc-Contract-Version' => ManagedMail::CONTRACT_VERSION,
                'Idempotency-Key' => $idempotencyKey,
            ])
            ->timeout(self::REQUEST_TIMEOUT_SECONDS)
            ->withBody($encoded, 'application/json');

        return $connection->caBundle === null
            ? $request
            : $request->withOptions(['verify' => $connection->caBundle]);
    }

    private function encodedPayload(
        #[SensitiveParameter] SentMessage $message,
        #[SensitiveParameter] ManagedAuthConnection $connection,
    ): string {
        $email = $message->getOriginalMessage();

        if (! $email instanceof Email || $this->hasCustomBody($email)) {
            throw new TransportException('Managed mail delivery failed.');
        }

        [$to, $cc, $bcc, $subject, $html, $text, $attachments] = ManagedMail::PAYLOAD_FIELDS;
        $recipientLists = [
            $to => $this->recipients($email->getTo()),
            $cc => $this->recipients($email->getCc()),
            $bcc => $this->recipients($email->getBcc()),
        ];
        $recipientCount = array_sum(array_map(count(...), $recipientLists));

        if ($recipientCount === 0 || ! ManagedMail::isRecipientCountWithinLimit($recipientCount)) {
            throw new TransportException('Managed mail delivery failed.');
        }

        $subjectValue = $email->getSubject();
        $htmlValue = $this->body($email->getHtmlBody());
        $textValue = $this->body($email->getTextBody());

        if ($subjectValue === null
            || preg_match('/[\r\n]/', $subjectValue) === 1
            || ($htmlValue === null && $textValue === null)) {
            throw new TransportException('Managed mail delivery failed.');
        }

        $mailPayload = [
            ...$recipientLists,
            $subject => $subjectValue,
            $html => $htmlValue,
            $text => $textValue,
            $attachments => array_map($this->attachment(...), $email->getAttachments()),
        ];

        if (array_keys($mailPayload) !== ManagedMail::PAYLOAD_FIELDS) {
            throw new TransportException('Managed mail delivery failed.');
        }

        $encoded = json_encode([
            'connection_id' => $connection->connectionId,
            'installation_id' => $connection->installationId,
            ...$mailPayload,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if (! ManagedMail::isMessageSizeWithinLimit(strlen($encoded))) {
            throw new TransportException('Managed mail delivery failed.');
        }

        return $encoded;
    }

    /**
     * @param  list<Address>  $addresses
     * @return list<array<string, string>>
     */
    private function recipients(#[SensitiveParameter] array $addresses): array
    {
        [$addressField, $nameField] = ManagedMail::RECIPIENT_FIELDS;

        return array_map(static function (Address $address) use ($addressField, $nameField): array {
            $name = $address->getName();

            if (preg_match('/[\r\n]/', $name) === 1) {
                throw new TransportException('Managed mail delivery failed.');
            }

            return $name === ''
                ? [$addressField => $address->getAddress()]
                : [$addressField => $address->getAddress(), $nameField => $name];
        }, $addresses);
    }

    /** @return array<string, string> */
    private function attachment(#[SensitiveParameter] DataPart $attachment): array
    {
        [$filenameField, $contentTypeField, $contentField] = ManagedMail::ATTACHMENT_FIELDS;
        $filename = $attachment->getFilename();
        $contentType = $attachment->getContentType();

        if ($filename === null
            || preg_match('/[\r\n]/', $filename) === 1
            || preg_match('/\A[A-Za-z0-9!#$&^_.+\-]+\/[A-Za-z0-9!#$&^_.+\-]+\z/D', $contentType) !== 1) {
            throw new TransportException('Managed mail delivery failed.');
        }

        return [
            $filenameField => $filename,
            $contentTypeField => $contentType,
            $contentField => base64_encode($attachment->getBody()),
        ];
    }

    private function body(#[SensitiveParameter] mixed $body): ?string
    {
        if ($body === null || is_string($body)) {
            return $body;
        }

        if (is_resource($body)) {
            return (new TextPart($body))->getBody();
        }

        throw new TransportException('Managed mail delivery failed.');
    }

    private function hasCustomBody(#[SensitiveParameter] Email $email): bool
    {
        return (new ReflectionProperty(Message::class, 'body'))->getValue($email) !== null;
    }

    private function responseMessageId(#[SensitiveParameter] Response $response): string
    {
        $payload = $response->json();
        $messageId = is_array($payload) ? ($payload['message_id'] ?? null) : null;

        if (! is_string($messageId)
            || preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/Di', $messageId) !== 1) {
            throw new TransportException('Managed mail delivery failed.');
        }

        return $messageId;
    }

    private function isRetryable(int $status): bool
    {
        return $status === 429 || $status >= 500;
    }

    private function retryAfter(#[SensitiveParameter] Response $response): int
    {
        $value = trim($response->header('Retry-After'));

        return $value !== '' && ctype_digit($value)
            ? min((int) $value, self::MAX_RETRY_AFTER_SECONDS)
            : 0;
    }
}
