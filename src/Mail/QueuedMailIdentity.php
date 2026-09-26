<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mail;

use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessing;
use SensitiveParameter;
use Symfony\Component\Mime\Email;

final class QueuedMailIdentity
{
    /** @var array<int, array{uuid: string, ordinal: int}> */
    private array $attempts = [];

    public function processing(JobProcessing $event): void
    {
        $uuid = $event->job->uuid();

        if (is_string($uuid) && $uuid !== '') {
            $this->attempts[spl_object_id($event->job)] = ['uuid' => $uuid, 'ordinal' => 0];
        }
    }

    public function finished(JobAttempted $event): void
    {
        unset($this->attempts[spl_object_id($event->job)]);
    }

    public function apply(#[SensitiveParameter] Email $email): void
    {
        $jobId = array_key_last($this->attempts);

        if ($jobId === null) {
            return;
        }

        $this->attempts[$jobId]['ordinal']++;

        if ($email->getHeaders()->has('Message-ID')) {
            return;
        }

        $identity = $this->attempts[$jobId]['uuid']."\0".$this->attempts[$jobId]['ordinal'];
        $email->getHeaders()->addIdHeader(
            'Message-ID',
            hash('sha256', $identity).'@managed-mail.builtforcloud',
        );
    }
}
