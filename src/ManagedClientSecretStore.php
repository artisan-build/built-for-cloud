<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Hmac\EncryptedHmacKey;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use SensitiveParameter;

/**
 * Custody of the managed-auth client secret delivered over the P1
 * enrolment/rotation calls (frozen design, "Secret custody").
 *
 * The row stores ciphertext, the CONTENT-ADDRESSED version of the
 * APP_KEY that produced it ({@see HmacKeyring} — the exact precedent,
 * reused, so the two stores can never drift on key parsing or ring
 * semantics), and a domain-separated digest used ONLY to compare a
 * lost-response retry without decrypting anything. Reads select the
 * row's exact key version from APP_KEY plus APP_PREVIOUS_KEYS and FAIL
 * CLOSED: a row whose key left the ring, or a MAC-invalid payload,
 * surfaces as {@see HmacKeyUnreadable} and the caller
 * ({@see ManagedAuthConnection} above all) refuses managed auth
 * outright. There is deliberately NO fallback to the environment seam
 * while ciphertext exists; `BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET`
 * answers only when no row does (the Owner-driven adopt path — package
 * follow-up #150 owns its removal).
 *
 * The row rides the SAME staged APP_KEY rewrap as the hmac store
 * (SEC-V3-08): `bfc:hmac:rewrap` sweeps and verifies it, and every
 * ciphertext-REPLACING verb refuses mid-cutover, in-transaction, with
 * {@see RewrapInProgress}. All writes run inside the CALLER's verb
 * transaction (enrolment/rotation/disconnect each own one locked
 * transaction spanning the authority row and this row); those verbs
 * hold {@see HmacWriterBarrier} around check, write and COMMIT — the
 * same discipline the hmac mint/rotate verbs use.
 */
final class ManagedClientSecretStore
{
    public const string KEY = 'installation';

    public const string RETRY_DIGEST_DOMAIN = 'bfc-managed-client-secret';

    public function __construct(private readonly HmacKeyring $keyring) {}

    /**
     * The domain-separated retry digest of one delivery of the secret
     * at one generation: a full SHA-256 over a namespaced construction
     * of the secret, never the secret itself. The same secret at a
     * different generation digests differently, so a stale retry cannot
     * be confirmed by digest alone, and the digest is computed without
     * ever decrypting the stored ciphertext.
     */
    public function retryDigest(#[SensitiveParameter] string $secret, int $generation): string
    {
        return hash('sha256', self::RETRY_DIGEST_DOMAIN.'|'.$generation.'|'.hash('sha256', $secret));
    }

    /**
     * Enrolment's write: the singleton row lands at generation 1 with a
     * fresh ciphertext under the write-primary. A row already existing
     * is the double-enrolment backstop and refuses without touching it.
     */
    public function install(#[SensitiveParameter] string $secret): void
    {
        $encrypted = $this->keyring->encrypt($secret);

        try {
            DB::table('bfc_managed_client_secrets')->insert([
                'key' => self::KEY,
                'client_secret_generation' => 1,
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
                'secret_retry_digest' => $this->retryDigest($secret, 1),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (QueryException $exception) {
            if (str_contains($exception->getMessage(), 'bfc_managed_client_secrets')) {
                throw new ManagedAuthRefused('already_managed', previous: $exception);
            }

            throw $exception;
        }
    }

    /**
     * Rotation's write: a compare-and-swap on the row's OWN monotonic
     * counter — the authority generation never moves here. A stale
     * expectation refuses; a fresh one replaces the ciphertext under
     * the write-primary and returns the new generation. Mid-rewrap (the
     * row still on an old key version) the replacement refuses
     * retry-later: interleaving a ciphertext swap with a half-finished
     * sweep is how rows fossilize under dropped keys.
     */
    public function rotate(int $expectedGeneration, #[SensitiveParameter] string $secret): int
    {
        if ($this->cutoverInProgress()) {
            throw RewrapInProgress::refusing('client secret rotation');
        }

        $encrypted = $this->keyring->encrypt($secret);
        $generation = $expectedGeneration + 1;

        $changed = DB::table('bfc_managed_client_secrets')
            ->where('key', self::KEY)
            ->where('client_secret_generation', $expectedGeneration)
            ->update([
                'client_secret_generation' => $generation,
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
                'secret_retry_digest' => $this->retryDigest($secret, $generation),
                'updated_at' => now(),
            ]);

        if ($changed !== 1) {
            throw new ManagedAuthRefused($this->exists() ? 'stale_generation' : 'not_managed');
        }

        return $generation;
    }

    /**
     * Disconnect's write: after authority acknowledgement the row is
     * deleted — the ciphertext, its key version and its digest leave
     * storage together. Idempotent by design: an exact disconnect retry
     * that completes after the clear must not fail on it.
     */
    public function clear(): void
    {
        DB::table('bfc_managed_client_secrets')->where('key', self::KEY)->delete();
    }

    public function exists(): bool
    {
        return DB::table('bfc_managed_client_secrets')->where('key', self::KEY)->exists();
    }

    public function generation(): ?int
    {
        $row = DB::table('bfc_managed_client_secrets')
            ->where('key', self::KEY)
            ->first(['client_secret_generation']);

        if ($row === null) {
            return null;
        }

        return (int) $row->client_secret_generation;
    }

    /**
     * The fail-closed read. Null ONLY while no persisted secret exists
     * (the environment fallback's lone jurisdiction); every other
     * outcome is the plaintext or {@see HmacKeyUnreadable}. The stored
     * version SELECTS the key — the ring is never scanned — so
     * unreadable state is loud and specific, never "mac invalid"
     * roulette, and an unreadable row can never be answered from the
     * environment seam instead.
     */
    public function plaintext(): ?string
    {
        $row = DB::table('bfc_managed_client_secrets')
            ->where('key', self::KEY)
            ->first(['secret_ciphertext', 'secret_key_version']);

        if ($row === null) {
            return null;
        }

        return $this->keyring->decrypt((string) $row->secret_ciphertext, is_string($row->secret_key_version) ? $row->secret_key_version : null);
    }

    /**
     * Whether an APP_KEY cutover over this row is in progress: the row
     * exists and still carries a non-primary key version. This is what
     * pauses {@see rotate()} — the managed-secret mirror of
     * {@see HmacKeyring::cutoverInProgress()} over the hmac store.
     */
    public function cutoverInProgress(): bool
    {
        return $this->oldVersionRow($this->keyring->writeVersion()) !== null;
    }

    /**
     * The rewrap sweep's input: the singleton row while it carries a
     * non-primary (or absent) key version, null once it has crossed.
     *
     * @return object{secret_ciphertext: string, secret_key_version: string|null}|null
     */
    public function oldVersionRow(string $writeVersion): ?object
    {
        /** @var object{secret_ciphertext: string, secret_key_version: string|null}|null $row */
        $row = DB::table('bfc_managed_client_secrets')
            ->where('key', self::KEY)
            ->where(function ($query) use ($writeVersion): void {
                $query->whereNull('secret_key_version')
                    ->orWhere('secret_key_version', '!=', $writeVersion);
            })
            ->first(['secret_ciphertext', 'secret_key_version']);

        return $row;
    }

    /**
     * The rewrap sweep's guarded write: re-encrypted ciphertext lands
     * only on the row whose version this sweep READ, so a concurrent
     * rotation's fresher ciphertext is never clobbered by a stale
     * rewrite.
     */
    public function rewrap(?string $fromKeyVersion, EncryptedHmacKey $encrypted): void
    {
        DB::table('bfc_managed_client_secrets')
            ->where('key', self::KEY)
            ->where(function ($query) use ($fromKeyVersion): void {
                $fromKeyVersion === null
                    ? $query->whereNull('secret_key_version')
                    : $query->where('secret_key_version', $fromKeyVersion);
            })
            ->update([
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
                'updated_at' => now(),
            ]);
    }
}
