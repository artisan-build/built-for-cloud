<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\HttpContract;

/** Closed command, case, and schema vocabulary shared by the P6c runners and tests. */
final class P6GateContract
{
    public const string SCHEMA = 'bfc.p6.live.v1';

    public const int CONTRACT_MAJOR = BuiltForCloud::API_VERSION;

    public const string CONTRACT_HEADER = HttpContract::MAJOR_HEADER;

    /** @var list<string> */
    public const array POSTGRES_CASES = [
        'uniqueness',
        'row_lock',
        'managed_transition',
        'replay',
        'purpose',
    ];

    /** @var list<string> */
    public const array LIVE_CASES = [
        'fresh_migration_and_install',
        'identical_install_rerun',
        'meta',
        'contract_major_accepted',
        'contract_major_missing_refused',
        'contract_major_malformed_refused',
        'contract_major_duplicate_field_refused',
        'contract_major_unsupported_refused',
        'fixed_purpose_admitted',
        'wrong_purpose_refused',
        'wrong_audience_refused',
        'wrong_installation_refused',
        'spoofed_client_refused',
        'cross_node_replay_refused',
        'cross_node_rotation_visible',
        'cross_node_revocation_visible',
        'single_shared_managed_refresh',
        'session_established_on_a',
        'session_accepted_on_b',
        'session_invalidated_on_a',
        'session_refused_on_b',
        'both_nodes_handled_traffic',
        'clean_teardown',
    ];

    /** @var list<string> */
    public const array COORDINATOR_COMMANDS = [
        'composer stan',
        'composer lint:test',
        'composer test',
        'composer test:pgsql',
        'composer test:p6c-live',
    ];

    /** @var list<string> */
    public const array SHARED_ROLES = ['cache', 'replay', 'session'];

    /** @var list<string> */
    public const array ISOLATED_DRIVERS = ['array', 'file', 'null', 'sync', 'sqlite'];
}
