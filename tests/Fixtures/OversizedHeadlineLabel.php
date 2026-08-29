<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;

/**
 * 65 cases — one past {@see DeclaresHeadlineStat::MAX_LABELS}. Every case
 * is a perfectly bounded identifier and the set is still compile-time:
 * this fixture exists so the CAP is a driven behaviour rather than a
 * sentence in a docblock.
 */
enum OversizedHeadlineLabel: string implements HeadlineLabel
{
    case Label1 = 'label-1';
    case Label2 = 'label-2';
    case Label3 = 'label-3';
    case Label4 = 'label-4';
    case Label5 = 'label-5';
    case Label6 = 'label-6';
    case Label7 = 'label-7';
    case Label8 = 'label-8';
    case Label9 = 'label-9';
    case Label10 = 'label-10';
    case Label11 = 'label-11';
    case Label12 = 'label-12';
    case Label13 = 'label-13';
    case Label14 = 'label-14';
    case Label15 = 'label-15';
    case Label16 = 'label-16';
    case Label17 = 'label-17';
    case Label18 = 'label-18';
    case Label19 = 'label-19';
    case Label20 = 'label-20';
    case Label21 = 'label-21';
    case Label22 = 'label-22';
    case Label23 = 'label-23';
    case Label24 = 'label-24';
    case Label25 = 'label-25';
    case Label26 = 'label-26';
    case Label27 = 'label-27';
    case Label28 = 'label-28';
    case Label29 = 'label-29';
    case Label30 = 'label-30';
    case Label31 = 'label-31';
    case Label32 = 'label-32';
    case Label33 = 'label-33';
    case Label34 = 'label-34';
    case Label35 = 'label-35';
    case Label36 = 'label-36';
    case Label37 = 'label-37';
    case Label38 = 'label-38';
    case Label39 = 'label-39';
    case Label40 = 'label-40';
    case Label41 = 'label-41';
    case Label42 = 'label-42';
    case Label43 = 'label-43';
    case Label44 = 'label-44';
    case Label45 = 'label-45';
    case Label46 = 'label-46';
    case Label47 = 'label-47';
    case Label48 = 'label-48';
    case Label49 = 'label-49';
    case Label50 = 'label-50';
    case Label51 = 'label-51';
    case Label52 = 'label-52';
    case Label53 = 'label-53';
    case Label54 = 'label-54';
    case Label55 = 'label-55';
    case Label56 = 'label-56';
    case Label57 = 'label-57';
    case Label58 = 'label-58';
    case Label59 = 'label-59';
    case Label60 = 'label-60';
    case Label61 = 'label-61';
    case Label62 = 'label-62';
    case Label63 = 'label-63';
    case Label64 = 'label-64';
    case Label65 = 'label-65';
}
