<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RuntimeException;

final class ConformanceFailed extends RuntimeException
{
    public function __construct(private readonly ConformanceReport $conformanceReport)
    {
        parent::__construct($conformanceReport->canonicalJson());
    }

    public function report(): ConformanceReport
    {
        return $this->conformanceReport;
    }
}
