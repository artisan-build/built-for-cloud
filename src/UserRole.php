<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum UserRole: string
{
    case Owner = 'owner';
    case Admin = 'admin';
    case Member = 'member';
}
