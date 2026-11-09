<?php
declare(strict_types=1);

if (is_post()) {
    if (Auth::session()) Auth::checkCsrf();
    if ($u = Auth::user()) Audit::log('logout', 'user:' . $u['username']);
    Auth::logout();
}
redirect('/login');
