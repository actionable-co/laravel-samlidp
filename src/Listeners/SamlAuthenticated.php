<?php

namespace CodeGreenCreative\SamlIdp\Listeners;

use Illuminate\Auth\Events\Authenticated;
use CodeGreenCreative\SamlIdp\Jobs\SamlSso;
use Illuminate\Support\Facades\Log;

class SamlAuthenticated
{
    /**
     * Listen for the Authenticated event
     *
     * @param  Authenticated $event [description]
     * @return [type]               [description]
     */
    public function handle(Authenticated $event)
    {
        if (
            in_array($event->guard, config('samlidp.guards')) &&
            request()->filled('SAMLRequest') &&
            !request()->is('saml/logout') &&
            request()->isMethod('get')
        ) {
            abort(response(SamlSso::dispatchSync($event->guard), 302));
        }

        $relayState = request()->input('RelayState');

        if ($relayState) {
            session(['saml_relay_state' => $relayState]);
        }

        if (!request()->filled('SAMLRequest')) {
            Log::error('SAMLRequest parameter is missing in the request.', ['userId' => $event->user->id]);
            return;
        }

        SamlSso::dispatch($event->user);
    }
}
